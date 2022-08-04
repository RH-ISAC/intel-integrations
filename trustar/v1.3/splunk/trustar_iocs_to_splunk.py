#!/usr/bin/env python3
"""Retrieve last 24 hours of IOCs from TruSTAR and push to Splunk via API.
   Use vetted enclave if none specified in trustar.conf file.

   NOTE: This script is a beta version. Use at your own risk.
   Associated documentation is available upon request.
"""

import json
import sys
from datetime import datetime, timedelta
from typing import List

import requests
from trustar import TruStar, datetime_to_millis

__author__ = 'Bradley Logan'
__version__ = '0.90'
__email__ = 'bradley.logan@rhisac.org'


SPLUNK_HEADERS = None
SPLUNK_BASE_URL = None
SPLUNK_KVSTORE_NAME = 'threat_intel'


def auth_to_splunk() -> bool:
    """Authenticate to Splunk.

    Returns
    _______
    bool
        True if successful, False if not successful.
    """
    global SPLUNK_HEADERS, SPLUNK_BASE_URL
    s_conf = TruStar.config_from_file('splunk.conf', 'main')
    SPLUNK_BASE_URL = s_conf['base_url']
    auth_data = {
        'username': s_conf['username'],
        'password': s_conf['password'],
        'output_mode': 'json',
    }

    url = f"{SPLUNK_BASE_URL}/services/auth/login"
    try:
        auth_resp = requests.post(url,
                                  data=auth_data,
                                  verify=False)
    except Exception as e:
        print(f"Unable to connect to Splunk. Check the base_url in your splunk.conf file: {str(e)}")
        return False

    if auth_resp.status_code == 401:
        print("Failed to authenticate to Splunk. Verify username/password in your splunk.conf file")
    try:
        SPLUNK_HEADERS = {'Authorization': f"Splunk {auth_resp.json()['sessionKey']}"}
    except Exception as e:
        print(f"Unexpected response from Splunk during authentication.")
        print(f"Response: {auth_resp.content}")
        return False
    return True


def check_splunk_kvstore() -> bool:
    """Check that the Splunk kvstore is configured and if not, create the collection.

    Returns
    _______
    bool
        True if success, False if any errors occurred
    """
    try:
        url = f'{SPLUNK_BASE_URL}/servicesNS/nobody/search/storage/collections/config/'

        # Check if collection exists
        resp = requests.get(url + SPLUNK_KVSTORE_NAME,
                            headers=SPLUNK_HEADERS,
                            verify=False)

        # If collection does not exist, create it
        if resp.status_code == 404 and 'Could not find object id' in str(resp.content):
            print(f'Creating new kvstore collection "{SPLUNK_KVSTORE_NAME}"')
            resp = requests.post(url,
                                 headers=SPLUNK_HEADERS,
                                 data={'name': SPLUNK_KVSTORE_NAME},
                                 verify=False)
            if not resp.status_code == 201:
                print(f'Failed to create kvstore collection {SPLUNK_KVSTORE_NAME}')
                return False
        return True
    except Exception as e:
        print(f"Failed to connect to Splunk: {str(e)}")
        return False


def post_iocs_to_splunk(iocs: List[dict]) -> bool:
    """Given a list of IOC dictionaries, post them to Splunk's API.

    Parameters
    __________
    iocs : list[dict]
        The IOCs to be posted to Splunk

    Returns
    _______
    bool
        True if success, False if any errors occurred
    """
    if not check_splunk_kvstore():  # If kvstore is not configured
        return False

    url = f'{SPLUNK_BASE_URL}/servicesNS/nobody/search/storage/collections/data/'
    url += f'{SPLUNK_KVSTORE_NAME}/batch_save'
    SPLUNK_HEADERS['Content-Type'] = 'application/json'
    try:
        resp = requests.post(url,
                             headers=SPLUNK_HEADERS,
                             json=iocs,
                             verify=False)
    except Exception as e:
        print(f"Failed to connect to Splunk: {str(e)}")
        return False

    if resp.status_code != 200:
        print(f"Unexpected response from Splunk: HTTP {resp.status_code}")
        print(f"Response: {resp.content}")
        return False
    else:
        return True


def build_field_values(inds: List[dict]) -> List[dict]:
    """Given a list of IOC dictionaries, modify the fields/values to prepare for upload to Splunk.

    Parameters
    __________
    iocs : list[dict]
        The IOCs to modify

    Returns
    _______
    list[dict]
        The IOCs with modified fields/values
    """
    output = []
    for ind in inds:
        fields = {
            'value': ind['value'],
            'ioc_type': ind['indicatorType'].lower(),
            'updated': int(ind['lastSeen'] / 1000),
            'source': "RH-ISAC Vetted",
            'tags': " | ".join([t['name'] for t in ind['tags']]),
        }
        if ind['indicatorType'] in ('CIDR_BLOCK', 'IP'):  # add cidr value
            try:
                assert int(ind['value'].split('/', 1)[1]) <= 32
                fields['cidr'] = ind['value']
            except:
                fields['cidr'] = f"{ind['value']}/32"
        elif ind['indicatorType'] == 'URL':  # handle domains with "URL" type
            value = ind['value']
            if '://' in value:  # get rid of URL scheme
                _, value = ind['value'].split('://', 1)
            if '/' in value:
                netloc, remainder = value.split('/', 1)
                if remainder or '@' in netloc or ':' in netloc:  # is a URL
                    fields['wildcard'] = f"*{value}"
                else:  # just a domain with '/' at the end
                    fields['ioc_type'] = 'domain'
                    fields['value'] = value[:-1]
            else:  # no path
                if '@' not in value and ':' not in value:
                    fields['ioc_type'] = 'domain'
                    fields['value'] = value
        output.append(fields)
    return output


def retrieve_last24h_iocs() -> List[dict]:
    """Query the TruSTAR API for last 24 hours of IOCs and return them.

    Returns
    _______
    list[dict]
        A list of IOCs as dictionaries
    """

    # Initiate API Object
    try:
        ts = TruStar(config_file='trustar.conf', config_role='rh-isac_vetted')
    except KeyError as e:
        print(f'{str(e)[1:-1]} in config file "trustar.conf". Exiting...')
        exit()

    # Identify enclaves to query.
    # Pull from "RH-ISAC Vetted Indicators" enclave if none specified
    if not ts.enclave_ids:
        enclaves = ["59cd8570-5dce-4e5b-b09c-9807530a7086"]
    else:
        enclaves = ts.enclave_ids

    # Setup to/from times and convert timestamps to milliseconds since epoch
    from_time = datetime.utcnow() - timedelta(hours=24)  # last 24 hours
    to_time = datetime.utcnow()
    print(f'\nRetrieving all IOCs between UTC {from_time} and {to_time}...')
    from_time = datetime_to_millis(from_time)
    to_time = datetime_to_millis(to_time)
    max_time = datetime_to_millis(datetime(3000, 1, 1))

    # To avoid API restrictions, query for 1000 IOCs at a time,
    # updating the to_time with each loop iteration
    pg_to = to_time
    all_metadata = []
    while True:
        page = ts.search_indicators_page(enclave_ids=enclaves,
                                         from_time=from_time,
                                         to_time=pg_to,
                                         page_size=1000)
        if not page.items:
            break  # if empty, then no IOCs left to fetch; terminate loop

        # get_indicators_metadata only accepts up to 1000 IOCs per call
        inds = ts.get_indicators_metadata(page.items, enclaves)

        earliest_lastseen = max_time  # initialize this with a large value
        for indicator in inds:
            all_metadata.append(indicator.to_dict())
            if indicator.last_seen < earliest_lastseen:
                earliest_lastseen = indicator.last_seen
        pg_to = earliest_lastseen - 1  # prepare for retrieval of next page
        if pg_to < from_time:
            break

    return all_metadata


if __name__ == '__main__':
    raw_iocs = retrieve_last24h_iocs()
    print(f'Retrieved {len(raw_iocs)} IOCs from TruSTAR')
    if not raw_iocs:
        print('No IOCs found in last 24h. Nothing to do.')
        sys.exit()

    iocs = build_field_values(raw_iocs)
    auth_result = auth_to_splunk()
    if auth_result:
        result = post_iocs_to_splunk(iocs)
        if result:
            print(f'Successfully uploaded {len(iocs)} IOCs to Splunk')
        else:
            print(f'Failed to upload IOCs to Splunk')
    else:
        print('Unable to authenticate to Splunk')