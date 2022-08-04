#!/usr/bin/env python3
"""Retrieve last 24 hours of IOCs from TruSTAR and push to Splunk via API.
   Use vetted enclave if none specified in trustar.conf file.

   NOTE: This script is a beta version. Use at your own risk.
   Associated documentation is available upon request.
"""

import json
import requests
import sys
import urllib3
from datetime import datetime, timedelta, timezone
from typing import List

from trustar2 import TruStar, Observables

__author__ = 'Bradley Logan'
__version__ = '0.90'
__email__ = 'bradley.logan@rhisac.org'


# Override defaults here
ENCLAVE_IDS = [
    "7a33144f-aef3-442b-87d4-dbf70d8afdb0",  # RH-ISAC Vetted Indicators
]
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
        print("Failed to authenticate to Splunk. Verify the username/password in your splunk.conf file")
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


def build_field_values(inds) -> List[dict]:
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

def retrieve_last24h_obls() -> List[dict]:
    """Query the TruSTAR 2.0 API for last 24 hours of Observables and return them.

    Returns
    _______
    list[dict]
        A list of Observables as dictionaries
    """

    # Instantiate API Object
    try:
        ts = TruStar.config_from_file(config_file_path="./trustar2.conf", config_role="rh-isac_vetted")
    except KeyError as e:
        print(f'{str(e)[1:-1]} in config file "trustar2.conf". Exiting...')
        exit()

    # Setup to/from times and convert timestamps to milliseconds since epoch
    to_time = datetime.now(timezone.utc)
    from_time = to_time - timedelta(hours=24)  # last 24 hours
    print(f'\nRetrieving all IOCs between UTC {from_time} and {to_time}...')
    from_time = int(from_time.timestamp() * 1000)
    to_time = int(to_time.timestamp() * 1000)

    # Query API for Observables
    # To avoid API limits, query for 1000 Observables at a time
    pages = (
        Observables(ts)
            .set_enclave_ids(ENCLAVE_IDS)
            .set_from(from_time)
            .set_to(to_time)
            .set_page_size(1000)  # Avoid API Limits
            .search()
    )
    obls = [obl for page in pages for obl in page.data]

    # only include most commonly used fields
    out = [
        {
            'value': obl.value,
            'indicatorType': obl.type,
            'priorityLevel': obl.priorityLevel,
            'correlationCount': obl.correlationCount,
            'whitelisted': obl.correlationCount,
            'weight': obl.weight,
            'reason': obl.reason,
            'source': obl.source,
            'sightings': obl.sightings,
            'notes': obl.notes,
            'tags': obl.tags,
            'firstSeen': obl.first_seen,
            'lastSeen': obl.last_seen,
            'enclave_Ids': obl.enclaveIds,
        } for obl in obls
    ]
    return out

if __name__ == '__main__':
    raw_iocs = retrieve_last24h_obls()
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