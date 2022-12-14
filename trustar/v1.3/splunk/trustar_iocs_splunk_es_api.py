#!/usr/bin/env python3
"""Retrieve last 24 hours of IOCs from TruSTAR and push to Splunk via API.
   Use vetted enclave if none specified in trustar.conf file.

   NOTE: This script is a beta version. Use at your own risk.
   Associated documentation is available upon request.
"""

import json
import sys
import urllib3
from datetime import datetime, timedelta
from typing import List, Dict

import requests
from trustar import TruStar, datetime_to_millis

__author__ = 'Bradley Logan'
__version__ = '0.91'
__email__ = 'bradley.logan@rhisac.org'

# If you have decided to not add certificate verification,
# uncomment the below line to disable the InsecureRequestWarning
urllib3.disable_warnings()

SPLUNK_HEADERS = None
SPLUNK_BASE_URL = None


def can_access_splunk() -> bool:
    """Get Splunk authentication token & url, and test connection/access.

    Returns
    _______
    bool
        True if successful, False if not successful.
    """
    global SPLUNK_HEADERS, SPLUNK_BASE_URL
    s_conf = TruStar.config_from_file('splunk.conf', 'main')
    SPLUNK_BASE_URL = s_conf['base_url']
    SPLUNK_HEADERS = {'Authorization': f"Bearer {s_conf['token']}"}

    url = f"{SPLUNK_BASE_URL}/services/authentication/current-context"
    try:
        test_resp = requests.get(url,
                                 headers=SPLUNK_HEADERS,
                                 verify=False)
    except Exception as e:
        print(f"Unable to connect to Splunk. Check the base_url in your splunk.conf file: {str(e)}")
        return False

    if test_resp.status_code == 401:
        print("Failed to authenticate to Splunk. Verify the username/password in your splunk.conf file")
        return False
    elif test_resp.status_code != 200:
        print("Unexpected response from Splunk. Unable to verify access.")
        return False
    return True


def dispatch_lookup_gen_searches() -> bool:
    """Kickoff the Splunk lookup_gen searches after.
    This should be run after new threat intel has been loaded.

    Returns
    _______
    bool
        True if success, False if any errors occurred
    """
    search_names = (
        "Threat - Threat Intelligence By CIDR - Lookup Gen",
        "Threat - Threat Intelligence By Domain - Lookup Gen",
        "Threat - Threat Intelligence By Email - Lookup Gen",
        "Threat - Threat Intelligence By Email Wildcard - Lookup Gen",
        "Threat - Threat Intelligence By File Hash - Lookup Gen",
        "Threat - Threat Intelligence By File Name - Lookup Gen",
        "Threat - Threat Intelligence By File Name Wildcard - Lookup Gen",
        "Threat - Threat Intelligence By System - Lookup Gen",
        "Threat - Threat Intelligence By URL - Lookup Gen",
        "Threat - Threat Intelligence By URL Wildcard - Lookup Gen",
    )
    all_success = True
    for name in search_names:
        url = f'{SPLUNK_BASE_URL}/services/saved/searches/{name}/dispatch'
        try:
            resp = requests.post(url,
                                 headers=SPLUNK_HEADERS,
                                 verify=False)
        except Exception as e:
            print(f"Failed to connect to Splunk: {str(e)}")
            return False

        if resp.status_code != 201:
            print(f"Unexpected response to dispatch of {name} saved search: {resp.status_code}")
            all_success = False
    return all_success


def post_iocs_to_splunk(lookup_name: str, iocs: List[dict]) -> bool:
    """Given a list of IOC dictionaries, group the IOCs by Splunk lookup type.

    Parameters
    __________
    lookup_name : str
        The name of the Splunk lookup to which to post the IOCs
    iocs : list[dict]
        The IOCs to be posted to Splunk

    Returns
    _______
    bool
        True if success, False if any errors occurred
    """
    body = {'item': json.dumps(iocs)}
    url = f'{SPLUNK_BASE_URL}/services/data/threat_intel/item/{lookup_name}'
    try:
        resp = requests.post(url,
                             headers=SPLUNK_HEADERS,
                             data=body,
                             verify=False)
    except Exception as e:
        print(f"Failed to connect to Splunk: {str(e)}")
        return False

    if resp.status_code != 201:
        print(f"Unexpected response from Splunk: HTTP {resp.status_code}")
        print(f"Response: {resp.content}")
        return False

    return True


def categorize(inds: List[dict]) -> Dict[str, List[dict]]:
    """Given a list of IOC dictionaries, group the IOCs by Splunk lookup type.

    Parameters
    __________
    iocs : list[dict]
        The IOCs to categorize

    Returns
    _______
    dict[str, list[dict]]
        Four lists of IOCs, one for each relevant Splunk lookup
    """
    cats = {
        'email_intel': [],
        'file_intel': [],
        'http_intel': [],
        'ip_intel': [],
    }
    for ind in inds:
        fields = {
            'description': " | ".join([t['name'] for t in ind['tags']]),
            'threat_key': "RH-ISAC Vetted",
            'time': int(ind['lastSeen'] / 1000),
        }
        if ind['indicatorType'] in ('CIDR_BLOCK', 'IP'):
            cats['ip_intel'].append({**fields, 'ip': ind['value']})
        elif ind['indicatorType'] == 'EMAIL_ADDRESS':
            cats['email_intel'].append({**fields, 'src_user': ind['value']})
        elif ind['indicatorType'] in ('MD5', 'SHA1', 'SHA256'):
            cats['file_intel'].append({**fields, 'file_hash': ind['value']})
        elif ind['indicatorType'] == 'SOFTWARE':
            cats['file_intel'].append({**fields, 'file_name': ind['value']})
        elif ind['indicatorType'] == 'URL':
            value = ind['value']
            if '://' in value:  # get rid of scheme
                _, value = ind['value'].split('://', 1)
            if '/' in value:
                netloc, remainder = value.split('/', 1)
                if remainder or '@' in netloc or ':' in netloc:  # is a URL
                    kind = 'url'
                else:  # just a domain with '/' at the end
                    value = value[:-1]
                    kind = 'domain'
            else:  # no path
                if '@' in value or ':' in value:
                    kind = 'url'
                else:
                    kind = 'domain'
            if kind == 'domain':
                cats['http_intel'].append({**fields, 'domain': value})
            else:  # url
                cats['http_intel'].append({**fields, 'url': f'*{value}'})
    return cats


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
        sys.exit()

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


def main():
    """Primary function used to extract IOCs from TruSTAR and push to Splunk

    Returns
    _______
    None
    """
    raw_iocs = retrieve_last24h_iocs()
    print(f'Retrieved {len(raw_iocs)} IOCs from TruSTAR')
    if not raw_iocs:
        print('No IOCs found in last 24h. Nothing to do.')
        sys.exit()

    ioc_cats = categorize(raw_iocs)
    have_splunk_access = can_access_splunk()
    if have_splunk_access:
        for lookup_name, iocs in ioc_cats.items():
            if not iocs:
                print(f'No IOCs for lookup {lookup_name}. Skipping.')
            else:  # post if there are some IOCs in the list
                result = post_iocs_to_splunk(lookup_name, iocs)
                if result:
                    print(f'Successfully uploaded {len(iocs)} IOCs to lookup {lookup_name}')
                else:
                    print(f'Failed to upload IOCs to lookup {lookup_name}')
        result = dispatch_lookup_gen_searches()
        if result:
            print("All Lookup Gen saved searches dispatched successfully")
        else:
            print("Some Lookup Gen saved searches were not dispatched successfully")
    else:
        print('Unable to authenticate to Splunk')


if __name__ == '__main__':
    main()
