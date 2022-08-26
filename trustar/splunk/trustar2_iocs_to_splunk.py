#!/usr/bin/env python3
"""Retrieve last 24 hours of IOCs from TruSTAR and push to Splunk via API.
   Use vetted enclave if none specified in trustar.conf file.

   NOTE: This script is a beta version. Use at your own risk.
   Associated documentation is available upon request.
"""

import requests
import sys
from datetime import datetime, timedelta, timezone
from typing import List
import configparser

from trustar2 import TruStar, Observables

__author__ = 'Bradley Logan, Ian Furr'
__version__ = '0.91'
__email__ = 'bradley.logan@rhisac.org, ian.furr@rhisac.org'


# Override defaults here
ENCLAVE_IDS = [
    "7a33144f-aef3-442b-87d4-dbf70d8afdb0",  # RH-ISAC Vetted Indicators
]
SPLUNK_HEADERS = None
SPLUNK_BASE_URL = None
SPLUNK_KVSTORE_NAME = 'threat_intel'

CONFIG_PATH = "./trustar/splunk/rh-isac.conf"
TRUSTAR_CONFIG_SECTION = "trustar"
SPLUNK_CONFIG_SECTION = "splunk"


def auth_to_splunk(splunk_creds: dict) -> bool:
    """Authenticate to Splunk.

    Parameters
    splunk_creds: dict
        A dict of configuration/credential items pulled from rh-isac.conf
        
    Returns
    _______
    bool
        True if successful, False if not successful.
    """
    global SPLUNK_HEADERS, SPLUNK_BASE_URL
    SPLUNK_BASE_URL = splunk_creds['base_url']
    auth_data = {
        'username': splunk_creds['username'],
        'password': splunk_creds['password'],
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

    Parameters
    ts_credentials: dict
        A dict of configuration/credential items pulled from rh-isac.conf

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

def retrieve_last24h_obls(ts_credentials: dict) -> List[dict]:
    """Query the TruSTAR 2.0 API for last 24 hours of Observables and return them.

    Returns
    _______
    list[dict]
        A list of Observables as dictionaries
    """

    # Instantiate API Object
    try:
        ts = TruStar(api_key=ts_credentials.get('user_api_key'),api_secret=ts_credentials.get('user_api_secret'),client_metatag=ts_credentials.get('client_metatag'))
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
    conf = configparser.ConfigParser()    
    if not conf.read(CONFIG_PATH):
        if not conf.read("../" + CONFIG_PATH):
            print(f'Config file {CONFIG_PATH} not found')
            exit()
    if TRUSTAR_CONFIG_SECTION not in conf.sections():
        print(f'Missing config section "{TRUSTAR_CONFIG_SECTION}". Please check the example configuration and try again.')
        exit()
    if SPLUNK_CONFIG_SECTION not in conf.sections():
        print(f'Missing config section "{SPLUNK_CONFIG_SECTION}". Please check the example configuration and try again.')
        exit()
    
    try:
        ts_credentials = {
            "user_api_key":conf['trustar']['user_api_key'],
            "user_api_secret":conf['trustar']['user_api_secret'],
            "client_metatag":conf['trustar']['client_metatag'],
        }

        splunk_creds = {
            "base_url": conf[SPLUNK_CONFIG_SECTION]['base_url'],
            "username": conf[SPLUNK_CONFIG_SECTION]['username'],
            "password": conf[SPLUNK_CONFIG_SECTION]['password'],
            "headers": conf[SPLUNK_CONFIG_SECTION]['headers']
        }

    except KeyError as e:
        print(f'Cannot find "{e}" in file {CONFIG_PATH}')
        exit()
    
    raw_iocs = retrieve_last24h_obls(ts_credentials)
    print(f'Retrieved {len(raw_iocs)} IOCs from TruSTAR')
    if not raw_iocs:
        print('No IOCs found in last 24h. Nothing to do.')
        sys.exit()

    iocs = build_field_values(raw_iocs)
    auth_result = auth_to_splunk(splunk_creds)
    if auth_result:
        result = post_iocs_to_splunk(iocs)
        if result:
            print(f'Successfully uploaded {len(iocs)} IOCs to Splunk')
        else:
            print(f'Failed to upload IOCs to Splunk')
    else:
        print('Unable to authenticate to Splunk')