#!/usr/bin/env python3
"""Retrieve last 24 hours of IOCs from MISP and push to Splunk via API.

   NOTE: This script is a beta version. Use at your own risk.
"""

import requests
import sys
import configparser

from typing import List
from pymisp import PyMISP

__author__ = 'Bradley Logan, Ian Furr'
__version__ = '0.4'
__email__ = 'bradley.logan@rhisac.org. Ian Furr'


# Override defaults here
# Splunk
SPLUNK_CONFIG_SECTION = "splunk"
SPLUNK_HEADERS = None
SPLUNK_BASE_URL = None
SPLUNK_KVSTORE_NAME = 'threat_intel'

# MISP
CONFIG_PATH = "./misp/splunk/rh-isac.conf"
MISP_CONFIG_SECTION = "RH-ISAC MISP"
MISP_URL = "https://misp.rhisac.org"
OUTPUT_FIELDS = ('value', 'type', 'timestamp', 'Tag', 'Event')
VETTED_TAG = "rhisac: vetted"



def auth_to_splunk(auth_details: dict) -> bool:
    """Authenticate to Splunk.
    
    Params
    _______
    auth_details: dict
        Dictionary of authentication details pulled from rh-isac.conf
    Returns
    _______
    bool
        True if successful, False if not successful.
    """
    global SPLUNK_HEADERS, SPLUNK_BASE_URL
    SPLUNK_BASE_URL = auth_details.get('BASE_URL')
    auth_data = {
        'username': auth_details.get('username'),
        'password': auth_details.get('password'),
        'output_mode': 'json',
    }

    url = f"{SPLUNK_BASE_URL}/services/auth/login"
    try:
        auth_resp = requests.post(url,
                                  data=auth_data,
                                  verify=False)
    except Exception as e:
        print(f"Unable to connect to Splunk. Check the base_url in your rh-isac.conf file: {str(e)}")
        return False

    if auth_resp.status_code == 401:
        print("Failed to authenticate to Splunk. Verify the username/password in your rh-isac.conf file are correct")
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
            'ioc_type': ind['type'].lower(),
            'updated': int(ind['timestamp']) / 1000,
            'source': "RH-ISAC Vetted",
            'tags': " | ".join([t['event'] for t in ind['tags']]),
        }
        if ind['type'] == 'url':  # handle domains with "URL" type
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
        if ind['type'] not in('ip-dst', 'email-src', 'md5', 'sha256', 'sha1', 'domain', 'url'):
            print(f"Error parsing IOC type: {ind['type']} \n Please record this mesage and notify RH-ISAC staff.")
            continue
        output.append(fields)
    return output


def get_last24h_vetted_iocs(key: str) -> List[dict]:
    """Query the MISP API for last 24 hours of RH-ISAC Vetted IOCs and return

    Returns
    _______
    list[dict]
        A list of IOCs as dictionaries
    """

    # Instantiate API Object
    try:
        misp = PyMISP(url=MISP_URL, key=key)
    except Exception as e:
        print(e)
        exit()

    print(f'\nGetting all IOCs added to MISP in past 24 hours...')

    # Query API for IOCs
    try:
        results = misp.search('attributes', tags=[VETTED_TAG], timestamp='1d')
        iocs = results['Attribute']
        print(f'Got {len(iocs)} IOCs from MISP')
    except Exception as e:
        print(f'Error while query MISP for IOCs: {str(e)}')
        exit()

    return iocs


def filter_results(iocs: List[dict]) -> List[dict]:
    """Take a list of IOC dictionaries and return a filtered list

    Returns
    _______
    list[dict]
        A list of IOCs as dictionaries

    Parameters
    ----------
    list[dict]
        A list of IOCs as dictionaries
    """
    out = []
    for ioc in iocs:
        keep = {}
        for k,v in ioc.items():
            if k not in OUTPUT_FIELDS:
                continue
            else:
                if k == 'Tag':
                    keep['tags'] = "|".join([x['name'] for x in v if x['name'] != VETTED_TAG])
                elif k == 'Event':
                    keep['event'] = v['info']
                else:
                    keep[k] = v
        out.append(keep)
    return out


def main():
    # Obtain Credentials
    conf = configparser.ConfigParser()    
    if not conf.read(CONFIG_PATH):
        if not conf.read(CONFIG_PATH):
            print(f'Config file {CONFIG_PATH} not found')
            exit()
    
    # Check config for relevant sections
    if SPLUNK_CONFIG_SECTION not in conf.sections():
        print(f'Missing config section "{SPLUNK_CONFIG_SECTION}". Please check the example configuration and try again.')
        exit()
    if MISP_CONFIG_SECTION not in conf.sections():
        print(f'Missing config section "{MISP_CONFIG_SECTION}". Please check the example configuration and try again.')
        exit()

    try:
        misp_key = conf[MISP_CONFIG_SECTION]['Key']
        splunk_credentials = {
            "splunk_user": conf[SPLUNK_CONFIG_SECTION]['username'],
            "splunk_pass": conf[SPLUNK_CONFIG_SECTION]['password'],
            "SPLUNK_BASE_URL": conf[SPLUNK_CONFIG_SECTION]['base_url'],
        }

    except KeyError as e:
        print(f'Cannot find "{e}" in file {CONFIG_PATH}')
        exit()
    
    raw_iocs = get_last24h_vetted_iocs(misp_key)
    
    print(f'Retrieved {len(raw_iocs)} IOCs from MISP')
    if not raw_iocs:
        print('No IOCs found in last 24h. Nothing to do.')
        sys.exit()

    # Filter MISP output to remove extranious fields
    filtered_iocs = filter_results(raw_iocs)

    # Process IOCs for Splunk Import
    iocs = build_field_values(filtered_iocs)    
    auth_result = auth_to_splunk(splunk_credentials)
    if auth_result:
        # Post to Splunk
        result = post_iocs_to_splunk(iocs)
        if result:
            print(f'Successfully uploaded {len(iocs)} IOCs to Splunk')
        else:
            print(f'Failed to upload IOCs to Splunk')
    else:
        print('Unable to authenticate to Splunk')

if __name__ == '__main__':
    main()