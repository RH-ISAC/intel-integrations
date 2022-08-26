#!/usr/bin/env python3
"""Retrieve last 24 hours of IOCs from MISP and push to Splunk via API.

   NOTE: This script is a beta version. Use at your own risk.
"""

import configparser
from typing import List
from pymisp import PyMISP 

import json
import urllib3
from typing import List, Dict

import requests


__author__ = 'Bradley Logan, Ian Furr'
__version__ = '0.3'
__email__ = 'bradley.logan@rhisac.org, ian.furr@rhisac.org'

# Override defaults here
CONFIG_PATH = "./misp/splunk/rh-isac.conf"
MISP_CONFIG_SECTION = "RH-ISAC MISP"
SPLUNK_CONFIG_SECTION = "splunk-es"
MISP_URL = "https://misp.rhisac.org"
OUTPUT_FIELDS = ('value', 'type', 'timestamp', 'Tag', 'Event')
VETTED_TAG = "rhisac: vetted"

# If you have decided to not add certificate verification,
# uncomment the below line to disable the InsecureRequestWarning
urllib3.disable_warnings()


def can_access_splunk(splunk_creds: dict) -> bool:
    """Get Splunk authentication token & url, and test connection/access.

    Returns
    _______
    bool
        True if successful, False if not successful.
    """
    SPLUNK_BASE_URL = splunk_creds.get('base_url')
    SPLUNK_HEADERS = {'Authorization': f"Bearer {splunk_creds.get('token')}"}

    url = f"{SPLUNK_BASE_URL}/services/authentication/current-context"
    try:
        test_resp = requests.get(url,
                                 headers=SPLUNK_HEADERS,
                                 verify=False)
    except Exception as e:
        print(f"Unable to connect to Splunk. Check the base_url in your rh-isac.conf file: {str(e)}")
        return False

    if test_resp.status_code == 401:
        print("Failed to authenticate to Splunk. Verify the token in the rh-isac.conf file is correct and has the proper access")
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
            'time': int(ind['timestamp']) / 1000,
        }
        if ind['type'] in ('ip-dst'):
            cats['ip_intel'].append({**fields, 'ip': ind['value']})
        elif ind['type'] == 'email-src':
            cats['email_intel'].append({**fields, 'src_user': ind['value']})
        elif ind['type'] in ('md5', 'sha1', 'sha256'):
            cats['file_intel'].append({**fields, 'file_hash': ind['value']})
        elif ind['type'] in ('domain'):
            cats['http_intel'].append({**fields, 'domain': ind['value']})
        elif ind['type'] == 'URL':
            value = ind['value']
            if '://' in value:  # get rid of scheme
                _, value = ind['value'].split('://', 1)
            cats['http_intel'].append({**fields, 'url': f'*{value}'})
        else:
            print(f"Error parsing IOC Type {ind['type']} \nPlease record this mesage and report it to RH-ISAC Staff.")
            continue
    return cats


def get_last24h_vetted_iocs() -> List[dict]:
    """Query the MISP API for last 24 hours of RH-ISAC Vetted IOCs and return

    Returns
    _______
    list[dict]
        A list of IOCs as dictionaries
    """

    # Instantiate API Object
    try:
        misp = PyMISP(MISP_URL, MISP_KEY)
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


if __name__ == '__main__':
    """Primary function used to extract IOCs from MISP and push to Splunk ES

    Returns
    _______
    None
    """
    conf = configparser.ConfigParser()    
    if not conf.read(CONFIG_PATH):
        if not conf.read("../" + CONFIG_PATH):
            print(f'Config file {CONFIG_PATH} not found')
            exit()
    if MISP_CONFIG_SECTION not in conf.sections():
        print(f'Missing config section "{MISP_CONFIG_SECTION}". Please check the example configuration and try again.')
        exit()
    if SPLUNK_CONFIG_SECTION not in conf.sections():
        print(f'Missing config section "{SPLUNK_CONFIG_SECTION}". Please check the example configuration and try again.')
        exit()
    
    try:
        MISP_KEY = conf[MISP_CONFIG_SECTION]['Key']
        SPLUNK_BASE_URL= conf[SPLUNK_CONFIG_SECTION]['base_url'],
        SPLUNK_TOKEN = conf[SPLUNK_CONFIG_SECTION]['token']
        SPLUNK_HEADERS = conf[SPLUNK_CONFIG_SECTION]['headers']

    except KeyError as e:
        print(f'Cannot find "{e}" in file {CONFIG_PATH}')
        exit()

    # Get IOCS from MISP and remove extra fields
    iocs = get_last24h_vetted_iocs()
    filtered_iocs = filter_results(iocs)
    # Categorize IOCs for Splunk
    ioc_cats = categorize(filtered_iocs)
    
    # Verify Splunk Access
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

