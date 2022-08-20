#!/usr/bin/env python3
"""Retrieve last 24 hours of IOCs from TruSTAR and upload to Crowdstrike

   NOTE: This script is a crude beta version. Use at your own risk.
"""

import json
import re
import configparser

from datetime import datetime, timedelta, timezone
from typing import List

from falconpy import IOC  # pip install crowdstrike-falconpy
from trustar2 import TruStar, Observables  # pip install trustar2


__author__ = 'Bradley Logan, Ian Furr'
__version__ = '0.4'
__email__ = 'bradley.logan@rhisac.org, ian.furr@rhisac.org'


# Override defaults here
ENCLAVE_IDS = [
    "59cd8570-5dce-4e5b-b09c-9807530a7086",  # RH-ISAC Vetted Indicators
]
TYPE_MAP = {
    'DOMAIN': 'domain',
    'IP4': 'ipv4',
    'IP6': 'ipv6',
    'MD5': 'md5',
    'SHA256': 'sha256',
}
# Override defaults here
CONFIG_PATH = "./rh-isac.conf"
TRUSTAR_CONFIG_SECTION = "TRUSTAR"



# Regex to identify URLs that only contain a domain (not an IP, and no path)
REXP = r'\w{2,}:\/\/(?=.*[A-Za-z])[A-Za-z0-9-\.]+\/?$'


def upload_iocs(iocs: List[dict], credentials: dict) -> None:
    """Upload a list of IOCs to the Crowdstrike API.

    Parameters
    ----------
    observables : List[dict]
        The observables to be uploaded

    Returns
    ----------
    None
        Nothing is returned
    """
    debug = False

    falcon = IOC(client_id=credentials.get("falcon_client_id"),
                client_secret=credentials.get("falcon_client_secret"))

    # API accepts up to 200 IOCs per request, so create blocks of 200 IOCs
    ioc_count = 0
    ioc_blocks = []
    ioc_block = []
    for ioc in iocs:
        if ioc['type'] not in TYPE_MAP:
            print(f"No Crowdstrike IOC type for TruSTAR type {ioc['type']}. Value: {ioc['value']}")
            continue
        ioc_dict = {
            'source': "RH-ISAC Vetted",
            'action': "detect",
            'expiration': "2023-01-01T00:00:00.000Z",
            'description': "|".join(ioc['tags']),
            'type': TYPE_MAP[ioc['type']],
            'value': ioc['value'],
            'severity': "HIGH",
            'applied_globally': True,
            #'platforms': ['windows'], # Uncomment this line if you are required to specify a platform type
        }
        ioc_block.append(ioc_dict)
        ioc_count += 1
        if len(ioc_block) >= 200:
            ioc_blocks.append(ioc_block)
            ioc_block = []
    if ioc_block:
        ioc_blocks.append(ioc_block)

    print(f"About to submit {ioc_count} IOCs in blocks of 200 or less\n")
    for i, block in enumerate(ioc_blocks):
        # Create IOCs using the IOC Service class
        print(f"Submitting block {i + 1} of {len(ioc_blocks)} to Crowdstrike...")
        body = {
            'comment': f"Uploading {len(block)} RH-ISAC Vetted IOCs",
            'indicators': block,
        }
        if debug:
            print(f"Block #{i}:\n {body}")
        response = falcon.indicator_create(body=body)
        print(" ")
        
        # Troubleshooting/Error handling
        if debug:
            print(response)
            print(" ")

        # If 400 is returned, check for duplicates and resubmit without them. 
        if int(response.get('status_code')) == 400:
            print("400 Response code recieved, processing IOCs with errors.")
            errors = response.get('body').get('resources')
            if debug:
                print(errors)
            # Iterate through the list of errors and check "message" 
            # field for duplicate type errors
            for error in errors:
                if "Warning: Duplicate type" in error.get('message'):
                    duplicate_ioc_value = error.get('value')
                    print(f"Removing duplicate IOC: {duplicate_ioc_value}")
                    for ioc in block:
                        # values that DO NOT contain errors
                            if ioc.get('value') == duplicate_ioc_value:
                                block.remove(ioc)
                                continue
                else:
                    print(f"Unknown error with value: {error.get('value')}")
                    print(f"Message: {error.get('message')}")
            body = {
                'comment': f"Uploading {len(block)} RH-ISAC Vetted IOCs",
                'indicators': block,
            }

            print(f"Uploading {len(block)} RH-ISAC Vetted IOCs")
            new_response = falcon.indicator_create(body=body)
            if int(response.get('status_code')) == 200:
                print(f"Block {i} submitted successfully.")
            
            elif debug:
                print(new_response)
            
            else:
                print("Unknown error:")
                print(new_response)
                

        elif int(response.get('status_code')) == 429:
            print("Error 429: Too many requests. Please wait and retry submissions.")
        
        elif int(response.get('status_code')) == 200:
            print(f"Block {i} submitted successfully.")
        
        else:
            print("Unknown response code:")
            print(response)
    return


def retrieve_last24h_obls(ts_credentials: dict) -> List[dict]:
    """Query the TruSTAR 2.0 API for last 24 hours of Observables and return them.

    Returns
    _______
    list[dict]
        A list of Observables as dictionaries
    """

    # Instantiate API Object
    try:
        ts = TruStar(api_key=ts_credentials.get('user_api_key'), api_secret=ts_credentials.get('user_api_secret'), client_metatag=ts_credentials.get('client_metatag'))
    except KeyError as e:
        print(f'{str(e)[1:-1]} in config file "rh-isac.conf". Exiting...')
        exit()

    # Setup to/from times and convert timestamps to milliseconds since epoch
    to_time = datetime.now(timezone.utc)
    from_time = to_time - timedelta(hours=24)  # last 24 hours
    print(f'\nRetrieving all IOCs between {from_time} and {to_time}...')
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

    # Reclassify as Domains those URL Observables that aren't really URLs
    obls = []
    for page in pages:
        for obl in page.data:
            obl_d = obl.serialize()
            if obl_d['type'] == 'URL':
                if '/' not in obl_d['value']:  # URLs always contain a '/'
                    obl_d['type'] = 'DOMAIN'
                else:
                    match = re.match(REXP, obl_d['value'])
                    if match:
                        obl_d['value'] = obl_d['value'].split('://', 1)[1].split('/', 1)[0]
                        obl_d['type'] = 'DOMAIN'
            obls.append(obl_d)
    print(f'Retrieved {len(obls)} IOCs')
    return obls


if __name__ == '__main__':
    # Call main function
    obls = retrieve_last24h_obls()
    if not obls:
        print(f'No IOCs found for the given time period. Exiting...')
        exit()
    upload_iocs(obls)

if __name__ == '__main__':
    # Parse config 
    conf = configparser.ConfigParser()    
    if not conf.read(CONFIG_PATH):
        if not conf.read("../" + CONFIG_PATH):
            print(f'Config file {CONFIG_PATH} not found')
            exit()
    
    try:
        if 'crowdstrike' not in conf.sections():
            print(f'Missing config section "crowdstrike". Please check the example configuration and try again.')
            exit()
        if TRUSTAR_CONFIG_SECTION not in conf.sections():
            print(f'Missing config section "{TRUSTAR_CONFIG_SECTION}". Please check the example configuration and try again.')
            exit()

        credentials = {
                "falcon_client_id":conf['crowdstrike']['falcon_client_id'],
                "falcon_client_secret":conf['crowdstrike']['falcon_client_secret'],
            }

        ts_credentials = {
            "user_api_key":conf[TRUSTAR_CONFIG_SECTION]['user_api_key'],
            "user_api_secret":conf[TRUSTAR_CONFIG_SECTION]['user_api_secret'],
            "client_metatag":conf[TRUSTAR_CONFIG_SECTION]['client_metatag'],
        }
    except KeyError as e:
        print(f'Cannot find "{e}" in file {CONFIG_PATH}')
        exit()

    # Retrieve Observables from TruSTAR
    obls = retrieve_last24h_obls(ts_credentials)
    if not obls:
        print(f'No IOCs found for the given time period. Exiting...')
        exit()
    
    # Upload to MS Graph API
    print("Uploading IOCs to Graph API.")
    upload_iocs(obls, credentials)