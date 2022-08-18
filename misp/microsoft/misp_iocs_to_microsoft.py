#!/usr/bin/env python3
"""Retrieve last 24 hours of IOCs from MISP and output to a JSON file.
"""

__author__ = 'Bradley Logan, Ian Furr'
__version__ = '0.2'
__email__ = 'bradley.logan@rhisac.org, ian.furr@rhisac.org'

import requests 
import urllib.parse
import urllib.request
import json
import configparser

from datetime import datetime, timedelta, timezone
from typing import List

from pymisp import PyMISP

# Override defaults here
CONFIG_PATH = "./misp/rh-isac.conf"
MISP_CONFIG_SECTION = "RH-ISAC MISP"
MISP_URL = "https://misp.rhisac.org"
OUTPUT_FIELDS = ('value', 'type', 'timestamp', 'Tag', 'Event')
OUTPUT_FILENAME = None
VETTED_TAG = "rhisac: vetted"
WINDOW = 120 # Amount of time to retail IOCs

# Enable Debug for additional output
debug = False


def get_last24h_vetted_iocs(key: str) -> List[dict]:
    """Query the MISP API for last 24 hours of RH-ISAC Vetted IOCs and return

    Returns
    _______
    list[dict]
        A list of IOCs as dictionaries
    """
    # Instantiate API Object
    try:
        misp = PyMISP(MISP_URL, key)
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

def get_token(credentials:dict) -> dict:
    """
    Retrieve an Azure AD authentication token and build headers for API requests.
    
    Parameters
    ----------
    credentials : dict
        A dictionary from configparser containing the graph api auth details
    
    Returns
    _______
    list[dict]
        A dict of headers to pass with future requests
    """
    ## Register an Azure Active Directory application with the 'ThreatIndicators.ReadWrite.OwnedBy' Microsoft Graph Permission.
    ## Get your Azure AD tenant administrator to grant administration consent to your application. This is a one-time activity unless permissions change for the application. 
    
    tenantId = credentials.get('tenantId')

    # Azure Active Directory token endpoint.
    url = "https://login.microsoftonline.com/%s/oauth2/v2.0/token" % (tenantId)
    body = {
        'client_id': credentials.get('appId'),
        'client_secret' : credentials.get('appSecret'),
        'grant_type': 'client_credentials',
        'scope': 'https://graph.microsoft.com/.default'
    }

    ## authenticate and obtain AAD Token for future calls
    data = urllib.parse.urlencode(body).encode("utf-8") # encodes the data into a 'x-www-form-urlencoded' type
    req = urllib.request.Request(url, data)
    response = urllib.request.urlopen(req)

    jsonResponse = json.loads(response.read().decode())
    # Grab the token from the response then store it in the headers dict.
    aadToken = jsonResponse["access_token"]
    headers = { 
        'Content-Type' : 'application/json',
        'Accept' : 'application/json',
        'Authorization' : "Bearer " + aadToken
    }
    if len(aadToken) > 0:
        print("Access token acquired.")
    else: 
        print("Unable to obtain AAD Token, check your credentials (and associated permissions) and try again.")
    return headers

def submit_ioc(tibody: dict = None, headers: dict = None) -> requests.Response:
    """
    Post a TI to the GraphAPI
    
    Parameters
    ----------
    tibody : dict
        The observable to be uploaded
    
    headers: dict
        Authentication headers to pass along with the request

    Returns
    ----------
    requests.Response
        The response to submission
    """
    ti_url = "https://graph.microsoft.com/beta/security/tiIndicators"
    
    # The request body must contain at least one email, file, or network observable.
    if tibody == None:
        raise ValueError ('Request body cannot be empty')

    # Make the POST request.
    response = requests.post(ti_url, json.dumps(tibody), headers=headers)

    if response.status_code == 201:
        if debug:
            # If additional visiblity is requested print the JSON contents of the response.
            json_response = response.json()
            print("Response :")
            print(json.dumps(json_response, indent=4))

    else:
        print(f"Error submitting IOC. Error code: {response.status_code}")
        print(f"Error Content:\n{response.content}")
        
    return response

def upload_iocs(iocs: List[dict], credentials: dict) -> None:
    """
    Upload a list of IOCs to the Sentinel Graph API.

    Parameters
    ----------
    iocs : List[dict]
        The observables to be uploaded
    
    credentials : dict
        A dictionary from configparser containing the graph api auth details

    Returns
    ----------
    None
        Nothing is returned
    """
    submitted_iocs = 0
    errored_iocs = []

    # Grab an up to date AAD token + associated auth headers before 
    # attempting to submit IOCs
    headers = get_token(credentials)

    for ioc in iocs:
        # Fill out the common features
        ioc_data = {
            "action": "alert", # REQUIRED - STRING -  Action to take if the indicator is detected within the environment (unknown, allow, block, alert)
            "azureTenantId": credentials.get('tenantId'), # REQURIED - STRING - Azure Active Directory tenant id of submitting client
            "description": ioc.get('event'), # REQUIRED - STRING - Describe the IOC (100chars or less)
            "expirationDateTime": str(datetime.now(timezone.utc) + timedelta(days=WINDOW)), # "2022-08-31T23:59:59.0+00:00", # Now plus 90 days # REQUIRED - DATETIMEOFFSET - indicate when the indicator should expire (UTC)
            "targetProduct": credentials.get('product'), # REQUIRED - STRING - Targeted security product (Azure Sentinel, Microsoft Defender ATP)
            "threatType": "WatchList", # REQUIRED - THREATTYPE - Type of Indicator (Botnet, C2, CryptoMining, Darknet, DDoS, MaliciousUrl, Malware, Phishing, Proxy, PUA, WatchList)
            "tlpLevel": "amber", # REQUIRED - TLPLEVEL - TLP Value for the IOC (unknown, white, green, amber, red.)
            "tags": ["RH-ISAC_Vetted"],
        }

        # Process IOC according to the type it is 
        type = ioc.get('type')
        # Lots of duplication here, but it was done with the idea of adding extra details in the future as they are available with other feeds.
        if type == "domain":
            if debug:
                print(f"domain: {ioc.get('value')}")
            domain_data = {
                "domainName":ioc.get('value'),
            }
            ioc_data.update(domain_data)
            submission = submit_ioc(ioc_data, headers)
            
        elif type == "md5":
            if debug:
                print(f"md5 hash: {ioc.get('value')}")
            hash_data = {
                "fileHashType":"md5",
                "fileHashValue":ioc.get('value'),
            }
            ioc_data.update(hash_data)
            submission = submit_ioc(ioc_data, headers)

        elif type == "sha256":
            if debug:
                print(f"sha256 hash: {ioc.get('value')}")
            hash_data = {   
                "fileHashType":"sha256",
                "fileHashValue":ioc.get('value'), 
            }
            ioc_data.update(hash_data)
            submission = submit_ioc(ioc_data, headers)

        elif type == "sha1":
            if debug:
                print(f"sha1 hash: {ioc.get('value')}")
            hash_data = {   
                "fileHashType":"sha1",
                "fileHashValue":ioc.get('value'), 
            }
            ioc_data.update(hash_data)
            submission = submit_ioc(ioc_data, headers)

        elif type == "ip-dst":
            if debug:
                print(f"ip: {ioc.get('value')}")
            net_data = {
                "networkIPv4":ioc.get('value'), 
            }
            ioc_data.update(net_data)
            submission = submit_ioc(ioc_data, headers)

        elif type == "url":
            if debug:
                print(f"URL: {ioc.get('value')}")
            url_data = {
                "url":ioc.get('value'), 
            }
            ioc_data.update(url_data)
            submission = submit_ioc(ioc_data, headers)

        elif type == "email-src":  
            if debug:
                print(f"Email: {ioc.get('value')}")
            email_data = {
                "emailSenderAddress":ioc.get('value'), 
            }
            ioc_data.update(email_data)
            submission = submit_ioc(ioc_data, headers)
        else:
            # If we dont have a type setup for this IOC, dont attempt to submit it, but add it to the error list. 
            print(f"Unrecognized IOC Type: {type}. IOC value: {ioc.get('value')}")
            errored_iocs.append(ioc)
            pass
            
        # Handle various return conditions
        # If a response is not returned
        if not submission:
            print(f"Error parsing IOC type. IOC value: {ioc.get('value')}")
            errored_iocs.append(ioc)

        # When requests are not submitted succesfully
        elif 201 != submission.status_code:
            print(f"Error submitting IOC value: {ioc.get('value')}")
            errored_iocs.append(ioc)

        # IOC submitted properly, add 1 to count.
        elif 201 == submission.status_code:
            submitted_iocs += 1

        # Unknown error, handle edge cases
        else:
            print(f"Unknown error occoured, IOC value: {ioc.get('value')}")
            errored_iocs.append(ioc)
            
    print(f"Attempted to submit all IOCs. {submitted_iocs} IOCs were submitted successfully and {len(errored_iocs)} were not submitted successfully.")

    if not debug and len(errored_iocs) > 0:
        print("To view the list of errored IOCs, enable the debug flag and rerun the script.")
    
    if debug:
        print("Errored IOCs:")
        print(errored_iocs)
    return

if __name__ == '__main__':
    conf = configparser.ConfigParser()    
    if not conf.read(CONFIG_PATH):
        if not conf.read("../" + CONFIG_PATH):
            print(f'Config file {CONFIG_PATH} not found')
            exit()
    
    # Verify expected config sections are present
    if 'microsoft' not in conf.sections():
        print(f'Missing config section "microsoft". Please check the example configuration and try again.')
        exit()
    if MISP_CONFIG_SECTION not in conf.sections():
        print(f'Missing config section "{MISP_CONFIG_SECTION}". Please check the example configuration and try again.')
        exit()
    
    try:
        misp_key = conf[MISP_CONFIG_SECTION]['Key']
        credentials = {
            "product":conf['microsoft']['product'],
            "tenantId":conf['microsoft']['tenantId'],
            "appId":conf['microsoft']['appId'],
            "appSecret":conf['microsoft']['appSecret'],   
        }
    except KeyError as e:
        print(f'Cannot find "{e}" in file {CONFIG_PATH}')
        exit()

  

    # Retrieve IOCs from MISP
    iocs = get_last24h_vetted_iocs(misp_key)

    # Filter results, if any, and output to file
    if not iocs:
        print('No IOCs found in last 24h. Nothing to output.')
    else:
        # Filter IOCs
        filtered = filter_results(iocs)
        # Upload IOCs to the Graph API
        upload_iocs(iocs=filtered, credentials=credentials)
