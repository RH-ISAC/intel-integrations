#!/usr/bin/env python3
"""Retrieve last 24 hours of IOCs from TruSTAR and upload to the Microsoft Graph API.

   WARNING: The Graph API for submitting Threat Indicators (TIs/IOCs) is in beta, 
   and may change at any time according to Microsoft. 
   
   If you experience issues with this script after its release, please escelate to 
   the RH-ISAC Integrations Team so that we can address them. 
"""

import json
import re
import requests 
import urllib.parse
import urllib.request
import configparser

from datetime import datetime, timedelta, timezone
from typing import List

from trustar2 import TruStar, Observables  # Install trustar2 module through RH-ISAC Github instructions


__author__ = 'Ian Furr'
__version__ = '0.4'
__email__ = 'ian.furr@rhisac.org'


# Override defaults here
ENCLAVE_IDS = [
    "59cd8570-5dce-4e5b-b09c-9807530a7086",  # RH-ISAC Vetted Indicators
]

CONFIG_PATH = "./trustar/microsoft/rh-isac.conf"
window = 120 # Number of days to retain IOC
debug = False # Set to "True" for added logging/visiblity

# Regex to identify URLs that only contain a domain (not an IP, and no path)
REXP = r'\w{2,}:\/\/(?=.*[A-Za-z])[A-Za-z0-9-\.]+\/?$'


def retrieve_last24h_obls(ts_credentials: dict) -> List[dict]:
    """Query the TruSTAR 2.0 API for last 24 hours of Observables and return them.

    Parameters
    ----------
    ts_credentials : dict
        A dictionary from configparser containing the TruSTAR auth details

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
            "description": "RHISAC Vetted IOC imported from TruSTAR", # REQUIRED - STRING - Describe the IOC (100chars or less)
            "expirationDateTime": str(datetime.now(timezone.utc) + timedelta(days=window)), # "2022-08-31T23:59:59.0+00:00", # Now plus 90 days # REQUIRED - DATETIMEOFFSET - indicate when the indicator should expire (UTC)
            "targetProduct": credentials.get('product'), # REQUIRED - STRING - Targeted security product (Azure Sentinel, Microsoft Defender ATP)
            "threatType": "WatchList", # REQUIRED - THREATTYPE - Type of Indicator (Botnet, C2, CryptoMining, Darknet, DDoS, MaliciousUrl, Malware, Phishing, Proxy, PUA, WatchList)
            "tlpLevel": "amber", # REQUIRED - TLPLEVEL - TLP Value for the IOC (unknown, white, green, amber, red.) 
        }

        # Process IOC according to the type it is 
        type = ioc.get('type')
        # Lots of duplication here, but it was done with the idea of adding extra details in the future as they are available with other feeds.
        if type == "DOMAIN":
            if debug:
                print(f"domain: {ioc.get('value')}")
            domain_data = {
                "domainName":ioc.get('value'),
            }
            ioc_data.update(domain_data)
            submission = submit_ioc(ioc_data, headers)
            
        elif type == "MD5":
            if debug:
                print(f"md5 hash: {ioc.get('value')}")
            hash_data = {
                "fileHashType":"md5",
                "fileHashValue":ioc.get('value'),
            }
            ioc_data.update(hash_data)
            submission = submit_ioc(ioc_data, headers)

        elif type == "SHA256":
            if debug:
                print(f"sha256 hash: {ioc.get('value')}")
            hash_data = {   
                "fileHashType":"sha256",
                "fileHashValue":ioc.get('value'), 
            }
            ioc_data.update(hash_data)
            submission = submit_ioc(ioc_data, headers)

        elif type == "SHA1":
            if debug:
                print(f"sha1 hash: {ioc.get('value')}")
            hash_data = {   
                "fileHashType":"sha1",
                "fileHashValue":ioc.get('value'), 
            }
            ioc_data.update(hash_data)
            submission = submit_ioc(ioc_data, headers)

        elif type == "IP4":
            if debug:
                print(f"ip: {ioc.get('value')}")
            net_data = {
                "networkIPv4":ioc.get('value'), 
            }
            ioc_data.update(net_data)
            submission = submit_ioc(ioc_data, headers)

        elif type == "URL":
            if debug:
                print(f"URL: {ioc.get('value')}")
            url_data = {
                "url":ioc.get('value'), 
            }
            ioc_data.update(url_data)
            submission = submit_ioc(ioc_data, headers)

        elif type == "EMAIL_ADDRESS":  
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
    
    if 'microsoft' not in conf.sections():
        print(f'Missing config section "microsoft". Please check the example configuration and try again.')
        exit()
    if 'trustar' not in conf.sections():
        print(f'Missing config section "trustar". Please check the example configuration and try again.')
        exit()

    credentials = {
        "product":conf['microsoft']['product'],
        "tenantId":conf['microsoft']['tenantId'],
        "appId":conf['microsoft']['appId'],
        "appSecret":conf['microsoft']['appSecret'],    
    }

    ts_credentials = {
        "user_api_key":conf['trustar']['user_api_key'],
        "user_api_secret":conf['trustar']['user_api_secret'],
        "client_metatag":conf['trustar']['client_metatag'],
    }

    # Retrieve Observables from TruSTAR
    obls = retrieve_last24h_obls(ts_credentials)
    if not obls:
        print(f'No IOCs found for the given time period. Exiting...')
        exit()
    
    # Upload to MS Graph API
    print("Uploading IOCs to Graph API.")
    upload_iocs(obls, credentials)
