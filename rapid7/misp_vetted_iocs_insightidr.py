#!/usr/bin/env python3
"""Retrieve last 24 hours of IOCs from MISP and upload to InsightIDR

   NOTE: RH-ISAC will not be held responsible for data loss, any other problems resulting
   from the use of this content, nor lack of waffles available for consumption.

   **THIS SCRIPT IS IN BETA DEVELOPMENT**
"""

import configparser
import requests

from typing import List
from datetime import timedelta, datetime
from pymisp import PyMISP

__author__ = "Bradley Logan, Ian Furr, Jordan Moore"
__version__ = "0.1"
__email__ = "bradley.logan@rhisac.org, ian.furr@rhisac.org, jordanmoore@marcuscorp.com"


# Override defaults here
ENCLAVE_IDS = [
    "59cd8570-5dce-4e5b-b09c-9807530a7086",  # RH-ISAC Vetted Indicators
]
TYPE_MAP = {
    "domain": "domain_names",
    "hostname": "domain_names",
    "ip-src": "ips",
    "ip-dst": "ips",
    "IP6": "ips",
    "md5": "hashes",
    "url": "urls"
}


# Override defaults here
CONFIG_PATH = "./config.conf"
MISP_CONFIG_SECTION = "RH-ISAC MISP"
MISP_URL = "https://misp.rhisac.org"
OUTPUT_FIELDS = ("value", "type", "timestamp", "Tag", "Event")
OUTPUT_FILENAME = None
VETTED_TAG = "rhisac: vetted"


def get_last24h_vetted_iocs(key: str) -> List[dict]:
    """Query the MISP API for last 24 hours of RH-ISAC Vetted IOCs and return

    Parameters
    ----------
    api (str):
        The misp api key as a string

    Returns
    -------
    list[dict]
        A list of IOCs as dictionaries
    """

    # Instantiate API Object
    try:
        misp = PyMISP(url=MISP_URL, key=key)
    except Exception as e:
        print(e)
        exit()

    print(f"\nGetting all IOCs added to MISP in past 24 hours...")

    # Query API for IOCs
    try:
        results = misp.search("attributes", tags=[VETTED_TAG], timestamp="1d")
        iocs = results["Attribute"]
        print(f"Got {len(iocs)} IOCs from MISP")
    except Exception as e:
        print(f"Error while query MISP for IOCs: {str(e)}")
        exit()

    return iocs


def filter_results(iocs: List[dict]) -> List[dict]:
    """Take a list of IOC dictionaries and return a filtered list

    Parameters
    ----------
    list[dict]
        A list of IOCs as dictionaries
    
    Returns
    -------
    list[dict]
        A filtered list of IOCs as dictionaries
    """
    out = []
    for ioc in iocs:
        keep = {}
        for k, v in ioc.items():
            if k not in OUTPUT_FIELDS:
                continue
            else:
                if k == "Tag":
                    keep["tags"] = "|".join(
                        [x["name"] for x in v if x["name"] != VETTED_TAG]
                    )
                elif k == "Event":
                    keep["event"] = v["info"]
                else:
                    keep[k] = v
        out.append(keep)
    print(f"Filtered {len(iocs)} IOCs down to {len(out)} IOCs.")
    return out

def split_results(iocs: List[dict]) -> dict[str,list[str]]:
    """Takes in a list of IOC dictionaries and returns a dictionary of 'bucketed' IOCs by type.
    
    Parameters
    ----------
    iocs (list[dict]):
        A list of IOCs as dictionaries
        
    Returns
    -------
    dict[str, list[str]]
        A dictionary mapping each category name to a list of all corresponding IOCs
    """
    results = {
        "ips":[],
        "hashes":[],
        "domain_names":[],
        "urls":[]
    }
    skipped = 0
    for ioc in iocs:
        if ioc["type"] in TYPE_MAP:
            results[TYPE_MAP[ioc["type"]]].append(ioc["value"]) 
        else:
            print(f"Skipped ioc of type {ioc['type']} (non-applicable as IDR Threat Type)")
            skipped += 1
    print(f"IOC Type Metrics:")
    for key,val in results.items():
        print(f"\t{key}: {len(val)}")
    return results

def upload_iocs(ioc_bundle: dict[str,list[str]], creds: dict[str, str]) -> None:
    """Upload a list of IOCs to your InsightIDR Community Threats.

    Parameters
    ----------
    ioc_bundle: (dict[str,list[str]])
        Dictionary of IOC types, each containing a list of corresponding values
    creds: (dict[str, str])
        Dictionary of credential data (identifier: value/api key)

    Returns
    ----------
    None
    """
    endpoint = creds["endpoint"]
    threat_key = creds["threat_key"]
    api_key = creds["api_key"]
    auth_header = {
        "X-Api-Key": api_key,
        "Content-Type": "application/json"
    }
    response = requests.post(
        url = f"https://{endpoint}.api.insight.rapid7.com/idr/v1/customthreats/key/{threat_key}/indicators/add",
        headers = auth_header,
        params = {"format": "json"},
        json = ioc_bundle
    )
    if not response.ok:
        print(f'ERROR - Response from IDR was {response.status_code} - {response.json()["message"]}')
        exit()

    results = response.json()
    if "rejected_indicators" in results:
        if results["rejected_indicators"]:
            rejects = "\n".join(results["rejected_indicators"])
            print(f"The following were rejected as IOCs:\n{rejects}")
    print(f"Done! IOCs added to {results['threat']['name']}.")


if __name__ == "__main__":
    conf = configparser.ConfigParser()
    if not conf.read(CONFIG_PATH):
        if not conf.read("../" + CONFIG_PATH):
            print(f"Config file {CONFIG_PATH} not found")
            exit()

    # Check config for relevant sections
    if "InsightIDR" not in conf.sections():
        print(
            f'Missing config section "InsightIDR". Check the example configuration and try again.'
        )
        exit()
    if MISP_CONFIG_SECTION not in conf.sections():
        print(
            f'Missing config section "{MISP_CONFIG_SECTION}". Check the example configuration and try again.'
        )
        exit()

    try:
        misp_key = conf[MISP_CONFIG_SECTION]["Key"]
        credentials = {
            "api_key": conf["InsightIDR"]["api_key"],
            "endpoint": conf["InsightIDR"]["api_endpoint"],
            "threat_key": conf["InsightIDR"]["threat_key"]
        }

    except KeyError as e:
        print(f'Cannot find "{e}" in file {CONFIG_PATH}')
        exit()

    # Call main function
    iocs = get_last24h_vetted_iocs(misp_key)

    # Filter results, if any, and output to file
    if not iocs:
        print("No IOCs found in last 24h. Nothing to output.")
    else:
        filtered = filter_results(iocs)
        split = split_results(filtered)
        upload_iocs(ioc_bundle=split, creds=credentials)  
