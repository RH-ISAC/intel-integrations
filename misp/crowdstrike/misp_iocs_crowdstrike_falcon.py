#!/usr/bin/env python3
"""Retrieve last 24 hours of IOCs from MISP and upload to Crowdstrike

   NOTE: RH-ISAC will not be held responsible for data loss, nor any other problems resulting 
   from the use of this content. 
   
   **THIS SCRIPT IS A BETA, AND IN DEVELOPMENT**
"""

import configparser

from typing import List
from datetime import timedelta, datetime
from pymisp import PyMISP
from falconpy import IOC  # pip install crowdstrike-falconpy


__author__ = "Bradley Logan, Ian Furr"
__version__ = "0.5"
__email__ = "bradley.logan@rhisac.org, ian.furr@rhisac.org"


# Override defaults here
ENCLAVE_IDS = [
    "59cd8570-5dce-4e5b-b09c-9807530a7086",  # RH-ISAC Vetted Indicators
]
TYPE_MAP = {
    "domain": "domain",
    "ip-dst": "ipv4",
    "IP6": "ipv6",
    "md5": "md5",
    "sha256": "sha256",
}


# Override defaults here
CONFIG_PATH = "./misp/crowdstrike/rh-isac.conf"
MISP_CONFIG_SECTION = "RH-ISAC MISP"
MISP_URL = "https://misp.rhisac.org"
OUTPUT_FIELDS = ("value", "type", "timestamp", "Tag", "Event")
OUTPUT_FILENAME = None
VETTED_TAG = "rhisac: vetted"


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
    return out


def upload_iocs(iocs: List[dict], creds: dict) -> None:
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

    expire = datetime.today() + timedelta(days=180)
    expiration_timestamp = expire.strftime("%Y-%m-%dT00:00:00.000Z")

    falcon = IOC(
        client_id=creds.get("falcon_client_id"),
        client_secret=creds.get("falcon_client_secret"),
    )

    # API accepts up to 200 IOCs per request, so create blocks of 200 IOCs
    ioc_count = 0
    ioc_blocks = []
    ioc_block = []
    for ioc in iocs:
        if ioc["type"] not in TYPE_MAP:
            print(
                f"No Crowdstrike IOC type for MISP type {ioc['type']}. Value: {ioc['value']}"
            )
            continue
        ioc_dict = {
            "source": "RH-ISAC Vetted",
            "action": "detect",
            "expiration": expiration_timestamp,
            "description": "",
            "type": TYPE_MAP[ioc["type"]],
            "value": ioc["value"],
            "severity": "HIGH",
            "applied_globally": True,
            "platforms": [
                "windows"
            ],  # Add additional platform types if you are targeting multiple OSs
        }
        if type(ioc["tags"]) == str:
            ioc_dict["description"] = ioc["tags"]
        else:
            ioc_dict["description"] = " | ".join(ioc["tags"])
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
            "comment": f"Uploading {len(block)} RH-ISAC Vetted IOCs",
            "indicators": block,
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
        if int(response.get("status_code")) == 400:
            print("400 Response code recieved, processing IOCs with errors.")
            errors = response.get("body").get("resources")
            if debug:
                print(errors)
            # Iterate through the list of errors and check "message"
            # field for duplicate type errors
            for error in errors:
                if "Warning: Duplicate type" in error.get("message"):
                    duplicate_ioc_value = error.get("value")
                    print(f"Removing duplicate IOC: {duplicate_ioc_value}")
                    for ioc in block:
                        # values that DO NOT contain errors
                        if ioc.get("value") == duplicate_ioc_value:
                            block.remove(ioc)
                            continue
                else:
                    print(f"Unknown error with value: {error.get('value')}")
                    print(f"Message: {error.get('message')}")
            body = {
                "comment": f"Uploading {len(block)} RH-ISAC Vetted IOCs",
                "indicators": block,
            }

            print(f"Uploading {len(block)} RH-ISAC Vetted IOCs")
            new_response = falcon.indicator_create(body=body)
            if int(response.get("status_code")) in (200, 201):
                print(f"Block {i} submitted successfully.")

            elif debug:
                print(new_response)

            else:
                print("Unknown error:")
                print(new_response)

        elif int(response.get("status_code")) == 429:
            print("Error 429: Too many requests. Please wait and retry submissions.")

        elif int(response.get("status_code")) in (200, 201):
            print(f"Block {i} submitted successfully.")

        else:
            print("Unknown response code:")
            print(response)
    return


if __name__ == "__main__":
    conf = configparser.ConfigParser()
    if not conf.read(CONFIG_PATH):
        if not conf.read("../" + CONFIG_PATH):
            print(f"Config file {CONFIG_PATH} not found")
            exit()

    # Check config for relevant sections
    if "crowdstrike" not in conf.sections():
        print(
            f'Missing config section "crowdstrike". Please check the example configuration and try again.'
        )
        exit()
    if MISP_CONFIG_SECTION not in conf.sections():
        print(
            f'Missing config section "{MISP_CONFIG_SECTION}". Please check the example configuration and try again.'
        )
        exit()

    try:
        misp_key = conf[MISP_CONFIG_SECTION]["Key"]
        credentials = {
            "falcon_client_id": conf["crowdstrike"]["falcon_client_id"],
            "falcon_client_secret": conf["crowdstrike"]["falcon_client_secret"],
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
        upload_iocs(iocs=filtered, creds=credentials)
