#!/usr/bin/env python3
"""
Retrieve last 24 hours of IOCs from MISP and send them to SumoLogic.

"""

__author__ = "Ian Furr"
__version__ = "0.3"
__email__ = "ian.furr@rhisac.org"

import requests
from datetime import datetime, timedelta
from pymisp import PyMISP
from config import sumologic_config as SUMOLOGIC_CONFIG, misp_config as MISP_CONFIG

MISP_URL = "https://misp.rhisac.org"
VETTED_TAG = "rhisac: vetted"


def get_misp_key() -> str:
    """
    Get the MISP authkey from a local config file
    Returns
    _______
    str
        The MISP authkey
    """
    try:

        key = MISP_CONFIG["key"]
        return key
    except KeyError as e:
        print(f'Cannot find "{e}" in misp_config.')
        exit()


def get_last24h_vetted_iocs() -> list[dict]:
    """
    Query the MISP API for last 24 hours of RH-ISAC Vetted IOCs and return
    Returns
    _______
    list[dict]
        A list of IOCs as dictionaries
    """

    # Instantiate API Object
    try:
        misp = PyMISP(MISP_URL, get_misp_key())
    except Exception as e:
        print(e)
        exit()

    print(f"Getting all IOCs added to MISP in past 24 hours...")

    # Query API for IOCs
    try:
        results = misp.search("attributes", tags=[VETTED_TAG], timestamp="1d")
        iocs = results["Attribute"]
        print(f"Got {len(iocs)} IOCs from MISP")
    except Exception as e:
        print(f"Error while query MISP for IOCs: {str(e)}")
        exit()

    return iocs


def format_iocs_for_sumo(misp_iocs: list[dict]) -> list[dict]:
    """
    Generate a list of IOCs formatted in a way Sumo can ingest them.

    Take a provided list of MISP IOCs in dict format, and convert them into sumo capatable dictionaries. Including the value, status, expiration, and a description including the Event Name, ID, and list of tags.

    Parameters
    ----------
    misp_iocs : list[dict]
        A list of MISP IOC dictionaries from a pyMISP query.

    Returns
    -------
    list[dict]
        A list of dicts formatted for SumoLogic.
    """
    sumo_indicators = []
    for ioc in misp_iocs:
        expiration = datetime.now() + timedelta(
            SUMOLOGIC_CONFIG["indicator_expiration"]
        )

        sumo_indicator = {
            "id": f"RHISAC-VETTED-{ioc['id']}",
            "indicator": ioc["value"],
            "type": ioc["type"],
            "source": "RHISAC - Vetted",
            "validFrom": datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "validUntil": expiration.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "confidence": "100",
            "threatType": "malicious-activity",
            "fields": {"threatLevel": "medium"},
        }
        sumo_indicators.append(sumo_indicator)
    return sumo_indicators


def send_iocs_to_sumo(iocs: list[dict]):
    """
    Send collected IOCs to SumoLogic

    Given a list of IOC dictionaries in a format that sumologic can consume, submit them and report any errors.

    Parameters
    ----------
    iocs : list[dict]
        List of IOCS that are formatted for usage in SumoLogic.
    """
    threatIntelSourceId = SUMOLOGIC_CONFIG["threatIntelSourceId"]
    sumo_endpoint = SUMOLOGIC_CONFIG["sumo_endpoint"]
    url = f"{sumo_endpoint}/sec/v1/threatInteldatastoreindicators/normalized/"
    iocs = {"indicators": iocs}
    resp = requests.post(
        url=url,
        json=iocs,
        auth=(SUMOLOGIC_CONFIG["accessId"], SUMOLOGIC_CONFIG["accessKey"]),
    )
    match resp.status_code:
        case 200:
            print(f"Successfully submitted {len(iocs['indicators'])} to SumoLogic.")
        case 301:
            print("Looks like things moved. Contact RH-ISAC Support.")
        case 401:
            print("Credential error. Check your API credentials and try again.")
        case 403:
            print(
                "This operation is not allowed for your account type or the user doesn't have the role capability to perform this action. "
            )
            print(
                "See troubleshooting link below for details. https://help.sumologic.com/docs/api/troubleshooting/"
            )
        case 404:
            print("Resource not Found.")
        case 405:
            print("Unsupported method for URL.")
        case 415:
            print("Invalid Content Type.")
        case 429:
            print("API Ratelimit encountered. Contact RH-ISAC Staff.")
        case 500:
            print("Internal error, please try again later.")
        case 503:
            print("Service Unavailible, try again later.")
        case _:
            print(f"Unknown status code {resp.status_code}")
    if resp.status_code != 200:
        print(f"Request Error Content:\n{resp.content.decode('UTF-8')}")
    return


if __name__ == "__main__":
    print(
        f"Starting RHISAC IOC to Sumologic v2 Script for {datetime.now().strftime('%Y-%m-%dT%H:%M')}"
    )
    # Get IOCs from MISP
    iocs = get_last24h_vetted_iocs()

    # Format IOCs for Sumo, then attempt to submit.
    if not iocs:
        print("No IOCs found in last 24h. Nothing to output.")
    else:
        iocs = format_iocs_for_sumo(iocs)
        send_iocs_to_sumo(iocs)
        print("Sent IOCs to Sumo. Exiting.")
