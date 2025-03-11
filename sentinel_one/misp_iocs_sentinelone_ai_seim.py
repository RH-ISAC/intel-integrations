#!/usr/bin/env python3
"""Retrieve last 24 hours of IOCs from MISP and upload to the SentinelOne AI SEIM endpoint

NOTE: RH-ISAC will not be held responsible for data loss, nor any other problems resulting
from the use of this content.

**THIS SCRIPT IS IN DEVELOPMENT**
"""

import requests
import datetime
from typing import List
from pymisp import PyMISP

from config import misp_config, sentinel_config

__author__ = "Ian Furr"
__version__ = "0.1"
__email__ = "ian.furr@rhisac.org"

# Sentinelone type must be uppercase.
TYPE_MAP = {
    "domain": "DNS",
    "ip-dst": "IPV4",
    "IP6": "IPV6",
    "md5": "MD5",
    "sha256": "SHA256",
    "sha1": "SHA1",
    "url": "URL",
}


# Override defaults here
MISP_URL = "https://misp.rhisac.org"
VETTED_TAG = "rhisac: vetted"

# Custom expiration ages (in days)
CUSTOM_IOC_EXPIRATION_AGE = {
    "DNS": 90,  # Default: 90 Max: 180
    "URL": 90,  # Default: 90 Max: 180
    "IPV4": 14,  # Default: 14 Max: 30
    "IPV6": 14,  # Default: 14 Max: 30
    "SHA256": 180,  # Default: 180 Max: 180
    "SHA1": 180,  # Default: 180 Max: 180
    "MD5": 180,  # Default: 180 Max: 180
}


def get_last24h_vetted_iocs(key: str) -> List[dict]:
    """
    Retrieve vetted IOCs from MISP based on the duration specified below.

    Given a valid MISP key poll the instance and retrieve any events that
    have been posted within the sepecified duration, and have the vetted
    tag specified in the global variables above.

    Parameters
    ----------
    key : str
        A valid MISP key.

    Returns
    -------
    List[dict]
        A list of MISP IOC dicts.
    """
    duration = 1
    # Instantiate API Object
    try:
        misp = PyMISP(url=MISP_URL, key=key)
    except Exception as e:
        print(e)
        exit()

    print(f"[ ] Fetching vetted IOCs added to MISP in past {duration*24} hours")

    # Query API for IOCs
    try:
        results = misp.search("attributes", tags=[VETTED_TAG], timestamp=f"{duration}d")
        iocs = results["Attribute"]
        print(f"[+] Got {len(iocs)} IOCs from MISP")
    except Exception as e:
        print(f"[!] Error while query MISP for IOCs: {str(e)}")
        exit()

    return iocs


def upload_iocs_to_sentinel(iocs: List[dict]) -> None:
    """
    Upload a list of IOCs to the SentinelOne API.

    Given a list of IOC dictionaries from MISP, submit them to the
    SentinelOne Threat Intelligence IOC API endpoint.

    Parameters
    ----------
    iocs : List[dict]
        The iocs to upload

    Returns
    ----------
    None
        Nothing is returned
    """
    data = []
    for ioc in iocs:
        if ioc["type"] not in TYPE_MAP:
            continue
        ioc_type = TYPE_MAP[ioc["type"]]
        sentinel_conversion = {
            "source": "RHISAC MISP - Vetted",
            "type": ioc_type,
            "externalId": ioc["uuid"],
            "value": ioc["value"],
            "method": "EQUALS",
            "name": f"RH-ISAC: {ioc['Event']['info']} - {ioc['type']} ",
            "validUntil": int(
                (
                    datetime.datetime.now()
                    + datetime.timedelta(CUSTOM_IOC_EXPIRATION_AGE[ioc_type])
                ).timestamp()
            ),
        }

        data.append(sentinel_conversion)

    print(f"[ ] About to submit {len(data)} IOCs to SentinelOne")

    auth_headers = {
        "Authorization": f"APIToken {sentinel_config['api_key']}",
        "Content-Type": "application/json",
    }
    url = f"{sentinel_config['sentinelone_url']}/web/api/v2.1/threat-intelligence/iocs"
    post_contents = {filter: {}, "data": data}
    response = requests.post(url, headers=auth_headers, json=data)
    if response.status_code == 200:
        print(f"[+] {len(data)} IOCs were submitted successfully.")

    else:
        print(
            f"[!] An Error has occoured submitting these IOCs: {response.status_code, response.text}"
        )
    return


if __name__ == "__main__":
    print(
        f"[ ] Starting RHISAC MISP to Sentinel import script {datetime.datetime.now(datetime.timezone.utc)}"
    )
    # Get IOCs from MISP
    iocs = get_last24h_vetted_iocs(misp_config["misp_key"])

    # Filter results, if any, and output to file
    if not iocs:
        print("No IOCs found in last 24h. Nothing to output.")
    else:
        upload_iocs_to_sentinel(iocs=iocs)
    print(f"[ ] Exiting {datetime.datetime.now(datetime.timezone.utc)}")
