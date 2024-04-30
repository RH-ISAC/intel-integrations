#!/usr/bin/env python3
"""Retrieve last 24 hours of IOCs from TruSTAR and output to a JSON file.
"""

__author__ = 'Ian Furr, Bradley Logan'
__version__ = '0.1'
__email__ = 'ian.furr@rhisac.org, bradley.logan@rhisac.org'

import json
from datetime import datetime, timedelta, timezone
from typing import List

from trustar2 import TruStar, Observables

# Override defaults here
ENCLAVE_IDS = [
    "59cd8570-5dce-4e5b-b09c-9807530a7086",  # RH-ISAC Vetted Indicators
]
OUTPUT_FILENAME = None

def obl_dict_to_json(observables: List[dict],
                     filename: str = None,
                     ) -> None:
    """Take a list of observable dictionaries and write to a JSON file.

    Parameters
    ----------
    observables : List[dict]
        The indicators to be written out to a file
    filename : str, optional
        The desired name/path for the output file
    """
    if not filename:
        now = datetime.now().strftime('%Y%m%dT%H%M%S')
        filename = f'rhisac_iocs_last24h_{now}.json'
    with open(filename, 'w') as f:
        f.write(json.dumps(observables))
    print(f'Wrote {len(observables)} IOCs to JSON file: {filename}')


def retrieve_last24h_obls() -> List[dict]:
    """Query the TruSTAR 2.0 API for last 24 hours of Observables and return them.

    Returns
    _______
    list[dict]
        A list of Observables as dictionaries
    """

    # Instantiate API Object
    try:
        ts = TruStar.config_from_file(config_file_path="./trustar2.conf", config_role="rh-isac_vetted")
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
            'tags': obl.tags,
            'firstSeen': obl.first_seen,
            'lastSeen': obl.last_seen,
        } for obl in obls
    ]
    return out


if __name__ == '__main__':
    # Call main function
    obls = retrieve_last24h_obls()

    # Output results, if any, to file
    if not obls:
        print('No IOCs found in last 24h. Nothing to output.')
    else:
        obl_dict_to_json(obls, OUTPUT_FILENAME)
