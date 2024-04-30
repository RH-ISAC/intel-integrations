#!/usr/bin/env python3
"""Retrieve last 24 hours of IOCs from TruSTAR and output to a CSV file.
   Use vetted enclave if none specified in trustar.conf file.
"""

import csv
from datetime import datetime, timedelta
from typing import List

from trustar import TruStar, datetime_to_millis

__author__ = 'Bradley Logan'
__version__ = '0.90'
__email__ = 'bradley.logan@rhisac.org'

# Override default here
OUTPUT_FILENAME = None


def ind_dict_to_csv(indicators: List[dict],
                    filename: str = None,
                    ) -> None:
    """Take a list of indicator dictionaries and write to a CSV file.

    Parameters
    ----------
    indicators : List[dict]
        The indicators to be written out to a file
    filename : str, optional
        The desired name/path for the output file
    """
    if not filename:
        now = datetime.now().strftime('%Y%m%dT%H%M%S')
        filename = f'rhisac_iocs_last24h_{now}.csv'
    with open(filename, 'w') as f:
        header = list(indicators[0].keys())

        # move tags column (if any) to end
        if 'tags' in header:
            header.remove('tags')
            header.append('tags')

        indwriter = csv.writer(f)
        indwriter.writerow(header)
        for ind in indicators:
            try:
                row = [ind[rh] for rh in header if rh != 'tags']
                if ind.get('tags') and isinstance(ind['tags'][0], dict):  # tags are dict
                    tags = [t['name'] for t in ind.get('tags', ())]
                else:  # tags are list of values
                    tags = [t for t in ind.get('tags', ())]
                row.append("|".join(tags))  # tags in one field, "|" separated
                indwriter.writerow(row)
            except Exception as exc:
                print(f"Error writing indicator {ind} to CSV: {str(exc)}")
    print(f'Wrote {len(indicators)} IOCs to CSV file: {filename}')


def retrieve_last24h_iocs() -> List[dict]:
    """Query the TruSTAR API for last 24 hours of IOCs and return them.

    Returns
    _______
    list[dict]
        A list of IOCs as dictionaries
    """

    # Initiate API Object
    try:
        ts = TruStar(config_file='trustar.conf', config_role='rh-isac_vetted')
    except KeyError as e:
        print(f'{str(e)[1:-1]} in config file "trustar.conf". Exiting...')
        exit()

    # Identify enclaves to query.
    # Pull from "RH-ISAC Vetted Indicators" enclave if none specified
    if not ts.enclave_ids:
        enclaves = ["59cd8570-5dce-4e5b-b09c-9807530a7086"]
    else:
        enclaves = ts.enclave_ids

    # Setup to/from times and convert timestamps to milliseconds since epoch
    from_time = datetime.utcnow() - timedelta(hours=24)  # last 24 hours
    to_time = datetime.utcnow()
    print(f'\nRetrieving all IOCs between UTC {from_time} and {to_time}...')
    from_time = datetime_to_millis(from_time)
    to_time = datetime_to_millis(to_time)
    max_time = datetime_to_millis(datetime(3000, 1, 1))

    # To avoid API restrictions, query for 1000 IOCs at a time,
    # updating the to_time with each loop iteration
    pg_to = to_time
    all_metadata = []
    while True:
        page = ts.search_indicators_page(enclave_ids=enclaves,
                                         from_time=from_time,
                                         to_time=pg_to,
                                         page_size=1000)
        if not page.items:
            break  # if empty, then no IOCs left to fetch; terminate loop

        # get_indicators_metadata only accepts up to 1000 IOCs per call
        inds = ts.get_indicators_metadata(page.items, enclaves)

        earliest_lastseen = max_time  # initialize this with a large value
        for indicator in inds:
            all_metadata.append(indicator.to_dict())
            if indicator.last_seen < earliest_lastseen:
                earliest_lastseen = indicator.last_seen
        pg_to = earliest_lastseen - 1  # prepare for retrieval of next page
        if pg_to < from_time:
            break

    # only include most commonly used fields
    out = [{'value': ind['value'],
            'indicatorType': ind['indicatorType'],
            'tags': [t['name'] for t in ind['tags']],
            'firstSeen': ind['firstSeen'],
            'lastSeen': ind['lastSeen'],
           } for ind in all_metadata]
    return out


if __name__ == '__main__':
    # Call main function
    iocs = retrieve_last24h_iocs()

    # Output results, if any, to file
    if not iocs:
        print('No IOCs found in last 24h. Nothing to output.')
    else:
        ind_dict_to_csv(iocs, OUTPUT_FILENAME)
