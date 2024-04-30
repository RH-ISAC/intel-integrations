#!/usr/bin/env python3
"""Retrieve IOCs from TruSTAR and output to a file.

Query TruSTAR for IOCs within specific enclaves.
Output will by default include all fields, but can be restricted to only
values, or only values and IndicatorTypes.
File format is JSON by default, but CSV can be selected.
"""

import argparse
import csv
import json
import sys
from datetime import datetime, timedelta, timezone
from typing import List

from requests.exceptions import HTTPError
from trustar import TruStar, datetime_to_millis

__author__ = 'Bradley Logan'
__version__ = '0.97'
__email__ = 'bradley.logan@rhisac.org'


def ind_dict_to_csv(indicators: List[dict],
                    filename: str = None,
                    split_tags: bool = False,
                    ) -> None:
    """Take a list of indicator dictionaries and write to a CSV file.

    Parameters
    ----------
    indicators : List[dict]
        The indicators to be written out to a file
    filename : str, optional
        The desired name/path for the output file
    split_tags: bool, optional
        If True, split tags into separate fields
    """
    if not filename:
        now = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'trustar_iocs_{now}.csv'
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
                if split_tags:
                    row.extend(tags)  # each tag gets own field
                else:
                    row.append("|".join(tags))  # tags in one field, "|" separated
                indwriter.writerow(row)
            except Exception as exc:
                print(f"Error writing indicator {ind} to CSV: {str(exc)}")
    print(f'Wrote IOCs to CSV file: {filename}')


def ind_dict_to_json(indicators: List[dict],
                     filename: str = None,
                     ) -> None:
    """Take a list of indicator dictionaries and write to a JSON file.

    Parameters
    ----------
    indicators : List[dict]
        The indicators to be written out to a file
    filename : str, optional
        The desired name/path for the output file
    """
    if not filename:
        now = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'trustar_iocs_{now}.json'
    with open(filename, 'w') as f:
        f.write(json.dumps(indicators))
    print(f'Wrote IOCs to JSON file: {filename}')


def retrieve_iocs(from_time: datetime = None,
                  to_time: datetime = None,
                  ioc_types: List[str] = None,
                  only_vals: bool = False,
                  only_vt: bool = False,
                  enclaves: List[str] = None,
                  min_calls: bool = False,
                  all_meta: bool = False,
                  ) -> List[dict]:
    """Query the TruSTAR API for IOCs in specific enclaves and return them.

    Parameters
    __________
    from_time : datetime, optional
        Start of the query time window
    to_time : datetime, optional
        End of the query time window
    ioc_types : list[str], optional
        A list of IOC types to which to limit the results
    only_vals : bool, optional
        If True, only return IOC values
    only_vt : bool, optional
        If True, only return values and types for each IOC
    min_calls : bool, optional
        If True, use minimum number of API calls to retrieve IOCs
    all_meta : bool, optional
        If True, include all available fields in output
    enclaves : list[str], optional
        A list of the IDs of the enclaves to query.
        If not None, overrides values in TruSTAR config file.

    Returns
    _______
    list[dict]
        A list of IOCs as dictionaries
    """
    # Validate arguments
    if only_vals and only_vt:
        print('Parameters "only_vals" and "only_vt" cannot both be True')
        return []

    # Initiate API Object
    ts = TruStar(config_file='trustar.conf', config_role='rh-isac_vetted')
    if not min_calls:  # Unnecessary API call
        try:
            _ = ts.ping()
        except HTTPError as exc:
            print(f'Failed to access API. Check your "trustar.conf" file:\n{str(exc)}')
            return []

    # Identify enclaves to query.
    # Pull from "RH-ISAC Vetted Indicators" enclave if none specified
    if not enclaves:
        if not ts.enclave_ids:
            enclaves = ["59cd8570-5dce-4e5b-b09c-9807530a7086"]
        else:
            enclaves = ts.enclave_ids

    # Confirm user has access to desired enclave(s)
    if not min_calls:  # Unnecessary API call
        usr_encs = ts.get_user_enclaves()
        usr_encs = {enc.id: enc.name for enc in usr_encs}
        try:
            print("Retrieving IOCs from the following enclave(s):")
            for encid in enclaves:
                print(f"   {encid}: {usr_encs[encid]}")
        except KeyError as exc:
            print(f'\nUser does not have access to enclave with ID {str(exc)}')

    # Setup to/from times and convert timestamps to milliseconds since epoch
    if not from_time:
        from_time = datetime.now(timezone.utc) - timedelta(hours=24)  # default last 24 hours
    if not to_time:
        to_time = datetime.now(timezone.utc)
    print(f'\nRetrieving all IOCs between UTC {from_time} and {to_time}...')
    from_time = datetime_to_millis(from_time)
    to_time = datetime_to_millis(to_time)

    # To avoid API restrictions, query for 1000 IOCs at a time,
    # updating the to_time with each loop iteration
    pg_to = to_time
    all_metadata = []
    while True:
        page = ts.search_indicators_page(enclave_ids=enclaves,
                                         from_time=from_time,
                                         to_time=pg_to,
                                         indicator_types=ioc_types,
                                         page_size=1000)
        if not page.items:
            break  # if empty, then no IOCs left to fetch; terminate loop

        # get_indicators_metadata only accepts up to 1000 IOCs per call
        inds = ts.get_indicators_metadata(page.items, enclaves)
        all_metadata.extend([indicator.to_dict() for indicator in inds])
        print(f'\rIOCs Retrieved: {len(all_metadata)}', end='')

        # Determine timestamp for next page
        earliest_lastseen = page.items[-1].last_seen  # items ordered by last_seen time, descending
        if earliest_lastseen > pg_to:  # this shouldn't happen
            print(f'\nERROR: Aborting. IOC last_seen outside of queried range: {page.items[-1]}')
        pg_to = earliest_lastseen - 1
        if pg_to < from_time:
            break

    if only_vt:
        out = [{'value': ind['value'],
                'indicatorType': ind['indicatorType']} for ind in all_metadata]
    elif only_vals:
        out = [{'value': ind['value']} for ind in all_metadata]
    elif all_meta:
        out = all_metadata
    else:  # only include most commonly used fields
        out = [{'value': ind['value'],
                'indicatorType': ind['indicatorType'],
                'tags': [t['name'] for t in ind['tags']],
                'firstSeen': ind['firstSeen'],
                'lastSeen': ind['lastSeen'],
               } for ind in all_metadata]

    print('')
    return out


if __name__ == '__main__':
    # Parse arguments if run on commandline
    parser = argparse.ArgumentParser()
    parser.description = 'Retrieve IOCs from specific TruSTAR enclaves. Default last 24 hours.'
    parser.add_argument('outfile', nargs='?', default=None,
                        help='The filename (or path and filename) to which '
                        'to write the IOCs')
    parser.add_argument('-a', '--all', action='store_true',
                        help='Include all available fields in output')
    parser.add_argument('-c', '--csv', action='store_true',
                        help='Output in CSV format (default is JSON)')
    parser.add_argument('-e', '--enclaves', default="",
                        help='A string of comma-separated enclave IDs to query'
                        ' (default is RH-ISAC Vetted Indicators enclave)')
    parser.add_argument('-f', '--from_time', default=None,
                        help='Search from "YYYY-MM-DD" or "YYYY-MM-DD_HH:MM:SS"'
                        ' (Enter as UTC. Default is last 24 hours.)')
    parser.add_argument('-it', '--types', default="",
                        help='A string of comma-separated indicator types to'
                        ' which to limit results')
    parser.add_argument('-l', '--last_days', default=None,
                        help='Search for IOCs updated in the last N days')
    parser.add_argument('-m', '--min_calls', action='store_true',
                        help='Minimize the number of API calls used to retrieve IOCs')
    parser.add_argument('-s', '--split_tags', action='store_true',
                        help='Split tags into separate CSV fields. (Ignored if not CSV output)')
    parser.add_argument('-t', '--to_time', default=None,
                        help='Search to "YYYY-MM-DD" or "YYYY-MM-DD_HH:MM:SS"'
                        ' (Enter as UTC. Default is last 24 hours.)')
    parser.add_argument('-v', '--only_vals', action='store_true',
                        help='Restrict output to only IOC values')
    parser.add_argument('-vt', '--only_vt', action='store_true',
                        help='Restrict output to only IOC values and IOC Types')
    args = parser.parse_args()

    # Convert strings to datetimes
    if args.last_days:
        try:
            days = int(args.last_days)
        except:
            print('Invalid integer provided for "last_days" argument')
            sys.exit()
        now = datetime.utcnow()
        dts = [now - timedelta(days=days), now]
    else:
        dts = [args.from_time, args.to_time]
        for i, dt in enumerate(dts):
            if dt:
                try:
                    dts[i] = datetime.strptime(dt, "%Y-%m-%d")
                except ValueError:
                    try:
                        dts[i] = datetime.strptime(dt, "%Y-%m-%d_%H:%M:%S")
                    except ValueError:
                        print(f'\nInvalid argument "{dt}" provided')
                        sys.exit()

    # convert enclave string and IOC Type string to lists
    enc_ids = args.enclaves.split(',') if args.enclaves else []
    ioc_types = args.types.split(',') if args.types else []

    # Call main function
    iocs = retrieve_iocs(
        dts[0],
        dts[1],
        ioc_types,
        args.only_vals,
        args.only_vt,
        enc_ids,
        args.min_calls,
        args.all,
    )

    # Output results, if any, to file
    if not iocs:
        print('No IOCs matched the query. Nothing to output.')
    else:
        if args.csv:
            ind_dict_to_csv(iocs, args.outfile, args.split_tags)
        else:
            ind_dict_to_json(iocs, args.outfile)
