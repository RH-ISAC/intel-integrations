#!/usr/bin/env python3
"""Retrieve IOCs from TruSTAR and output to a file.

Query TruSTAR for IOCs within specific enclaves.
Output will by default include all fields, but can be restricted to only
values, or only values and IndicatorTypes.
File format is JSON by default, but CSV can be selected.
"""

__author__ = 'Ian Furr, Bradley Logan'
__version__ = '0.1'
__email__ = 'ian.furr@rhisac.org bradley.logan@rhisac.org'

import argparse
import csv
import json
import sys

from datetime import datetime, timedelta, timezone
from typing import List
from xmlrpc.client import DateTime
from requests.exceptions import HTTPError

from trustar2 import TruStar, Observables, Account

def obl_dict_to_csv(observables: List[dict],
                    filename: str = None,
                    split_tags: bool = False,
                    ) -> None:
    """Take a list of observable dictionaries and write to a CSV file.

    Parameters
    ----------
    observables : List[dict]
        The observables to be written out to a file
    filename : str, optional
        The desired name/path for the output file
    split_tags: bool, optional
        If True, split tags into separate fields
    """
    if not filename:
        now = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'trustar_iocs_{now}.csv'
    with open(filename, 'w') as f:
        header = list(observables[0].keys())

        # move tags column (if any) to end
        if 'tags' in header:
            header.remove('tags')
            header.append('tags')

        oblwriter = csv.writer(f)
        oblwriter.writerow(header)
        for obl in observables:
            try:
                row = [obl[rh] for rh in header if rh != 'tags']
                if obl.get('tags') and isinstance(obl['tags'][0], dict):  # tags are dict
                    tags = [t['name'] for t in obl.get('tags', ())]
                else:  # tags are list of values
                    tags = [t for t in obl.get('tags', ())]
                if split_tags:
                    row.extend(tags)  # each tag gets own field
                else:
                    row.append("|".join(tags))  # tags in one field, "|" separated
                oblwriter.writerow(row)
            except Exception as exc:
                print(f"Error writing observable {obl} to CSV: {str(exc)}")
    print(f'Wrote IOCs to CSV file: {filename}')


def obl_dict_to_json(observables: List[dict],
                     filename: str = None,
                     ) -> None:
    """Take a list of observable dictionaries and write them to a JSON file.

    Parameters
    ----------
    observable : List[dict]
        The indicators to be written out to a file
    filename : str, optional
        The desired name/path for the output file
    """
    if not filename:
        now = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'trustar_iocs_{now}.json'
    with open(filename, 'w') as f:
        f.write(json.dumps(observables))
    print(f'Wrote IOCs to JSON file: {filename}')
    
    return



def retrieve_obls(
                from_time: DateTime = None,
                to_time: DateTime = None,
                ioc_types: List[str] = None,
                only_vals: bool = False,
                only_vt: bool = False,
                enclaves: List[str] = None,
                all_meta: bool = False,
                ) -> List[dict]:
    """ Query the TruSTAR 2.0 API for Observables based on provided 
        date/content filters and return them.
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
    all_meta : bool, optional
        If True, include all available fields in output
    enclaves : list[str], optional
        A list of the IDs of the enclaves to query.
        If none, values in TruSTAR config file will be used.

    Returns
    _______
    list[dict]
        A list of IOCs as dictionaries
    """

    # Instantiate API Object
    try:
        ts = TruStar.config_from_file("./trustar2.conf", "rh-isac-vetted")
    except KeyError as e:
        print(f'{str(e)[1:-1]} in config file "trustar2.conf". Exiting...')
        exit()

    # If enclaves arent defined when calling the script, grab the list of 
    # avalable enclaves for the account
    if not enclaves:
        account_enclaves = Account(ts).get_enclaves().data 
        if not account_enclaves:
            enclaves = ["59cd8570-5dce-4e5b-b09c-9807530a7086"] # RH-ISAC Vetted Indicators
        else:
            for enclave in account_enclaves:
                enclaves.append(enclave.id)
    
    if not len(ioc_types):
        ioc_types = ["IP4", "IP6", "DOMAIN", "CIDR_BLOCK", "EMAIL_ADDRESS", 
                    "PHONE_NUMBER", "URL", "MD5", "SHA1", "SHA256", 
                    "REGISTRY_KEY", "SOFTWARE", "BITCOIN_ADDRESS"]

    # Setup to/from times and convert timestamps to milliseconds since epoch
    if not from_time:
        from_time = datetime.now(timezone.utc) - timedelta(hours=24)  # default last 24 hours
    if not to_time:
        to_time = datetime.now(timezone.utc)
    print(f'\nRetrieving all IOCs between UTC {from_time} and {to_time}...')
    print(type(from_time))
    print(from_time)
    
    from_time = int(from_time.timestamp() * 1000)
    to_time = int(to_time.timestamp() * 1000)

    # Query API for Observables
    # To avoid API limits, query for 1000 Observables at a time
    pages = (
        Observables(ts)
            .set_enclave_ids(enclaves)
            .set_from(from_time)
            .set_to(to_time)
                .set_search_types(ioc_types)
            .set_page_size(500)  # Avoid API Limits
            .search()
    )
    obls = [obl for page in pages for obl in page.data]

    # Filter output based on calling flags
    # return only value
    if only_vals:
        out = [
            {
                'value': obl.value,
            } for obl in obls
        ]

    # if vt (return values and types)
    elif only_vt:
        out = [
            {
                'value': obl.value,
                'indicatorType': obl.type,
            } for obl in obls
        ]

    # if all_metadata is requested, return all the values in the obl
    elif all_meta:
        out = [
            {
                'value': obl.value,
                'indicatorType': obl.type,
                'priorityLevel': obl.priorityLevel,
                'correlationCount': obl.correlationCount,
                'whitelisted': obl.correlationCount,
                'weight': obl.weight,
                'reason': obl.reason,
                'source': obl.source,
                'sightings': obl.sightings,
                'notes': obl.notes,
                'tags': obl.tags,
                'firstSeen': obl.first_seen,
                'lastSeen': obl.last_seen,
                'enclave_Ids': obl.enclaveIds,
            } for obl in obls
        ]
        
    # if output not specificed, include most commonly used fields
    else:
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


    ## Argument Validation
    if args.only_vals and args.only_vt:
        print('Parameters "only_vals" and "only_vt" cannot both be True')
        sys.exit()

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

    # Get obls w/specified return filters
    obls = retrieve_obls(
        dts[0],
        dts[1],
        ioc_types,
        args.only_vals,
        args.only_vt,
        enc_ids,
        args.all,
    )

    # Output results, if any, to file
    if not obls:
        print('No IOCs matched the query. Nothing to output.')
    else:
        if args.csv:
            obl_dict_to_csv(obls, args.outfile, args.split_tags)
        else:
            obl_dict_to_json(obls, args.outfile)
