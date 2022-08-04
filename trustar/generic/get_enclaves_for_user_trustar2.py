#!/usr/bin/env python3
"""Output a list of TruSTAR enclaves to which a API user has access
using the TruSTAR 2.0 API.

By default, prints to the screen a list of enclave IDs and names,
sorted by enclave name.
Arguments can be used to output in raw JSON, or pretty-print JSON.
Arguments also can filter output based on enclave create/update rights.
"""
__author__ = "Ian Furr, Bradley Logan"
__version__ = "0.1"
__email__ = 'ian.furr@rhisac.org, bradley.logan@rhisac.org'

import argparse
from enum import Enum
import sys
import json
import operator
from typing import Dict, List

from requests.exceptions import HTTPError

from trustar2 import TruStar, Account
from trustar2.models.enclave import Enclave

def enclaves_to_json(enclaves: list[Enclave]) -> list[Dict]: 
    """ Convert a list of Enclave objects to list of enclaves formatted as Dicts
        
    Parameters
    __________
    enclave: Enclave
        a TruSTAR Enclave Object to be converted to a JSON formatted string.
    """
    json_enclaves = []
    for enclave in enclaves:
        enclave_dict = {'id': enclave.id, 'name': enclave.name, 
            'type': enclave.type, 'read': enclave.read, 'create': enclave.create, 
            'update': enclave.update, 'workflow_supported': enclave.workflow_supported}
        json_enclaves.append(enclave_dict)

    return json_enclaves

def filter_enclaves(enclaves: list, 
                    create: int = 2,  
                    update: int = 2 ) -> List[Enclave]: 
    """ Filter a list of TruSTAR Enclaves based on access permissions.
        
    Parameters
    __________
    enclaves: List[Enclaves]
        a list of TruSTAR Enclave Objects to filter.
    create: int, optional
        If specified parse the list for enclaves with matching create permissions 
        (0 None, 1 Create, 2 Ignore)
    update: int, optional
        If specified parse the list for enclaves with matching update permissions 
        (0 None, 1 Create, 2 Ignore)
    """
    filtered_enclaves = []
    for enclave in enclaves:
        # Create - matches, Update - ignored
        if create == enclave.create and update == 2:
            filtered_enclaves.append(enclave)
            continue
        # Create - ignored, Update - matches
        elif create == 2 and update == enclave.update:
            filtered_enclaves.append(enclave)
            continue
        # Create - matches, Update - matches
        elif create == enclave.create and update == enclave.update:
            filtered_enclaves.append(enclave)
            continue
        else:  
            continue

    return filtered_enclaves


if __name__ == '__main__':
    # Parse arguments
    parser = argparse.ArgumentParser()
    parser.description = ('Output the TruSTAR enclaves to which the given API user has '
                        'access. Default output is just enclave_id and enclave_name.')
    parser.add_argument('-p', '--pretty', action='store_true',
                        help='Output all fields in pretty print JSON format')
    parser.add_argument('-j', '--json', action='store_true',
                        help='Output all fields as a simple JSON string')
    parser.add_argument('-c', '--create', action='store_true',
                        help='Only return enclaves where user has create permissions')
    parser.add_argument('-C', '--no_create', action='store_true',
                        help='Only return enclaves where user does not have create permissions')
    parser.add_argument('-u', '--update', action='store_true',
                        help='Only return enclaves where user has update permissions')
    parser.add_argument('-U', '--no_update', action='store_true',
                        help='Only return enclaves where user does not have update permissions')
    parser.add_argument('-r', '--raw', action='store_true',
                        help='Simply print results of Python SDK call')
    args = parser.parse_args()

    # Validate user-supplied arguments
    if args.raw and (args.create or args.update or args.no_create or args.no_update):
        print('Cannot filter on a field when raw output is selected')
        sys.exit()
    if args.raw and (args.pretty or args.json):
        print('Display options cannot be used with raw output')
        sys.exit()
    if args.pretty and args.json:
        print('Multiple display options can not be used at the same time')
        sys.exit()
    if args.create and args.no_create:
        print('Create and not_create filters cannot both be selected')
        sys.exit()
    if args.update and args.no_update:
        print('Update and not_update filters cannot both be selected')
        sys.exit()

    # Set Create and Update vars for filter matching
    # 0 = "no_create", 1 = "create", 2 = "ignore" # TODO: Less hacky solution
    if args.create == 1:
        create = 1
    elif args.no_create == 1:
        create = 0
    else: 
        create = 2

    # 0 = "no_create", 1 = "create", 2 = "ignore"
    if args.update == 1:
        update = 1
    elif args.no_update == 1:
        update = 0
    else: 
        update = 2

    # Create a TruSTAR API Object
    try:
        ts = TruStar.config_from_file(config_file_path="./trustar2.conf", config_role="rh-isac_vetted")
    except KeyError as e:
        print(f'{str(e)[1:-1]} in config file "trustar2.conf". Exiting...')
        exit()

    try:
        # Validate credentials against API
        _ = Account(ts).ping()
    except HTTPError as exc:
        print(f'Failed to access API. Check your "trustar2.conf" file:\n{str(exc)}')
        sys.exit()
        
    # Get list of enclaves to which user has access
    enclaves = Account(ts).get_enclaves().data

    # Print raw SDK Results
    if args.raw:
        print(enclaves)
        sys.exit()

    # Optional Result Filter
    if create != 2 or update != 2:
        final_enclaves = filter_enclaves(enclaves=enclaves)

    # Return all enclaves if no filtering is applied
    else:
        final_enclaves = enclaves

    # Convert final encalves into a dict with json formatted strings inside
    final_enclaves = enclaves_to_json(final_enclaves)

    if args.pretty:
        print(json.dumps(sorted(final_enclaves, key=operator.itemgetter('name')), indent=3))
    elif args.json:
        print(json.dumps(sorted(final_enclaves, key=operator.itemgetter('name'))))
    else: 
        for enclave in sorted(final_enclaves, key=operator.itemgetter('name')):
            print(f"{enclave['id']}: {enclave['name']}")
    print("")

