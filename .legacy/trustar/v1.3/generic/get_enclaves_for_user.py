#!/usr/bin/env python3
"""Output a list of TruSTAR enclaves to which a API user has access.

By default, prints to the screen a list of enclave IDs and names,
sorted by enclave name.
Arguments can be used to output in raw JSON, or pretty-print JSON.
Arguments also can filter output based on enclave create/update rights.
"""

import argparse
import json
import operator
import sys
from typing import Dict, List

from requests.exceptions import HTTPError
from trustar import TruStar
from trustar.models import EnclavePermissions

__author__ = "Bradley Logan"
__version__ = "0.9"
__email__ = 'bradley.logan@rhisac.org'


def filter_enclaves(encs: Dict[str, EnclavePermissions],
                    create: bool = False,
                    no_create: bool = False,
                    update: bool = False,
                    no_update: bool = False,
                    ) -> List[dict]:
    """Filter a list of TruSTAR enclaves based on access rights.

    Parameters
    __________
    encs : List[EnclavePermissions]
        a list of TruSTAR EnclavePermissions objects to be filtered
    create: boolean, optional
        Only return enclaves where user has create permissions
    no_create: boolean, optional
        Only return enclaves where user does not have create permissions
    update: boolean, optional
        Only return enclaves where user has update permissions
    no_update: boolean, optional
        Only return enclaves where user does not have update permissions

    Returns
    _______
    list[dict]
        A list of enclave permissions as dictionaries
    """
    if create and update:
        dicts = [encs[id].to_dict() for id in encs if encs[id].create and encs[id].update]
    elif no_create and no_update:
        dicts = [encs[id].to_dict() for id in encs if not encs[id].create and not encs[id].update]
    elif create and no_update:
        dicts = [encs[id].to_dict() for id in encs if encs[id].create and not encs[id].update]
    elif no_create and update:
        dicts = [encs[id].to_dict() for id in encs if not encs[id].create and encs[id].update]
    elif create:
        dicts = [encs[id].to_dict() for id in encs if encs[id].create]
    elif no_create:
        dicts = [encs[id].to_dict() for id in encs if not encs[id].create]
    elif update:
        dicts = [encs[id].to_dict() for id in encs if encs[id].update]
    elif no_update:
        dicts = [encs[id].to_dict() for id in encs if not encs[id].update]
    else:
        dicts = []

    return dicts


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
if args.create and args.no_create:
    print('Create and not_create filters cannot both be selected')
    sys.exit()
if args.update and args.no_update:
    print('Update and not_update filters cannot both be selected')
    sys.exit()

# Initiate API Object
ts = TruStar(config_file='trustar.conf', config_role='rh-isac')
try:
    _ = ts.ping()
except HTTPError as exc:
    print(f'Failed to access API. Check your "trustar.conf" file:\n{str(exc)}')
    sys.exit()

# Get list of enclaves to which user has access
usr_encs = ts.get_user_enclaves()

# Print raw SDK results, if requested
if args.raw:
    print(usr_encs)
    sys.exit()

# Filter results, if requested
if args.create or args.no_create or args.update or args.no_update:
    all_encs = {enc.id: enc for enc in usr_encs}
    enc_dicts = filter_enclaves(all_encs,
                                args.create,
                                args.no_create,
                                args.update,
                                args.no_update)
else:  # return all enclaves
    enc_dicts = [enc.to_dict() for enc in usr_encs]

# Output in desired format
if args.pretty:
    print(json.dumps(sorted(enc_dicts, key=operator.itemgetter('name')), indent=3))
elif args.json:
    print(json.dumps(sorted(enc_dicts, key=operator.itemgetter('name'))))
else:
    for enc in sorted(enc_dicts, key=operator.itemgetter('name')):
        print(f"{enc['id']}: {enc['name']}")
print('')
