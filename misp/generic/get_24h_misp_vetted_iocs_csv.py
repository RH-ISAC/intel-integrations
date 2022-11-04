#!/usr/bin/env python3
"""Retrieve last 24 hours of IOCs from MISP and output to a csv file.
"""

__author__ = 'Ian Furr'
__version__ = '0.1'
__email__ = 'ian.furr@rhisac.org'

import csv
from configparser import ConfigParser
from datetime import datetime
from typing import List

from pymisp import PyMISP

# Override defaults here
CONFIG_PATH = "./misp/rh-isac.conf"
CONFIG_SECTION = "RH-ISAC MISP"
MISP_URL = "https://misp.rhisac.org"
OUTPUT_FIELDS = ('value', 'type', 'timestamp', 'Tag', 'Event')
OUTPUT_FILENAME = None
VETTED_TAG = "rhisac: vetted"


def get_misp_key() -> str:
    """Get the MISP authkey from a local config file

    Returns
    _______
    str
        The MISP authkey
    """
    config = ConfigParser()
    if not config.read(CONFIG_PATH):
        if not config.read("../" + CONFIG_PATH):
            print(f'Config file {CONFIG_PATH} not found')
            exit()
    try:

        key = config[CONFIG_SECTION]['Key']
        return key
    except KeyError as e:
        print(f'Cannot find "{e}" in file {CONFIG_PATH}')
        exit()


def get_last24h_vetted_iocs() -> List[dict]:
    """Query the MISP API for last 24 hours of RH-ISAC Vetted IOCs and return

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

    print(f'\nGetting all IOCs added to MISP in past 24 hours...')

    # Query API for IOCs
    try:
        results = misp.search('attributes', tags=[VETTED_TAG], timestamp='1d')
        iocs = results['Attribute']
        print(f'Got {len(iocs)} IOCs from MISP')
    except Exception as e:
        print(f'Error while query MISP for IOCs: {str(e)}')
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
        for k,v in ioc.items():
            if k not in OUTPUT_FIELDS:
                continue
            else:
                if k == 'Tag':
                    keep['tags'] = "|".join([x['name'] for x in v if x['name'] != VETTED_TAG])
                elif k == 'Event':
                    keep['event'] = v['info']
                else:
                    keep[k] = v
        out.append(keep)
    return out

def ioc_dicts_to_csv(iocs: List[dict], 
                      filename: str = None,
                      ) -> None:
    """Take a list of ioc dictionaries and write to a CSV file.

    Parameters
    ----------
    iocs : List[dict]
        The indicators to be written out to a file
    filename : str, optional
        The desired name/path for the output file
    """
    if not filename:
        now = datetime.now().strftime('%Y%m%dT%H%M%S')
        filename = f'rhisac_iocs_last24h_{now}.csv'
        
    with open(filename, 'w', newline='') as f:
        header = list(iocs[0].keys())

        # move tags column (if any) to end
        if 'tags' in header:
            header.remove('tags')
            header.append('tags')

        indwriter = csv.writer(f)
        indwriter.writerow(header)
        for ioc in iocs:
            try:
                row = [ioc[rh] for rh in header if rh != 'tags']
                if ioc.get('tags'): # Check to see if tags exist for obl
                    row.append(str(ioc.get('tags')).replace("\"","'"))
                indwriter.writerow(row)
            except Exception as exc:
                print(f"Error writing indicator {ioc} to CSV: {str(exc)}")
    print(f'Wrote {len(iocs)} IOCs to CSV file: {filename}')


if __name__ == '__main__':
    # Call main function
    iocs = get_last24h_vetted_iocs()

    # Filter results, if any, and output to file
    if not iocs:
        print('No IOCs found in last 24h. Nothing to output.')
    else:
        filtered = filter_results(iocs)
        ioc_dicts_to_csv(filtered, OUTPUT_FILENAME)
