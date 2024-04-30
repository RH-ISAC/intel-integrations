#!/usr/bin/env python3
""" Create a csv file with indicators from the last 24 hrs.
"""
__author__ = "Ian Furr"
__version__ = "0.1"
__email__ = 'ian.furr@rhisac.org'

import csv
import sys
from requests.exceptions import HTTPError
from datetime import datetime, timedelta, timezone

from trustar2 import TruStar, Account, log, Submission, Observables

ENCLAVE_IDS = [
    "59cd8570-5dce-4e5b-b09c-9807530a7086",  # RH-ISAC
]

if __name__ == '__main__':
    # Create a TruSTAR API Object
    try:
        ts = TruStar.config_from_file(config_file_path="./trustar2.conf", config_role="rh-isac-vetted")
    except KeyError as e:
        print(f'{str(e)[1:-1]} in config file "trustar2.conf". Exiting...')
        exit()

    try:
        # Validate credentials against API
        _ = Account(ts).ping()
    except HTTPError as exc:
        print(f'Failed to access API. Check your "trustar2.conf" file:\n{str(exc)}')
        sys.exit()
    
    # initialize logger
    logger = log.get_logger(__name__)

    # set report query range to the past week (7 24-hour periods)
    
    to_time = datetime.now(timezone.utc)
    from_time = to_time - timedelta(days=1)  # last 7 days
    print(f'\nRetrieving all IOCs between UTC {from_time} and {to_time}...')
    from_time = int(from_time.timestamp() * 1000)
    to_time = int(to_time.timestamp() * 1000)

    # define CSV column names
    HEADERS = [
        "report_id",
        "report_title",
        "report_tags",
        "indicator_value",
        "indicator_type"
    ]

# open the output csv to create it
now = datetime.now().strftime('%Y%m%d_%H%M%S')
filename = f'trustar_iocs_{now}.csv'
with open(filename, 'w') as f:

    # create csv writer object
    writer = csv.DictWriter(f, HEADERS)
    # write header row
    writer.writeheader()

    try:
        # keep count of reports (for logging)
        report_count = 0

        # get all reports from the specified enclaves and in the given time interval
        pages = (
            Submission(ts)
                .set_enclave_ids(ENCLAVE_IDS)
                .set_from(from_time)
                .set_to(to_time)
                .set_page_size(500)
                .search()        
        )
        submissions = [submission for page in pages for submission in page.data]

        
        out = [
        {
            'guid': submission.guid,
            'enclave_guid': submission.enclave_guid,
            'title': submission.title,
            'tags': submission.tags,
            'created': submission.created,
            'updated': submission.updated,
        } for submission in submissions
        ]
        
        # Iterate through list of reports, 
        # get observables (indicators) associated with each
        for submission in out:
            logger.info("Found report %s." % submission.get('guid'))
            
            obl_pages = (
                Observables(ts)
                    .set_enclave_ids(ENCLAVE_IDS)
                    .set_from(from_time)
                    .set_to(to_time)
                    .set_page_size(500)  # Avoid API Limits
                    .search()
            )
            obls = [obl for page in obl_pages for obl in page.data]

            # Include most commonly used fields
            obl_out = [
            {
                'value': obl.value,
                'indicatorType': obl.type,
                'tags': obl.tags,
                'firstSeen': obl.first_seen,
                'lastSeen': obl.last_seen,
                } for obl in obls
            ]
    
            # keep count of indicators for this report (for logging)
            obl_count = 0

            # Iterate through the observables returned for tags, then parse for csv
            try:
                for obl in obl_out:
                    
                    tags = ""
                    if submission.get('tags'):
                        tags = "|".join(submission.get('tags'))
                        logger.info("Tags: %s" % tags)
                    line = {
                        'report_id': submission.get('guid'),
                        'report_title': submission.get('title'),
                        'report_tags': tags,
                        'indicator_value': obl.get('value'),
                        'indicator_type': obl.get('indicatorType'),
                    }
                    
                    writer.writerow(line)
                    obl_count += 1
            except Exception as e:
                logger.warning("Error: Can't get IOCs for report: %s. Skipping." % submission.id)
                print("")
                continue
            logger.info("Wrote %d indicators for report." % obl_count)
            print("")

            report_count += 1

        logger.info("Found %d reports." % report_count)

    except Exception as e:
        logger.error("Error: %s" % e)
        raise

