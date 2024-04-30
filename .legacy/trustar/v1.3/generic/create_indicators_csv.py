import csv
from datetime import datetime, timedelta

from trustar import datetime_to_millis, log, TruStar


# initialize SDK
ts = TruStar(config_file='trustar.conf', config_role='rh-isac_vetted')

# initialize logger
logger = log.get_logger(__name__)

# set report query range to the past week (7 24-hour periods)
to_time = datetime.now()
from_time = to_time - timedelta(days=7)

# convert to millis since epoch
to_time = datetime_to_millis(to_time)
from_time = datetime_to_millis(from_time)

# define CSV column names
HEADERS = [
    "report_id",
    "report_title",
    "report_tags",
    "indicator_value",
    "indicator_type"
]

# open the output csv to create it
with open('indicators.csv', 'w') as f:

    # create csv writer object
    writer = csv.DictWriter(f, HEADERS)
    # write header row
    writer.writeheader()

    try:
        # keep count of reports (for logging)
        report_count = 0

        # get all reports from the specified enclaves and in the given time interval
        reports = ts.get_reports(from_time=from_time,
                                 to_time=to_time,
                                 is_enclave=True,
                                 enclave_ids=ts.enclave_ids)

        # iterate over the reports, finding the tags and indicators for each
        for report in reports:

            logger.info("Found report %s." % report.id)

            # get all tags for the report and convert list to string
            tags = [tag.name for tag in ts.get_enclave_tags(report.id)]

            # join tags into a semicolon-separated list
            tags = ';'.join(tags)

            logger.info("Tags: %s" % tags)
            logger.info("Writing indicators for report...")

            # keep count of indicators for this report (for logging)
            indicator_count = 0

            try:
                # get indicators for report and write CSV row for each
                for indicator in ts.get_indicators_for_report(report.id):

                    # create CSV row
                    row = {
                        'report_id': report.id,
                        'report_title': report.title,
                        'report_tags': tags,
                        'indicator_value': indicator.value,
                        'indicator_type': indicator.type
                    }
                    # write the CSV row to the file
                    writer.writerow(row)

                    indicator_count += 1
            except Exception as e:
                logger.warning("Error: Can't get IOCs for report: %s. Skipping." % report.id)
                print("")
                continue

            logger.info("Wrote %d indicators for report." % indicator_count)
            print("")

            report_count += 1

        logger.info("Found %d reports." % report_count)

    except Exception as e:
        logger.error("Error: %s" % e)
        raise
