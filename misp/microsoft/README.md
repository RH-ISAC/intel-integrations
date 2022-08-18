# ./INTEL-INTEGRATIONS/MISP/MICROSOFT
A storage place for Microsoft integrations for the RH-ISAC MISP instance.

> **Warning**
> Use the content in this repository at your own risk. RH-ISAC will not be held responsible for data loss, nor any other problems resulting from the use of this content.

## Requirements
This integration does not have any additional requirements from our base scripts.
- Python 3.9+
- PyMISP `pip install pymisp` (https://github.com/MISP/PyMISP)

> **Note**
> We strongly recomend the usage of [virtual environments](https://docs.python.org/3/library/venv.html) to provide a clean space to install dependancies.

## MISP API Configuration
A valid **rh-isac.conf** file is the easiest way to setup access and authentication to the MISP and Microsoft Graph APIs. To set up the MISP portion of the api check the MISP Configuration section of the [README.md file in /misp/](../../README.md).


## Graph API Config
The [full guide](https://docs.microsoft.com/en-us/azure/sentinel/connect-threat-intelligence-tip) from Microsoft provides instructions on how to configure the Azure App to integrate with an external TIP. RH-ISAC also has some documentation in Member Exchange (link to come) that details the same process.


## PyMISP - Python Library to access MISP
1. Documentation: https://pymisp.readthedocs.io
2. Source: https://github.com/MISP/PyMISP

## Microsoft Graph API/Sentinel/Defender Resources
1. Threat Indicator Graph API Overview: https://docs.microsoft.com/en-us/graph/api/resources/tiindicator?view=graph-rest-beta
2. TIP Integration Guide: https://docs.microsoft.com/en-us/azure/sentinel/connect-threat-intelligence-tip

