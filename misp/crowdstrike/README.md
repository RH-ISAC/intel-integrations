# ./INTEL-INTEGRATIONS/MISP/CROWDSTRIKE
A storage place for Crowdstrike integrations for the RH-ISAC MISP instance.

> **Warning**
> Use the content in this repository at your own risk. RH-ISAC will not be held responsible for data loss, nor any other problems resulting from the use of this content.

## Requirements
- Python 3.9+
- PyMISP `pip install pymisp` (https://github.com/MISP/PyMISP)
- CrowdStrike Falcon Python Module (FalconPy) `pip install crowdstrike-falconpy`

> **Note**
> We strongly recomend the usage of [virtual environments](https://docs.python.org/3/library/venv.html) to provide a clean space to install dependancies.

## MISP API Configuration
A valid **rh-isac.conf** file is the easiest way to setup access and authentication to the MISP and Microsoft Graph APIs. To set up the MISP portion of the api check the MISP Configuration section of the [README.md file in /misp/](../../README.md).


## Falcon API Config
Retrieve your falcon API key and secret from the falcon console and palce them into the relevant sections in your **rh-isac.conf** file.


## PyMISP - Python Library to access MISP
1. Documentation: https://pymisp.readthedocs.io
2. Source: https://github.com/MISP/PyMISP

## Falcon Resources
1. Falcon API Swagger Docs (REQUIRES AUTH): https://assets.falcon.laggar.gcw.crowdstrike.com/support/api/swagger-eagle.html#/
2. FalconPy Github: https://github.com/CrowdStrike/falconpy

