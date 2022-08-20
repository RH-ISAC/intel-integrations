# ./INTEL-INTEGRATIONS/TRUSTAR/CROWDSTRIKE

> **Warning**
> Use the content in this repository at your own risk. RH-ISAC will not be held responsible for data loss, nor any other problems resulting from the use of this content. 

**THIS SCRIPT IS A IN BETA**

## Requirements
- Python 3.9+
- The TruSTAR Python SDK
   - To install, follow the instructions in the [README in the TruSTAR directory](../README.md) of this repo
- CrowdStrike Falcon Python Module (FalconPy) `pip install crowdstrike-falconpy`

> **Note**
> We strongly recomend the usage of [virtual environments](https://docs.python.org/3/library/venv.html) to provide a clean space to install dependancies.

## Configuration
### TruSTAR Configuration
A valid **rh-isac.conf** file is the easiest way to setup access and authentication to the TruSTAR and the CrowdStrike APIs. Detailed instructions can be found in the [README in the TruSTAR directory](../README.md) however you can retrieve your TruSTAR API credentials in the TruSTAR portal. https://station.trustar.co/settings/api


### Falcon API Config
Retrieve your falcon API key and secret from the falcon console and palce them into the relevant sections in your **rh-isac.conf** file.

## TruSTAR Python SDK & REST API
1. TruSTAR Python SDK
   1. Documentation: https://docs.trustar.co/sdk/index.html
   2. Source: https://github.com/trustar/trustar-python
2. TruSTAR REST API
   1. Documentation: https://docs.trustar.co/api/index.html
   2. Usage Policy: https://support.trustar.co/article/m5kl5anpiz-api-rate-limit-quota


## Falcon Resources
1. Falcon API Swagger Docs (REQUIRES AUTH): https://assets.falcon.laggar.gcw.crowdstrike.com/support/api/swagger-eagle.html#/
2. FalconPy Github: https://github.com/CrowdStrike/falconpy

