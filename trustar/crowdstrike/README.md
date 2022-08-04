# Crowdstrike Falcon Integration Script
> **Warning**
> Use the content in this repository at your own risk. RH-ISAC will not be held responsible for data loss, nor any other problems resulting from the use of this content. **THIS SCRIPT IS A BETA VERSION**

## Requirements
The CrowdStrike script requires:
1. The TruSTAR Python SDK
   1. To install, follow the instructions in the README in the root of this repo
2. The CrowdStrike Falcon Python Module (FalconPy)
    1. `pip install crowdstrike-falconpy`
3. A valid **trustar.conf** and **cs_config.json** file
   1. See CONFIGURATION section below

## Configuration
Valid **trustar2.conf** and **cs_config.json** files are requred to authentication to the TruSTAR and CrowdStrike APIs.
1. Make a copy of **trustar_example2.conf** and **cs_config_example.json** and name them **trustar2.conf** and **cs_config.json** respectively.
2. Lookup your TruSTAR API Key and API Secret in TruSTAR station and place them in the spots specified in the **trustar2.conf** file
   1. https://station.trustar.co/settings/api
3. Retrive your CrowdStrike Falcon API ID and Secret Key and place them in the specified locations in the **cs_config.json** file
4. Save the files in the same directory as your TruSTAR Python script
Run the scripts



## TruSTAR Python SDK & REST API
1. TruSTAR Python SDK
   1. Documentation: https://docs.trustar.co/sdk/index.html
   2. Source: https://github.com/trustar/trustar-python
2. TruSTAR REST API
   1. Documentation: https://docs.trustar.co/api/index.html
   2. Usage Policy: https://support.trustar.co/article/m5kl5anpiz-api-rate-limit-quota

## CrowdStrike Falcon
1. API Documentation
    1. Swagger Docs: https://assets.falcon.laggar.gcw.crowdstrike.com/support/api/swagger-eagle.html#/
2. FalconPy Documentation
    1. Github: https://github.com/CrowdStrike/falconpy