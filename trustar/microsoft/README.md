# ./INTEL-INTEGRATIONS/TRUSTAR/MICROSOFT
> **Warning**
> Use the content in this repository at your own risk. RH-ISAC will not be held responsible for data loss, nor any other problems resulting from the use of this content.

> **Warning**
> The section of the Microsoft Graph API used to create threat indicators is a beta version which may change at any time. Please alert the RH-ISAC staff if you begin to experience issues due to any changes. 

**THIS SCRIPT IS A BETA VERSION**

## Requirements
- Python 3.9+
- TruSTAR Python SDK
   - RH-ISAC mantains an updated version of the Offical TruSTAR repo that can be found on [our github](https://github.com/RH-ISAC/trustar-sdk2-proto)
   - Clone and pip install that repo (`git clone https://github.com/RH-ISAC/trustar-sdk2-proto` `pip install <PATH TO DOWNLOADED REPO>`)

> **Note**
> We strongly recomend the usage of [virtual environments](https://docs.python.org/3/library/venv.html) to provide a clean space to install dependancies.

## TruSTAR Configuration
A valid **rh-isac.conf** file is requred to authenticate to the TruSTAR and MS Graph APIs.
1. Make a copy of **rh-isac.conf.example** and name it **rh-isac.conf**.
2. Lookup your TruSTAR API Key and API Secret in TruSTAR station and place them in the newly created **rh-isac.conf**
   1. Keys can be rotated and accessed here: https://station.trustar.co/settings/api

## Graph API Config
The [full guide](https://docs.microsoft.com/en-us/azure/sentinel/connect-threat-intelligence-tip) from Microsoft provides instructions on how to configure the Azure App to integrate with an external TIP. RH-ISAC also has some documentation in Member Exchange (link to come) that details the same process.

# Documentation/Reference
## TruSTAR Python SDK & REST API
1. TruSTAR Python SDK
   1. Documentation: https://docs.trustar.co/sdk/index.html
   2. Examples: https://github.com/RH-ISAC/trustar-sdk2-proto/blob/main/documentation.md
   3. Source: https://github.com/RH-ISAC/trustar-sdk2-proto
2. TruSTAR REST API
   1. Documentation: https://docs.trustar.co/api/index.html
   2. Usage Policy: https://support.trustar.co/article/m5kl5anpiz-api-rate-limit-quota

## Microsoft Graph API/Sentinel/Defender Resources
1. Threat Indicator Graph API Overview: https://docs.microsoft.com/en-us/graph/api/resources/tiindicator?view=graph-rest-beta
2. TIP Integration Guide: https://docs.microsoft.com/en-us/azure/sentinel/connect-threat-intelligence-tip

