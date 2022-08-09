# Sentinel Integration Script
> **Warning**
> Use the content in this repository at your own risk. RH-ISAC will not be held responsible for data loss, nor any other problems resulting from the use of this content. **THIS SCRIPT IS A BETA VERSION**

> **Warning**
> The section of the Microsoft Graph API used to create threat indicators is a beta version which may change at any time. Please alert the RH-ISAC staff if you begin to experience issues due to any changes. 


## Requirements
The Graph API script requires:
1. The TruSTAR Python SDK
   1. To install, follow the instructions in the TruStar directory of this repo
3. A valid **aad_config.conf** file
   1. See *CONFIGURATION* section below

## Configuration
A valid **aad_config.conf** file is requred to authenticate to the TruSTAR and MS Graph APIs.
1. Make a copy of **aad_config_example.conf** and name it **aad_config.conf**.
2. Lookup your TruSTAR API Key and API Secret in TruSTAR station and place them in the spots specified in the **trustar2.conf** file
   1. Keys can be rotated and accessed here: https://station.trustar.co/settings/api
3. Follow the instructions in the *Configuring the Azure AD App* section below to obtain the App credentials in the **aad** section of the config.
4. The **product** field can have one of two strings, either "Azure Sentinel" or "Microsoft Defender ATP". Use whichever matches the product you are integrating with.
5. Save the file in the same directory as your TruSTAR Python script

## Configuring the Azure AD App
The integration requires access to the MS Graph API which is configured through an Azure Active Direcory Application. 
Follow the instructions in this guide from microsoft: https://docs.microsoft.com/en-us/azure/sentinel/connect-threat-intelligence-tip


# Documentation/Reference
## TruSTAR Python SDK & REST API
1. TruSTAR Python SDK
   1. Documentation: https://docs.trustar.co/sdk/index.html
   2. Examples: https://github.com/RH-ISAC/trustar-sdk2-proto/blob/main/documentation.md
   3. Source: https://github.com/RH-ISAC/trustar-sdk2-proto
2. TruSTAR REST API
   1. Documentation: https://docs.trustar.co/api/index.html
   2. Usage Policy: https://support.trustar.co/article/m5kl5anpiz-api-rate-limit-quota

## Microsoft
1. TIP Integration Progess
    1. Overview: https://docs.microsoft.com/en-us/azure/sentinel/connect-threat-intelligence-tip
2. Indicator API Fields
   https://docs.microsoft.com/en-us/graph/api/resources/tiindicator?view=graph-rest-beta
