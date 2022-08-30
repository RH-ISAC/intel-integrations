# ./INTEL-INTEGRATIONS/MISP/MICROSOFT 
A storage place for Microsoft related integrations for the RH-ISAC MISP instance.

> **Warning**
> Use the content in this repository at your own risk. RH-ISAC will not be held responsible for data loss, nor any other problems resulting from the use of this content. **This script is a beta version and intended to be used as an example.**

## Requirements
- Python 3.9+
- PyMISP `pip install pymisp` (https://github.com/MISP/PyMISP)


> **Note**
> We strongly recomend the usage of [virtual environments](https://docs.python.org/3/library/venv.html) to provide a clean space to install dependancies.

## Configuration
These scripts use a configuration file named **rh-isac.conf**. It contains the details to authenticate to the RH-ISAC MISP Instance, and the target of each of the integrations. There are example files (**rh-isac.conf.example**) inside of each integration directory that contain the details needed to authenticate to the targets of that integration. 

### MISP Configuration
To obtain your MISP Credentials authenticate to the RH-ISAC MISP instance, then navigate to your [profile page](https://misp.rhisac.org/users/view/me) and select `Auth Keys`. Select `Add authentication key` and follow the prompts through key creation. Once you have your key, copy it out of the MISP UI and into your **rh-isac.conf**.

```
# RH-ISAC MISP - Check the ./misp/README.md file for details.
[RH-ISAC MISP]
key = <MISP API KEY HERE>
```
The `key` field is your MISP API key.

### Graph API Config
The process for integrating with Sentinel and Windows Defender is a little more involved. Microsoft has a fairly in-depth [guide](https://docs.microsoft.com/en-us/azure/sentinel/connect-threat-intelligence-tip). RH-ISAC also has a guide in progess with additional screenshots in the works and this documentation will be updated with a link soon. 

```
[microsoft]
product = Azure Sentinel
tenantId = <MICROSOFT AZURE TENANT ID HERE>
appId = <MICROSOFT GRAPH API APPID HERE>
appSecret = <MICROSOFT GRAPH API SECRET KEY HERE>
```

The `product` field dictates which Microsoft product you are targeting, it can either be "*Azure Sentinel*" or "*Microsoft Defender ATP*". The `tenantId` field should be filled with your Tenant ID. (This can be found in various places in the Azure UI, or via the Powershell `Connect-AzAccount` commandlet.) During the application setup process you should find and copy the `appId` and `appSecret` as the secret will *not be shown again*.


# Documentation/Reference
## PyMISP - Python Library to access MISP
1. Documentation: https://pymisp.readthedocs.io
2. Source: https://github.com/MISP/PyMISP

## Microsoft Graph API/Sentinel/Defender Resources
1. Threat Indicator Graph API Overview: https://docs.microsoft.com/en-us/graph/api/resources/tiindicator?view=graph-rest-beta
2. TIP Integration Guide: https://docs.microsoft.com/en-us/azure/sentinel/connect-threat-intelligence-tip

