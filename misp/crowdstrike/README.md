# ./INTEL-INTEGRATIONS/MISP/CROWDSTRIKE 
A storage place for CrowdStrike related integrations for the RH-ISAC MISP instance.

> **Warning**
> Use the content in this repository at your own risk. RH-ISAC will not be held responsible for data loss, nor any other problems resulting from the use of this content. **This script is a beta version and intended to be used as an example.**

## Requirements
- Python 3.9+
- PyMISP `pip install pymisp` (https://github.com/MISP/PyMISP)
- CrowdStrike Falcon Python Module (FalconPy) `pip install crowdstrike-falconpy`

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

### CrowdStrike Configuration
To connect your script to CrowdStrike you'll need to authenticate to falcon, and retrieve your Falcon API Key and Secret key.

```
[crowdstrike]
falcon_client_id = <API ID GOES HERE>
falcon_client_secret = <API SECRET GOES HERE>
```

The `falcon_client_id` is your CrowdStrike API client ID and the `falcon_client_secret` is your CrowdStrike API Secret Key and they can be retrieved from the Falcon Console.


# Documentation/Reference
## PyMISP - Python Library to access MISP
1. Documentation: https://pymisp.readthedocs.io
2. Source: https://github.com/MISP/PyMISP

## CrowdStrike/Falcon Resources
1. Falcon API Swagger Docs (REQUIRES AUTH): https://assets.falcon.laggar.gcw.crowdstrike.com/support/api/swagger-eagle.html#/
2. FalconPy Github: https://github.com/CrowdStrike/falconpy
