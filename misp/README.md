# ./INTEL-INTEGRATIONS/MISP
A storage place for MISP related scripts. You can find generic MISP->CSV or MISP->JSON scripts in the generic directory, or integration specific scripts inside of the directories with the same name. 

> **Warning**
> Use the content in this repository at your own risk. RH-ISAC will not be held responsible for data loss, nor any other problems resulting from the use of this content.

## Requirements
- Python 3.9+
- PyMISP `pip install pymisp` (https://github.com/MISP/PyMISP)
- Application specific modules (depending on the script)

> **Note**
> We strongly recomend the usage of [virtual environments](https://docs.python.org/3/library/venv.html) to provide a clean space to install dependancies.

## Configuration
A valid **rh-isac.conf** file is the easiest way to setup access and authentication to the MISP API.
1. Make a copy of **rh-isac.conf.example** and name it **rh-isac.conf**
2. Generate an auth key in MISP
   1. Visit https://misp.rhisac.org/users/view/me
   2. Select `Auth Keys`
   3. Then `Add authentication key`
   4. Add a comment to the comment field to easily identify the key in the future. If you dont plan to write any data back to the RH-ISAC MISP instance, we also recomend using the read only flag to limit unnecessary permissions on the key.
   5. Finally choose `Submit`
   6. Copy the key presented on the next screen into your **rh-isac.conf** where it says `<MISP API KEY HERE>`
3. Save the file in the same directory as the MISP Python scripts you would like to go

## PyMISP - Python Library to access MISP
1. Documentation: https://pymisp.readthedocs.io
2. Source: https://github.com/MISP/PyMISP

## MISP Integrations
- CrowdStrike Falcon:
- Splunk (and Splunk ES):
- Microsoft (Sentinel & Defender for Endpoint): Retrieve the last 24 hours of RH-ISAC Vetted IOCs from MISP and output them to a JSON file.

## Generic MISP Scripts
- get_24h_misp_vetted_iocs.py: Retrieve the last 24 hours of RH-ISAC Vetted IOCs from MISP and output them to a JSON file.

## cURL Example (non-Python)
### Retrieve IOCs from MISP
Other attributes can be found here: https://www.misp-project.org/openapi/#tag/Attributes/operation/restSearchAttributes
```bash
curl -H "Authorization: <AUTH_KEY>" -H "Content-Type: application/json" -H "Accept: application/json" -d '{"limit":"10", "from":"2022-08-01"}' -X POST https://misp-pre.rhisac.org/attributes/restSearch
```
