# Sunsetting of this Integration
This integration has been depricated in favor of the MISP42 Splunk App. More details about that integration can be found here: 
https://splunkbase.splunk.com/app/4335
https://github.com/remg427/misp42splunk


# ./INTEL-INTEGRATIONS/MISP/SPLUNK 
A storage place for Splunk related integrations for the RH-ISAC MISP instance.

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

### Splunk Configuration
#### Splunk
```
[splunk]
base_url = https://localhost:8089
username = <SPLUNK USERNAME>
password = <SPLUNK PASSWORD>
headers = <SPLUNK HEADERS>
```
The `base_url` field will be the hostname of your splunk instance, followed by the port you have exposed (similar to the example text above). The `username` and `password` should be the account details for whichever account you've set up to access your splunk instance, and has the permissions to write IOCs.

#### Splunk ES
```
[splunk-es]
base_url = https://localhost:8089
token = <ENTER AUTH TOKEN HERE>
headers = <SPLUNK HEADERS>
```
The `base_url` field will be the hostname of your splunk instance, followed by the port you have exposed (similar to the example text above). The `token` field should contain the splunk access token that you have created, that has the permissions to write IOCs.
# Documentation/Reference
## PyMISP - Python Library to access MISP
1. Documentation: https://pymisp.readthedocs.io
2. Source: https://github.com/MISP/PyMISP
