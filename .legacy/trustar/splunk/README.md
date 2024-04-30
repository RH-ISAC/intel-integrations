# ./INTEL-INTEGRATIONS/TRUSTAR/SPLUK 
A storage place for Splunk and Splunk ES related integrations for the RH-ISAC TruSTAR instance.

> **Warning**
> Use the content in this repository at your own risk. RH-ISAC will not be held responsible for data loss, nor any other problems resulting from the use of this content. **This script is a beta version and intended to be used as an example.**

## Requirements
- Python 3.9+
- TruSTAR Python SDK (trustar-sdk2-proto or trustar-python-sdk1 See instructions below)

> **Note**
> We strongly recomend the usage of [virtual environments](https://docs.python.org/3/library/venv.html) to provide a clean space to install dependancies.

## Configuration
These scripts use a configuration file named **rh-isac.conf**. It contains the details to authenticate to the RH-ISAC TruSTAR Instance, and the target of each of the integrations. There are example files (**rh-isac.conf.example**) inside of each integration directory that contain the details needed to authenticate to the targets of that integration. 

### TruSTAR Configuration
To obtain your TruSTAR API details, authenticate to TruSTAR and then browse to `https://station.trustar.co/settings/api`. From there you can access or rotate your API and Secret key. 

```
[trustar]
auth_endpoint = https://api.trustar.co/oauth/token
api_endpoint = https://api.trustar.co/api/2.0
user_api_key = <TruSTAR API KEY HERE>
user_api_secret = <TruSTAR SECRET KEY HERE>
# RH-ISAC Vetted IOCs Enclave
enclave_ids = 7a33144f-aef3-442b-87d4-dbf70d8afdb0
client_metatag = RHISAC Vetted Indicator AAD Script
```

The `auth_endpoint` and `api_endpoint` fields are both TruSTAR defaults, and shouldnt need to be changed unless you are switching which version of the API that you are targeting. The `user_api_key` and `user_api_secret` are your API creds obtained from `https://station.trustar.co/settings/api`. The `enclave_ids` field will determine what TruSTAR Enclave you retrieve data from. The default value, the RH-ISAC Vetted Indicators Enclave, is populated by RH-ISAC Analysts each day with validated indicators from our members. The field will accept multiple enclaves, so if desired you could add a comma, followed by the Enclave ID of another enclave you wish to pull data from. The last field, `client_metatag` is an arbitrary string the API uses to gather metadata. You can leave it as the default, or change it to whatever you see fit. 

#### TruSTAR Python Module Configuration
TruSTAR has two Python modules (*trustar-python-sdk1* and *trustar-sdk2-proto*) they host for interacting with the TruSTAR APIs. RH-ISAC has cloned and updated them to the latest requirements so that they can be used with our scripts. The [TruSTAR v2.0 API](https://github.com/RH-ISAC/trustar-sdk2-proto) module should be used for all new integrations. However, if you require access to the old APIs you can find the [TruSTAR 1.3 API](https://github.com/RH-ISAC/trustar-python-sdk1) module on our github as well.

To install the module:
1. Clone the repo you need (Use TruSTAR2 unless you have a specific version to use TruSTAR 1.3)
2. Run `pip install /path/to/repo` where `/path/to/repo` is the path to the location you cloned the TruSTAR Repo
3. Test your install by attempting to import a TruSTAR module from a Python shell. IE: `from trustar2 import TruStar` and if that works you are all set.

### Splunk Configuration
#### Splunk
```
[splunk]
base_url = https://localhost:8089
username = <SPLUNK USERNAME>
password = <SPLUNK PASSWORD>
headers = <SPLUNK HEADERS>
```
The `base_url` field will be the hostname of your splunk instance, followed by the port you have exposed (similar to the example text above). The `username` and `password` should be the account details for whichever account you've set up to access your splunk instance, and has the permissions to write IOCs. Lastly the `headers` field can be used if your splunk instance required additional headers.

#### Splunk ES
```
[splunk-es]
base_url = https://localhost:8089
token = <ENTER AUTH TOKEN HERE>
headers = <SPLUNK HEADERS>
```
The `base_url` field will be the hostname of your splunk instance, followed by the port you have exposed (similar to the example text above). The `token` field should contain the splunk access token that you have created, that has the permissions to write IOCs. Lastly the `headers` field can be used if your splunk instance required additional headers.


# Documentation/Reference
## TruSTAR Python SDK & REST API
1. TruSTAR Python SDK
   1. Documentation: https://docs.trustar.co/sdk/index.html
   2. Examples: https://github.com/RH-ISAC/trustar-sdk2-proto/blob/main/documentation.md
   3. Source: https://github.com/RH-ISAC/trustar-sdk2-proto
2. TruSTAR REST API
   1. Documentation: https://docs.trustar.co/api/index.html
   2. Usage Policy: https://support.trustar.co/article/m5kl5anpiz-api-rate-limit-quota
