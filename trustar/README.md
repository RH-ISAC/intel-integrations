# ./INTEL-INTEGRATIONS/TRUSTAR
A storage place for TruSTAR related scripts. You can find various TruSTAR utility scripts in the **generic** directory. These include scripts to get account permissions details, and some that will let you pull IOCs and store them in JSON or CSV files. Integration specific scripts can be found inside of the directories named after the relevant vendor. 

> **Warning**
> Use the content in this repository at your own risk. RH-ISAC will not be held responsible for data loss, nor any other problems resulting from the use of this content. **These scripts are beta versions and intended to be used as examples.**

## Requirements
- Python 3.9+
- TruSTAR or TruSTAR2 python module (See the **TruSTAR Configuration** section below)
- Application specific modules (depending on the script)

> **Note**
> We strongly recomend the usage of [virtual environments](https://docs.python.org/3/library/venv.html) to provide a clean space to install dependancies.

## Configuration
A valid **rh-isac.conf** file is the easiest way to setup access and authentication to the TruSTAR API.
1. Make a copy of **rh-isac.conf.example** and name it **rh-isac.conf**
2. Authenticate to TruSTAR and then browse to `https://station.trustar.co/settings/api`. From there you can access or rotate your API and Secret key. 
3. Copy the API and Secret Keys into your **rh-isac.conf** and save it into the proper directory.

### TruSTAR Configuration
TruSTAR hosts two Python modules (*trustar-python-sdk1* and *trustar-sdk2-proto*) for interacting with the TruSTAR APIs. RH-ISAC has cloned and updated them to the latest requirements so that they can be used with our scripts. The [TruSTAR v2.0 API](https://github.com/RH-ISAC/trustar-sdk2-proto) module should be used for all new integrations. However, if you require access to the old APIs you can find the [TruSTAR 1.3 API](https://github.com/RH-ISAC/trustar-python-sdk1) module on our github as well.

To install the module:
1. Clone the repo you need (Use TruSTAR2 unless you have a specific reason to use TruSTAR 1.3)
2. Run `pip install /path/to/repo` where `/path/to/repo` is the path to the location you cloned the TruSTAR Repo
3. Test your install by attempting to import a TruSTAR module from a Python shell. IE: `from trustar2 import TruStar` and if that works you are all set.

## TruSTAR Integrations
- CrowdStrike Falcon: Retrieve the last 24 hours of RH-ISAC Vetted IOCs from TruSTAR and export them into the Falcon API.
- Splunk (and Splunk ES): Retrieve the last 24 hours of RH-ISAC Vetted IOCs from TruSTAR and export them into Splunk APIs.
- Microsoft (Sentinel & Defender for Endpoint): Retrieve the last 24 hours of RH-ISAC Vetted IOCs from TruSTAR and export them into the MS Graph APIs for consumption by Microsoft (Azure) Sentinel and Microsoft Defender.

## Generic TruSTAR Scripts
- create_indicators_trustar2.py - Retrieves 24h of IOCs from TruSTAR and exports them as a CSV file
- get_24h_trustar2_iocs_csv.py - Retrieves 24h of IOCs from TruSTAR and exports them as a CSV file
- get_24h_trustar2_iocs.ps1 - Python script to retrieve 24h of IOCs from TruSTAR and export as a JSON file
- get_24h_trustar2_iocs.sh - Bash script to retrieve 24h of IOCs from TruSTAR and export as a JSON file
- get_24h_trustar2_iocs_json.py - Retrieves 24h of IOCs from TruSTAR and exports them as a JSON file
- get_enclaves_for_user_trustar2.py - Retrieve a list of TruSTAR envlaves that a user can access (Also has availiblity to filter based on access permissions)
- get_trustar2_iocs.py - Retrieves IOCs from TruSTAR and exports them either CSV or JSON (allows filtering of returned fields and returning IOCs from a specific range of time)
- trustar2.conf.example - Example configuration file for TruSTAR2 scripts

## Resources
1. TruSTAR Python SDK
   1. Documentation: https://docs.trustar.co/sdk/index.html
   2. Source: https://github.com/trustar/trustar-python
2. TruSTAR REST API
   1. Documentation: https://docs.trustar.co/api/index.html
   2. Rate Limit Details: https://support.trustar.co/article/m5kl5anpiz-api-rate-limit-quota

## Uninstall TruSTAR Python SDK
To uninstall, simply run:
```bash
pip uninstall trustar2
```
## cURL Examples (non-Python)
### Authentication (Get your access token)
```bash
curl -u <TruSTAR_API_KEY>:<TruSTAR_API_SECRET> -d "grant_type=client_credentials" https://api.trustar.co/oauth/token
```
### Retrieve IOCs from RH-ISAC Vetted Indicators enclave
Use your access token from the last step.<br>
Default is to retrieve last 30 days. You can adjust the pageSize up to 1000.<br>
Other parameters can be found here: https://docs.trustar.co/api/v13/indicators/search_indicators.html
```bash
curl -H "Authorization: Bearer <ACCESS_TOKEN>" "https://api.trustar.co/api/1.3/indicators/search?enclaveIds=59cd8570-5dce-4e5b-b09c-9807530a7086&pageSize=100"
```

## Legacy Script Config Instructions:
Initial versions of the integration scripts used seperate config files to store credentials for each service (*trustar.conf/trustar2.conf*) these instructions pertain to setting those up
A valid **trustar2.conf** file is the easiest way to setup access and authentication to the TruSTAR API. (If you are using the 1.3 version of the API use the Trustar_example.conf example in the /v1.3/ Directory )
1. Make a copy of **trustar2.conf.example** and name the copy **trustar2.conf**
2. Lookup your TruSTAR API Key and API Secret in TruSTAR station
   1. https://station.trustar.co/settings/api
3. In your **trustar2.conf** file:
   1. Replace `<COPY API KEY HERE>` with your API Key
   2. Replace `<COPY API SECRET HERE>` with your API Secret
4. Save the file in the same directory as your TruSTAR Python script
