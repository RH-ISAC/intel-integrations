# TruSTAR
A space for RH-ISAC members to share TruSTAR-related scripts<br>

> **Warning**
> Use the content in this repository at your own risk. RH-ISAC will not be held responsible for data loss, nor any other problems resulting from the use of this content.

## Requirements
Most of the scripts in this repo require the TruSTAR or TruSTAR2 python module. RH-ISAC hosts custom versions that we have modified to be up to date with current Python versions and they can be found here:
- TruSTAR: https://github.com/RH-ISAC/trustar-python-sdk1
- TruSTAR 2: https://github.com/RH-ISAC/trustar-sdk2-proto

Additionally, the python scripts are all written with 3.9+ in mind, so earlier versions may have some compatability issues.

### Installation
1. Clone the repo you need (Use TruSTAR2 unless you have a specific version to use TruSTAR 1)
   - We recomend using a Virtual Environment to run these scripts to avoid dependancy issues.
2. Run `pip install /path/to/repo` where `/path/to/repo` is the path to the location you cloned the TruSTAR Python module
3. Test the instillation by attempting to import a TruSTAR module from a Python shell.


## Configuration
A valid **trustar2.conf** file is the easiest way to setup access and authentication to the TruSTAR API. (If you are using the 1.3 version of the API use the Trustar_example.conf example in the /v1.3/ Directory )
1. Make a copy of **trustar2_example.conf** and name the copy **trustar2.conf**
2. Lookup your TruSTAR API Key and API Secret in TruSTAR station
   1. https://station.trustar.co/settings/api
3. In your **trustar2.conf** file:
   1. Replace `<COPY API KEY HERE>` with your API Key
   2. Replace `<COPY API SECRET HERE>` with your API Secret
4. Save the file in the same directory as your TruSTAR Python script

## TruSTAR Python SDK & REST API
1. TruSTAR Python SDK
   1. Documentation: https://docs.trustar.co/sdk/index.html
   2. Source: https://github.com/trustar/trustar-python
2. TruSTAR REST API
   1. Documentation: https://docs.trustar.co/api/index.html
   2. Usage Policy: https://support.trustar.co/article/m5kl5anpiz-api-rate-limit-quota

### Uninstall TruSTAR Python SDK
To uninstall, simply use:
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
