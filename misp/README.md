# MISP
A space for RH-ISAC members to share MISP-related scripts<br>

> **Warning**
> Use the content in this repository at your own risk. RH-ISAC will not be held responsible for data loss, nor any other problems resulting from the use of this content.

## Requirements
Most of the scripts in this repo require the PyMISP python module.

Additionally, the python scripts are all written with 3.9+ in mind, so earlier versions may have some compatability issues.


## Configuration
A valid **misp.conf** file is the easiest way to setup access and authentication to the MISP API.
1. Make a copy of **misp_example.conf** and name the copy **misp.conf**
2. Generate an auth key in MISP
   1. https://misp.rhisac.org/users/view/me
3. In your **misp.conf** file:
   1. Replace `<COPY AUTH KEY HERE>` with your MISP Auth Key
4. Save the file in the same directory as your MISP Python script

## PyMISP - Python Library to access MISP
1. Documentation: https://pymisp.readthedocs.io
2. Source: https://github.com/MISP/PyMISP


## cURL Example (non-Python)
### Retrieve IOCs from MISP
Other attributes can be found here: https://www.misp-project.org/openapi/#tag/Attributes/operation/restSearchAttributes
```bash
curl -H "Authorization: <AUTH_KEY>" -H "Content-Type: application/json" -H "Accept: application/json" -d '{"limit":"10", "from":"2022-08-01"}' -X POST https://misp-pre.rhisac.org/attributes/restSearch
```
