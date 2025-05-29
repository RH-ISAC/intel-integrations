# ./INTEL-INTEGRATIONS/
A repository of example scripts for integrating RH-ISAC threat intel with various security tools. Check out the [RH-ISAC integration documentation hub](https://community.rhisac.org/misp/integrations) on Member Exchange to find more details about each integration, and other possible integration options.

> **Warning**
> Use the content in this repository at your own risk. RH-ISAC will not be held responsible for data loss, nor any other problems resulting from the use of this content. **These scripts are beta versions and intended to be used as an examples.**

## Requirements
- Python 3.9+
- PyMISP `pip install pymisp` (https://github.com/MISP/PyMISP)
- Application specific modules (depending on the script)

> **Note**
> We strongly recomend the usage of [virtual environments](https://docs.python.org/3/library/venv.html) to provide a clean space to install dependancies.

## Configuration
A valid **rh-isac.conf** or **config.py** file is the easiest way to setup access and authentication to the MISP API. Review each scripts README.md to identify proper setup instructions.
1. Make a copy of the relevant config file, and remove the .example from the end.
2. Generate an auth key in MISP
   1. Visit https://misp.rhisac.org/users/view/me
   2. Select `Auth Keys`
   3. Then `Add authentication key`
   4. Add a comment to the comment field to easily identify the key in the future. If you dont plan to write any data back to the RH-ISAC MISP instance, we also recomend using the read only flag to limit unnecessary permissions on the key.
   5. Finally choose `Submit`
   6. Copy the key presented on the next screen into your config file where it says `<MISP API KEY HERE>`
3. Save the file in the same directory as the MISP Python scripts you would like to run.

## PyMISP - Python Library to access MISP
1. Documentation: https://pymisp.readthedocs.io
2. Source: https://github.com/MISP/PyMISP


## cURL Example (non-Python)
### Retrieve IOCs from MISP
Other attributes can be found here: https://www.misp-project.org/openapi/#tag/Attributes/operation/restSearchAttributes
```bash
curl -H "Authorization: <AUTH_KEY>" -H "Content-Type: application/json" -H "Accept: application/json" -d '{"limit":"10", "last":"1d", "tags":"rhisac: vetted"}' -X POST https://misp.rhisac.org/attributes/restSearch
```

## Resources for RH-ISAC Members
- General MISP Overview Slides: https://community.rhisac.org/discussion/misp-overview-slides
- RH-ISAC MISP Documentation: https://rhis.ac/misp
