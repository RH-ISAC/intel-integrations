# ./INTEL-INTEGRATIONS/SUMOLOGIC 
A storage place for SentinelOne related integrations for the RH-ISAC MISP instance.

> **Warning**
> Use the content in this repository at your own risk. RH-ISAC will not be held responsible for data loss, nor any other problems resulting from the use of this content. **This script is a beta version and intended to be used as an example.**

## Requirements
- Python 3.9+
- PyMISP `pip install pymisp` (https://github.com/MISP/PyMISP)

> **Note**
> We strongly recomend the usage of [virtual environments](https://docs.python.org/3/library/venv.html) to provide a clean space to install dependancies.

## Configuration
1. Create a working directory to host the script and any necessary configuration files.
2. Clone the RH-ISAC integrations `repo git clone https://github.com/RH-ISAC/intel-integrations.git` and extract the SentinelOne scripts and configuration files into your working directory.
3. Set up a virtual environment to host the dependencies.
4. Install the dependencies pip install pymisp
5. Rename the config.py.example to config.py.
6. Generate a MISP API Key following these instructions and add it to the newly created config.py file.
7. Save the config file and test the script to ensure that indicators are being pulled into SumoLogic as expected.
8. Schedule the script to run on a daily basis.

### Custom Configuration Options
By detault, the script uses the normal indicator expiration dates from Sentinel, but they can be changed in the CUSTOM_IOC_EXPIRATION_AGE dictionary towards the top of the file. 


# Documentation/Reference
## PyMISP - Python Library to access MISP
1. Documentation: https://pymisp.readthedocs.io
2. Source: https://github.com/MISP/PyMISP

