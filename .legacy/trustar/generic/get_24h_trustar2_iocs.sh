#!/bin/bash

# __author__ = 'Ian Furr, Bradley Logan'
# __version__ = '0.1'
# __email__ = 'ian.furr@rhisac.org, bradley.logan@rhisac.org'

# Print the help information
Help()
{
   # Display Help
   echo "A simple shell script that uses CURL to grab the past 24 hours of"
   echo "RH-ISAC vetted IOCs from TruSTAR and output to a file in JSON format."
   echo
   echo "REQUIRED: jq - a lightweight and flexible command-line JSON processor"
   echo
   echo "Syntax: get_-24h_trustar_iocs [-k|s|h]"
   echo "options:"
   echo "  -k=API_KEY    Your TruSTAR API Key"
   echo "  -s=SECRET     Your TruSTAR API Secret"
   echo "  -h            Print this help"
   echo
}

# Handle commandline arguments
while getopts 'k:s:h' flag; do
  case "${flag}" in
    k) key="${OPTARG}" ;;
    s) secret="${OPTARG}" ;;
    *) Help
       exit 1 ;;
  esac
done

# jq install instructions
install=(
    'Mac: brew install jq'
    'Debian/Ubuntu: sudo apt-get install jq'
    'Fedora: sudo dnf install jq'
)

# Check to see if jq is installed
if ! command -v jq &> /dev/null
then
    printf 'jq could not be found. Please install.\n'
    printf '    %s\n' "${install[@]}"
    exit
fi

# Get key and secret if not provided as commandline arguments
if [ -z "$key" ]; then
    printf "Enter your TruSTAR API Key: ";
    read -s key;
fi
if [ -z "$secret" ]; then
    printf "\nEnter your TruSTAR API Secret: ";
    read -s secret;
    echo
fi

# Authenticate to TruSTAR and get Access Token
resp=$(curl -u $key:$secret -d "grant_type=client_credentials" https://api.trustar.co/oauth/token)
token=$(echo $resp | jq -r '.access_token')

# Get IOCs from TruSTAR RH-ISAC Vetted Indicators enclave
ago_24h=$(($(date -v-24H "+%s") * 1000))
filename=$(echo "rhisac_iocs_last24h_""$(date +%Y%m%dT%H%M%S)"".json")
curl -H "Authorization: Bearer $token" "https://api.trustar.co/api/2.0/observables/search?from=$ago_24h&pageSize=1000&enclaveIds=59cd8570-5dce-4e5b-b09c-9807530a7086" > $filename
echo
echo Wrote response to $filename
