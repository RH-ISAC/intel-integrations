# __author__ = 'Bradley Logan'
# __version__ = '0.90'
# __email__ = 'bradley.logan@rhisac.org'

# A simple powershell script that grabs the past 24 hours of
# RH-ISAC vetted IOCs from TruSTAR and outputs to a file in JSON format"

param ($api_key, $api_secret)

$vetted_enclave_id = "59cd8570-5dce-4e5b-b09c-9807530a7086"

# Prompt for credentials if they weren't provided on commandline
if ($api_key -eq $null) {
    $creds = Get-Credential -Title "Enter your TruSTAR credentials" -Message "User = API Key, Password = API Secret"
} elseif ($api_secret -eq $null) {
    $creds = Get-Credential -Title "Enter your TruSTAR credentials" -Message "User = API Key, Password = API Secret" -UserName $api_key
} else {
    $PWord = ConvertTo-SecureString -String $api_secret -AsPlainText -Force
    $creds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $api_key, $PWord
}

# Authenticate to TruSTAR and get Access Token
$params = @{
    Uri = "https://api.trustar.co/oauth/token" 
    Method = "Post"
    Body = "grant_type=client_credentials"
    Authentication = "Basic"
    Credential = $creds
}
$response = Invoke-RestMethod @params
$token = $response.access_token

# Get last 24 hours of IOCs from TruSTAR RH-ISAC Vetted Indicators enclave
$ago_24h_unix = [int][double]::Parse($(Get-Date -date (Get-Date).AddDays(-1).ToUniversalTime()-uformat %s))
$ago_24h_unix_ms = $ago_24h_unix * 1000  # must provide as milliseconds since epoch
$params = @{
    Uri = "https://api.trustar.co/api/1.3/indicators/search?from=$ago_24h_unix_ms&pageSize=1000&enclaveIds=$vetted_enclave_id"
    Method = "Post"
    Headers = @{"Authorization" = "Bearer $token"}
    ContentType = "application/json"
}
$response = Invoke-RestMethod @params

# Output to file
$now = Get-Date -Format "yyyyMMddTHHmmss"
$filename = "rhisac_iocs_last24h_$($now).json"
$response | ConvertTo-Json -Depth 50 | Out-File -FilePath $filename
Write-Host "Response written to file: $filename"