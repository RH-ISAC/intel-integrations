# __author__ = 'Ian Furr, Bradley Logan'
# __version__ = '0.1'
# __email__ = 'ian.furr@rhisac.org, bradley.logan@rhisac.org'

# A simple powershell script that grabs the past 24 hours of
# RH-ISAC vetted IOCs from TruSTAR and outputs to a file in JSON format"

param ($api_key, $api_secret)

$vetted_enclave_id = "59cd8570-5dce-4e5b-b09c-9807530a7086"

# Prompt for credentials if they weren't provided on commandline
if ($null -eq $api_key) {
    $creds = Get-Credential -Message "User = API Key, Password = API Secret"
} elseif ($null -eq $api_secret ) {
    $creds = Get-Credential -Message "User = API Key, Password = API Secret" -UserName $api_key
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

$response = Invoke-RestMethod -Uri "https://api.trustar.co/oauth/token" -Method 'Post' -Body "grant_type=client_credentials" -Credential $creds
$token = $response.access_token

# Get last 24 hours of IOCs from TruSTAR RH-ISAC Vetted Indicators enclave
$ago_24h_unix = [int][double]::Parse($(Get-Date -date (Get-Date).AddDays(-1).ToUniversalTime()-uformat %s))
$ago_24h_unix_ms = $ago_24h_unix * 1000  # must provide as milliseconds since epoch

$uri = "https://api.trustar.co/api/2.0/observables/search?from=$ago_24h_unix_ms&pageSize=1000&enclaveIds=$vetted_enclave_id"
$headers = @{"Authorization" = "Bearer $token"
            "Client-Type" = "API"
            "Client-Metatag" = "RH-ISAC_IOC_SCRIPT"}

$response = Invoke-RestMethod -Uri $uri -Method 'Post' -Headers $headers -ContentType "application/json"

# Output to file
$now = Get-Date -Format "yyyyMMddTHHmmss"
$filename = "rhisac_iocs_last24h_$($now).json"
$response | ConvertTo-Json -Depth 50 | Out-File -FilePath $filename
Write-Host "Response written to file: $filename"
