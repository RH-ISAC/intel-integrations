# __author__ = 'Ian Furr'
# __version__ = '0.1'
# __email__ = 'ian.furr@rhisac.org'

# A quick powershell script that grabs the last 24 hours of
# RH-ISAC vetted IOCs from MISP and dumps them to a JSON file."

$api_key=$args[0]

# Prompt for credentials if they weren't provided on commandline
if ($null -eq $api_key) {
    $api_key = Read-Host "Please enter your MISP API Key"
}


$date = [DateTime]::Now.AddDays(-1)
$yesterday= '{0:yyyy-MM-dd}' -f $date

$headers= @{
    "Authorization"=$api_key;
    "Content-Type"="application/json";
    "Accept"="application/json"
}

$body='{"limit":"10", "from":"'+$yesterday+'", "tags":"rhisac: vetted"}'

$req = Invoke-WebRequest -Headers $headers -Uri https://misp.rhisac.org/attributes/restSearch -Method Post -Body $body

# Output to file
$now = Get-Date -Format "yyyyMMddTHHmmss"
$filename = "rhisac_iocs_last24h_$($now).json"
$req.content | Out-File -FilePath $filename
#$req.content | ConvertTo-Json | Out-File -FilePath $filename
Write-Host "Response written to file: $filename"
