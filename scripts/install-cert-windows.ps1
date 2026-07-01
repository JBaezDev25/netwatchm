# NetWatchM - Install self-signed certificate on Windows
# Run this in PowerShell as Administrator

$ServerIP = "10.0.0.10"
$Port     = 8765
$CertUrl  = "https://${ServerIP}:${Port}/cert"
$CertFile = "$env:TEMP\netwatchm.crt"

# Step 1: Bypass cert validation for the download (cert not trusted yet)
[Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}

# Step 2: Download the cert
Write-Host "Downloading cert from $CertUrl ..."
$client = New-Object Net.WebClient
$client.DownloadFile($CertUrl, $CertFile)
Write-Host "Cert saved to $CertFile"

# Step 3: Install into Windows Trusted Root
Write-Host "Installing into Trusted Root..."
Import-Certificate -FilePath $CertFile -CertStoreLocation Cert:\LocalMachine\Root

# Step 4: Restore cert validation
[Net.ServicePointManager]::ServerCertificateValidationCallback = $null

Write-Host ""
Write-Host "Done! Restart Chrome or Edge, then open:" -ForegroundColor Green
Write-Host "  https://${ServerIP}:${Port}/" -ForegroundColor Cyan
Write-Host "No more certificate warning."
