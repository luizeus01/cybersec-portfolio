[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Add-Type -AssemblyName System.Windows.Forms

Write-Host ""
Write-Host "=========================================================" -ForegroundColor DarkGray
Write-Host "               Check-List-IP v1.0" -ForegroundColor Cyan
Write-Host "           Bulk IP Reputation Checker" -ForegroundColor Cyan
Write-Host "=========================================================" -ForegroundColor DarkGray
Write-Host ""
Write-Host "Input : CSV file" -ForegroundColor Green
Write-Host "Output: CSV report" -ForegroundColor Green
Write-Host ""
Write-Host "The input CSV must contain at least one column with the header 'IP'." -ForegroundColor Yellow
Write-Host ""
Write-Host "Example:" -ForegroundColor Yellow
Write-Host "IP" -ForegroundColor DarkGray
Write-Host "8.8.8.8" -ForegroundColor DarkGray
Write-Host "1.1.1.1" -ForegroundColor DarkGray
Write-Host "192.168.1.1" -ForegroundColor DarkGray
Write-Host ""
Write-Host "Please select the input CSV file containing the IP addresses..." -ForegroundColor Cyan
Start-Sleep -Seconds 2

$OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
$OpenFileDialog.Title = "Select the input CSV file"
$OpenFileDialog.Filter = "CSV files (*.csv)|*.csv|All files (*.*)|*.*"

if ($OpenFileDialog.ShowDialog() -ne "OK") {
    Write-Host "Operation cancelled by user." -ForegroundColor Yellow
    exit
}

$InputCsv = $OpenFileDialog.FileName

Write-Host ""
Write-Host "Input file selected successfully:" -ForegroundColor Green
Write-Host $InputCsv -ForegroundColor DarkGray
Write-Host ""
Write-Host "Please choose the folder and file name to save the exported results..." -ForegroundColor Cyan
Start-Sleep -Seconds 2

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

$SaveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
$SaveFileDialog.Title = "Folder to save exported file"
$SaveFileDialog.Filter = "CSV files (*.csv)|*.csv"
$SaveFileDialog.FileName = "Check-List-IP_Results_$Timestamp.csv"

if ($SaveFileDialog.ShowDialog() -ne "OK") {
    Write-Host "Operation cancelled by user." -ForegroundColor Yellow
    exit
}

$OutputCsv = $SaveFileDialog.FileName

$AbuseIPDBApiKey = "" # <====== Insert here your AbuseIPDB API Key

$Ips = Import-Csv -Path $InputCsv

$IpColumn = ($Ips[0].PSObject.Properties.Name | Where-Object { $_ -match 'ip' } | Select-Object -First 1)
if (-not $IpColumn) {
    Write-Error "No column containing 'IP' found in the CSV. Please adjust the file."
    exit
}

$Headers = @{
    "Key"    = $AbuseIPDBApiKey
    "Accept" = "application/json"
}

$Results = [System.Collections.Generic.List[object]]::new()
$Total = $Ips.Count
$Current = 0

$Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

foreach ($ip in $Ips) {
    $Current++

    $IpAddress = $ip.$IpColumn
    $Url = 'https://api.abuseipdb.com/api/v2/check?ipAddress={0}&maxAgeInDays=90' -f $IpAddress

    try {
        $Response = Invoke-RestMethod `
            -Uri $Url `
            -Headers $Headers `
            -Method Get `
            -TimeoutSec 20

        $Score = $Response.data.abuseConfidenceScore
        $Country = $Response.data.countryCode
        $Domain = $Response.data.domain
        $UsageType = $Response.data.usageType
        $TotalReports = $Response.data.totalReports
        $IsTrusted = if ($Score -lt 50) { "Reliable" } else { "Suspicious" }

        $Results.Add([PSCustomObject]@{
            IP                   = $IpAddress
            AbuseConfidenceScore = $Score
            Status               = $IsTrusted
            Country              = $Country
            Domain               = $Domain
            UsageType            = $UsageType
            TotalReports         = $TotalReports
            Error                = "-"
        })
    }
    catch {
        $ErrorMessage = "API failure"

        if ($_.Exception.Response) {
            $StatusCode = $_.Exception.Response.StatusCode.Value__
            $StatusDesc = $_.Exception.Response.StatusDescription
            $ErrorMessage = "$StatusCode - $StatusDesc"
        }
        else {
            $ErrorMessage = $_.Exception.Message
        }

        $Results.Add([PSCustomObject]@{
            IP                   = $IpAddress
            AbuseConfidenceScore = "N/A"
            Status               = "Error"
            Country              = "-"
            Domain               = "-"
            UsageType            = "-"
            TotalReports         = "-"
            Error                = $ErrorMessage
        })
    }

    $Percent = [math]::Round(($Current / $Total) * 100, 0)

    Write-Progress `
        -Activity "Checking IP reputation on AbuseIPDB" `
        -Status "Checking $IpAddress ($Current of $Total)" `
        -PercentComplete $Percent
}

Write-Progress `
    -Activity "Checking IP reputation on AbuseIPDB" `
    -Completed

$Results | Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8

$Stopwatch.Stop()
$Elapsed = $Stopwatch.Elapsed
$AverageSpeed = if ($Elapsed.TotalSeconds -gt 0) {
    [math]::Round($Total / $Elapsed.TotalSeconds, 2)
}
else {
    0
}

Write-Host ""
Write-Host "==========================================" -ForegroundColor DarkGray
Write-Host " Check completed successfully!" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor DarkGray
Write-Host " Processed IPs : $Total" -ForegroundColor Cyan
Write-Host (" Elapsed Time  : {0:hh\:mm\:ss\.fff}" -f $Elapsed) -ForegroundColor Cyan
Write-Host " Average Speed : $AverageSpeed IP/s" -ForegroundColor Cyan
Write-Host " Results File  : $OutputCsv" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor DarkGray