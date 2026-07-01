<#
=========================================================
 IOC-Reputation-Checker
 Threat Intelligence Lookup Utility
 Version  : v1.7
 Updated  : 2026-07-01

 Author   : Luiz Gustavo
 Project Repository: https://github.com/luizeus01/cybersec-portfolio/tree/dev/tools/IOC-Reputation-Checker
 GitHub   : https://github.com/luizeus01/cybersec-portfolio
 =========================================================
#>
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase

$AppVersion = "v1.7"
$VirusTotalApiKey = "" # <==================== Add your API key from Virus Total
$VpnApiKey = ""
$WindowTitle = "IOC Reputation Checker $AppVersion - IP, Domain, URL, Hash"
$BackgroundColor = "#1E1E1E"

function Get-InputType($query) {

    $ipObj = $null

    if ([System.Net.IPAddress]::TryParse($query, [ref]$ipObj)) {
        return "ip_addresses"
    }
    elseif ($query -match '^(https?|ftp)://') {
        return "urls"
    }
    elseif ($query -match '^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}([/?].+)$') {
        return "urls"
    }
    elseif ($query -match '^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$') {
        return "domains"
    }
    elseif ($query -match '^[a-fA-F0-9]{32}$') {
        return "files"
    }
    elseif ($query -match '^[a-fA-F0-9]{40}$') {
        return "files"
    }
    elseif ($query -match '^[a-fA-F0-9]{64}$') {
        return "files"
    }

    return $null
}

function Get-VTReputation($query) {
    
    if ([string]::IsNullOrWhiteSpace($VirusTotalApiKey)) {
    return @{
        Success = $false
        Error = "VirusTotal API Key not configured. Please set the `$VirusTotalApiKey variable."
        }
    }

    $type = Get-InputType $query

    if (-not $type) {
        
        return @{ Success = $false; Error = "Invalid input. Enter a valid IP, domain, hash, or URL." }
    }

    if ($type -eq "urls") { # VirusTotal requires URLs to be Base64 URL-safe encoded
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($query)
        $encoded = [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+','-').Replace('/','_')
        $url = "https://www.virustotal.com/api/v3/urls/$encoded"
        $link = "https://www.virustotal.com/gui/url/$encoded"
    } elseif ($type -eq "ip_addresses") {
        $url = "https://www.virustotal.com/api/v3/ip_addresses/$query"
        $link = "https://www.virustotal.com/gui/ip-address/$query"
    } elseif ($type -eq "domains") {
        $url = "https://www.virustotal.com/api/v3/domains/$query"
        $link = "https://www.virustotal.com/gui/domain/$query"
    } else {
        $url = "https://www.virustotal.com/api/v3/files/$query"
        $link = "https://www.virustotal.com/gui/file/$query"
    }

    try {
        $headers = @{ "x-apikey" = $VirusTotalApiKey }
        $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get -ErrorAction Stop
        $attributes = $response.data.attributes
        $stats = $response.data.attributes.last_analysis_stats

        return @{
            # IP return
            Success    = $true
            Type       = $type
            Harmless   = $stats.harmless
            Malicious  = $stats.malicious
            Suspicious = $stats.suspicious
            Owner      = $attributes.as_owner
            ASN        = $attributes.asn
            Country    = $attributes.country
            Link       = $link

            # DOMAIN return
            Registrar  = $attributes.registrar
            Created    = $attributes.creation_date
            Reputation = $attributes.reputation

            # FILE return
            FileName   = $attributes.meaningful_name
            FileType   = $attributes.type_description
            FileSize   = $attributes.size
        }
    } catch { # Maps VirusTotal API responses to user-friendly messages
        $errorMsg = $_.Exception.Message
        if ($errorMsg -match "403") { $msg = "Error 403: Invalid API Key." }
        elseif ($errorMsg -match "404") { $msg = "Error 404: Not found." }
        elseif ($errorMsg -match "429") { $msg = "Error 429: Rate limit exceeded." }
        elseif ($errorMsg -match "400") { $msg = "Error 400: Bad request." }
        else { $msg = "Error: $errorMsg" }

        return @{ Success = $false; Error = $msg }
    }
}


function Get-IPPrivacyStatus($ip) {

    if ([string]::IsNullOrWhiteSpace($VpnApiKey)) {
        return @{
            Success = $false
            Status  = "N/A"
        }
    }

    try {
        $url = "https://vpnapi.io/api/$ip`?key=$VpnApiKey"
        $response = Invoke-RestMethod -Uri $url -Method Get -ErrorAction Stop

        $security = $response.security
        $flags = @()

        if ([System.Convert]::ToBoolean($security.vpn)) {
            $flags += "VPN"
        }

        if ([System.Convert]::ToBoolean($security.proxy)) {
            $flags += "Proxy"
        }

        if ([System.Convert]::ToBoolean($security.tor)) {
            $flags += "Tor"
        }

        if ([System.Convert]::ToBoolean($security.relay)) {
            $flags += "Relay"
        }

        $status = if ($flags.Count -gt 0) {
            $flags -join "/"
        } else {
            "No"
        }

        return @{
            Success = $true
            Status  = $status
        }
    }
    catch {
        return @{
            Success = $false
            Status  = "N/A"
        }
    }
}


function New-RoundedButton($content, $margin) {
    $button = New-Object System.Windows.Controls.Button
    $button.Content = $content
    $button.Margin = $margin
    $button.Height = 40
    $button.FontSize = 16
    $button.Foreground = "White"
    $button.VerticalAlignment = "Top"
    $button.Cursor = [System.Windows.Input.Cursors]::Hand
    $button.Background = "#007ACC"

    $template = @"
<ControlTemplate xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
                 xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
                 TargetType="Button">
  <Border x:Name="border" Background="{TemplateBinding Background}" CornerRadius="6" BorderThickness="0">
    <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
  </Border>
  <ControlTemplate.Triggers>
    <Trigger Property="IsMouseOver" Value="True">
      <Setter TargetName="border" Property="Background" Value="#3399FF"/>
    </Trigger>
  </ControlTemplate.Triggers>
</ControlTemplate>
"@

    $reader = [System.Xml.XmlReader]::Create([System.IO.StringReader]$template)
    $templateObj = [Windows.Markup.XamlReader]::Load($reader)
    $button.Template = $templateObj

    return $button
}

#  responsive interface of windows
$DesignWidth = 410
$DesignHeight = 360

$Window = New-Object System.Windows.Window
$Window.Title = $WindowTitle
$Window.Width = $DesignWidth
$Window.Height = $DesignHeight
$Window.MinWidth = 280
$Window.MinHeight = 240
$Window.WindowStartupLocation = "CenterScreen"
$Window.Background = $BackgroundColor
$Window.Foreground = "White"
$Window.ResizeMode = "CanResizeWithGrip"
$Window.Topmost = $true

# Viewbox keeps the existing layout proportional when the window is resized
$Viewbox = New-Object System.Windows.Controls.Viewbox
$Viewbox.Stretch = "Uniform"
$Viewbox.StretchDirection = "Both"
$Window.Content = $Viewbox

$Grid = New-Object System.Windows.Controls.Grid
$Grid.Width = $DesignWidth
$Grid.Height = $DesignHeight
$Viewbox.Child = $Grid

$TextBorder = New-Object System.Windows.Controls.Border
$TextBorder.CornerRadius = 6
$TextBorder.Background = "#2E2E2E"
$TextBorder.Margin = "20,20,20,0"
$TextBorder.Height = 30
$TextBorder.VerticalAlignment = "Top"
$InputBox = New-Object System.Windows.Controls.TextBox
$InputBox.FontSize = 16
$InputBox.Background = "Transparent"
$InputBox.Foreground = "White"
$InputBox.CaretBrush = "White"
$InputBox.BorderThickness = 0
$TextBorder.Child = $InputBox
[void]$Grid.Children.Add($TextBorder)

$TextBorder.BorderThickness = 1
$TextBorder.BorderBrush = "#2E2E2E"
$InputBox.Add_MouseEnter({ $TextBorder.BorderBrush = "#e7e8e9ff"; $InputBox.Background = "#33FFFFFF" })
$InputBox.Add_MouseLeave({ if (-not $InputBox.IsFocused) { $TextBorder.BorderBrush = "#2E2E2E"; $InputBox.Background = "Transparent" } })
$InputBox.Add_GotFocus({ $TextBorder.BorderBrush = "#e7e8e9ff"; $InputBox.Background = "#33FFFFFF" })
$InputBox.Add_LostFocus({ $TextBorder.BorderBrush = "#2E2E2E"; $InputBox.Background = "Transparent" })

$CheckButton = New-RoundedButton "Check" "20,70,20,0"
[void]$Grid.Children.Add($CheckButton)

$ResultLabel = New-Object System.Windows.Controls.TextBlock
$ResultLabel.Margin = "20,130,20,20"
$ResultLabel.TextWrapping = "Wrap"
$ResultLabel.FontSize = 14
[void]$Grid.Children.Add($ResultLabel)

$IPDetailsLabel = New-Object System.Windows.Controls.TextBlock
$IPDetailsLabel.Margin = "200,130,20,20"
$IPDetailsLabel.TextWrapping = "Wrap"
$IPDetailsLabel.FontSize = 14
$IPDetailsLabel.Text = ""
[void]$Grid.Children.Add($IPDetailsLabel)

$ButtonPanel = New-Object System.Windows.Controls.StackPanel
$ButtonPanel.Orientation = "Horizontal"
$ButtonPanel.Margin = "20,240,20,0"
[void]$Grid.Children.Add($ButtonPanel)

$VTButton = New-RoundedButton "Open in VirusTotal" "0,0,5,0"
$VTButton.Width = 350
$VTButton.FontSize = 14
$VTButton.Background = "#444"
$VTButton.Visibility = "Collapsed"
[void]$ButtonPanel.Children.Add($VTButton)

$AbuseButton = New-RoundedButton "Open in AbuseIPDB" "5,0,0,0"
$AbuseButton.Width = 170
$AbuseButton.FontSize = 14
$AbuseButton.Background = "#444"
$AbuseButton.Visibility = "Collapsed"
[void]$ButtonPanel.Children.Add($AbuseButton)

$NoticeLabel = New-Object System.Windows.Controls.TextBlock
$NoticeLabel.Margin = "20,300,20,5"
$NoticeLabel.FontSize = 11
$NoticeLabel.Foreground = "Gray"
$NoticeLabel.Text = "$([char]0x26A0) This tool never loads or executes URLs. API lookups only."
$NoticeLabel.TextWrapping = "Wrap"
[void]$Grid.Children.Add($NoticeLabel)

$CheckButton.Add_Click({
    $query = $InputBox.Text.Trim()
    $VTButton.Visibility = "Collapsed"
    $AbuseButton.Visibility = "Collapsed"
    $VTButton.Width = 350
    $IPDetailsLabel.Text = ""

    if ([string]::IsNullOrWhiteSpace($query)) {
        $ResultLabel.Text = "Please enter a valid IP, domain, hash, or URL."
        $ResultLabel.Foreground = "Yellow"
        return
    }

    # Basic input sanitization to prevent unsafe payloads
    if ($query -match '[<>\"]' -or $query -match '(?i)javascript:') {
        $ResultLabel.Text = "Potentially unsafe input detected."
        $ResultLabel.Foreground = "Yellow"
        return
    }

    $ResultLabel.Foreground = "White"
    $ResultLabel.Text = "Checking VirusTotal..."
    $ResultLabel.Dispatcher.Invoke("Render", [action]{})

    Start-Sleep -Milliseconds 200
    $data = Get-VTReputation $query

    #Truncate long IOC name to preserve layout
    if ($data.Success) { 
        $type = $data.Type
        
        $displayIOC = if ($query.Length -gt 28) {
            "$($query.Substring(0, 9))...$($query.Substring($query.Length - 10))"
        } else {
            $query
        }
        
        $ResultLabel.Text = "Type: $($data.Type)`nHarmless: $($data.Harmless)`nMalicious: $($data.Malicious)`nSuspicious: $($data.Suspicious)`nIOC: $displayIOC"

        if ($data.Malicious -gt 0) {
            $ResultLabel.Foreground = "Red"
            $IPDetailsLabel.Foreground = "Red"
        } elseif ($data.Suspicious -gt 0) {
            $ResultLabel.Foreground = "Orange"
            $IPDetailsLabel.Foreground = "Orange"
        } else {
            $ResultLabel.Foreground = "Green"
            $IPDetailsLabel.Foreground = "Green"
        }

        if ($type -eq "ip_addresses") {
            $ownerValue = if ($data.Owner) { $data.Owner } else { "N/A" }
            $asnValue = if ($data.ASN) { $data.ASN } else { "N/A" }
            $countryValue = if ($data.Country) { $data.Country } else { "N/A" }

            $privacyResult = Get-IPPrivacyStatus $query
            $privacyValue = $privacyResult.Status

            $IPDetailsLabel.Text = "Owner: $ownerValue`nASN: $asnValue`nCountry: $countryValue`nVPN/Proxy/Tor: $privacyValue"
        }
        elseif ($type -eq "domains") {
            $registrarValue = if ($data.Registrar) { $data.Registrar } else { "N/A" }
            $reputationValue = if ($null -ne $data.Reputation) { $data.Reputation } else { "N/A" }

            $createdValue = if ($data.Created) {
                [DateTimeOffset]::FromUnixTimeSeconds($data.Created).DateTime.ToString("yyyy-MM-dd")
            } else {
                "N/A"
            }

            $IPDetailsLabel.Text = "Registrar: $registrarValue`nCreated: $createdValue`nReputation: $reputationValue"
        }
        
        #Truncate long File Name to preserve layout
        elseif ($type -eq "files") {
            $fileNameValue = if ($data.FileName) { $data.FileName } else { "N/A" }

            if ($fileNameValue.Length -gt 30) {
                $fileNameValue = "$($fileNameValue.Substring(0,15))...$($fileNameValue.Substring($fileNameValue.Length - 10))"
            }

            $fileTypeValue = if ($data.FileType) { $data.FileType } else { "N/A" }

            $fileSizeValue = if ($data.FileSize) {
                if ($data.FileSize -ge 1MB) {
                    "{0:N2} MB" -f ($data.FileSize / 1MB)
                }
                elseif ($data.FileSize -ge 1KB) {
                    "{0:N2} KB" -f ($data.FileSize / 1KB)
                }
                else {
                    "$($data.FileSize) bytes"
                }
            } else {
                "N/A"
            }

            $IPDetailsLabel.Text = "File Name: $fileNameValue`nFile Type: $fileTypeValue`nFile Size: $fileSizeValue"
        }

        if ($type -eq "ip_addresses" -or $type -eq "domains") {
            $VTButton.Width = 170
            $VTButton.Visibility = "Visible"
            $AbuseButton.Visibility = "Visible"
            $AbuseButton.Tag = $query
        } else {
            $VTButton.Width = 350
            $VTButton.Visibility = "Visible"
        }

        $VTButton.Tag = $data.Link
    } else {
        $ResultLabel.Foreground = "Yellow"
        $ResultLabel.Text = $data.Error
    }
})

$InputBox.Add_KeyDown({
    if ($_.Key -eq "Return") {
        $CheckButton.RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Button]::ClickEvent))
    }
})

$VTButton.Add_Click({
    if ($VTButton.Tag) {
        Start-Process $VTButton.Tag
    }
})

$AbuseButton.Add_Click({
    if ($AbuseButton.Tag) {
        Start-Process "https://www.abuseipdb.com/check/$($AbuseButton.Tag)"
    }
})

$Window.ShowDialog() | Out-Null
$Window.Close()
[System.Windows.Threading.Dispatcher]::ExitAllFrames()