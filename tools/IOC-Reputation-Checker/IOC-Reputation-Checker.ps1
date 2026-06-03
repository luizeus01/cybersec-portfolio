<#
=========================================================
 IOC-Reputation-Checker
 Threat Intelligence Lookup Utility

 Author   : Luiz Gustavo
 GitHub   : https://github.com/luizeus01/cybersec-portfolio
 =========================================================
#>
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase

$ApiKey = "" # <==================== Add your API key from Virus Total
$WindowTitle = "IOC Reputation Checker - IP, Domain, URL, Hash"
$BackgroundColor = "#1E1E1E"

function Get-InputType($query) {
    if ($query -match '^(?:\d{1,3}\.){3}\d{1,3}$') {
        return "ip_addresses"
    } elseif ($query -match '^(([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|([0-9A-Fa-f]{1,4}:){1,7}:|([0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}|([0-9A-Fa-f]{1,4}:){1,5}(:[0-9A-Fa-f]{1,4}){1,2}|([0-9A-Fa-f]{1,4}:){1,4}(:[0-9A-Fa-f]{1,4}){1,3}|([0-9A-Fa-f]{1,4}:){1,3}(:[0-9A-Fa-f]{1,4}){1,4}|([0-9A-Fa-f]{1,4}:){1,2}(:[0-9A-Fa-f]{1,4}){1,5}|[0-9A-Fa-f]{1,4}:((:[0-9A-Fa-f]{1,4}){1,6})|:((:[0-9A-Fa-f]{1,4}){1,7}|:))$') {
        return "ip_addresses"
    } elseif ($query -match '^(https?|ftp)://') {
        return "urls"
    } elseif ($query -match '^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}([/?].+)$') {
        return "urls"
    } elseif ($query -match '^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$') {
        return "domains"
    } elseif ($query -match '^[a-fA-F0-9]{32}$') {
        return "files"
    } elseif ($query -match '^[a-fA-F0-9]{40}$') {
        return "files"
    } elseif ($query -match '^[a-fA-F0-9]{64}$') {
        return "files"
    } else {
        return $null
    }
}

function Get-VTReputation($query) {
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
        $headers = @{ "x-apikey" = $ApiKey }
        $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get -ErrorAction Stop
        $stats = $response.data.attributes.last_analysis_stats

        return @{
            Success    = $true
            Type       = $type
            Harmless   = $stats.harmless
            Malicious  = $stats.malicious
            Suspicious = $stats.suspicious
            Link       = $link
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

$Window = New-Object System.Windows.Window
$Window.Title = $WindowTitle
$Window.Width = 410
$Window.Height = 360
$Window.WindowStartupLocation = "CenterScreen"
$Window.Background = $BackgroundColor
$Window.Foreground = "White"
$Window.ResizeMode = "NoResize"
$Window.Topmost = $true

$Grid = New-Object System.Windows.Controls.Grid
$Window.Content = $Grid

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
$InputBox.BorderThickness = 0
$TextBorder.Child = $InputBox
$Grid.Children.Add($TextBorder)

$TextBorder.BorderThickness = 1
$TextBorder.BorderBrush = "#2E2E2E"
$InputBox.Add_MouseEnter({ $TextBorder.BorderBrush = "#e7e8e9ff"; $InputBox.Background = "#33FFFFFF" })
$InputBox.Add_MouseLeave({ if (-not $InputBox.IsFocused) { $TextBorder.BorderBrush = "#2E2E2E"; $InputBox.Background = "Transparent" } })
$InputBox.Add_GotFocus({ $TextBorder.BorderBrush = "#e7e8e9ff"; $InputBox.Background = "#33FFFFFF" })
$InputBox.Add_LostFocus({ $TextBorder.BorderBrush = "#2E2E2E"; $InputBox.Background = "Transparent" })

$CheckButton = New-RoundedButton "Check" "20,70,20,0"
$Grid.Children.Add($CheckButton)

$ResultLabel = New-Object System.Windows.Controls.TextBlock
$ResultLabel.Margin = "20,130,20,20"
$ResultLabel.TextWrapping = "Wrap"
$ResultLabel.FontSize = 14
$Grid.Children.Add($ResultLabel)

$ButtonPanel = New-Object System.Windows.Controls.StackPanel
$ButtonPanel.Orientation = "Horizontal"
$ButtonPanel.Margin = "20,240,20,0"
$Grid.Children.Add($ButtonPanel)

$VTButton = New-RoundedButton "Open in VirusTotal" "0,0,5,0"
$VTButton.Width = 350
$VTButton.FontSize = 14
$VTButton.Background = "#444"
$VTButton.Visibility = "Collapsed"
$ButtonPanel.Children.Add($VTButton)

$AbuseButton = New-RoundedButton "Open in AbuseIPDB" "5,0,0,0"
$AbuseButton.Width = 170
$AbuseButton.FontSize = 14
$AbuseButton.Background = "#444"
$AbuseButton.Visibility = "Collapsed"
$ButtonPanel.Children.Add($AbuseButton)

$NoticeLabel = New-Object System.Windows.Controls.TextBlock
$NoticeLabel.Margin = "20,300,20,5"
$NoticeLabel.FontSize = 11
$NoticeLabel.Foreground = "Gray"
$NoticeLabel.Text = "$([char]0x26A0) This tool never loads or executes URLs. VirusTotal API only."
$NoticeLabel.TextWrapping = "Wrap"
$Grid.Children.Add($NoticeLabel)

$CheckButton.Add_Click({
    $query = $InputBox.Text.Trim()
    $VTButton.Visibility = "Collapsed"
    $AbuseButton.Visibility = "Collapsed"
    $VTButton.Width = 350

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

    if ($data.Success) {
        $type = $data.Type
        $ResultLabel.Text = "Type: $($data.Type)`nHarmless: $($data.Harmless)`nMalicious: $($data.Malicious)`nSuspicious: $($data.Suspicious)`nSEARCH: $query"

        if ($data.Malicious -gt 0) {
            $ResultLabel.Foreground = "Red"
        } elseif ($data.Suspicious -gt 0) {
            $ResultLabel.Foreground = "Orange"
        } else {
            $ResultLabel.Foreground = "Green"
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