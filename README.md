# Cybersecurity Portfolio

This repository contains cybersecurity tools, KQL queries, and threat hunting resources developed for learning, security automation, and operational use.

## Tools

### [IOC Reputation Checker](tools/IOC-Reputation-Checker)

PowerShell-based WPF widget designed to simplify IOC reputation analysis through VirusTotal and AbuseIPDB integrations.

Supported indicators:

- IPv4
- IPv6
- Domains
- URLs
- File hashes (MD5, SHA1, and SHA256)

Main features:

- Automatic IOC type detection
- VirusTotal integration
- AbuseIPDB integration
- Input validation and sanitization
- Lightweight PowerShell WPF interface

### [Check-List-IP](tools/Check-IP-List)

PowerShell tool designed to check the reputation of multiple IP addresses through the AbuseIPDB API and export the results to a CSV report.

Main features:

- Bulk IP reputation checks from a CSV file
- AbuseIPDB enrichment with a 90-day report history
- Automatic `Reliable` and `Suspicious` classification
- Progress tracking, elapsed time, and average processing speed
- Timestamped CSV report with reputation and error details
- Graphical file selection and export dialogs

## KQL Queries

A collection of Microsoft Sentinel and Defender hunting queries focused on:

- Sign-in analysis
- Threat hunting
- Authentication investigations
- Endpoint telemetry analysis

Current examples:

- `SigninLogs`
- `AADNonInteractiveUserSignInLogs`

## Technologies

- Microsoft Sentinel
- Microsoft Defender XDR
- Kusto Query Language (KQL)
- PowerShell
- WPF
- VirusTotal API
- AbuseIPDB API

## Author

### Connect with me

**Luiz Gustavo**

- [LinkedIn](https://linkedin.com/in/luiz-gustavo-lz)
- [YouTube](https://www.youtube.com/@LuizGustavoCyberSec)

More content will be added over time.