# Cybersecurity Portfolio

This repository contains cybersecurity tools, KQL queries, investigation resources, and demonstration datasets developed for security operations, threat hunting, automation, and continuous learning.

All public examples are sanitized and use fictional or generic data. No organizational or customer information is included.

## Tools

### [IOC Reputation Checker](tools/IOC-Reputation-Checker)

PowerShell-based WPF tool designed to simplify IOC reputation analysis through VirusTotal and AbuseIPDB integrations.

Supported indicators:

- IPv4 and IPv6 addresses
- Domains and URLs
- File hashes (MD5, SHA1, and SHA256)

Main features:

- Automatic IOC type detection
- VirusTotal and AbuseIPDB enrichment
- Input validation and sanitization
- Lightweight graphical interface

### [Check-List-IP](tools/Check-IP-List)

PowerShell tool designed to check the reputation of multiple IP addresses through the AbuseIPDB API and export the results to a CSV report.

Main features:

- Bulk IP reputation checks from a CSV file
- AbuseIPDB enrichment with a 90-day report history
- Automatic `Reliable` and `Suspicious` classification
- Progress tracking and processing statistics
- Timestamped CSV reports with reputation and error details
- Graphical file selection and export dialogs

## [KQL Queries](KQL)

A structured collection of Microsoft Sentinel and Microsoft Defender XDR queries focused on identity, endpoint, and network investigations.

```text
KQL/
├── Investigation/
│   ├── Endpoint/
│   │   ├── Process/
│   │   └── Telemetry/
│   ├── Identity/
│   │   └── Sign-ins/
│   └── Network/
└── Tables-Demo/
```

### Investigation

Reusable queries designed to support common SOC investigation workflows.

Current coverage includes:

- Interactive and non-interactive sign-in analysis
- User sign-in baselines and authentication methods
- Device process activity and execution chain analysis
- Device telemetry coverage validation
- Remote IP access analysis
- Identity, endpoint, and network investigation workflows

Featured queries:

#### Identity

- [`authentication-methods-used.kql`](KQL/Investigation/Identity/Sign-ins/authentication-methods-used.kql)
- [`signin-baseline.kql`](KQL/Investigation/Identity/Sign-ins/signin-baseline.kql)
- [`user-interactive-signin.kql`](KQL/Investigation/Identity/Sign-ins/user-interactive-signin.kql)
- [`user-noninteractive-signin.kql`](KQL/Investigation/Identity/Sign-ins/user-noninteractive-signin.kql)

#### Endpoint

- [`device-process-activity-search.kql`](KQL/Investigation/Endpoint/Process/device-process-activity-search.kql)
- [`device-telemetry-coverage-summary.kql`](KQL/Investigation/Endpoint/Telemetry/device-telemetry-coverage-summary.kql)

#### Network

- [`remote-ip-access-summary.kql`](KQL/Investigation/Network/remote-ip-access-summary.kql)

### [Demo Tables](KQL/Tables-Demo)

Reusable KQL datasets created for hands-on labs, query testing, video demonstrations, and Microsoft Sentinel training.

Available scenarios include:

- Identity information
- Interactive and non-interactive sign-ins
- Authentication methods and MFA
- Device, location, IP address, and risk scenarios
- Successful and failed authentication events

All users, domains, IP addresses, devices, and events are fictional and intended exclusively for demonstration purposes.

## Technologies

- Microsoft Sentinel
- Microsoft Defender XDR
- Microsoft Entra ID
- Kusto Query Language (KQL)
- Azure Log Analytics
- PowerShell and WPF
- VirusTotal API
- AbuseIPDB API

## Author

### Luiz Gustavo

- [LinkedIn](https://linkedin.com/in/luiz-gustavo-lz)
- [YouTube](https://www.youtube.com/@LuizGustavoCyberSec)

More investigation resources, threat hunting queries, detection engineering content, and security automation projects will be added over time.
