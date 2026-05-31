# IOC-Reputation-Checker

PowerShell-based widget designed to simplify IOC reputation analysis by integrating multiple threat intelligence sources into a lightweight and easy-to-use interface.

## Overview

Security analysts frequently need to investigate indicators such as:

* IP Addresses
* Domains
* URLs
* File Hashes

Instead of manually opening multiple websites and performing repetitive lookups, this tool centralizes the investigation process and provides quick access to reputation information.

Currently supported integrations:

* VirusTotal
* AbuseIPDB

---

## Features

### IOC Detection

Automatically identifies the input type:

* IPv4
* IPv6
* Domains
* URLs
* MD5 Hashes
* SHA1 Hashes
* SHA256 Hashes

### Threat Intelligence Integration

* VirusTotal reputation lookup
* AbuseIPDB reputation lookup
* Direct access to investigation portals

### Security Controls

* Basic input sanitization
* URL execution prevention
* HTTPS communication only
* TLS 1.2 enforcement

### User Interface

* Lightweight PowerShell WPF GUI
* Quick investigation workflow
* Keyboard support (Enter key)
* Visual severity indicators

---

## Example Workflow

1. Enter an IOC.
2. Click **Check**.
3. Review reputation results.
4. Open the IOC directly in VirusTotal or AbuseIPDB for further investigation.

---

## Technologies

* PowerShell
* WPF
* VirusTotal API
* AbuseIPDB API

---

## Requirements

* Windows
* PowerShell 5.1 or later
* VirusTotal API Key

---

## Configuration

Insert your VirusTotal API Key in the following variable:

```powershell
$ApiKey = ""
```

For public repositories, it is recommended to store API keys outside the source code.

---

## Screenshots

Screenshots will be added in future releases.

---

## Future Improvements

Planned enhancements include:

* Additional Threat Intelligence providers
* IP geolocation enrichment (Country)
* VPN / Proxy identification
* Improved input validation
* Enhanced error handling
* UI improvements

---

## Disclaimer

This tool is intended for educational, research, and operational cybersecurity purposes.

Users are responsible for complying with applicable policies, licensing terms, and API usage limitations.