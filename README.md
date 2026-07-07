# Windows Server Audit Scripts

[![PSScriptAnalyzer](https://github.com/Jarnon404/windows-server-audit-scripts/actions/workflows/psscriptanalyzer.yml/badge.svg)](https://github.com/Jarnon404/windows-server-audit-scripts/actions/workflows/psscriptanalyzer.yml)
[![Pester Tests](https://github.com/Jarnon404/windows-server-audit-scripts/actions/workflows/pester.yml/badge.svg)](https://github.com/Jarnon404/windows-server-audit-scripts/actions/workflows/pester.yml)
[![Secret Scan](https://github.com/Jarnon404/windows-server-audit-scripts/actions/workflows/gitleaks.yml/badge.svg)](https://github.com/Jarnon404/windows-server-audit-scripts/actions/workflows/gitleaks.yml)
[![Public Safety Check](https://github.com/Jarnon404/windows-server-audit-scripts/actions/workflows/public-safety-check.yml/badge.svg)](https://github.com/Jarnon404/windows-server-audit-scripts/actions/workflows/public-safety-check.yml)
[![Release](https://img.shields.io/github/v/release/Jarnon404/windows-server-audit-scripts?label=release)](https://github.com/Jarnon404/windows-server-audit-scripts/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
Public-safe PowerShell audit scripts for Windows Server and domain-controller focused inventory reporting.

This repository contains sanitized audit scripts originally prepared for operational Windows Server review work. The public version is intentionally cleaned so it can be shared without customer-specific data.

## Included scripts

### Windows Server Audit

```text
scripts/windows-server-audit/Windows-Server-Audit.ps1
```

Collects general Windows Server inventory and operational state information, including:

- computer and operating system information
- update and reboot state
- services and processes
- listening ports
- firewall rules
- installed applications
- Defender status and recent detections when available
- local users and groups
- optional SQL-related discovery where available
- HTML report output

### Windows Domain Controller Audit

```text
scripts/domain-controller-audit/Windows-DomainController-Audit.ps1
```

Collects Windows Server and domain-controller focused audit information, including:

- server role and feature information
- AD DS / domain-controller indicators
- local groups and local administrators
- privileged Active Directory groups when modules are available
- listening ports
- installed applications
- HTML report output

## Repository safety model

This repository is intended to be public-safe.

The repository should not contain:

- customer names
- tenant identifiers
- internal hostnames
- private IP addresses
- usernames or email addresses from real environments
- passwords, secrets, API keys or tokens
- generated audit reports
- exported CSV, JSON, HTML or log files from real systems

Generated audit output should stay outside the repository.

## Requirements

- Windows PowerShell 5.1 or PowerShell 7 where compatible
- Administrator permissions recommended
- Remote PowerShell / WinRM when auditing remote servers
- RSAT / Active Directory module for AD-specific sections where applicable

## Usage

Run from an elevated PowerShell session.

```powershell
cd C:\Path\To\Repository

.\scripts\windows-server-audit\Windows-Server-Audit.ps1
```

or:

```powershell
.\scripts\domain-controller-audit\Windows-DomainController-Audit.ps1
```

The scripts ask for a target computer name at startup. Leaving the value empty audits the local computer.

## Output

By default, generated reports are written under:

```text
AuditReports\<ComputerName>\
```

Generated output files are intentionally excluded from Git.

## Quality checks

This repository includes GitHub Actions for:

- PSScriptAnalyzer
- Pester repository tests
- secret scanning
- public safety checks

## License

MIT License.

## Public safety note

This repository is intended to contain only public-safe material. Do not commit customer-specific data, tenant identifiers, credentials, generated audit reports, internal hostnames, private IP addresses or environment-specific exports.
