# Network Configuration Menu Script
![Network Configuration Menu](Network_Configuration_Menu.png)

## Description
A powerful PowerShell script for managing IPv4 network settings with GDPR-compliant privacy controls. Features static IP/DHCP configuration, network diagnostics, subnet calculator, and comprehensive configuration management.

## Key Features

### Network Management
- **Static IP & DHCP**: Switch between static and DHCP configurations
- **Configuration Save/Load**: Backup and restore network settings via XML
- **Network Testing**: Gateway, DNS, and internet connectivity diagnostics
- **Subnet Calculator**: CIDR calculations, binary representations, subnetting guides
- **Interface Management**: Rename and manage multiple network adapters

### GDPR Privacy & Compliance
- **User Consent Management**: Explicit opt-in for logging
- **IP Pseudonymization**: Automatic masking (192.168.1.xxx)
- **User Rights**: Access, Erasure, Rectification, Data Portability
- **Local Storage Only**: No external data transmission
- **Privacy Dashboard**: Dedicated menu for privacy controls (Option 11)

### User Experience
- **Intuitive Menu**: Easy navigation with quick actions ('q', 't', 'c', 'd', 'i')
- **Smart Validation**: IP, subnet, DNS, and hostname validation
- **Auto Version Sync**: Version tracking from script header
- **AppData Storage**: Organized file management in `%APPDATA%`
- **Pure ASCII**: Maximum compatibility across systems
- **PSScriptAnalyzer Clean**: Zero code quality issues

## Quick Actions
- `q` - Quick DHCP configuration
- `t` - Quick network connectivity test
- `c` - Clear screen
- `d` - DNS cache flush
- `i` - Interface information (MAC, speed, status)

## GDPR Compliance

**Data Collected**: Interface names, IP addresses (pseudonymized), configuration settings, timestamps  
**Legal Basis**: Explicit user consent (GDPR Article 6(1)(a))  
**Storage**: Local only (`%APPDATA%\Network_Configuration_Script`)  
**User Rights**: Full GDPR compliance with access, erasure, rectification, portability

## Prerequisites
- Windows OS with PowerShell 5.1+
- Administrator privileges
- Script execution policy:
  ```powershell
  Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass
  ```

## Usage

1. **Download**: Get `Network_Configuration.ps1` from [releases](https://github.com/Dantdmnl/Network_Configuration_Script/releases)
2. **Run**: Right-click → Run with PowerShell (as Administrator)
3. **First Run**: Accept GDPR consent banner
4. **Configure**: Follow interactive prompts