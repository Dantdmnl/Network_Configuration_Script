# Network Configuration Menu Script
![Network Configuration Menu](Network_Configuration_Menu.png)

## Description
A powerful PowerShell script for managing IPv4 network settings with GDPR-compliant privacy controls. Features static IP/DHCP configuration, **real-time network monitoring**, network diagnostics, subnet calculator, and comprehensive configuration management.

**Version**: 2.2  
**Status**: Production Ready

## Key Features

### Network Management
- **Live Interface Monitoring** : Real-time event tracking with interactive controls
  - Cable plug/unplug detection with link status
  - IP acquisition, loss, and configuration changes
  - Gateway and DNS server monitoring
  - DHCP/Static configuration transitions
  - WiFi connection and signal strength tracking
  - On-demand diagnostics (D), status (S), clear log (C)
  - Dynamic window title with live stats
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

## Live Network Monitoring (Option 12)

Monitor your network interface in real-time with comprehensive event tracking:

### Features
- **Event Detection**: Cable connections, IP changes, DHCP/Static transitions, Gateway/DNS updates
- **Interactive Controls**:
  - `D` - Run network diagnostics (Gateway, DNS, Internet)
  - `S` - Show current interface status
  - `C` - Clear event log
  - `Q/Esc` - Exit monitoring
- **Live Window Title**: Real-time status updates showing interface state, IP, config type, and event count
- **Color-Coded Events**: Green (acquired), Red (lost), Yellow (changed), Cyan (updated)
- **Detailed Diagnostics**: Ping tests with min/max/avg latency and packet loss percentages

### Example Events
```
[16:54:41] CABLE UNPLUGGED - No link detected
[16:54:41] IP ADDRESS LOST - Was 192.168.1.69
[16:54:41] GATEWAY LOST - Was 192.168.1.1
[16:54:41] DNS SERVERS CLEARED - Was 1.1.1.1, 9.9.9.9, 1.0.0.1
[16:54:48] CABLE PLUGGED IN - Link established
[16:54:48] IP ADDRESS ACQUIRED: 192.168.1.69
[16:54:48] GATEWAY ACQUIRED: 192.168.1.1
[16:54:48] DNS SERVERS CONFIGURED: 1.1.1.1, 9.9.9.9, 1.0.0.1
```

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
  Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
  ```

## Usage

1. **Download**: Get `Network_Configuration.ps1` from [releases](https://github.com/Dantdmnl/Network_Configuration_Script/releases)
2. **Run**: Right-click → Run with PowerShell (as Administrator)
3. **First Run**: Accept GDPR consent banner
4. **Configure**: Follow interactive prompts
