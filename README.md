# Network Configuration Menu Script

![Network Configuration Menu](Network_Configuration_Menu.png)

## Description

A powerful PowerShell 5.1-compatible script for managing IPv4 network settings with GDPR-aware privacy controls. Features static IP/DHCP configuration, **modern IP profiles**, real-time network monitoring, diagnostics, subnet tools, **MAC vendor lookup**, managed backups, and log retention.

**Version**: 2.9

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
- **MAC Vendor Lookup**: Identify device manufacturers from MAC addresses
  - Online API integration with local caching
  - Supports multiple MAC formats (colons, dashes, or no separators)
  - Automatic retry for offline scenarios
  - Displays vendor info in IP configuration view
  - Interactive lookup tool (Option V)
- **Advanced IP Conflict Detection**: Multi-layered scanning (6 methods)
  - NetBIOS name query (catches Windows devices)
  - Gratuitous ARP with cache clear
  - ICMP ping verification
  - PowerShell ARP cache analysis
  - TCP port scan (SMB ports 445, 139)
  - Final comprehensive ARP check
- **Static IP & DHCP**: Switch between static and DHCP configurations
  - Automatic cleanup of residual IP addresses (prevents APIPA accumulation)
  - Post-configuration verification
  - Subnet-aware gateway suggestions and strict IPv4/subnet input validation
- **IP Profiles**: Save and apply reusable JSON profiles with names, groups, adapter metadata, gateway/DNS settings, and legacy XML fallback. Profile replacement requires confirmation.
- **Diagnostics**: Connectivity test, DNS lookup, traceroute, TCP port check, ARP table, and subnet calculator
- **Subnet Calculator**: CIDR calculations, binary representations, subnetting guides, and safer blank/invalid input handling
- **Interface Management**: Rename and manage multiple network adapters

### Privacy Controls

- **User Consent Management**: Explicit opt-in for logging
- **IP Pseudonymization**: Automatic masking (192.168.1.xxx)
- **User Rights**: Access, logs-only deletion, full local-data deletion, consent changes, and data portability
- **Local Storage**: Logs, profiles, and backups stay on your computer. MAC vendor lookup sends the first six MAC digits (the vendor prefix) to `api.macvendors.com`; update checks download the script from GitHub.
- **Privacy Dashboard**: Dedicated menu for privacy controls
- **Retention Controls**: Log rotation plus age/count cleanup for logs and managed backups
- **Log Viewer**: Search current and rotated JSON logs by message text, severity, and date; page through results in the console

### User Experience

- **Intuitive Menu**: Grouped configuration, diagnostics, and tools sections with single-key actions
- **Smart Validation**: IP, subnet, DNS, and hostname validation
- **Consistent Prompts**: `y/yes/n/no` confirmation handling across common workflows
- **Auto Version Sync**: Version tracking from script header
- **Safer Updates**: Downloads are parsed and staged before replacement, with a managed backup of the previous script
- **AppData Storage**: Organized file management in `%APPDATA%`
- **Pure ASCII**: Maximum compatibility across systems
- **PSScriptAnalyzer Clean**: Clean with the included project settings for this interactive console utility

## Quick Actions

- `v` - MAC vendor lookup (identify device manufacturers)
- `q` - Quick DHCP configuration
- `t` - Quick network connectivity test
- `n` - DNS lookup
- `r` - Traceroute
- `o` - TCP port check
- `a` - ARP table
- `c` - Refresh menu
- `d` - DNS cache flush
- `i` - Adapter details (MAC, speed, status)
- `l` - Query logs (recent entries, filters, and raw log access)

## Log Viewer

Press `l` in the main menu or choose **Query Logs** in the Privacy menu. The viewer searches the current log and retained rotated archives, shows newest entries first, and displays 20 results per page. Choose **Query** to filter by exact severity (`DEBUG`, `INFO`, `WARN`, `ERROR`, or `CRITICAL`), a case-insensitive literal message search, and an inclusive date range (`yyyy-MM-dd`). Results are capped at 200 by default; you can request up to 1,000. The raw current log can still be opened in Notepad.

Logging consent controls new entries. Previously saved logs remain viewable until deleted.

## Live Network Monitoring (Option 12)

Monitor your network interface in real-time with comprehensive event tracking:

### Features

- **Event Detection**: Cable connections, IP changes, DHCP/Static transitions, Gateway/DNS updates, WiFi network switching
- **Smart DHCP Tracking**: Time-based DHCP renewal detection (prevents false positives)
- **Activity Heartbeat**: Shows monitoring status during idle periods (every 60 seconds)
- **Interactive Controls**:
  - `D` - Run network diagnostics (Gateway, DNS, Internet)
  - `S` - Show current interface status
  - `C` - Clear event log
  - `Q/Esc` - Exit monitoring
- **Live Window Title**: Real-time status updates showing interface state, IP, config type, and event count
- **Color-Coded Events**: Green (acquired), Red (lost), Yellow (changed), Cyan (updated)
- **WiFi Support**: SSID display, signal strength, network switching detection
- **Detailed Diagnostics**: Ping tests with min/max/avg latency and packet loss percentages
- **Consent-Based Logging**: Monitoring events are logged only after opt-in, with IP address masking

### Example Events

```text
[14:23:15] NETWORK DISCONNECTED - No link detected
[14:23:15] IP ADDRESS LOST - Was 192.168.1.xxx
[14:23:15] GATEWAY LOST - Was 192.168.1.1
[14:23:15] DNS SERVERS CLEARED - Was 1.1.1.1, 1.0.0.1
[14:23:15] LINK SPEED CHANGED: 1.0 Gbps -> 100 Mbps
[14:23:22] NETWORK CONNECTED - Link established
[14:23:22] DHCP REQUEST - Requesting IP address...
[14:23:22] IP ADDRESS ACQUIRED: 10.0.0.xxx
[14:23:22] DHCP: Acquired from 10.0.0.1
[14:23:22] DHCP LEASE: Expires Friday, 2 December 2025 14:23:20
[14:23:22] GATEWAY ACQUIRED: 10.0.0.1
[14:23:22] DNS SERVERS CONFIGURED: 8.8.8.8, 8.8.4.4
  [Monitoring active - No events for 1 minute]
```

## Privacy Controls

- **Data Collected**: Interface names, log IP addresses (pseudonymized), saved profiles/backups, configuration settings, timestamps
- **Logging Choice**: Logging requires opt-in consent; saved profiles and backups are created by user actions
- **Storage**: Local only (`%APPDATA%\Network_Configuration_Script`)
- **Data Controls**: View logs, delete stored data, change logging consent, and export local data

## Prerequisites

- Windows OS with PowerShell 5.1+
- Administrator privileges
- Script execution policy

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

## Hardware Compatibility

Most standard Windows Ethernet and Wi-Fi adapters should work through the built-in networking cmdlets used by this script. Some Realtek and MediaTek Wi-Fi adapters, especially in virtualized, passthrough, or vendor-driver-specific setups, may behave inconsistently when switching between DHCP and static IPv4 configuration. If an adapter reports that an IP address or gateway already exists during a static change, try DHCP rollback, reconnect the adapter, update the vendor driver, or use the Windows network settings UI for that adapter.

## Usage

1. **Download**: Get `Network_Configuration.ps1` from [releases](https://github.com/Dantdmnl/Network_Configuration_Script/releases)
2. **Run**: Right-click -> Run with PowerShell. If needed, the script will request administrator elevation.
3. **First Run**: Choose whether to enable optional logging
4. **Configure**: Follow interactive prompts

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for release history.
