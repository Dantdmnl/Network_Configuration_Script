# Network Configuration Menu Script
![Network Configuration Menu](Network_Configuration_Menu.png)

## Description
A powerful PowerShell script for managing IPv4 network settings with support for static IPs, DHCP configurations, and advanced network diagnostics. Features enhanced error handling, configuration management, and a comprehensive subnet calculator.

## Features

### Core Functionality
- **Static IP and DHCP Configuration**: Seamlessly switch between static IP and DHCP modes
- **Configuration Management**: Save and load network configurations to/from XML files for easy backups
- **Network Connectivity Testing**: Comprehensive network diagnostics including gateway, DNS, and internet connectivity tests
- **Subnet Calculator**: Advanced subnet calculations with binary representations, CIDR notation, and subnetting guides

### User Experience
- **Intuitive Menu-Driven Interface**: Easy-to-navigate menu system with quick actions
- **Smart Input Validation**: Robust validation for IP addresses, subnet masks, DNS servers, and hostnames
- **Enhanced Error Handling**: Clear error messages and graceful error recovery
- **Dynamic Version Display**: Version information extracted automatically from script header
- **Quick Actions**: Shortcuts for common tasks (Quick DHCP, status check, quick test, refresh)

### Configuration & Storage
- **AppData Storage**: All configuration, log, version, and interface files stored in AppData for better organization
- **Automatic File Migration**: Seamlessly migrates old config files to AppData location
- **Interface Persistence**: Saves and reuses selected network interfaces across sessions
- **Log Rotation**: Automatic log file management with configurable size limits and archive retention

### Network Features
- **Smart Gateway Suggestions**: Intelligent gateway recommendations based on entered IP address
- **Flexible Gateway Input**: Enter last octet, .1/.254, full IP, or skip gateway configuration
- **Strict DNS Validation**: Accepts full IPv4 addresses or valid FQDNs/hostnames only
- **Interface Management**: Rescan interfaces and toggle visibility of down/disabled adapters
- **Multi-Interface Support**: Works with multiple network adapters including Ethernet and WiFi

### Advanced Capabilities
- **Comprehensive Network Testing**: Tests gateway connectivity, public DNS servers, local DNS, and name resolution
- **Parallel DNS Testing**: Fast network diagnostics using parallel job execution
- **Subnet Calculator**: 
  - IP address validation and network calculations
  - CIDR and subnet mask conversion
  - Network/broadcast address computation
  - Usable IP range identification
  - Binary representation display
  - Network class determination
  - Private/public IP detection
  - Subnetting recommendations

### Safety & Security
- **Administrator Elevation**: Automatically requests admin privileges when needed
- **Confirmation Prompts**: Defaults to 'y' for faster workflow while maintaining safety
- **Strict Input Validation**: Cancels operations immediately on invalid input
- **Interface Requirement Blocking**: Prevents configuration actions until valid interface is selected
- **Rollback Protection**: Validates existing configurations before making changes

## Prerequisites
- **Windows OS with PowerShell.**
- **Having permission to run PowerShell as an administrator.**
- **Allow script execution:**
  ```powershell
  Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass

## Usage

To download and execute the script locally, follow these steps:

1. **Download the Script**  
   - Visit the [releases tab](https://github.com/Dantdmnl/Network_Configuration_Script/releases) on the GitHub repository.  
   - Download the latest version of the **`Network_Configuration.ps1`** file.

2. **Run the Script**  
   - Locate the downloaded file on your computer.  
   - Right-click the file and select **Run with PowerShell**.

3. **Follow the Prompts**  
   - The script will provide a series of interactive prompts to guide you through configuring your network settings.  
   - If an invalid IP address is entered during static IP configuration, the process will be cancelled and you will be notified immediately.  
   - Respond to each prompt with the required inputs.
