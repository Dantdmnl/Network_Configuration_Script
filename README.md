# Network Configuration Menu Script
![Network Configuration Menu](Network_Configuration_Menu.png)
## Description
Easily manage IPv4 network settings with this PowerShell script, supporting static IPs and DHCP configurations.

## Features
- **Apply and save static IP configurations to XML for easy backups.**
- **Save and reuse selected network interfaces for quick setup.**
- **Switch seamlessly between static IP and DHCP modes.**
- **Display and manage detailed current network settings, including IP, gateway, DNS, and MAC addresses.**
- **Rescan available network interfaces and toggle visibility of downed interfaces in the interface menu.**
- **Store configurations securely in both XML and plain-text formats.**
- **Intuitive, menu-driven interface for efficient navigation.**
- **An update function to make your life easier.**
- **Network Connectivity test function.**

## Prerequisites
- **Windows OS with PowerShell.**
- **Having permission to run PowerShell as an administrator.**
- **Allow script execution:**
  ```powershell
  Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass

## Usage
### Method 1: Download and Run the Script Locally

To download and execute the script locally, follow these steps:

1. **Download the Script**  
   - Visit the [releases tab](https://github.com/Dantdmnl/Network_Configuration_Script/releases) on the GitHub repository.  
   - Download the latest version of the **`Network_Configuration.ps1`** file.

2. **Run the Script**  
   - Locate the downloaded file on your computer.  
   - Right-click the file and select **Run with PowerShell**.

3. **Follow the Prompts**  
   - The script will provide a series of interactive prompts to guide you through configuring your network settings.  
   - Respond to each prompt with the required inputs.
### Method 2 - Run the Script Directly from GitHub:
1. **Open PowerShell as Administrator**.
    - Press **`Win + S`**, type **PowerShell**, right-click on it, and select **Run as Administrator**.
2. **Execute the Script**

   In the elevated PowerShell window, run the following command:
   ```powershell
   iex "& { $(iwr -useb 'https://raw.githubusercontent.com/Dantdmnl/Network_Configuration_Script/refs/heads/main/Network_Configuration.ps1') }"
3. **Follow the Prompts**
    - The script will guide you through a series of interactive prompts to configure your network settings.
    - Provide the required inputs as prompted by the script.
