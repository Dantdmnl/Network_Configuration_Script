# Version: 1.4

# Check for elevation and re-run as administrator if needed
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Start-Process -FilePath "PowerShell" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Definition)`"" -Verb RunAs
    exit
}

# Function to log messages
function Log-Message {
    param (
        [string]$Message,
        [string]$Level = "INFO"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "$timestamp [$Level] $Message"
    
    $logPath = "$env:USERPROFILE\network_config.log"
    Add-Content -Path $logPath -Value $logEntry
}

function Update-Script {
    param (
        [string]$RemoteScriptURL = "https://raw.githubusercontent.com/Dantdmnl/Network_Configuration_Script/refs/heads/main/Network_Configuration.ps1",
        [string]$VersionFileName = "version.txt"
    )

    # Define the user's profile path for version tracking
    $userProfile = [Environment]::GetFolderPath('UserProfile')
    $versionFilePath = Join-Path $userProfile $VersionFileName

    # Determine the current script path
    $CurrentScriptPath = if ($MyInvocation.MyCommand.Path -and (Test-Path $MyInvocation.MyCommand.Path)) {
        $MyInvocation.MyCommand.Path
    } elseif ($PSScriptRoot -and $PSScriptRoot -ne "") {
        Join-Path -Path $PSScriptRoot -ChildPath (Split-Path -Leaf $PSCommandPath)
    } else {
        Write-Host "Unable to determine the script's current path automatically. Please provide the script's full path."
        Read-Host "Enter the full path to the current script"
    }

    Write-Host "Checking for script updates..." -ForegroundColor Yellow
    Log-Message "Checking for script updates..."

    # Ensure the version file exists
    if (-not (Test-Path $versionFilePath)) {
        Write-Host "Version file not found. Creating a new one with version 1.0." -ForegroundColor Yellow
        Log-Message "Version file not found. Creating a new one with version 1.0."
        Set-Content -Path $versionFilePath -Value "1.0"
    }

    $currentVersion = (Get-Content $versionFilePath).Trim()

    try {
        # Fetch the remote script content
        $RemoteScriptContent = Invoke-WebRequest -Uri $RemoteScriptURL -UseBasicParsing
        if (-not $RemoteScriptContent) {
            Write-Host "Failed to fetch the remote script. Please check the URL." -ForegroundColor Red
            Log-Message "Failed to fetch the remote script. Please check the URL." "ERROR"
            return
        }

        # Extract the version line from the remote script
        $VersionLine = ($RemoteScriptContent.Content -split "`n" | Select-Object -First 10 | Where-Object { $_ -match "# Version:" })

        if ($VersionLine) {
            # Strict regex to extract only the version number
            $RemoteVersion = ($VersionLine -replace ".*# Version:\s*([0-9]+\.[0-9]+).*", '$1').Trim()
        } else {
            Write-Host "Could not find a valid version in the remote script." -ForegroundColor Red
            Log-Message "Could not find a valid version in the remote script." "ERROR"
            return
        }

        # Ensure the version is valid
        if (-not $RemoteVersion -or $RemoteVersion -notmatch "^\d+\.\d+$") {
            Write-Host "Invalid version format in the remote script." -ForegroundColor Red
            Log-Message "Invalid version format in the remote script." "ERROR"
            return
        }

        # Compare versions
        if ($RemoteVersion -ne $currentVersion) {
            Write-Host "An updated version of the script is available (Current: $currentVersion, Remote: $RemoteVersion)." -ForegroundColor Cyan
            Log-Message "An updated version of the script is available (Current: $currentVersion, Remote: $RemoteVersion)."

            # Ask the user if they want to update
            $Response = Read-Host "Would you like to update to the latest version? (y/n)"
            if ($Response -eq 'y') {
                # Backup the current script
                $BackupPath = "$CurrentScriptPath.bak"
                Copy-Item -Path $CurrentScriptPath -Destination $BackupPath -Force
                Write-Host "A backup of the current script has been saved as $BackupPath." -ForegroundColor Yellow
                Log-Message "A backup of the current script has been saved as $BackupPath."

                # Update the script
                $RemoteScriptContent.Content | Set-Content -Path $CurrentScriptPath -Force
                Set-Content -Path $versionFilePath -Value $RemoteVersion
                Write-Host "The script has been updated successfully to version $RemoteVersion. Rerun the script to apply the update." -ForegroundColor Green
                Log-Message "The script has been updated successfully to version $RemoteVersion."
            } else {
                Write-Host "The script was not updated." -ForegroundColor Yellow
                Log-Message "The script was not updated."
            }
        } else {
            Write-Host "The script is up-to-date (Version: $currentVersion)." -ForegroundColor Green
            Log-Message "The script is up-to-date (Version: $currentVersion)."
        }
    } catch {
        Write-Host "An error occurred while checking for updates: $_" -ForegroundColor Red
        Log-Message "An error occurred while checking for updates: $_" "ERROR"
    }
}

# Function to calculate prefix length from subnet mask
function Get-PrefixLength {
    param ([string]$SubnetInput)

    if ($SubnetInput -match "^\d+(\.\d+){3}$") {
        # It's a subnet mask like 255.255.255.0
        $binarySubnetMask = [Convert]::ToString([IPAddress]::Parse($SubnetInput).Address, 2).PadLeft(32, '0')
        return ($binarySubnetMask -split '').Where({ $_ -eq '1' }).Count
    } elseif ($SubnetInput -match "^\d+$") {
        # It's a prefix length like 24
        return [int]$SubnetInput
    } elseif ($SubnetInput -match "^/\d+$") {
        # It's a prefix length like /24
        return [int]($SubnetInput -replace "/")
    } else {
        throw "Invalid subnet format. Please enter a valid subnet mask (e.g., 255.255.255.0) or prefix length (e.g., 24 or /24)."
    }
}

# Define the path to save the configuration securely
$configPath = "$env:USERPROFILE\static_ip_config.xml"
$interfacePath = "$env:USERPROFILE\selected_interface.txt"

# Function to save selected interface
function Save-SelectedInterface {
    param ([string]$InterfaceName)
    Set-Content -Path $interfacePath -Value $InterfaceName
    Log-Message "Selected interface saved: $InterfaceName"
}

# Function to load selected interface
function Load-SelectedInterface {
    if (Test-Path $interfacePath) {
        return Get-Content -Path $interfacePath
    } else {
        return $null
    }
}

# Function to save static IP configuration
function Save-StaticIPConfig {
    param (
        [string]$IPAddress,
        [string]$SubnetMask,
        [string]$Gateway = $null,  # Make Gateway optional
        [string]$PrimaryDNS,
        [string]$SecondaryDNS = $null
    )

    $config = @{
        IPAddress = $IPAddress
        SubnetMask = $SubnetMask
        PrimaryDNS = $PrimaryDNS
    }

    if ($Gateway) {
        $config["Gateway"] = $Gateway
    } else {
        Log-Message "No Gateway specified. Skipping Gateway configuration."
    }

    if ($SecondaryDNS) {
        $config["SecondaryDNS"] = $SecondaryDNS
    }

    $configPath = "$env:USERPROFILE\static_ip_config.xml"
    $config | Export-Clixml -Path $configPath

    Log-Message "Static IP configuration saved."
}

# Function to load static IP configuration
function Load-StaticIPConfig {
    if (Test-Path $configPath) {
        return Import-Clixml -Path $configPath
    } else {
        Write-Host "No saved configuration found." -ForegroundColor Yellow
        Log-Message "No saved configuration found."
        return $null
    }
}

function Set-StaticIP {
    param (
        [string]$InterfaceName,
        [string]$IPAddress,
        [string]$SubnetMask,
        [string]$Gateway = $null,  # Make Gateway optional
        [string]$PrimaryDNS,
        [string]$SecondaryDNS = $null  # Secondary DNS is also optional
    )

    Write-Host "Setting static IP configuration..." -ForegroundColor Cyan
    Log-Message "Setting static IP configuration for interface: $InterfaceName"

    try {
        # Validate and convert subnet input
        $prefixLength = Get-PrefixLength -SubnetInput $SubnetMask

        # Remove existing IP configurations to avoid conflicts
        $existingIPConfig = Get-NetIPAddress -InterfaceAlias $InterfaceName -ErrorAction SilentlyContinue
        if ($existingIPConfig) {
            $existingIPConfig | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
        }

        # Remove existing gateway configuration
        $existingRoute = Get-NetRoute -InterfaceAlias $InterfaceName -ErrorAction SilentlyContinue
        if ($existingRoute) {
            $existingRoute | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
        }

        # Set IP address and subnet mask
        $params = @{
            InterfaceAlias = $InterfaceName
            IPAddress = $IPAddress
            PrefixLength = $prefixLength
        }

        if ($Gateway) {
            $params["DefaultGateway"] = $Gateway
        } else {
            Write-Host "No Gateway specified. Skipping Default Gateway configuration." -ForegroundColor Yellow
            Log-Message "No Gateway specified. Skipping Default Gateway configuration."
        }

        New-NetIPAddress @params -ErrorAction Stop

        # Set DNS servers
        $dnsServers = @($PrimaryDNS)
        if ($SecondaryDNS) {
            $dnsServers += $SecondaryDNS
        }

        Set-DnsClientServerAddress -InterfaceAlias $InterfaceName -ServerAddresses $dnsServers -ErrorAction Stop

        Write-Host "Static IP configuration applied successfully." -ForegroundColor Green
        Log-Message "Static IP configuration applied successfully."
    } catch {
        $errorMessage = "Error: Unable to set static IP configuration. $_"
        Write-Host $errorMessage -ForegroundColor Red
        Log-Message $errorMessage "ERROR"
    }
}

# Function to set DHCP configuration
function Set-DHCP {
    param ([string]$InterfaceName)

    Write-Host "Switching to DHCP configuration..." -ForegroundColor Cyan
    Log-Message "Switching to DHCP configuration for interface: $InterfaceName"

    try {
        # Validate interface alias
        $interface = Get-NetIPInterface -InterfaceAlias $InterfaceName -ErrorAction Stop

        Write-Host "Releasing IP address..." -ForegroundColor Yellow
        Remove-NetIPAddress -InterfaceAlias $InterfaceName -Confirm:$false -ErrorAction Stop
        
        Write-Host "Flushing DNS cache..." -ForegroundColor Yellow
        Clear-DnsClientCache -ErrorAction Stop

        Write-Host "Enabling DHCP..." -ForegroundColor Yellow
        Set-NetIPInterface -InterfaceAlias $InterfaceName -Dhcp Enabled -ErrorAction Stop
        Set-DnsClientServerAddress -InterfaceAlias $InterfaceName -ResetServerAddresses -ErrorAction Stop

        Write-Host "Renewing DHCP lease..." -ForegroundColor Yellow
        ipconfig /release > $null 2>&1
        ipconfig /renew > $null 2>&1

        Start-Sleep -Seconds 5  # Wait for DHCP process

        # Fetch IP configuration
        $ipConfig = Get-NetIPConfiguration -InterfaceAlias $InterfaceName

        if ($ipConfig.IPv4Address.IPAddress -like "169.254.*") {
            Write-Host "Error: Still assigned an APIPA address. Possible network issue." -ForegroundColor Red
            Write-Host "Performing dynamic ping test..." -ForegroundColor Cyan
            $gateway = $ipConfig.IPv4DefaultGateway.NextHop
            if ($gateway) {
                Test-Connection -ComputerName $gateway -Count 4 | Format-Table -AutoSize
            } else {
                Write-Host "No gateway detected. Please verify network connectivity." -ForegroundColor Red
            }
        } else {
            Write-Host "DHCP configuration applied successfully!" -ForegroundColor Green
            Write-Host "IP Address: $($ipConfig.IPv4Address.IPAddress)" -ForegroundColor Cyan
            Write-Host "Subnet Mask: /$($ipConfig.IPv4Address.PrefixLength)" -ForegroundColor Cyan
            Write-Host "Default Gateway: $($ipConfig.IPv4DefaultGateway.NextHop)" -ForegroundColor Cyan
            Write-Host "DNS Servers: $($ipConfig.DnsServer.ServerAddresses -join ', ')" -ForegroundColor Cyan
            Log-Message "DHCP configuration applied successfully."
        }
    } catch {
        $errorMessage = "Error: Unable to apply DHCP configuration. Please check the interface name and network settings. $_"
        Write-Host $errorMessage -ForegroundColor Red
        Log-Message $errorMessage "ERROR"
        Write-Host "Available interfaces:" -ForegroundColor Yellow
        Get-NetIPInterface | Select-Object -Property InterfaceAlias, AddressFamily, Dhcp
    }
}

# Function to show IP configuration
function Show-IPInfo {
    param ([string]$InterfaceName)

    Write-Host "Fetching current IP configuration for interface: $InterfaceName..." -ForegroundColor Cyan
    Log-Message "Fetching current IP configuration for interface: $InterfaceName"

    $ipInfo = Get-NetIPAddress -InterfaceAlias $InterfaceName -ErrorAction SilentlyContinue
    $dnsInfo = Get-DnsClientServerAddress -InterfaceAlias $InterfaceName -ErrorAction SilentlyContinue
    $gatewayInfo = Get-NetRoute -InterfaceAlias $InterfaceName -ErrorAction SilentlyContinue | Where-Object { $_.NextHop -ne "0.0.0.0" -and $_.DestinationPrefix -eq "0.0.0.0/0" }

    if ($ipInfo) {
        Write-Host "IP Address: $($ipInfo.IPAddress)" -ForegroundColor Green
        Write-Host "Subnet Mask: /$($ipInfo.PrefixLength)" -ForegroundColor Green
    } else {
        Write-Host "No IP address assigned." -ForegroundColor Red
    }

    if ($gatewayInfo) {
        Write-Host "Default Gateway: $($gatewayInfo.NextHop)" -ForegroundColor Green
    } else {
        Write-Host "Default Gateway: Not configured." -ForegroundColor Red
    }

    if ($dnsInfo.ServerAddresses) {
        Write-Host "DNS Servers: $($dnsInfo.ServerAddresses -join ", ")" -ForegroundColor Green
    } else {
        Write-Host "No DNS servers configured." -ForegroundColor Red
    }
}

# Function to select network interface with advanced options
function Select-NetworkInterface {
    $showDownInterfaces = $false  # Toggle for showing/hiding down interfaces

    while ($true) {
        # Filter interfaces based on the toggle
        if ($showDownInterfaces) {
            $interfaces = Get-NetAdapter
        } else {
            $interfaces = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
        }

        if ($interfaces.Count -eq 0) {
            Write-Host "No network interfaces found with the current filter." -ForegroundColor Red
            $showDownInterfaces = $true  # Automatically show down interfaces in case of no results
            continue
        }

        Write-Host "`nAvailable Network Interfaces:" -ForegroundColor Cyan
        $interfaces | ForEach-Object {
            Write-Host "$($_.InterfaceIndex): $($_.Name) (MAC: $($_.MacAddress)) - Status: $($_.Status)"
        }

        Write-Host "`nOptions:"
        Write-Host "Enter the number corresponding to the desired interface."
        Write-Host "Press 'r' to rescan interfaces."
        Write-Host "Press 't' to toggle hiding/unhiding down interfaces."
        Write-Host "Press 'q' to quit interface selection."

        $input = Read-Host "Your choice"

        switch ($input.ToLower()) {
            "r" {
                Write-Host "Rescanning interfaces..." -ForegroundColor Yellow
                continue  # Rescan interfaces
            }
            "t" {
                $showDownInterfaces = -not $showDownInterfaces
                Write-Host "Toggled interface visibility. Showing down interfaces: $showDownInterfaces" -ForegroundColor Yellow
                continue  # Refresh list
            }
            "q" {
                Write-Host "Exiting interface selection..." -ForegroundColor Cyan
                return $null
            }
            default {
                if ($input -match "^\d+$") {
                    $inputInt = [int]$input  # Convert input to integer
                    $selectedInterface = $interfaces | Where-Object { $_.InterfaceIndex -eq $inputInt }
                    if ($null -ne $selectedInterface) {
                        Write-Host "Selected Interface: $($selectedInterface.Name)" -ForegroundColor Green
                        Save-SelectedInterface -InterfaceName $selectedInterface.Name
                        return $selectedInterface.Name
                    } else {
                        Write-Host "Invalid selection. Please try again." -ForegroundColor Red
                    }
                } else {
                    Write-Host "Invalid input. Please enter a valid number." -ForegroundColor Red
                }
            }
        }
    }
}

# Function to open the log file
function Open-LogFile {
    $logPath = "$env:USERPROFILE\network_config.log"
    if (Test-Path $logPath) {
        Start-Process -FilePath "notepad.exe" -ArgumentList $logPath
    } else {
        Write-Host "Log file not found." -ForegroundColor Red
    }
}

# Main logic
$interfaceName = Load-SelectedInterface
if ($interfaceName) {
    Write-Host "Currently selected interface: $interfaceName" -ForegroundColor Cyan
    $host.UI.RawUI.WindowTitle = "Network Configuration - $interfaceName"
} else {
    Write-Host "No interface selected. Please select a network interface." -ForegroundColor Yellow
    $interfaceName = Select-NetworkInterface
    if ($interfaceName) {
        $host.UI.RawUI.WindowTitle = "Network Configuration - $interfaceName"
    }
}

while ($true) {
    Write-Host "`nPlease select an option:" -ForegroundColor Yellow
    Write-Host "1. Set static IP configuration manually"
    Write-Host "2. Set DHCP configuration"
    Write-Host "3. Show current IP configuration"
    Write-Host "4. Enter and save static IP configuration"
    Write-Host "5. Load saved static IP configuration"
    Write-Host "6. Change network interface"
    Write-Host "7. Open log file"
    Write-Host "8. Check for updates"
    Write-Host "9. Exit"

    $choice = Read-Host "Enter your choice"

    switch ($choice) {
        "1" {
            # Set static IP configuration manually
            $IPAddress = Read-Host "Enter IP Address (e.g., 192.168.1.25)"
            $SubnetMask = Read-Host "Enter Subnet Mask (e.g., 255.255.255.0)"
            $Gateway = Read-Host "Enter Gateway (e.g., 192.168.1.1)"
            $PrimaryDNS = Read-Host "Enter Primary DNS (e.g., 1.1.1.1)"
            $SecondaryDNS = Read-Host "Enter Secondary DNS (e.g., 1.0.0.1)"
            Set-StaticIP -InterfaceName $interfaceName `
                         -IPAddress $IPAddress `
                         -SubnetMask $SubnetMask `
                         -Gateway $Gateway `
                         -PrimaryDNS $PrimaryDNS `
                         -SecondaryDNS $SecondaryDNS
        }
        "2" {
            # Set DHCP configuration
            Set-DHCP -InterfaceName $interfaceName
        }
        "3" {
            # Show current IP configuration
            Show-IPInfo -InterfaceName $interfaceName
        }
        "4" {
            # Save static IP configuration
            $IPAddress = Read-Host "Enter IP Address (e.g., 192.168.1.25)"
            $SubnetMask = Read-Host "Enter Subnet Mask (e.g., 255.255.255.0)"
            $Gateway = Read-Host "Enter Gateway (e.g., 192.168.1.1)"
            $PrimaryDNS = Read-Host "Enter Primary DNS (e.g., 1.1.1.1)"
            $SecondaryDNS = Read-Host "Enter Secondary DNS (e.g., 1.0.0.1)"
            Save-StaticIPConfig -IPAddress $IPAddress `
                                -SubnetMask $SubnetMask `
                                -Gateway $Gateway `
                                -PrimaryDNS $PrimaryDNS `
                                -SecondaryDNS $SecondaryDNS
        }
        "5" {
            # Load and apply saved static IP configuration
            $config = Load-StaticIPConfig
            if ($config) {
                Write-Host "Loaded Configuration:" -ForegroundColor Green
                Write-Host "IP Address: $($config.IPAddress)"
                Write-Host "Subnet Mask: $($config.SubnetMask)"
                Write-Host "Gateway: $($config.Gateway)"
                Write-Host "Primary DNS: $($config.PrimaryDNS)"
                Write-Host "Secondary DNS: $($config.SecondaryDNS)"
                
                Set-StaticIP -InterfaceName $interfaceName `
                             -IPAddress $config.IPAddress `
                             -SubnetMask $config.SubnetMask `
                             -Gateway $config.Gateway `
                             -PrimaryDNS $config.PrimaryDNS `
                             -SecondaryDNS $config.SecondaryDNS
            } else {
                Write-Host "No static IP configuration found. Please ensure the configuration is saved." -ForegroundColor Yellow
            }
        }
        "6" {
            # Change network interface
            $interfaceName = Select-NetworkInterface
            if ($interfaceName) {
                $host.UI.RawUI.WindowTitle = "Network Configuration - $interfaceName"
            }
        }
        "7" {
            # Open log file
            Open-LogFile
        }
        "8" {
            # Check for updates
            Update-Script
        }
        "9" {
            # Exit the script
            Write-Host "Exiting..." -ForegroundColor Cyan
            Log-Message "Script exited by user."
            exit
        }
        default {
            Write-Host "Invalid choice. Please try again." -ForegroundColor Red
        }
    }
}
