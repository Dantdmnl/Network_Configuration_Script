# Check for elevation and re-run as administrator if needed
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Start-Process -FilePath "PowerShell" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Definition)`"" -Verb RunAs
    exit
}

# Function to calculate prefix length from subnet mask
function Get-PrefixLength {
    param ([string]$SubnetInput)

    if ($SubnetInput -match "^\d+(\.\d+){3}$") {
        # It's a subnet mask like 255.255.255.0
        $binarySubnetMask = [Convert]::ToString([IPAddress]::Parse($SubnetInput).Address, 2).PadLeft(32, '0')
        $prefixLength = ($binarySubnetMask -split '').Where({ $_ -eq '1' }).Count
        return $prefixLength
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

# Function to save static IP configuration
function Save-StaticIPConfig {
    param (
        [string]$IPAddress,
        [string]$SubnetMask,
        [string]$Gateway,
        [string]$PrimaryDNS,
        [string]$SecondaryDNS
    )

    $config = @{
        IPAddress = $IPAddress
        SubnetMask = $SubnetMask
        Gateway = $Gateway
        PrimaryDNS = $PrimaryDNS
        SecondaryDNS = $SecondaryDNS
    }

    $config | Export-Clixml -Path $configPath -Force
    Write-Host "Configuration saved securely." -ForegroundColor Green
}

# Function to load static IP configuration
function Load-StaticIPConfig {
    if (Test-Path $configPath) {
        return Import-Clixml -Path $configPath
    } else {
        Write-Host "No saved configuration found." -ForegroundColor Yellow
        return $null
    }
}

# Function to manually enter static IP configuration
function Enter-StaticIPConfig {
    Write-Host "Enter the static IP configuration:" -ForegroundColor Cyan
    $IPAddress = Read-Host "Enter IP Address (e.g., 192.168.1.25)"
    $SubnetMask = Read-Host "Enter Subnet Mask or Prefix Length (e.g., 255.255.255.0, 24, or /24)"
    $Gateway = Read-Host "Enter Gateway (e.g., 192.168.1.1)"
    $PrimaryDNS = Read-Host "Enter Primary DNS (e.g., 1.1.1.1)"
    $SecondaryDNS = Read-Host "Enter Secondary DNS (e.g., 1.0.0.1)"

    # Validate and convert subnet input
    $prefixLength = Get-PrefixLength -SubnetInput $SubnetMask

    # Save both forms for future use
    Save-StaticIPConfig -IPAddress $IPAddress -SubnetMask $SubnetMask -Gateway $Gateway -PrimaryDNS $PrimaryDNS -SecondaryDNS $SecondaryDNS
}

# Function to set static IP configuration
function Set-StaticIP {
    param (
        [string]$InterfaceName,
        [string]$IPAddress,
        [string]$SubnetMask,
        [string]$Gateway,
        [string]$PrimaryDNS,
        [string]$SecondaryDNS
    )

    Write-Host "Setting static IP configuration..." -ForegroundColor Cyan

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

    # Set IP address, subnet mask, and gateway
    New-NetIPAddress -InterfaceAlias $InterfaceName -IPAddress $IPAddress -PrefixLength $prefixLength -DefaultGateway $Gateway -ErrorAction Stop

    # Set DNS servers
    Set-DnsClientServerAddress -InterfaceAlias $InterfaceName -ServerAddresses @($PrimaryDNS, $SecondaryDNS) -ErrorAction Stop

    Write-Host "Static IP configuration applied successfully." -ForegroundColor Green
}

# Function to set DHCP configuration
function Set-DHCP {
    param ([string]$InterfaceName)

    Write-Host "Switching to DHCP configuration..." -ForegroundColor Cyan

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
        }
    } catch {
        Write-Host "Error: Unable to apply DHCP configuration. Please check the interface name and network settings." -ForegroundColor Red
        Write-Host "Available interfaces:" -ForegroundColor Yellow
        Get-NetIPInterface | Select-Object -Property InterfaceAlias, AddressFamily, Dhcp
    }
}

# Function to show IP configuration
function Show-IPInfo {
    param ([string]$InterfaceName)

    Write-Host "Fetching current IP configuration..." -ForegroundColor Cyan

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

# Function to select network interface
function Select-NetworkInterface {
    $interfaces = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
    if ($interfaces.Count -eq 0) {
        Write-Host "No active network interfaces found." -ForegroundColor Red
        exit
    }

    Write-Host "Available Network Interfaces:" -ForegroundColor Cyan
    $interfaces | ForEach-Object { Write-Host "$($_.InterfaceIndex): $($_.Name)" }

    $selectedIndex = Read-Host "Enter the number corresponding to the desired interface"
    $selectedInterface = $interfaces | Where-Object { $_.InterfaceIndex -eq [int]$selectedIndex }

    if ($null -eq $selectedInterface) {
        Write-Host "Invalid selection. Exiting..." -ForegroundColor Red
        exit
    }

    Write-Host "Selected Interface: $($selectedInterface.Name)" -ForegroundColor Green
    return $selectedInterface.Name
}

# Main logic
$interfaceName = Select-NetworkInterface

while ($true) {
    Write-Host "Please select an option:" -ForegroundColor Yellow
    Write-Host "1. Set static IP configuration (use saved settings)"
    Write-Host "2. Set DHCP configuration"
    Write-Host "3. Show current IP configuration"
    Write-Host "4. Enter and save static IP configuration"
    Write-Host "5. Exit"

    $choice = Read-Host "Enter your choice"

    switch ($choice) {
        "1" {
            $config = Load-StaticIPConfig
            if ($config) {
                Set-StaticIP -InterfaceName $interfaceName `
                             -IPAddress $config.IPAddress `
                             -SubnetMask $config.SubnetMask `
                             -Gateway $config.Gateway `
                             -PrimaryDNS $config.PrimaryDNS `
                             -SecondaryDNS $config.SecondaryDNS
            } else {
                Write-Host "No saved configuration to apply." -ForegroundColor Red
            }
        }
        "2" {
            Set-DHCP -InterfaceName $interfaceName
        }
        "3" {
            Show-IPInfo -InterfaceName $interfaceName
        }
        "4" {
            Enter-StaticIPConfig
        }
        "5" {
            Write-Host "Exiting..." -ForegroundColor Cyan
            exit
        }
        default {
            Write-Host "Invalid choice. Please try again." -ForegroundColor Red
        }
    }
}
