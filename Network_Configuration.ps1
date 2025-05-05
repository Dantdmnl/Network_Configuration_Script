# Version: 1.8

# Check for elevation and re-run as administrator if needed
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Start-Process -FilePath "PowerShell" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Definition)`"" -Verb RunAs
    exit
}

# Define log settings with user-configurable directory
$Global:LogDirectory = if ($env:LOG_DIRECTORY) { $env:LOG_DIRECTORY } else { "$env:USERPROFILE\Logs" }
$Global:LogFileName = "network_config.log"
$Global:MaxLogSizeMB = 5      # Max log file size (MB) before rotation
$Global:MaxLogArchives = 5    # Number of rotated log files to keep
$Global:MinLogLevel = "INFO"  # Minimum log level to record (DEBUG, INFO, WARN, ERROR, CRITICAL)

# Ensure log directory exists
if (-not (Test-Path -Path $Global:LogDirectory)) {
    New-Item -ItemType Directory -Path $Global:LogDirectory -Force | Out-Null
}

$Global:LogFile = Join-Path -Path $Global:LogDirectory -ChildPath $Global:LogFileName

# Define log level priorities
$Global:LogLevels = @{
    "DEBUG"    = 1
    "INFO"     = 2
    "WARN"     = 3
    "ERROR"    = 4
    "CRITICAL" = 5
}

# Function to rotate logs
function Rotate-Logs {
    if (Test-Path -Path $Global:LogFile) {
        $fileSizeMB = (Get-Item $Global:LogFile).Length / 1MB
        if ($fileSizeMB -ge $Global:MaxLogSizeMB) {
            # Remove oldest log if it exceeds the max archives
            $oldestLog = "$Global:LogFile.$Global:MaxLogArchives.log"
            if (Test-Path -Path $oldestLog) {
                Remove-Item -Path $oldestLog -Force
            }

            # Shift logs down (newest first)
            for ($i = $Global:MaxLogArchives - 1; $i -ge 1; $i--) {
                $oldLog = "$Global:LogFile.$i.log"
                $newLog = "$Global:LogFile.$($i + 1).log"
                if (Test-Path -Path $oldLog) {
                    Rename-Item -Path $oldLog -NewName $newLog -Force
                }
            }

            # Rename current log to archive #1
            Rename-Item -Path $Global:LogFile -NewName "$Global:LogFile.1.log" -Force
        }
    }
}

# Function to log messages
function Log-Message {
    param (
        [string]$Message,
        [ValidateSet("DEBUG", "INFO", "WARN", "ERROR", "CRITICAL")]
        [string]$Level = "INFO"
    )

    # Skip logging if level is below the configured minimum
    if ($Global:LogLevels[$Level] -lt $Global:LogLevels[$Global:MinLogLevel]) { return }

    # Rotate logs if needed
    Rotate-Logs

    # Format log entry
    $logEntry = "{""timestamp"":""$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"", ""level"":""$Level"", ""message"":""$Message""}"
    
    # Write log entry to file
    $logEntry | Out-File -FilePath $Global:LogFile -Append -Encoding UTF8
}

Log-Message -Message "Script initialized." -Level "INFO"

# Function to open the log file
function Open-LogFile {
    if (Test-Path -Path $Global:LogFile) {
        Start-Process -FilePath "notepad.exe" -ArgumentList $Global:LogFile
    } else {
        Write-Host "Log file not found." -ForegroundColor Red
    }
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
    Log-Message -Message "Checking for script updates..." -Level "INFO"

    # Ensure the version file exists
    if (-not (Test-Path $versionFilePath)) {
        Write-Host "Version file not found. Creating a new one with version 0.0" -ForegroundColor Yellow
        Log-Message -Message "Version file not found. Creating a new one with version 0.0" -Level "WARN"
        Set-Content -Path $versionFilePath -Value "0.0"
    }

    $currentVersion = (Get-Content $versionFilePath).Trim()

    try {
        # Fetch the remote script content
        $RemoteScriptContent = Invoke-WebRequest -Uri $RemoteScriptURL -UseBasicParsing
        if (-not $RemoteScriptContent -or -not $RemoteScriptContent.Content) {
            Write-Host "Failed to fetch the remote script. Please check the URL." -ForegroundColor Red
            Log-Message -Message "Failed to fetch the remote script. Please check the URL." -Level "ERROR"
            return
        }

        # Extract the version line from the remote script
        $VersionLine = ($RemoteScriptContent.Content -split "`n" | Where-Object { $_ -match "# Version:" })[0]

        if ($VersionLine) {
            # Extract the version number using a strict regex
            $RemoteVersion = ($VersionLine -replace ".*# Version:\s*([0-9]+\.[0-9]+).*", '$1').Trim()

            # Validate the extracted version format
            if (-not $RemoteVersion -or $RemoteVersion -notmatch "^\d+\.\d+$") {
                Write-Host "Invalid version format in the remote script." -ForegroundColor Red
                Log-Message -Message "Invalid version format in the remote script. Version Line: $VersionLine" -Level "CRITICAL"
                return
            }
        } else {
            Write-Host "Could not find a valid version line in the remote script." -ForegroundColor Red
            Log-Message -Message "Could not find a valid version line in the remote script." -Level "ERROR"
            return
        }

        # Compare versions
        if ($RemoteVersion -ne $currentVersion) {
            Write-Host "An updated version of the script is available (Current: $currentVersion, Remote: $RemoteVersion)." -ForegroundColor Cyan
            Log-Message -Message "An updated version of the script is available (Current: $currentVersion, Remote: $RemoteVersion)." -Level "WARN"

            # Ask the user if they want to update
            $Response = Read-Host "Would you like to update to the latest version? (y/n)"
            if ($Response -eq 'y') {
                # Backup the current script
                $BackupPath = "$CurrentScriptPath.bak"
                Copy-Item -Path $CurrentScriptPath -Destination $BackupPath -Force
                Write-Host "A backup of the current script has been saved as $BackupPath." -ForegroundColor Yellow
                Log-Message -Message "A backup of the current script has been saved as $BackupPath." -Level "INFO"

                # Update the script
                $RemoteScriptContent.Content | Set-Content -Path $CurrentScriptPath -Force
                Set-Content -Path $versionFilePath -Value $RemoteVersion
                Write-Host "The script has been updated successfully to version $RemoteVersion. Rerun the script to apply the update." -ForegroundColor Green
                Log-Message -Message "The script has been updated successfully to version $RemoteVersion." -Level "INFO"
            } else {
                Write-Host "The script was not updated." -ForegroundColor Yellow
                Log-Message -Message "The script was not updated." -Level "WARN"
            }
        } else {
            Write-Host "The script is up-to-date (Version: $currentVersion)." -ForegroundColor Green
            Log-Message -Message "The script is up-to-date (Version: $currentVersion)." -Level "INFO"
        }
    } catch {
        Write-Host "An error occurred while checking for updates: $_" -ForegroundColor Red
        Log-Message -Message "An error occurred while checking for updates: $_" -Level "CRITICAL"
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

# Function to suggest a default gateway based on IP address
function Suggest-Gateway {
    param (
        [string]$IPAddress
    )

    $ipParts = $IPAddress -split '\.'
    if ($ipParts.Count -ne 4) {
        throw "Invalid IP address format."
    }

    # Suggest different gateways based on common network patterns
    switch ("$($ipParts[0]).$($ipParts[1])") {
        "192.168" {
            return "$($ipParts[0]).$($ipParts[1]).$($ipParts[2]).1"
        }
        "172.16" {
            return "$($ipParts[0]).$($ipParts[1]).$($ipParts[2]).254"
        }
        default {
            return "$($ipParts[0]).$($ipParts[1]).$($ipParts[2]).1"
        }
    }
}

# Define the path to save the configuration securely
$configPath = "$env:USERPROFILE\static_ip_config.xml"
$interfacePath = "$env:USERPROFILE\selected_interface.txt"

# Function to save selected interface
function Save-SelectedInterface {
    param ([string]$InterfaceName)
    Set-Content -Path $interfacePath -Value $InterfaceName
    Log-Message -Message "Selected interface saved: $InterfaceName" -Level "INFO"
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
        [string]$Gateway = $null,
        [string]$PrimaryDNS,
        [string]$SecondaryDNS = $null
    )

    $config = @{
        IPAddress   = $IPAddress
        SubnetMask  = $SubnetMask
        PrimaryDNS  = $PrimaryDNS
    }

    if ($Gateway) {
        $config["Gateway"] = $Gateway
    } else {
        Log-Message -Message "No Gateway specified. Skipping Gateway configuration." -Level "WARN"
        Write-Host "No Gateway specified. Skipping Gateway configuration." -ForegroundColor Yellow
    }

    if ($SecondaryDNS) {
        $config["SecondaryDNS"] = $SecondaryDNS
    }

    $config | Export-Clixml -Path $configPath

    Log-Message -Message "Static IP configuration saved." -Level "INFO"
    Write-Host "Static IP configuration saved." -ForegroundColor Green
}

# Function to load static IP configuration
function Load-StaticIPConfig {
    if (Test-Path $configPath) {
        $config = Import-Clixml -Path $configPath

        return @{
            IPAddress     = $config.IPAddress
            SubnetMask    = $config.SubnetMask
            Gateway       = $config.Gateway       # May be $null
            PrimaryDNS    = $config.PrimaryDNS
            SecondaryDNS  = $config.SecondaryDNS  # May be $null
        }
    } else {
        Write-Host "No saved configuration found." -ForegroundColor Yellow
        Log-Message -Message "No saved configuration found." -Level "WARN"
        return $null
    }
}

# Prompts user for IP settings; used by options 1 (set) and 4 (save)
function Prompt-ForIPSettings {
    param (
        [string]$InterfaceName
    )

    $IPAddress = Read-Host "Enter IP Address (e.g., 192.168.1.25)"
    $SubnetMask = Read-Host "Enter Subnet Mask (e.g., 255.255.255.0 or 24)"

    $suggestedGateway = Suggest-Gateway -IPAddress $IPAddress
    $GatewayInput = Read-Host "Enter Gateway [`Enter` to use suggested: $suggestedGateway, type 'none' to skip]"

    switch ($GatewayInput.ToLower()) {
        ""     { $Gateway = $suggestedGateway }
        "none" { $Gateway = $null }
        default { $Gateway = $GatewayInput }
    }

    $PrimaryDNS = Read-Host "Enter Primary DNS (default: 1.1.1.1)"
    if (-not $PrimaryDNS) {
        $PrimaryDNS = "1.1.1.1"
    }

    $suggestedSecondary = "1.0.0.1"
    $SecondaryDNSInput = Read-Host "Enter Secondary DNS [`Enter` to use suggested: $suggestedSecondary, type 'none' to skip]"

    switch ($SecondaryDNSInput.ToLower()) {
        ""     { $SecondaryDNS = $suggestedSecondary }
        "none" { $SecondaryDNS = $null }
        default { $SecondaryDNS = $SecondaryDNSInput }
    }

    return @{
        IPAddress     = $IPAddress
        SubnetMask    = $SubnetMask
        Gateway       = $Gateway
        PrimaryDNS    = $PrimaryDNS
        SecondaryDNS  = $SecondaryDNS
    }
}

# Function to set static IP
function Set-StaticIP {
    param (
        [string]$InterfaceName,
        [string]$IPAddress,
        [string]$SubnetMask,
        [string]$Gateway = $null,
        [string]$PrimaryDNS,
        [string]$SecondaryDNS = $null
    )

    Write-Host "Setting static IP configuration..." -ForegroundColor Cyan
    Log-Message -Message "Setting static IP configuration for interface: $InterfaceName" -Level "INFO"

    try {
        # Verify interface exists
        $adapter = Get-NetAdapter -Name $InterfaceName -ErrorAction Stop

        # Convert subnet mask to prefix length
        $prefixLength = Get-PrefixLength -SubnetInput $SubnetMask

        # Remove existing IPv4 addresses
        $existingIPv4 = Get-NetIPAddress -InterfaceAlias $InterfaceName -AddressFamily IPv4 -ErrorAction SilentlyContinue
        if ($existingIPv4) {
            $existingIPv4 | Remove-NetIPAddress -Confirm:$false -ErrorAction Stop
        }

        # Remove existing default route
        $existingRoute = Get-NetRoute -InterfaceAlias $InterfaceName -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue
        if ($existingRoute) {
            $existingRoute | Remove-NetRoute -Confirm:$false -ErrorAction Stop
        }

        # Prepare new static IP parameters
        $params = @{
            InterfaceAlias = $InterfaceName
            IPAddress      = $IPAddress
            PrefixLength   = $prefixLength
        }
        if ($Gateway) {
            $params["DefaultGateway"] = $Gateway
        } else {
            Write-Host "No Gateway specified. Skipping Default Gateway configuration." -ForegroundColor Yellow
            Log-Message -Message "No Gateway specified. Skipping Default Gateway configuration." -Level "WARN"
        }

        # Apply new static IP
        New-NetIPAddress @params -ErrorAction Stop > $null

        # Prepare DNS list
        $dnsServers = @()
        if ($PrimaryDNS) { $dnsServers += $PrimaryDNS }
        if ($SecondaryDNS) { $dnsServers += $SecondaryDNS }

        if ($dnsServers.Count -gt 0) {
            Set-DnsClientServerAddress -InterfaceAlias $InterfaceName -ServerAddresses $dnsServers -ErrorAction Stop
        } else {
            Write-Host "No DNS servers specified. Skipping DNS configuration." -ForegroundColor Yellow
            Log-Message -Message "No DNS servers specified. Skipping DNS configuration." -Level "WARN"
        }

        # Show summary
        $ipConfig = Get-NetIPConfiguration -InterfaceAlias $InterfaceName -ErrorAction Stop
        Write-Host "Static IP configuration applied successfully." -ForegroundColor Green
        Write-Host "IP Address:   $($ipConfig.IPv4Address.IPAddress)" -ForegroundColor Cyan
        Write-Host "Subnet Mask:  /$($ipConfig.IPv4Address.PrefixLength)" -ForegroundColor Cyan
        Write-Host "Default GW:   $($ipConfig.IPv4DefaultGateway.NextHop)" -ForegroundColor Cyan
        Write-Host "DNS Servers:  $($ipConfig.DnsServer.ServerAddresses -join ', ')" -ForegroundColor Cyan
        Log-Message -Message "Static IP configuration applied successfully." -Level "INFO"
    } catch {
        $errorMessage = "Error: Unable to set static IP configuration. $_"
        Write-Host $errorMessage -ForegroundColor Red
        Log-Message -Message $errorMessage -Level "CRITICAL"
    }
}

# Function to set DHCP configuration
function Set-DHCP {
    param ([string]$InterfaceName = $Global:SelectedInterfaceAlias)

    Write-Host "Switching to DHCP configuration..." -ForegroundColor Cyan
    Log-Message -Message "Switching to DHCP for interface: $InterfaceName" -Level "INFO"

    try {
        # Validate the interface
        $interface = Get-NetIPInterface -InterfaceAlias $InterfaceName -ErrorAction Stop

        Write-Host "Releasing IP address..." -ForegroundColor Yellow
        Remove-NetIPAddress -InterfaceAlias $InterfaceName -Confirm:$false -ErrorAction Stop

        Write-Host "Flushing DNS cache..." -ForegroundColor Yellow
        Clear-DnsClientCache -ErrorAction Stop

        Write-Host "Enabling DHCP..." -ForegroundColor Yellow
        Set-NetIPInterface -InterfaceAlias $InterfaceName -Dhcp Enabled -ErrorAction Stop
        Set-DnsClientServerAddress -InterfaceAlias $InterfaceName -ResetServerAddresses -ErrorAction Stop

        Write-Host "Renewing DHCP lease..." -ForegroundColor Yellow
        ipconfig /release "$InterfaceName" > $null 2>&1
        ipconfig /renew "$InterfaceName" > $null 2>&1

        Start-Sleep -Seconds 5

        $ipConfig = Get-NetIPConfiguration -InterfaceAlias $InterfaceName

        if ($ipConfig.IPv4Address.IPAddress -like "169.254.*") {
            Write-Host "Warning: Still assigned an APIPA address. Possible network issue." -ForegroundColor Red
            Write-Host "Trying dynamic ping test..." -ForegroundColor Cyan
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
            Log-Message -Message "DHCP configuration applied successfully for $InterfaceName." -Level "INFO"
        }

    } catch {
        $errorMessage = "Error applying DHCP configuration to ${InterfaceName}: $_"
        Write-Host $errorMessage -ForegroundColor Red
        Log-Message -Message $errorMessage -Level "ERROR"
        Write-Host "Available interfaces:" -ForegroundColor Yellow
        Get-NetIPInterface | Select-Object InterfaceAlias, AddressFamily, Dhcp
    }
}

# Function to test network connectivity using a specific interface
function Test-NetworkConnectivity {
    Write-Host "Performing network connectivity test on interface: $InterfaceName" -ForegroundColor Cyan
    Log-Message -Message "Starting network connectivity test for interface: $InterfaceName" -Level "INFO"

    # Ensure an interface is loaded
    if (-not $InterfaceName) {
        Write-Host "ERROR: No network interface is currently loaded." -ForegroundColor Red
        Log-Message -Message "Error: No network interface is currently loaded." -Level "CRITICAL"
        return
    }

    # Fetch IP configuration safely
    $ipConfig = Get-NetIPConfiguration -InterfaceAlias $InterfaceName -ErrorAction SilentlyContinue
    if (-not $ipConfig) {
        Write-Host "ERROR: No network configuration found for interface: $InterfaceName" -ForegroundColor Red
        Log-Message -Message "No network configuration found for interface: $InterfaceName" -Level "ERROR"
        return
    }

    # Get the IPv4 address of the selected interface
    $sourceIP = $ipConfig.IPv4Address.IPAddress
    if (-not $sourceIP) {
        Write-Host "ERROR: No IPv4 address found for interface: $InterfaceName" -ForegroundColor Red
        Log-Message -Message "Error: No IPv4 address found for interface: $InterfaceName" -Level "ERROR"
        return
    }

    # Separate gateway ping
    $gateway = @{ Name = "Default Gateway"; IP = $ipConfig.IPv4DefaultGateway.NextHop }

    # Test the gateway connection
    if ($gateway.IP) {
        Write-Host "Pinging $($gateway.Name): $($gateway.IP) using interface IP $sourceIP..." -ForegroundColor Yellow
        Log-Message "Pinging $($gateway.Name): $($gateway.IP) using interface IP $sourceIP"

        # Ping the gateway with the specified source IP
        $pingResult = Test-Connection -ComputerName $gateway.IP -Count 4 -Source $sourceIP -ErrorAction SilentlyContinue

        if ($pingResult) {
            $avgMs = ($pingResult | Measure-Object -Property ResponseTime -Average).Average
            Write-Host "SUCCESS: $($gateway.Name) ($($gateway.IP)) is reachable. Avg Response Time: $avgMs ms" -ForegroundColor Green
            Log-Message -Message "$($gateway.Name) ($($gateway.IP)) is reachable. Avg Response Time: $avgMs ms" -Level "INFO"
        } else {
            Write-Host "FAILURE: Cannot reach $($gateway.Name) ($($gateway.IP))" -ForegroundColor Red
            Log-Message -Message "Failed to reach $($gateway.Name) ($($gateway.IP))" -Level "ERROR"
        }
    }


    Write-Host "Running ping tests using interface IP: $sourceIP..." -ForegroundColor Yellow
    Log-Message -Message "Running ping tests using interface IP: $sourceIP" -Level "INFO"

    # Define test targets with descriptions
    $testTargets = @(
        @{ Name = "Cloudflare DNS"; IP = "1.1.1.1" },
        @{ Name = "Cloudflare Secondary DNS"; IP = "1.0.0.1" },
        @{ Name = "Google DNS"; IP = "8.8.8.8" },
        @{ Name = "Google Secondary DNS"; IP = "8.8.4.4" },
        @{ Name = "Quad9 DNS"; IP = "9.9.9.9" },
        @{ Name = "OpenDNS"; IP = "208.67.222.222" }
    )

    # Add local DNS servers if available
    if ($ipConfig.DnsServer -and $ipConfig.DnsServer.ServerAddresses) {
        foreach ($dns in $ipConfig.DnsServer.ServerAddresses) {
            $testTargets += @{ Name = "Local DNS Server"; IP = $dns }
        }
    }

    # Run parallel ping tests
    $jobs = @()
    foreach ($target in $testTargets) {
        if ($target.IP) {
            $jobs += Start-Job -ScriptBlock {
                param ($target, $sourceIP)
                $pingResult = Test-Connection -ComputerName $target.IP -Count 4 -ErrorAction SilentlyContinue
                if ($pingResult) {
                    $avgMs = ($pingResult | Measure-Object -Property ResponseTime -Average).Average
                    Write-Host "SUCCESS: $($target.Name) ($($target.IP)) is reachable. Avg Response Time: $avgMs ms" -ForegroundColor Green
                } else {
                    Write-Host "FAILURE: Cannot reach $($target.Name) ($($target.IP)) from $sourceIP." -ForegroundColor Red
                }
            } -ArgumentList $target, $sourceIP
        }
    }

    # Wait for all jobs to finish and output results
    foreach ($job in $jobs) {
        $result = Receive-Job -Job $job -Wait
        if ($result) { Write-Host $result }
        Remove-Job -Job $job
    }

    # Define domains to resolve
    $domains = @("google.com", "cloudflare.com", "microsoft.com")

    # Initialize a collection to store results
    $results = @()

    # Testing DNS resolution dynamically
    foreach ($domain in $domains) {
        $resolvedIps = @()  # Store resolved IPs for the current domain
        foreach ($target in $testTargets) {
            # Resolve the domain using the DNS server
            try {
                $dnsResults = Resolve-DnsName -Name $domain -Server $target.DnsServer -ErrorAction Stop | Select-Object -ExpandProperty IPAddress
                if ($dnsResults) {
                    $resolvedIps += $dnsResults
                }
            } catch {
                Write-Host "Failed to resolve $domain via $($target.DnsServer)" -ForegroundColor Red
            }
        }

        if ($resolvedIps.Count -gt 0) {
            # Remove duplicate IPs
            $uniqueIps = $resolvedIps | Sort-Object -Unique
            $ips = $uniqueIps -join ", "
            # Add the result for this domain to the output collection
            $results += [PSCustomObject]@{
                Domain    = $domain
                ResolvedIps = $ips
            }
        } else {
            # No IPs resolved, add a result for the domain
            $results += [PSCustomObject]@{
                Domain    = $domain
                ResolvedIps = "No resolution found"
            }
        }
    }

    # Output the results in a clean format
    foreach ($result in $results) {
        Write-Host "DNS resolution successful for: $($result.Domain)"
        Write-Host "Resolved IP(s): $($result.ResolvedIps)" -ForegroundColor Cyan
        Write-Host ""  # Add an empty line for better separation
    }
    Write-Host "Network test completed on interface: $InterfaceName" -ForegroundColor Cyan
    Log-Message -Message "Network connectivity test completed on interface: $InterfaceName" -Level "INFO"
}

# Function to show IP configuration
function Show-IPInfo {
    param ([string]$InterfaceName = $Global:SelectedInterfaceAlias)

    if (-not $InterfaceName) {
        Write-Host "No network interface selected. Please choose one using option 6." -ForegroundColor Red
        return
    }

    try {
        $config = Get-NetIPConfiguration -InterfaceAlias $InterfaceName -ErrorAction Stop
        $ipv4 = $config.IPv4Address
        $gateway = $config.IPv4DefaultGateway
        $dns = $config.DnsServer.ServerAddresses

        Write-Host "Current IP configuration for interface: $InterfaceName" -ForegroundColor Cyan
        Write-Host "IP Address: $($ipv4.IPAddress)" -ForegroundColor White
        Write-Host "Subnet Mask: /$($ipv4.PrefixLength)" -ForegroundColor White
        if ($gateway) {
            Write-Host "Default Gateway: $($gateway.NextHop)" -ForegroundColor White
        } else {
            Write-Host "Default Gateway: (not set)" -ForegroundColor DarkYellow
        }
        Write-Host "DNS Servers: $($dns -join ', ')" -ForegroundColor White

    } catch {
        Write-Host "Error retrieving IP configuration: $_" -ForegroundColor Red
        Log-Message -Message "Error retrieving IP configuration for ${InterfaceName}: $_" -Level "ERROR"
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
    Write-Host "8. Test Network Connectivity"
    Write-Host "9. Check for updates"
    Write-Host "0. Exit"

    $choice = Read-Host "Enter your choice"

    switch ($choice) {
        "1" {
            $settings = Prompt-ForIPSettings
            Set-StaticIP -InterfaceName $interfaceName `
                        -IPAddress $settings.IPAddress `
                        -SubnetMask $settings.SubnetMask `
                        -Gateway $settings.Gateway `
                        -PrimaryDNS $settings.PrimaryDNS `
                        -SecondaryDNS $settings.SecondaryDNS
        }
        "2" {
            Set-DHCP -InterfaceName $interfaceName
        }
        "3" {
            Show-IPInfo -InterfaceName $interfaceName
        }
        "4" {
                $settings = Prompt-ForIPSettings
                Save-StaticIPConfig -IPAddress $settings.IPAddress `
                                    -SubnetMask $settings.SubnetMask `
                                    -Gateway $settings.Gateway `
                                    -PrimaryDNS $settings.PrimaryDNS `
                                    -SecondaryDNS $settings.SecondaryDNS
        }
        "5" {
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
            $interfaceName = Select-NetworkInterface
            if ($interfaceName) {
                $host.UI.RawUI.WindowTitle = "Network Configuration - $interfaceName"
            }
        }
        "7" {
            Open-LogFile
        }
        "8" {
            Test-NetworkConnectivity
        }
        "9" {
            Update-Script
        }
        "0" {
            Write-Host "Exiting..." -ForegroundColor Cyan
            Log-Message "Script exited by user."
            exit
        }
        default {
            Write-Host "Invalid choice. Please try again." -ForegroundColor Red
        }
    }
}