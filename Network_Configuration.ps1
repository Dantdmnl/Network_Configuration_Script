# Version: 1.9


#region File Path Migration (deduplicated)
$script:AppDataDir = Join-Path $env:APPDATA 'Network_Configuration_Script'
if (-not (Test-Path $script:AppDataDir)) {
    New-Item -Path $script:AppDataDir -ItemType Directory | Out-Null
}
$script:ConfigFile = 'IPConfiguration.xml'
$script:LogFileName = 'network_config.log'
$script:VersionFile = 'version.txt'
$script:InterfaceFile = 'selected_interface.txt'
$script:ConfigPath = Join-Path $script:AppDataDir $script:ConfigFile
$script:LogPath = Join-Path $script:AppDataDir $script:LogFileName
$script:VersionPath = Join-Path $script:AppDataDir $script:VersionFile
$script:InterfacePath = Join-Path $script:AppDataDir $script:InterfaceFile
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
foreach ($file in @($script:ConfigFile, $script:LogFileName, $script:VersionFile, $script:InterfaceFile)) {
    $oldScriptPath = Join-Path $scriptDir $file
    $oldUserProfilePath = Join-Path $env:USERPROFILE $file
    $newPath = Join-Path $script:AppDataDir $file
    if ((Test-Path $oldScriptPath) -and -not (Test-Path $newPath)) {
        Move-Item -Path $oldScriptPath -Destination $newPath
    }
    if ((Test-Path $oldUserProfilePath) -and -not (Test-Path $newPath)) {
        Move-Item -Path $oldUserProfilePath -Destination $newPath
    }
}
#endregion

# Check for elevation and re-run as administrator if needed
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Start-Process -FilePath "PowerShell" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Definition)`"" -Verb RunAs
    exit
}


#region Logging Settings
$script:MaxLogSizeMB = 5      # Max log file size (MB) before rotation
$script:MaxLogArchives = 5    # Number of rotated log files to keep
$script:MinLogLevel = "INFO"  # Minimum log level to record
$script:LogFile = $script:LogPath
$script:LogLevels = @{
    "DEBUG"    = 1
    "INFO"     = 2
    "WARN"     = 3
    "ERROR"    = 4
    "CRITICAL" = 5
}
#endregion

# Function to rotate logs

#region Logging Functions
function Invoke-LogRotation {
    if (Test-Path -Path $script:LogFile) {
        $fileSizeMB = (Get-Item $script:LogFile).Length / 1MB
        if ($fileSizeMB -ge $script:MaxLogSizeMB) {
            $oldestLog = "$script:LogFile.$script:MaxLogArchives.log"
            if (Test-Path -Path $oldestLog) {
                Remove-Item -Path $oldestLog -Force
            }
            for ($i = $script:MaxLogArchives - 1; $i -ge 1; $i--) {
                $oldLog = "$script:LogFile.$i.log"
                $newLog = "$script:LogFile.$($i + 1).log"
                if (Test-Path -Path $oldLog) {
                    Rename-Item -Path $oldLog -NewName $newLog -Force
                }
            }
            Rename-Item -Path $script:LogFile -NewName "$script:LogFile.1.log" -Force
        }
    }
}

# Function to log messages

function Write-LogMessage {
    param (
        [string]$Message,
        [ValidateSet("DEBUG", "INFO", "WARN", "ERROR", "CRITICAL")]
        [string]$Level = "INFO"
    )
    if ($script:LogLevels[$Level] -lt $script:LogLevels[$script:MinLogLevel]) { return }
    Invoke-LogRotation
    $logEntry = "{""timestamp"": ""$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"", ""level"": ""$Level"", ""message"": ""$Message""}"
    $logEntry | Out-File -FilePath $script:LogFile -Append -Encoding UTF8
}
#endregion

Write-LogMessage -Message "Script initialized." -Level "INFO"


# Extract version dynamically from the script header
$script:ScriptVersion = "Unknown"
try {
    $scriptContent = Get-Content -Path $MyInvocation.MyCommand.Path -TotalCount 5
    $versionLine = $scriptContent | Where-Object { $_ -match "^# Version:" } | Select-Object -First 1
    if ($versionLine) {
        $script:ScriptVersion = ($versionLine -replace "^# Version:\s*", "").Trim()
    }
} catch {
    # Keep default if extraction fails
}

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
    $versionFilePath = $global:VersionPath

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
    Write-LogMessage -Message "Checking for script updates..." -Level "INFO"

    # Ensure the version file exists
    if (-not (Test-Path $versionFilePath)) {
        Write-Host "Version file not found. Creating a new one with version 0.0" -ForegroundColor Yellow
        Write-LogMessage -Message "Version file not found. Creating a new one with version 0.0" -Level "WARN"
        Set-Content -Path $versionFilePath -Value "0.0"
    }

    $currentVersion = (Get-Content $versionFilePath).Trim()

    try {
        # Fetch the remote script content
        $RemoteScriptContent = Invoke-WebRequest -Uri $RemoteScriptURL -UseBasicParsing
        if (-not $RemoteScriptContent -or -not $RemoteScriptContent.Content) {
            Write-Host "Failed to fetch the remote script. Please check the URL." -ForegroundColor Red
            Write-LogMessage -Message "Failed to fetch the remote script. Please check the URL." -Level "ERROR"
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
                Write-LogMessage -Message "Invalid version format in the remote script. Version Line: $VersionLine" -Level "CRITICAL"
                return
            }
        } else {
            Write-Host "Could not find a valid version line in the remote script." -ForegroundColor Red
            Write-LogMessage -Message "Could not find a valid version line in the remote script." -Level "ERROR"
            return
        }

        # Compare versions
        if ($RemoteVersion -ne $currentVersion) {
            Write-Host "An updated version of the script is available (Current: $currentVersion, Remote: $RemoteVersion)." -ForegroundColor Cyan
            Write-LogMessage -Message "An updated version of the script is available (Current: $currentVersion, Remote: $RemoteVersion)." -Level "WARN"

            # Ask the user if they want to update
            $Response = Read-Host "Would you like to update to the latest version? (y/n)"
            if ($Response -eq 'y') {
                # Backup the current script
                $BackupPath = "$CurrentScriptPath.bak"
                Copy-Item -Path $CurrentScriptPath -Destination $BackupPath -Force
                Write-Host "A backup of the current script has been saved as $BackupPath." -ForegroundColor Yellow
                Write-LogMessage -Message "A backup of the current script has been saved as $BackupPath." -Level "INFO"

                # Update the script
                $RemoteScriptContent.Content | Set-Content -Path $CurrentScriptPath -Force
                Set-Content -Path $versionFilePath -Value $RemoteVersion
                Write-Host "The script has been updated successfully to version $RemoteVersion. Rerun the script to apply the update." -ForegroundColor Green
                Write-LogMessage -Message "The script has been updated successfully to version $RemoteVersion." -Level "INFO"
            } else {
                Write-Host "The script was not updated." -ForegroundColor Yellow
                Write-LogMessage -Message "The script was not updated." -Level "WARN"
            }
        } else {
            Write-Host "The script is up-to-date (Version: $currentVersion)." -ForegroundColor Green
            Write-LogMessage -Message "The script is up-to-date (Version: $currentVersion)." -Level "INFO"
        }
    } catch {
        Write-Host "An error occurred while checking for updates: $_" -ForegroundColor Red
        Write-LogMessage -Message "An error occurred while checking for updates: $_" -Level "CRITICAL"
    }
}

# Input validation functions for enhanced robustness
function Test-ValidIPAddress {
    param ([string]$IPAddress)
    
    if ([string]::IsNullOrWhiteSpace($IPAddress)) { return $false }
    
    try {
        $ip = [System.Net.IPAddress]::Parse($IPAddress)
        # Check if it's IPv4 and not in reserved ranges
        if ($ip.AddressFamily -eq 'InterNetwork') {
            $bytes = $ip.GetAddressBytes()
            # Exclude invalid ranges: 0.x.x.x, 127.x.x.x, 224-255.x.x.x
            if ($bytes[0] -eq 0 -or $bytes[0] -eq 127 -or $bytes[0] -ge 224) {
                return $false
            }
            return $true
        }
        return $false
    } catch {
        return $false
    }
}

function Test-ValidSubnetMask {
    param ([string]$SubnetInput)
    
    if ([string]::IsNullOrWhiteSpace($SubnetInput)) { return $false }
    
    # Check if it's a prefix length (8-30 or /8-/30)
    if ($SubnetInput -match "^/?([8-9]|[12][0-9]|30)$") {
        return $true
    }
    
    # Check if it's a valid subnet mask notation
    if ($SubnetInput -match "^\d+(\.\d+){3}$") {
        try {
            $mask = [System.Net.IPAddress]::Parse($SubnetInput)
            # Get mask bytes for validation
            $null = $mask.GetAddressBytes()
            
            # Convert to binary and check if it's a valid subnet mask
            $binaryMask = [Convert]::ToString($mask.Address, 2).PadLeft(32, '0')
            
            # Valid subnet mask should have consecutive 1s followed by consecutive 0s
            if ($binaryMask -match "^1*0*$" -and $binaryMask -ne "00000000000000000000000000000000") {
                return $true
            }
        } catch {
            return $false
        }
    }
    
    return $false
}

function Test-ValidInterfaceName {
    param ([string]$InterfaceName)
    
    if ([string]::IsNullOrWhiteSpace($InterfaceName)) { return $false }
    
    try {
        $null = Get-NetAdapter -Name $InterfaceName -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

function Test-ValidDNSServer {
    param ([string]$DNSServer)

    if ([string]::IsNullOrWhiteSpace($DNSServer)) { return $false }

    # Only accept full IPv4 addresses (four octets, each 0-255)
    if ($DNSServer -match "^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$") {
        $octets = $DNSServer -split '\.'
        foreach ($octet in $octets) {
            if ([int]$octet -lt 0 -or [int]$octet -gt 255) { return $false }
        }
        return Test-ValidIPAddress -IPAddress $DNSServer
    }

    # Accept valid hostname/FQDN (must contain at least one dot, not just digits and dots)
    if ($DNSServer -match "^(?=.{1,253}$)(?![0-9.]+$)[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$") {
        return $true
    }

    return $false
}

function Get-ValidatedInput {
    param (
        [string]$Prompt,
        [scriptblock]$ValidationFunction,
        [string]$ErrorMessage = "Invalid input. Please try again.",
        [int]$MaxAttempts = 3,
        [string]$DefaultValue = $null
    )
    
    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        if ($DefaultValue) {
            $userInput = Read-Host "$Prompt (default: $DefaultValue)"
            if ([string]::IsNullOrWhiteSpace($userInput)) { 
                $userInput = $DefaultValue 
            }
        } else {
            $userInput = Read-Host $Prompt
        }
        
        if (& $ValidationFunction $userInput) {
            return $userInput
        } else {
            Write-Host $ErrorMessage -ForegroundColor Red
            if ($attempt -eq $MaxAttempts) {
                throw "Maximum validation attempts exceeded for input: $Prompt"
            }
        }
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
function Get-SuggestedGateway {
    param (
        [string]$IPAddress
    )

    $ipParts = $IPAddress -split '\.'
    if ($ipParts.Count -ne 4) {
        throw "Invalid IP address format."
    }

    $base = "$($ipParts[0]).$($ipParts[1]).$($ipParts[2])"
    $gw1 = "$base.1"
    $gw254 = "$base.254"
    return @($gw1, $gw254)
}



#region Config Paths
$configPath = $script:ConfigPath
$interfacePath = $script:InterfacePath
#endregion

# Function to save selected interface
function Save-SelectedInterface {
    param ([string]$InterfaceName)
    Set-Content -Path $interfacePath -Value $InterfaceName
    Write-LogMessage -Message "Selected interface saved: $InterfaceName" -Level "INFO"
}

# Function to load selected interface
function Get-SavedInterface {
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
        Write-LogMessage -Message "No Gateway specified. Skipping Gateway configuration." -Level "WARN"
        Write-Host "No Gateway specified. Skipping Gateway configuration." -ForegroundColor Yellow
    }

    if ($SecondaryDNS) {
        $config["SecondaryDNS"] = $SecondaryDNS
    }

    $config | Export-Clixml -Path $configPath

    Write-LogMessage -Message "Static IP configuration saved." -Level "INFO"
    Write-Host "Static IP configuration saved." -ForegroundColor Green
}

# Function to load static IP configuration
function Get-SavedIPConfig {
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
        Write-LogMessage -Message "No saved configuration found." -Level "WARN"
        return $null
    }
}

# Prompts user for IP settings with enhanced validation; used by options 1 (set) and 4 (save)
function Read-IPConfigurationSettings {
    param (
        [string]$InterfaceName
    )


    if ([string]::IsNullOrWhiteSpace($InterfaceName)) {
        Write-Host "No valid network interface selected. Please choose one using option 6 before configuring IP settings." -ForegroundColor Red
        Write-LogMessage -Message "Attempted IP configuration with no valid interface." -Level "ERROR"
        return $null
    }

    Write-Host "Configuring IP settings for interface: $InterfaceName" -ForegroundColor Cyan
    Write-LogMessage -Message "Starting IP configuration prompts for interface: $InterfaceName" -Level "INFO"

    try {
        # Get and validate IP Address
            try {
                $IPAddress = Get-ValidatedInput -Prompt "Enter IP Address (e.g., 192.168.1.25)" `
                                               -ValidationFunction { param($ip) Test-ValidIPAddress -IPAddress $ip } `
                                               -ErrorMessage "Invalid IP address. Please enter a valid IPv4 address (e.g., 192.168.1.25)."
            } catch {
                Write-Host "Static IP configuration cancelled: Invalid IP address entered after all attempts." -ForegroundColor Yellow
                Write-LogMessage -Message "Static IP configuration cancelled: Invalid IP address entered after all attempts." -Level "WARN"
                return $null
            }

        # Get and validate Subnet Mask
        $SubnetMask = Get-ValidatedInput -Prompt "Enter Subnet Mask (e.g., 255.255.255.0 or 24)" `
                                        -ValidationFunction { param($mask) Test-ValidSubnetMask -SubnetInput $mask } `
                                        -ErrorMessage "Invalid subnet mask. Please enter a valid subnet mask (e.g., 255.255.255.0) or prefix length (e.g., 24)."

        # Suggest and validate Gateway
        $suggestedGateways = Get-SuggestedGateway -IPAddress $IPAddress
        Write-Host "Suggested Gateways: $($suggestedGateways -join ', ')" -ForegroundColor Yellow

        $base = ($IPAddress -split '\.')[0..2] -join '.'
        $GatewayInput = Read-Host "Enter Gateway [Enter=.1, 254=.254, or last octet, full IP, 'none' to skip]"

        $Gateway = $null
        $inputTrim = $GatewayInput.Trim()
        switch ($inputTrim.ToLower()) {
            "" {
                $Gateway = "$base.1"
                Write-LogMessage -Message "Using suggested gateway: $Gateway" -Level "INFO"
            }
            "none" {
                $Gateway = $null
                Write-LogMessage -Message "User chose to skip gateway configuration." -Level "INFO"
            }
            default {
                if ($inputTrim -match "^\d{1,3}$" -and [int]$inputTrim -ge 0 -and [int]$inputTrim -le 255) {
                    $Gateway = "$base.$inputTrim"
                    Write-LogMessage -Message "User provided gateway last octet: $GatewayInput, resolved to $Gateway" -Level "INFO"
                } elseif (Test-ValidIPAddress -IPAddress $inputTrim) {
                    $Gateway = $inputTrim
                    Write-LogMessage -Message "User provided full gateway IP: $GatewayInput" -Level "INFO"
                } elseif ($inputTrim -eq ".254") {
                    $Gateway = "$base.254"
                    Write-LogMessage -Message "User selected .254 gateway: $Gateway" -Level "INFO"
                } else {
                    Write-Host "Invalid gateway input. Skipping gateway configuration." -ForegroundColor Yellow
                    $Gateway = $null
                    Write-LogMessage -Message "Invalid gateway provided by user: $GatewayInput. Skipping gateway." -Level "WARN"
                }
            }
        }

        # Get and validate Primary DNS


        $PrimaryDNS = $null
        for ($attempt = 1; $attempt -le 3; $attempt++) {
            $PrimaryDNSInput = Read-Host "Enter Primary DNS (default: 1.1.1.1)"
            if ([string]::IsNullOrWhiteSpace($PrimaryDNSInput)) {
                $PrimaryDNSInput = "1.1.1.1"
            }
            if (Test-ValidDNSServer -DNSServer $PrimaryDNSInput) {
                $PrimaryDNS = $PrimaryDNSInput
                Write-LogMessage -Message "User provided primary DNS: $PrimaryDNSInput" -Level "INFO"
                break
            } else {
                Write-Host "Invalid DNS server. Please enter a valid IP address or hostname." -ForegroundColor Red
                Write-LogMessage -Message "Invalid primary DNS provided by user: $PrimaryDNSInput. Re-prompting." -Level "WARN"
                if ($attempt -eq 3) {
                    Write-Host "Maximum attempts reached. Using default primary DNS: 1.1.1.1" -ForegroundColor Yellow
                    $PrimaryDNS = "1.1.1.1"
                    Write-LogMessage -Message "Maximum attempts reached for primary DNS. Using default." -Level "WARN"
                    break
                }
            }
        }

            # Get and validate Secondary DNS (optional)
            $suggestedSecondary = "1.0.0.1"
            $SecondaryDNS = $null
            for ($attempt = 1; $attempt -le 3; $attempt++) {
                $SecondaryDNSInput = Read-Host "Enter Secondary DNS [Enter to use suggested: $suggestedSecondary, type 'none' to skip]"
                $inputTrim = $SecondaryDNSInput.ToLower().Trim()
                if ($inputTrim -eq "") {
                    $SecondaryDNS = $suggestedSecondary
                    Write-LogMessage -Message "Using suggested secondary DNS: $suggestedSecondary" -Level "INFO"
                    break
                } elseif ($inputTrim -eq "none") {
                    $SecondaryDNS = $null
                    Write-LogMessage -Message "User chose to skip secondary DNS configuration." -Level "INFO"
                    break
                } elseif (Test-ValidDNSServer -DNSServer $SecondaryDNSInput) {
                    $SecondaryDNS = $SecondaryDNSInput
                    Write-LogMessage -Message "User provided secondary DNS: $SecondaryDNSInput" -Level "INFO"
                    break
                } else {
                    Write-Host "Invalid secondary DNS server. Please enter a valid IP address or hostname." -ForegroundColor Red
                    Write-LogMessage -Message "Invalid secondary DNS provided by user: $SecondaryDNSInput. Re-prompting." -Level "WARN"
                    if ($attempt -eq 3) {
                        Write-Host "Maximum attempts reached. Skipping secondary DNS configuration." -ForegroundColor Yellow
                        $SecondaryDNS = $null
                        Write-LogMessage -Message "Maximum attempts reached for secondary DNS. Skipping." -Level "WARN"
                        break
                    }
                }
            }

        # Display configuration summary for confirmation
        Write-Host "`nConfiguration Summary:" -ForegroundColor Green
        Write-Host "IP Address: $IPAddress" -ForegroundColor White
        Write-Host "Subnet Mask: $SubnetMask" -ForegroundColor White
        Write-Host "Gateway: $(if($Gateway) { $Gateway } else { '(none)' })" -ForegroundColor White
        Write-Host "Primary DNS: $PrimaryDNS" -ForegroundColor White
        Write-Host "Secondary DNS: $(if($SecondaryDNS) { $SecondaryDNS } else { '(none)' })" -ForegroundColor White

        $confirmation = Read-Host "`nProceed with this configuration? (y/n, default: y)"
        if ([string]::IsNullOrWhiteSpace($confirmation)) { 
            $confirmation = 'y' 
        }
        if ($confirmation.ToLower() -ne 'y') {
            Write-Host "Configuration cancelled by user." -ForegroundColor Yellow
            Write-LogMessage -Message "IP configuration cancelled by user." -Level "INFO"
            return $null
        }

        Write-LogMessage -Message "IP configuration validated and confirmed by user." -Level "INFO"

        return @{
            IPAddress     = $IPAddress
            SubnetMask    = $SubnetMask
            Gateway       = $Gateway
            PrimaryDNS    = $PrimaryDNS
            SecondaryDNS  = $SecondaryDNS
        }

    } catch {
        $errorMessage = "Error during IP settings input: $_"
        Write-Host $errorMessage -ForegroundColor Red
        Write-LogMessage -Message $errorMessage -Level "ERROR"
        return $null
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
    Write-LogMessage -Message "Setting static IP configuration for interface: $InterfaceName" -Level "INFO"

    try {
        # Verify interface exists
        $null = Get-NetAdapter -Name $InterfaceName -ErrorAction Stop

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
            Write-LogMessage -Message "No Gateway specified. Skipping Default Gateway configuration." -Level "WARN"
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
            Write-LogMessage -Message "No DNS servers specified. Skipping DNS configuration." -Level "WARN"
        }

        # Show summary
        $ipConfig = Get-NetIPConfiguration -InterfaceAlias $InterfaceName -ErrorAction Stop
        Write-Host "Static IP configuration applied successfully." -ForegroundColor Green
        Write-Host "IP Address:   $($ipConfig.IPv4Address.IPAddress)" -ForegroundColor Cyan
        Write-Host "Subnet Mask:  /$($ipConfig.IPv4Address.PrefixLength)" -ForegroundColor Cyan
        Write-Host "Default GW:   $($ipConfig.IPv4DefaultGateway.NextHop)" -ForegroundColor Cyan
        Write-Host "DNS Servers:  $($ipConfig.DnsServer.ServerAddresses -join ', ')" -ForegroundColor Cyan
        Write-LogMessage -Message "Static IP configuration applied successfully." -Level "INFO"
    } catch {
        $errorMessage = "Error: Unable to set static IP configuration. $_"
        Write-Host $errorMessage -ForegroundColor Red
        Write-LogMessage -Message $errorMessage -Level "CRITICAL"
    }
}

# Function to set DHCP configuration (optimized for speed and robustness)
function Set-DHCP {
    param (
        [string]$InterfaceName = $Global:SelectedInterfaceAlias,
        [int]$MaxRetries = 3,
        [int]$RetryDelaySeconds = 2
    )

    # Input validation
    if ([string]::IsNullOrWhiteSpace($InterfaceName)) {
        Write-Host "Error: No interface name provided." -ForegroundColor Red
        Write-LogMessage -Message "Error: No interface name provided for DHCP configuration." -Level "ERROR"
        return $false
    }

    Write-Host "Switching to DHCP configuration..." -ForegroundColor Cyan
    Write-LogMessage -Message "Switching to DHCP for interface: $InterfaceName" -Level "INFO"

    # Validate interface exists and is operational
    try {
        $interface = Get-NetAdapter -Name $InterfaceName -ErrorAction Stop
        if ($interface.Status -ne "Up") {
            Write-Host "Warning: Interface '$InterfaceName' is not in 'Up' status. Current status: $($interface.Status)" -ForegroundColor Yellow
            Write-LogMessage -Message "Interface '$InterfaceName' status: $($interface.Status)" -Level "WARN"
        }
    } catch {
        Write-Host "Error: Interface '$InterfaceName' not found or inaccessible." -ForegroundColor Red
        Write-LogMessage -Message "Interface '$InterfaceName' not found: $_" -Level "ERROR"
        return $false
    }

    # Retry mechanism for DHCP configuration
    for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {
        try {
            Write-Host "Attempt $attempt of $MaxRetries..." -ForegroundColor Yellow
            
            # Step 1: Clear existing IP configuration (parallel operations where possible)
            Write-Host "Releasing existing IP configuration..." -ForegroundColor Yellow
            
            # Remove existing IP addresses (IPv4 only for speed)
            $existingIPs = Get-NetIPAddress -InterfaceAlias $InterfaceName -AddressFamily IPv4 -ErrorAction SilentlyContinue
            if ($existingIPs) {
                $existingIPs | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
            }

            # Step 2: Enable DHCP and reset DNS in parallel
            Write-Host "Enabling DHCP..." -ForegroundColor Yellow
            
            # Use jobs for parallel execution
            $dhcpJob = Start-Job -ScriptBlock {
                param($InterfaceName)
                Set-NetIPInterface -InterfaceAlias $InterfaceName -Dhcp Enabled -ErrorAction Stop
            } -ArgumentList $InterfaceName

            $dnsJob = Start-Job -ScriptBlock {
                param($InterfaceName)
                Set-DnsClientServerAddress -InterfaceAlias $InterfaceName -ResetServerAddresses -ErrorAction Stop
            } -ArgumentList $InterfaceName

            # Wait for both jobs to complete
            Wait-Job $dhcpJob, $dnsJob | Out-Null
            
            # Check for errors in parallel jobs
            $null = Receive-Job $dhcpJob -ErrorAction SilentlyContinue
            $null = Receive-Job $dnsJob -ErrorAction SilentlyContinue
            
            Remove-Job $dhcpJob, $dnsJob -Force

            # Step 3: Trigger DHCP renewal using PowerShell cmdlets (faster than ipconfig)
            Write-Host "Renewing DHCP lease..." -ForegroundColor Yellow
            
            # Use Restart-NetAdapter for immediate DHCP renewal
            Restart-NetAdapter -Name $InterfaceName -Confirm:$false -ErrorAction Stop

            # Step 4: Wait for DHCP lease with adaptive timeout
            $maxWait = 10 # Maximum wait time in seconds
            $waitInterval = 0.5 # Check every 500ms
            $waitTime = 0
            $dhcpSuccess = $false

            Write-Host "Waiting for DHCP lease..." -ForegroundColor Yellow

            while ($waitTime -lt $maxWait -and -not $dhcpSuccess) {
                Start-Sleep -Milliseconds ($waitInterval * 1000)
                $waitTime += $waitInterval

                try {
                    $ipConfig = Get-NetIPConfiguration -InterfaceAlias $InterfaceName -ErrorAction SilentlyContinue
                    if ($ipConfig -and $ipConfig.IPv4Address -and $ipConfig.IPv4Address.IPAddress) {
                        $currentIP = $ipConfig.IPv4Address.IPAddress
                        
                        # Check if we got a valid DHCP address (not APIPA)
                        if ($currentIP -notlike "169.254.*" -and $currentIP -ne "0.0.0.0") {
                            $dhcpSuccess = $true
                            break
                        }
                    }
                } catch {
                    # Continue waiting
                }
                
                Write-Host "." -NoNewline -ForegroundColor Gray
            }
            Write-Host "" # New line after dots

            # Step 5: Verify and display results
            if ($dhcpSuccess) {
                $ipConfig = Get-NetIPConfiguration -InterfaceAlias $InterfaceName -ErrorAction Stop
                Write-Host "DHCP configuration applied successfully!" -ForegroundColor Green
                Write-Host "IP Address: $($ipConfig.IPv4Address.IPAddress)" -ForegroundColor Cyan
                Write-Host "Subnet Mask: /$($ipConfig.IPv4Address.PrefixLength)" -ForegroundColor Cyan
                
                if ($ipConfig.IPv4DefaultGateway) {
                    Write-Host "Default Gateway: $($ipConfig.IPv4DefaultGateway.NextHop)" -ForegroundColor Cyan
                } else {
                    Write-Host "Default Gateway: (none configured)" -ForegroundColor DarkYellow
                }
                
                if ($ipConfig.DnsServer.ServerAddresses) {
                    Write-Host "DNS Servers: $($ipConfig.DnsServer.ServerAddresses -join ', ')" -ForegroundColor Cyan
                } else {
                    Write-Host "DNS Servers: (none configured)" -ForegroundColor DarkYellow
                }
                
                Write-LogMessage -Message "DHCP configuration applied successfully for $InterfaceName in attempt $attempt." -Level "INFO"
                
                # Clear DNS cache for immediate effect
                Clear-DnsClientCache -ErrorAction SilentlyContinue
                
                return $true
            } else {
                # Check if we got APIPA address
                $ipConfig = Get-NetIPConfiguration -InterfaceName $InterfaceName -ErrorAction SilentlyContinue
                if ($ipConfig -and $ipConfig.IPv4Address.IPAddress -like "169.254.*") {
                    Write-Host "Warning: Received APIPA address ($($ipConfig.IPv4Address.IPAddress)). Network may have DHCP issues." -ForegroundColor Yellow
                    Write-LogMessage -Message "APIPA address assigned on attempt $attempt. Possible network DHCP issue." -Level "WARN"
                } else {
                    Write-Host "Warning: No valid IP address received within timeout period." -ForegroundColor Yellow
                    Write-LogMessage -Message "No valid IP address received on attempt $attempt." -Level "WARN"
                }

                if ($attempt -lt $MaxRetries) {
                    Write-Host "Retrying in $RetryDelaySeconds seconds..." -ForegroundColor Yellow
                    Start-Sleep -Seconds $RetryDelaySeconds
                }
            }

        } catch {
            $errorMessage = "Attempt $attempt failed: $_"
            Write-Host $errorMessage -ForegroundColor Red
            Write-LogMessage -Message $errorMessage -Level "ERROR"
            
            if ($attempt -lt $MaxRetries) {
                Write-Host "Retrying in $RetryDelaySeconds seconds..." -ForegroundColor Yellow
                Start-Sleep -Seconds $RetryDelaySeconds
            }
        }
    }

    # If we get here, all attempts failed
    Write-Host "Failed to configure DHCP after $MaxRetries attempts." -ForegroundColor Red
    Write-Host "Available interfaces:" -ForegroundColor Yellow
    Get-NetAdapter | Select-Object Name, Status, LinkSpeed | Format-Table -AutoSize
    Write-LogMessage -Message "Failed to configure DHCP for $InterfaceName after $MaxRetries attempts." -Level "CRITICAL"
    return $false
}

# Function to test network connectivity using a specific interface (optimized)
function Test-NetworkConnectivity {
    param (
        [string]$InterfaceName = $Global:SelectedInterfaceAlias,
        [bool]$QuickTest = $false,
        [int]$TimeoutSeconds = 30
    )

    Write-Host "Performing network connectivity test on interface: $InterfaceName" -ForegroundColor Cyan
    if ($QuickTest) {
        Write-Host "(Running in quick test mode)" -ForegroundColor Yellow
    }
    Write-LogMessage -Message "Starting network connectivity test for interface: $InterfaceName (Quick: $QuickTest)" -Level "INFO"

    # Input validation
    if ([string]::IsNullOrWhiteSpace($InterfaceName)) {
        Write-Host "ERROR: No network interface is currently loaded." -ForegroundColor Red
        Write-LogMessage -Message "Error: No network interface is currently loaded." -Level "CRITICAL"
        return $false
    }

    # Validate interface exists
    if (-not (Test-ValidInterfaceName -InterfaceName $InterfaceName)) {
        Write-Host "ERROR: Interface '$InterfaceName' not found or inaccessible." -ForegroundColor Red
        Write-LogMessage -Message "Interface '$InterfaceName' not found or inaccessible." -Level "ERROR"
        return $false
    }

    # Fetch IP configuration with better error handling
    try {
        $ipConfig = Get-NetIPConfiguration -InterfaceAlias $InterfaceName -ErrorAction Stop
        if (-not $ipConfig.IPv4Address -or -not $ipConfig.IPv4Address.IPAddress) {
            Write-Host "ERROR: No IPv4 address configured on interface: $InterfaceName" -ForegroundColor Red
            Write-LogMessage -Message "No IPv4 address configured on interface: $InterfaceName" -Level "ERROR"
            return $false
        }
    } catch {
        Write-Host "ERROR: Failed to get network configuration for interface '$InterfaceName': $_" -ForegroundColor Red
        Write-LogMessage -Message "Failed to get network configuration for interface '$InterfaceName': $_" -Level "ERROR"
        return $false
    }

    $sourceIP = $ipConfig.IPv4Address.IPAddress
    Write-Host "Using source IP: $sourceIP" -ForegroundColor Cyan

    # Test results tracking
    $testResults = @{
        Gateway = $null
        PublicDNS = @()
        LocalDNS = @()
        DNSResolution = @()
        OverallSuccess = $true
    }

    # 1. Test Gateway Connection (Priority Test)
    if ($ipConfig.IPv4DefaultGateway -and $ipConfig.IPv4DefaultGateway.NextHop) {
        $gateway = $ipConfig.IPv4DefaultGateway.NextHop
        Write-Host "`nTesting Gateway connectivity..." -ForegroundColor Yellow
        Write-Host "Gateway: $gateway" -ForegroundColor White

        try {
            $pingCount = if ($QuickTest) { 2 } else { 4 }
            $gatewayResult = Test-Connection -ComputerName $gateway -Count $pingCount -ErrorAction Stop
            
            if ($gatewayResult) {
                $avgMs = [math]::Round(($gatewayResult | Measure-Object -Property ResponseTime -Average).Average, 1)
                $maxMs = ($gatewayResult | Measure-Object -Property ResponseTime -Maximum).Maximum
                $minMs = ($gatewayResult | Measure-Object -Property ResponseTime -Minimum).Minimum
                
                Write-Host "[OK] Gateway is reachable" -ForegroundColor Green
                Write-Host "  Response time: Min=$minMs ms, Max=$maxMs ms, Avg=$avgMs ms" -ForegroundColor Gray
                
                $testResults.Gateway = @{ 
                    Status = "Success"; 
                    IP = $gateway; 
                    AvgResponseTime = $avgMs 
                }
                Write-LogMessage -Message "Gateway $gateway is reachable. Avg: $avgMs ms" -Level "INFO"
            }
        } catch {
            Write-Host "[FAIL] Gateway is unreachable" -ForegroundColor Red
            $testResults.Gateway = @{ Status = "Failed"; IP = $gateway; Error = $_.Exception.Message }
            $testResults.OverallSuccess = $false
            Write-LogMessage -Message "Gateway $gateway is unreachable: $_" -Level "ERROR"
        }
    } else {
        Write-Host "`n! No default gateway configured" -ForegroundColor DarkYellow
        Write-LogMessage -Message "No default gateway configured for interface $InterfaceName" -Level "WARN"
    }

    # 2. Test Public DNS Servers (Parallel)
    Write-Host "`nTesting Public DNS servers..." -ForegroundColor Yellow
    
    $publicDnsServers = if ($QuickTest) {
        @("1.1.1.1", "8.8.8.8")  # Quick test with only 2 servers
    } else {
        @("1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9")
    }
    
    $dnsJobs = @()
    foreach ($dns in $publicDnsServers) {
        $dnsJobs += Start-Job -ScriptBlock {
            param($dns, $pingCount)
            try {
                $result = Test-Connection -ComputerName $dns -Count $pingCount -ErrorAction Stop
                if ($result) {
                    $avg = [math]::Round(($result | Measure-Object -Property ResponseTime -Average).Average, 1)
                    return @{ Server = $dns; Status = "Success"; AvgResponseTime = $avg }
                }
            } catch {
                return @{ Server = $dns; Status = "Failed"; Error = $_.Exception.Message }
            }
            return @{ Server = $dns; Status = "Failed"; Error = "No response" }
        } -ArgumentList $dns, $(if ($QuickTest) { 2 } else { 3 })
    }

    # Wait for DNS tests with timeout
    $dnsJobResults = @()
    foreach ($job in $dnsJobs) {
        try {
            $result = Wait-Job $job -Timeout $TimeoutSeconds | Receive-Job
            if ($result) {
                $dnsJobResults += $result
                
                if ($result.Status -eq "Success") {
                    Write-Host "[OK] $($result.Server) - $($result.AvgResponseTime) ms" -ForegroundColor Green
                    $testResults.PublicDNS += $result
                } else {
                    Write-Host "[FAIL] $($result.Server) - Failed" -ForegroundColor Red
                }
            }
        } catch {
            Write-Host "[FAIL] DNS test timeout for job" -ForegroundColor Red
        }
        Remove-Job $job -Force -ErrorAction SilentlyContinue
    }

    # 3. Test Local DNS Servers
    if ($ipConfig.DnsServer -and $ipConfig.DnsServer.ServerAddresses) {
        Write-Host "`nTesting Local DNS servers..." -ForegroundColor Yellow
        
        foreach ($localDns in $ipConfig.DnsServer.ServerAddresses) {
            if (Test-ValidIPAddress -IPAddress $localDns) {
                try {
                    $pingCount = if ($QuickTest) { 2 } else { 3 }
                    $result = Test-Connection -ComputerName $localDns -Count $pingCount -ErrorAction Stop
                    
                    if ($result) {
                        $avg = [math]::Round(($result | Measure-Object -Property ResponseTime -Average).Average, 1)
                        Write-Host "[OK] $localDns - $avg ms" -ForegroundColor Green
                        $testResults.LocalDNS += @{ Server = $localDns; Status = "Success"; AvgResponseTime = $avg }
                    }
                } catch {
                    Write-Host "[FAIL] $localDns - Failed" -ForegroundColor Red
                    $testResults.LocalDNS += @{ Server = $localDns; Status = "Failed"; Error = $_.Exception.Message }
                }
            }
        }
    }

    # 4. Test DNS Resolution
    if (-not $QuickTest) {
        Write-Host "`nTesting DNS resolution..." -ForegroundColor Yellow
        
        $testDomains = @("google.com", "cloudflare.com")
        foreach ($domain in $testDomains) {
            try {
                $resolveResult = Resolve-DnsName -Name $domain -ErrorAction Stop
                if ($resolveResult) {
                    $resolvedIPs = $resolveResult | Where-Object { $_.Type -eq 'A' } | Select-Object -ExpandProperty IPAddress
                    if ($resolvedIPs) {
                        Write-Host "[OK] $domain -> $($resolvedIPs -join ', ')" -ForegroundColor Green
                        $testResults.DNSResolution += @{ Domain = $domain; Status = "Success"; IPs = $resolvedIPs }
                    }
                }
            } catch {
                Write-Host "[FAIL] $domain - Resolution failed" -ForegroundColor Red
                $testResults.DNSResolution += @{ Domain = $domain; Status = "Failed"; Error = $_.Exception.Message }
                $testResults.OverallSuccess = $false
            }
        }
    }

    # 5. Summary
    Write-Host ""
    Write-Host ("="*50) -ForegroundColor Cyan
    Write-Host "Network Test Summary for $InterfaceName" -ForegroundColor Cyan
    Write-Host ("="*50) -ForegroundColor Cyan

    $successCount = 0
    $totalTests = 0

    # Gateway summary
    if ($testResults.Gateway) {
        $totalTests++
        if ($testResults.Gateway.Status -eq "Success") { 
            $successCount++ 
            Write-Host "Gateway: [PASS]" -ForegroundColor Green
        } else {
            Write-Host "Gateway: [FAIL]" -ForegroundColor Red
        }
    }

    # DNS summary  
    $dnsSuccess = ($testResults.PublicDNS + $testResults.LocalDNS | Where-Object { $_.Status -eq "Success" }).Count
    $dnsTotal = ($testResults.PublicDNS + $testResults.LocalDNS).Count
    if ($dnsTotal -gt 0) {
        $totalTests++
        if ($dnsSuccess -gt 0) { 
            $successCount++
            Write-Host "DNS Connectivity: [PASS] ($dnsSuccess/$dnsTotal servers)" -ForegroundColor Green
        } else {
            Write-Host "DNS Connectivity: [FAIL] (0/$dnsTotal servers)" -ForegroundColor Red
        }
    }

    # DNS Resolution summary
    if ($testResults.DNSResolution.Count -gt 0) {
        $totalTests++
        $resolutionSuccess = ($testResults.DNSResolution | Where-Object { $_.Status -eq "Success" }).Count
        if ($resolutionSuccess -gt 0) {
            $successCount++
            Write-Host "DNS Resolution: [PASS] ($resolutionSuccess/$($testResults.DNSResolution.Count) domains)" -ForegroundColor Green
        } else {
            Write-Host "DNS Resolution: [FAIL]" -ForegroundColor Red
        }
    }

    # Overall result
    $overallSuccess = $successCount -eq $totalTests -and $testResults.OverallSuccess
    if ($overallSuccess) {
        Write-Host ""
        Write-Host "Overall Result: [NETWORK OK]" -ForegroundColor Green
        Write-LogMessage -Message "Network connectivity test PASSED for interface $InterfaceName" -Level "INFO"
    } else {
        Write-Host ""
        Write-Host "Overall Result: [NETWORK ISSUES DETECTED]" -ForegroundColor Red
        Write-LogMessage -Message "Network connectivity test FAILED for interface $InterfaceName" -Level "WARN"
    }

    Write-Host ("="*50) -ForegroundColor Cyan
    return $overallSuccess
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
        
        # Filter DNS servers to show only IPv4 addresses
        $ipv4DnsServers = $dns | Where-Object { $_ -match "^\d+\.\d+\.\d+\.\d+$" }
        if ($ipv4DnsServers) {
            Write-Host "DNS Servers (IPv4): $($ipv4DnsServers -join ', ')" -ForegroundColor White
        } else {
            Write-Host "DNS Servers (IPv4): (none configured)" -ForegroundColor DarkYellow
        }
        
        # Show IPv6 DNS servers separately if any exist
        $ipv6DnsServers = $dns | Where-Object { $_ -notmatch "^\d+\.\d+\.\d+\.\d+$" -and $_ -ne "" }
        if ($ipv6DnsServers) {
            Write-Host "DNS Servers (IPv6): $($ipv6DnsServers -join ', ')" -ForegroundColor Gray
        }

    } catch {
        Write-Host "Error retrieving IP configuration: $_" -ForegroundColor Red
        Write-LogMessage -Message "Error retrieving IP configuration for ${InterfaceName}: $_" -Level "ERROR"
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

        $userChoice = Read-Host "Your choice"

        switch ($userChoice.ToLower()) {
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
                if ($userChoice -match "^\d+$") {
                    $inputInt = [int]$userChoice  # Convert input to integer
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


#region Main Logic
$interfaceName = Get-SavedInterface
if ($interfaceName) {
    Write-Host "Previously selected interface: $interfaceName" -ForegroundColor Cyan
    $host.UI.RawUI.WindowTitle = "Network Configuration - $interfaceName"
    try {
        $null = Get-NetAdapter -Name $interfaceName -ErrorAction Stop
    } catch {
        Write-Host "Warning: Previously selected interface '$interfaceName' no longer exists." -ForegroundColor Yellow
        $interfaceName = $null
    }
}
if (-not $interfaceName) {
    Write-Host "No valid interface selected. You can select one using option 6." -ForegroundColor Yellow
    $host.UI.RawUI.WindowTitle = "Network Configuration - No Interface"
}
#endregion

# Function to get current interface status (lazy-loaded for performance)
function Get-InterfaceStatus {
    param ([string]$InterfaceName)
    
    if ([string]::IsNullOrWhiteSpace($InterfaceName)) {
        return "No interface selected"
    }
    
    try {
        # Quick check - just get the IP address without full configuration
        $ipAddress = (Get-NetIPAddress -InterfaceAlias $InterfaceName -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1).IPAddress
        if ($ipAddress) {
            $dhcpEnabled = (Get-NetIPInterface -InterfaceAlias $InterfaceName -AddressFamily IPv4 -ErrorAction SilentlyContinue).Dhcp
            $configType = if ($dhcpEnabled -eq "Enabled") { "DHCP" } else { "Static" }
            return "$InterfaceName | IP: $ipAddress | Type: $configType"
        } else {
            return "$InterfaceName | Status: No IP configured"
        }
    } catch {
        return "$InterfaceName | Status: Unknown"
    }
}

while ($true) {
    # Display current interface status (only when explicitly refreshed for speed)
    $statusInfo = Get-InterfaceStatus -InterfaceName $interfaceName
    Write-Host "`nCurrent: $statusInfo" -ForegroundColor Cyan

    Write-Host ""
    Write-Host ("="*60) -ForegroundColor Gray
    Write-Host "Network Configuration Script v$script:ScriptVersion" -ForegroundColor Cyan
    Write-Host ("="*60) -ForegroundColor Gray
    Write-Host "Please select an option:" -ForegroundColor Yellow
    Write-Host "1. Set static IP configuration manually" -ForegroundColor White
    Write-Host "2. Set DHCP configuration" -ForegroundColor White
    Write-Host "3. Show current IP configuration" -ForegroundColor White
    Write-Host "4. Enter and save static IP configuration" -ForegroundColor White
    Write-Host "5. Load saved static IP configuration" -ForegroundColor White
    Write-Host "6. Change network interface" -ForegroundColor White
    Write-Host "7. Open log file" -ForegroundColor White
    Write-Host "8. Test Network Connectivity" -ForegroundColor White
    Write-Host "9. Check for updates" -ForegroundColor White
    Write-Host "0. Exit" -ForegroundColor White
    Write-Host ""
    Write-Host "Quick actions: 'q' = Quick DHCP, 's' = Show status, 't' = Quick test, 'r' = Refresh interface status" -ForegroundColor DarkGray

    $choice = Read-Host "Enter your choice"

    # Block actions that require a valid interface
    $requiresInterface = @("1","2","3","4","5","8","q","s","t")
    if ($requiresInterface -contains $choice -and -not $interfaceName) {
        Write-Host "No valid network interface selected. Please choose one using option 6 before proceeding." -ForegroundColor Red
        continue
    }

    switch ($choice) {
        "1" {
            try {
                $settings = Read-IPConfigurationSettings -InterfaceName $interfaceName
                if ($settings) {
                    Set-StaticIP -InterfaceName $interfaceName `
                                -IPAddress $settings.IPAddress `
                                -SubnetMask $settings.SubnetMask `
                                -Gateway $settings.Gateway `
                                -PrimaryDNS $settings.PrimaryDNS `
                                -SecondaryDNS $settings.SecondaryDNS
                } else {
                    Write-Host "Static IP configuration was cancelled." -ForegroundColor Yellow
                }
            } catch {
                Write-Host "Error during static IP configuration: $_" -ForegroundColor Red
                Write-LogMessage -Message "Error during static IP configuration: $_" -Level "ERROR"
            }
        }
        "2" {
            try {
                Write-Host "Configuring DHCP..." -ForegroundColor Cyan
                $result = Set-DHCP -InterfaceName $interfaceName
                if ($result) {
                    Write-Host "DHCP configuration completed successfully." -ForegroundColor Green
                } else {
                    Write-Host "DHCP configuration failed. Check the logs for details." -ForegroundColor Red
                }
            } catch {
                Write-Host "Error during DHCP configuration: $_" -ForegroundColor Red
                Write-LogMessage -Message "Error during DHCP configuration: $_" -Level "ERROR"
            }
        }
        "3" {
            try {
                Show-IPInfo -InterfaceName $interfaceName
            } catch {
                Write-Host "Error displaying IP information: $_" -ForegroundColor Red
                Write-LogMessage -Message "Error displaying IP information: $_" -Level "ERROR"
            }
        }
        "4" {
            try {
                $settings = Read-IPConfigurationSettings -InterfaceName $interfaceName
                if ($settings) {
                    Save-StaticIPConfig -IPAddress $settings.IPAddress `
                                        -SubnetMask $settings.SubnetMask `
                                        -Gateway $settings.Gateway `
                                        -PrimaryDNS $settings.PrimaryDNS `
                                        -SecondaryDNS $settings.SecondaryDNS
                } else {
                    Write-Host "Configuration save was cancelled." -ForegroundColor Yellow
                }
            } catch {
                Write-Host "Error saving static IP configuration: $_" -ForegroundColor Red
                Write-LogMessage -Message "Error saving static IP configuration: $_" -Level "ERROR"
            }
        }
        "5" {
            try {
                $config = Get-SavedIPConfig
                if ($config) {
                    Write-Host "Loaded Configuration:" -ForegroundColor Green
                    Write-Host "IP Address: $($config.IPAddress)"
                    Write-Host "Subnet Mask: $($config.SubnetMask)"
                    Write-Host "Gateway: $(if($config.Gateway) { $config.Gateway } else { '(none)' })"
                    Write-Host "Primary DNS: $($config.PrimaryDNS)"
                    Write-Host "Secondary DNS: $(if($config.SecondaryDNS) { $config.SecondaryDNS } else { '(none)' })"
                    
                    $confirmation = Read-Host "`nApply this configuration? (y/n, default: y)"
                    if ([string]::IsNullOrWhiteSpace($confirmation)) { 
                        $confirmation = 'y' 
                    }
                    if ($confirmation.ToLower() -eq 'y') {
                        Set-StaticIP -InterfaceName $interfaceName `
                                     -IPAddress $config.IPAddress `
                                     -SubnetMask $config.SubnetMask `
                                     -Gateway $config.Gateway `
                                     -PrimaryDNS $config.PrimaryDNS `
                                     -SecondaryDNS $config.SecondaryDNS
                    } else {
                        Write-Host "Configuration not applied." -ForegroundColor Yellow
                    }
                } else {
                    Write-Host "No static IP configuration found. Please save a configuration first (option 4)." -ForegroundColor Yellow
                }
            } catch {
                Write-Host "Error loading static IP configuration: $_" -ForegroundColor Red
                Write-LogMessage -Message "Error loading static IP configuration: $_" -Level "ERROR"
            }
        }
        "6" {
            try {
                $interfaceName = Select-NetworkInterface
                if ($interfaceName) {
                    $host.UI.RawUI.WindowTitle = "Network Configuration - $interfaceName"
                    Write-Host "Interface changed to: $interfaceName" -ForegroundColor Green
                } else {
                    Write-Host "No interface selected." -ForegroundColor Yellow
                }
            } catch {
                Write-Host "Error selecting network interface: $_" -ForegroundColor Red
                Write-LogMessage -Message "Error selecting network interface: $_" -Level "ERROR"
            }
        }
        "7" {
            try {
                Open-LogFile
            } catch {
                Write-Host "Error opening log file: $_" -ForegroundColor Red
                Write-LogMessage -Message "Error opening log file: $_" -Level "ERROR"
            }
        }
        "8" {
            try {
                $quickTest = Read-Host "Run quick test? (y/n, default: n)"
                $isQuickTest = $quickTest.ToLower() -eq 'y'
                
                $result = Test-NetworkConnectivity -InterfaceName $interfaceName -QuickTest $isQuickTest
                if ($result) {
                    Write-Host "`nNetwork connectivity test completed successfully." -ForegroundColor Green
                } else {
                    Write-Host "`nNetwork connectivity issues detected. Check the results above." -ForegroundColor Yellow
                }
            } catch {
                Write-Host "Error during network connectivity test: $_" -ForegroundColor Red
                Write-LogMessage -Message "Error during network connectivity test: $_" -Level "ERROR"
            }
        }
        "9" {
            Update-Script
        }
        "q" {
            # Quick DHCP configuration
            Write-Host "Quick DHCP configuration..." -ForegroundColor Cyan
            try {
                $result = Set-DHCP -InterfaceName $interfaceName -MaxRetries 2
                if ($result) {
                    Write-Host "Quick DHCP setup completed." -ForegroundColor Green
                } else {
                    Write-Host "Quick DHCP setup failed." -ForegroundColor Red
                }
            } catch {
                Write-Host "Error during quick DHCP: $_" -ForegroundColor Red
            }
        }
        "s" {
            # Quick status display
            Write-Host "Quick status check..." -ForegroundColor Cyan
            try {
                Show-IPInfo -InterfaceName $interfaceName
            } catch {
                Write-Host "Error getting status: $_" -ForegroundColor Red
            }
        }
        "t" {
            # Quick network test
            Write-Host "Quick network test..." -ForegroundColor Cyan
            try {
                $null = Test-NetworkConnectivity -InterfaceName $interfaceName -QuickTest $true
            } catch {
                Write-Host "Error during quick test: $_" -ForegroundColor Red
            }
        }
        "r" {
            # Refresh interface status
            Write-Host "Refreshing interface status..." -ForegroundColor Cyan
            # Just refresh the status, it will be displayed at the start of the next loop
        }
        "0" {
            Write-Host "Exiting..." -ForegroundColor Cyan
            Write-LogMessage "Script exited by user."
            exit
        }
        default {
            Write-Host "Invalid choice. Please try again." -ForegroundColor Red
        }
    }
}
