# Version: 2.3
# Network Configuration Script
# 
# Features:
# - Static IP and DHCP configuration
# - Live Interface Monitoring with real-time event tracking
# - Network connectivity testing (Gateway, DNS, Internet)
# - Configuration save/load (XML)
# - Subnet Calculator with CIDR calculations
# - Interface management and renaming
# - GDPR-compliant logging with user consent
# - Data pseudonymization (IP addresses)
# - Privacy & Data Management dashboard
#
# Credits:
# - Subnet Calculator: Inspired by various PowerShell community implementations
#   including work from robert-gaines, Jzubia, and other contributors


#region File Path Migration (deduplicated)
$script:AppDataDir = Join-Path $env:APPDATA 'Network_Configuration_Script'
if (-not (Test-Path $script:AppDataDir)) {
    New-Item -Path $script:AppDataDir -ItemType Directory | Out-Null
}
$script:ConfigFile = 'IPConfiguration.xml'
$script:LogFileName = 'network_config.log'
$script:VersionFile = 'version.txt'
$script:InterfaceFile = 'selected_interface.txt'
$script:ConsentFile = 'gdpr_consent.txt'
$script:ConfigPath = Join-Path $script:AppDataDir $script:ConfigFile
$script:LogPath = Join-Path $script:AppDataDir $script:LogFileName
$script:VersionPath = Join-Path $script:AppDataDir $script:VersionFile
$script:InterfacePath = Join-Path $script:AppDataDir $script:InterfaceFile
$script:ConsentPath = Join-Path $script:AppDataDir $script:ConsentFile
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
foreach ($file in @($script:ConfigFile, $script:LogFileName, $script:VersionFile, $script:InterfaceFile, $script:ConsentFile)) {
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

# Ensure version.txt reflects the current script version
# Extract version from the header comment (first line: # Version: X.X)
$scriptContent = Get-Content $MyInvocation.MyCommand.Path -TotalCount 1
if ($scriptContent -match '# Version:\s*(\d+\.\d+)') {
    $currentScriptVersion = $matches[1]
    
    if (Test-Path $script:VersionPath) {
        $savedVersion = (Get-Content $script:VersionPath -ErrorAction SilentlyContinue).Trim()
        if ($savedVersion -ne $currentScriptVersion) {
            Set-Content -Path $script:VersionPath -Value $currentScriptVersion -Force
        }
    } else {
        Set-Content -Path $script:VersionPath -Value $currentScriptVersion -Force
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

#region GDPR Compliance
$script:LoggingConsent = $false
$script:PseudonymizeData = $true  # Always pseudonymize IP addresses by default

# Function to check and request GDPR consent
function Get-GDPRConsent {
    if (Test-Path $script:ConsentPath) {
        try {
            $consentData = Get-Content $script:ConsentPath -Raw | ConvertFrom-Json
            $script:LoggingConsent = $consentData.LoggingConsent
            $script:PseudonymizeData = if ($null -ne $consentData.PseudonymizeData) { $consentData.PseudonymizeData } else { $true }
            return
        } catch {
            # Invalid consent file, request new consent (will continue to show privacy notice)
            Write-Verbose "Consent file is invalid or corrupted: $_"
        }
    }
    
    # Show privacy notice
    Clear-Host
    Write-Host "===========================================================================" -ForegroundColor Cyan
    Write-Host "                         PRIVACY NOTICE (GDPR)                            " -ForegroundColor Cyan
    Write-Host "===========================================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "This script can collect the following data for troubleshooting purposes:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  - Network interface names (e.g., 'Ethernet', 'Wi-Fi')" -ForegroundColor White
    Write-Host "  - IP addresses (pseudonymized: 192.168.1.xxx)" -ForegroundColor White
    Write-Host "  - Subnet masks and gateway addresses (pseudonymized)" -ForegroundColor White
    Write-Host "  - DNS server addresses (pseudonymized)" -ForegroundColor White
    Write-Host "  - Script actions and errors" -ForegroundColor White
    Write-Host "  - Timestamps of operations" -ForegroundColor White
    Write-Host ""
    Write-Host "Data Protection:" -ForegroundColor Green
    Write-Host "  [OK] All data is stored locally on your computer" -ForegroundColor Gray
    Write-Host "  [OK] No data is sent to external servers" -ForegroundColor Gray
    Write-Host "  [OK] IP addresses are pseudonymized (last octet hidden)" -ForegroundColor Gray
    Write-Host "  [OK] You can delete all logs at any time" -ForegroundColor Gray
    Write-Host "  [OK] Logs are stored in: $script:AppDataDir" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Your Rights:" -ForegroundColor Green
    Write-Host "  - Right to access your data (view logs)" -ForegroundColor Gray
    Write-Host "  - Right to delete your data (clear all logs)" -ForegroundColor Gray
    Write-Host "  - Right to withdraw consent at any time" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Note: Logging helps diagnose network configuration issues." -ForegroundColor DarkGray
    Write-Host "      The script will function normally if you decline." -ForegroundColor DarkGray
    Write-Host ""
    
    $response = (Read-Host "Do you consent to logging with data pseudonymization? (y/n)").Trim().ToLower()
    
    if ($response -eq 'y') {
        $script:LoggingConsent = $true
        $consentData = @{
            LoggingConsent = $true
            PseudonymizeData = $true
            ConsentDate = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
            Version = "2.3"
        }
        $consentData | ConvertTo-Json | Set-Content -Path $script:ConsentPath
        Write-Host ""
        Write-Host "[OK] Thank you. Logging enabled with data pseudonymization." -ForegroundColor Green
        Write-Host "  You can manage your data via the 'Privacy & Data' menu option." -ForegroundColor Gray
    } else {
        $script:LoggingConsent = $false
        $consentData = @{
            LoggingConsent = $false
            PseudonymizeData = $true
            ConsentDate = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
            Version = "2.3"
        }
        $consentData | ConvertTo-Json | Set-Content -Path $script:ConsentPath
        Write-Host ""
        Write-Host "[OK] Logging disabled. The script will function normally." -ForegroundColor Yellow
    }
    Write-Host ""
    Start-Sleep -Seconds 2
}

# Function to pseudonymize IP addresses (GDPR data minimization)
function Hide-IPAddress {
    param ([string]$IPAddress)
    
    if (-not $script:PseudonymizeData -or [string]::IsNullOrWhiteSpace($IPAddress)) {
        return $IPAddress
    }
    
    # Hide last octet of IPv4 addresses
    if ($IPAddress -match '^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)\d{1,3}$') {
        return $IPAddress -replace '^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)\d{1,3}$', '${1}xxx'
    }
    
    # Hide last segments of IPv6 addresses
    if ($IPAddress -match ':') {
        $parts = $IPAddress -split ':'
        if ($parts.Count -gt 2) {
            $parts[-1] = 'xxxx'
            $parts[-2] = 'xxxx'
            return $parts -join ':'
        }
    }
    
    return $IPAddress
}

# Function to show GDPR data management menu
function Show-GDPRMenu {
    Clear-Host
    Write-Host "===========================================================================" -ForegroundColor Cyan
    Write-Host "                      PRIVACY & DATA MANAGEMENT                           " -ForegroundColor Cyan
    Write-Host "===========================================================================" -ForegroundColor Cyan
    Write-Host ""
    
    $consentStatus = if ($script:LoggingConsent) { "Enabled" } else { "Disabled" }
    $pseudoStatus = if ($script:PseudonymizeData) { "Enabled" } else { "Disabled" }
    
    Write-Host "Current Settings:" -ForegroundColor Yellow
    Write-Host "  Logging: $consentStatus" -ForegroundColor White
    Write-Host "  Data Pseudonymization: $pseudoStatus" -ForegroundColor White
    Write-Host "  Data Location: $script:AppDataDir" -ForegroundColor Gray
    Write-Host ""
    
    Write-Host "Options:" -ForegroundColor Cyan
    Write-Host "  [1] View Privacy Notice" -ForegroundColor White
    Write-Host "  [2] View Current Logs" -ForegroundColor White
    Write-Host "  [3] Delete All Logs (Right to be Forgotten)" -ForegroundColor White
    Write-Host "  [4] Change Logging Consent" -ForegroundColor White
    Write-Host "  [5] Export Data (Data Portability)" -ForegroundColor White
    Write-Host "  [b] Back to Main Menu" -ForegroundColor White
    Write-Host ""
    
    $choice = (Read-Host "Select an option").Trim()
    
    switch ($choice) {
        "1" {
            Show-PrivacyNotice
            Read-Host "`nPress Enter to continue"
            Show-GDPRMenu
        }
        "2" {
            Open-LogFile
            Show-GDPRMenu
        }
        "3" {
            Remove-AllLogs
            Read-Host "`nPress Enter to continue"
            Show-GDPRMenu
        }
        "4" {
            Update-GDPRConsent
            Read-Host "`nPress Enter to continue"
            Show-GDPRMenu
        }
        "5" {
            Export-UserData
            Read-Host "`nPress Enter to continue"
            Show-GDPRMenu
        }
        "b" {
            return
        }
        default {
            Write-Host "Invalid option. Please try again." -ForegroundColor Red
            Start-Sleep -Seconds 1
            Show-GDPRMenu
        }
    }
}

# Function to show privacy notice
function Show-PrivacyNotice {
    Clear-Host
    Write-Host "===========================================================================" -ForegroundColor Cyan
    Write-Host "                    PRIVACY NOTICE & DATA POLICY                          " -ForegroundColor Cyan
    Write-Host "===========================================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "1. DATA CONTROLLER" -ForegroundColor Yellow
    Write-Host "   This script runs locally on your computer. You are the data controller." -ForegroundColor White
    Write-Host ""
    Write-Host "2. DATA COLLECTED" -ForegroundColor Yellow
    Write-Host "   - Network interface names" -ForegroundColor White
    Write-Host "   - IP addresses (pseudonymized by default)" -ForegroundColor White
    Write-Host "   - Network configuration settings" -ForegroundColor White
    Write-Host "   - Timestamps of operations" -ForegroundColor White
    Write-Host "   - Error messages and diagnostic information" -ForegroundColor White
    Write-Host ""
    Write-Host "3. PURPOSE OF PROCESSING" -ForegroundColor Yellow
    Write-Host "   - Troubleshooting network configuration issues" -ForegroundColor White
    Write-Host "   - Providing operational history for review" -ForegroundColor White
    Write-Host "   - Debugging script errors" -ForegroundColor White
    Write-Host ""
    Write-Host "4. LEGAL BASIS" -ForegroundColor Yellow
    Write-Host "   - Your explicit consent (GDPR Article 6(1)(a))" -ForegroundColor White
    Write-Host ""
    Write-Host "5. DATA STORAGE" -ForegroundColor Yellow
    Write-Host "   - Location: $script:AppDataDir" -ForegroundColor White
    Write-Host "   - Retention: Logs are rotated after 5MB, keeping 5 archives" -ForegroundColor White
    Write-Host "   - Access: Only you (local storage)" -ForegroundColor White
    Write-Host ""
    Write-Host "6. DATA SHARING" -ForegroundColor Yellow
    Write-Host "   - NO data is shared with third parties" -ForegroundColor Green
    Write-Host "   - NO data is transmitted over the internet" -ForegroundColor Green
    Write-Host "   - All data remains on your local computer" -ForegroundColor Green
    Write-Host ""
    Write-Host "7. YOUR RIGHTS (GDPR)" -ForegroundColor Yellow
    Write-Host "   - Right to access (view logs)" -ForegroundColor White
    Write-Host "   - Right to rectification (edit consent)" -ForegroundColor White
    Write-Host "   - Right to erasure (delete all logs)" -ForegroundColor White
    Write-Host "   - Right to data portability (export data)" -ForegroundColor White
    Write-Host "   - Right to withdraw consent (disable logging)" -ForegroundColor White
    Write-Host ""
    Write-Host "8. DATA SECURITY" -ForegroundColor Yellow
    Write-Host "   - IP addresses are pseudonymized (last octet replaced with 'xxx')" -ForegroundColor White
    Write-Host "   - Logs stored with restricted file permissions" -ForegroundColor White
    Write-Host "   - Automatic log rotation to prevent excessive data retention" -ForegroundColor White
    Write-Host ""
    Write-Host "9. CONTACT" -ForegroundColor Yellow
    Write-Host "   This is an open-source tool. For questions, visit:" -ForegroundColor White
    Write-Host "   https://github.com/Dantdmnl/Network_Configuration_Script" -ForegroundColor Cyan
}

# Function to delete all logs (Right to be Forgotten)
function Remove-AllLogs {
    Write-Host ""
    Write-Host "=== Right to be Forgotten ===" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "This will permanently delete:" -ForegroundColor Yellow
    Write-Host "  - All log files" -ForegroundColor White
    Write-Host "  - All rotated log archives" -ForegroundColor White
    Write-Host "  - Consent record (you will be asked again)" -ForegroundColor White
    Write-Host ""
    Write-Host "Note: Configuration files (IP settings, interface) will NOT be deleted." -ForegroundColor Gray
    Write-Host ""
    
    $confirm = (Read-Host "Are you sure you want to delete all logs? (yes/no)").Trim().ToLower()
    
    if ($confirm -eq 'yes') {
        $deletedCount = 0
        
        # Delete main log file
        if (Test-Path $script:LogFile) {
            Remove-Item -Path $script:LogFile -Force
            $deletedCount++
            Write-Host "  [OK] Deleted main log file" -ForegroundColor Green
        }
        
        # Delete rotated logs
        for ($i = 1; $i -le $script:MaxLogArchives; $i++) {
            $archiveLog = "$script:LogFile.$i.log"
            if (Test-Path $archiveLog) {
                Remove-Item -Path $archiveLog -Force
                $deletedCount++
                Write-Host "  [OK] Deleted log archive $i" -ForegroundColor Green
            }
        }
        
        # Delete consent file
        if (Test-Path $script:ConsentPath) {
            Remove-Item -Path $script:ConsentPath -Force
            Write-Host "  [OK] Deleted consent record" -ForegroundColor Green
        }
        
        $script:LoggingConsent = $false
        
        Write-Host ""
        Write-Host "[OK] Successfully deleted $deletedCount log file(s)" -ForegroundColor Green
        Write-Host "  Your data has been erased." -ForegroundColor Green
    } else {
        Write-Host "[X] Deletion cancelled" -ForegroundColor Yellow
    }
}

# Function to update consent
function Update-GDPRConsent {
    Write-Host ""
    Write-Host "=== Change Logging Consent ===" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Current Status: " -NoNewline
    if ($script:LoggingConsent) {
        Write-Host "Logging ENABLED" -ForegroundColor Green
    } else {
        Write-Host "Logging DISABLED" -ForegroundColor Red
    }
    Write-Host ""
    
    $newConsent = (Read-Host "Enable logging? (y/n)").Trim().ToLower()
    
    $script:LoggingConsent = ($newConsent -eq 'y')
    
    $consentData = @{
        LoggingConsent = $script:LoggingConsent
        PseudonymizeData = $true
        ConsentDate = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        Version = "2.3"
    }
    $consentData | ConvertTo-Json | Set-Content -Path $script:ConsentPath
    
    Write-Host ""
    if ($script:LoggingConsent) {
        Write-Host "[OK] Logging enabled" -ForegroundColor Green
    } else {
        Write-Host "[OK] Logging disabled" -ForegroundColor Yellow
    }
}

# Function to export user data (Data Portability)
function Export-UserData {
    Write-Host ""
    Write-Host "=== Data Portability ===" -ForegroundColor Cyan
    Write-Host ""
    
    $exportPath = Join-Path $env:USERPROFILE "Desktop\NetworkScript_DataExport_$(Get-Date -Format 'yyyyMMdd_HHmmss').zip"
    
    try {
        $tempDir = Join-Path $env:TEMP "NetworkScript_Export_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        New-Item -Path $tempDir -ItemType Directory -Force | Out-Null
        
        # Copy all data files
        $filesToExport = @(
            @{Path = $script:LogFile; Name = "logs\network_config.log"},
            @{Path = $script:ConfigPath; Name = "config\IPConfiguration.xml"},
            @{Path = $script:ConsentPath; Name = "consent\gdpr_consent.txt"},
            @{Path = $script:InterfacePath; Name = "config\selected_interface.txt"}
        )
        
        foreach ($file in $filesToExport) {
            if (Test-Path $file.Path) {
                $destDir = Join-Path $tempDir (Split-Path $file.Name)
                if (-not (Test-Path $destDir)) {
                    New-Item -Path $destDir -ItemType Directory -Force | Out-Null
                }
                Copy-Item -Path $file.Path -Destination (Join-Path $tempDir $file.Name) -Force
            }
        }
        
        # Copy rotated logs
        for ($i = 1; $i -le $script:MaxLogArchives; $i++) {
            $archiveLog = "$script:LogFile.$i.log"
            if (Test-Path $archiveLog) {
                $logsDir = Join-Path $tempDir "logs"
                Copy-Item -Path $archiveLog -Destination (Join-Path $logsDir "network_config.$i.log") -Force
            }
        }
        
        # Create README
        $readme = @"
NETWORK CONFIGURATION SCRIPT - DATA EXPORT
Export Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Script Version: 2.2

This archive contains all data collected by the Network Configuration Script.

CONTENTS:
- logs/           : All log files (current and rotated)
- config/         : Network configuration files
- consent/        : GDPR consent record

DATA FORMAT:
- Logs are in JSON format
- Configuration files are in XML format
- All IP addresses are pseudonymized (last octet replaced with 'xxx')

YOUR RIGHTS:
You have the right to:
- Access this data at any time
- Request deletion of all data
- Withdraw consent for logging
- Receive data in a portable format (this export)

For more information, visit:
https://github.com/Dantdmnl/Network_Configuration_Script
"@
        $readme | Set-Content -Path (Join-Path $tempDir "README.txt")
        
        # Create ZIP archive
        Compress-Archive -Path "$tempDir\*" -DestinationPath $exportPath -Force
        
        # Cleanup temp directory
        Remove-Item -Path $tempDir -Recurse -Force
        
        Write-Host "[OK] Data exported successfully!" -ForegroundColor Green
        Write-Host "  Location: $exportPath" -ForegroundColor Cyan
        Write-Host ""
        
        $openExport = (Read-Host "Open export location? (y/n)").Trim().ToLower()
        if ($openExport -eq 'y') {
            Start-Process -FilePath "explorer.exe" -ArgumentList "/select,`"$exportPath`""
        }
    } catch {
        Write-Host "[X] Error exporting data: $_" -ForegroundColor Red
    }
}

# Check GDPR consent on script start
Get-GDPRConsent
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
    
    # Respect GDPR consent - only log if user consented
    if (-not $script:LoggingConsent) { return }
    
    if ($script:LogLevels[$Level] -lt $script:LogLevels[$script:MinLogLevel]) { return }
    
    # Pseudonymize IP addresses in the message
    if ($script:PseudonymizeData) {
        # Match IPv4 addresses and pseudonymize them
        $Message = $Message -replace '\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.)\d{1,3}\b', '${1}xxx'
        
        # Match common IPv6 patterns and pseudonymize
        $Message = $Message -replace '([0-9a-fA-F]{1,4}:){6}[0-9a-fA-F]{1,4}', '$&:xxxx:xxxx'
    }
    
    Invoke-LogRotation
    $logEntry = "{""timestamp"": ""$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"", ""level"": ""$Level"", ""message"": ""$Message""}"
    $logEntry | Out-File -FilePath $script:LogFile -Append -Encoding UTF8
}
#endregion

Write-LogMessage -Message "Script initialized." -Level "INFO"

# Loading animation function with progress steps
function Show-LoadingAnimation {
    param (
        [string]$Message = "Initializing",
        [string[]]$Steps = @(),
        [int]$StepDelayMs = 300
    )
    
    if ($Steps.Count -eq 0) {
        # Simple loading with progress dots
        Write-Host -NoNewline "$Message"
        for ($i = 0; $i -lt 3; $i++) {
            Write-Host -NoNewline "."
            Start-Sleep -Milliseconds 200
        }
        Write-Host " [OK]" -ForegroundColor Green
    } else {
        # Multi-step loading with checkmarks
        Write-Host $Message -ForegroundColor Cyan
        foreach ($step in $Steps) {
            Write-Host -NoNewline "  [" -ForegroundColor Gray
            Write-Host -NoNewline "..." -ForegroundColor Yellow
            Write-Host -NoNewline "]" -ForegroundColor Gray
            Write-Host -NoNewline " $step"
            Start-Sleep -Milliseconds $StepDelayMs
            Write-Host "`r  " -NoNewline
            Write-Host "[OK]" -ForegroundColor Green -NoNewline
            Write-Host " $step"
        }
    }
}

# Extract version dynamically from the script header
$script:ScriptVersion = "Unknown"
try {
    $scriptContent = Get-Content -Path $MyInvocation.MyCommand.Path -TotalCount 5
    $versionLine = $scriptContent | Where-Object { $_ -match "^# Version:" } | Select-Object -First 1
    if ($versionLine) {
        $script:ScriptVersion = ($versionLine -replace "^# Version:\s*", "").Trim()
    }
} catch {
    # Keep default version if extraction fails (using default: "Unknown")
    Write-LogMessage -Message "Could not extract version from script header: $_" -Level "DEBUG"
}

# Function to open the log file
function Open-LogFile {
    if (Test-Path -Path $script:LogFile) {
        Start-Process -FilePath "notepad.exe" -ArgumentList $script:LogFile
    } else {
        Write-Host "Log file not found." -ForegroundColor Red
    }
}

function Update-NetworkScript {
    param (
        [string]$RemoteScriptURL = "https://raw.githubusercontent.com/Dantdmnl/Network_Configuration_Script/refs/heads/main/Network_Configuration.ps1"
    )

    # Define the user's profile path for version tracking
    $versionFilePath = $script:VersionPath

    # Determine the current script path
    $CurrentScriptPath = if ($MyInvocation.MyCommand.Path -and (Test-Path $MyInvocation.MyCommand.Path)) {
        $MyInvocation.MyCommand.Path
    } elseif ($PSScriptRoot -and $PSScriptRoot -ne "") {
        Join-Path -Path $PSScriptRoot -ChildPath (Split-Path -Leaf $PSCommandPath)
    } else {
        Write-Host "Unable to determine the script's current path automatically. Please provide the script's full path." -ForegroundColor Yellow
        $manualPath = (Read-Host "Enter the full path to the current script").Trim()
        if (-not (Test-Path $manualPath)) {
            Write-Host "Error: The specified path does not exist." -ForegroundColor Red
            Write-LogMessage -Message "Manual script path not found: $manualPath" -Level "ERROR"
            return
        }
        $manualPath
    }
    
    if (-not $CurrentScriptPath) {
        Write-Host "Error: Could not determine script path. Update cancelled." -ForegroundColor Red
        Write-LogMessage -Message "Could not determine script path for update." -Level "ERROR"
        return
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
        try {
            $remoteVer = [version]$RemoteVersion
            $currentVer = [version]$currentVersion
            
            if ($remoteVer -gt $currentVer) {
                Write-Host "An updated version of the script is available (Current: $currentVersion, Remote: $RemoteVersion)." -ForegroundColor Cyan
                Write-LogMessage -Message "An updated version of the script is available (Current: $currentVersion, Remote: $RemoteVersion)." -Level "WARN"

                # Ask the user if they want to update
                $Response = (Read-Host "Would you like to update to the latest version? (y/n)").Trim()
                if ($Response -eq 'y') {
                    # Backup the current script (with timestamp to avoid overwrites)
                    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                    $BackupPath = "$CurrentScriptPath.bak_$timestamp"
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
            } elseif ($remoteVer -eq $currentVer) {
                Write-Host "The script is up-to-date (Version: $currentVersion)." -ForegroundColor Green
                Write-LogMessage -Message "The script is up-to-date (Version: $currentVersion)." -Level "INFO"
            } else {
                Write-Host "Your version ($currentVersion) is newer than the remote version ($RemoteVersion)." -ForegroundColor Yellow
                Write-LogMessage -Message "Local version ($currentVersion) is newer than remote ($RemoteVersion)." -Level "INFO"
            }
        } catch {
            Write-Host "Error comparing versions: $_" -ForegroundColor Red
            Write-LogMessage -Message "Error comparing versions (Current: $currentVersion, Remote: $RemoteVersion): $_" -Level "ERROR"
            return
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
    
    # Check if it's a prefix length (8-32 or /8-/32)
    if ($SubnetInput -match "^/?([8-9]|[12][0-9]|3[0-2])$") {
        return $true
    }
    
    # Check if it's a valid subnet mask notation
    if ($SubnetInput -match "^\d+(\.\d+){3}$") {
        try {
            $octets = $SubnetInput -split '\.'
            
            # Validate each octet is 0-255
            foreach ($octet in $octets) {
                $num = [int]$octet
                if ($num -lt 0 -or $num -gt 255) {
                    return $false
                }
            }
            
            # Convert to binary and check if it's a valid subnet mask
            $binaryMask = ""
            foreach ($octet in $octets) {
                $binaryMask += [Convert]::ToString([int]$octet, 2).PadLeft(8, '0')
            }
            
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
            $userInput = (Read-Host "$Prompt (default: $DefaultValue)").Trim()
            if ([string]::IsNullOrWhiteSpace($userInput)) { 
                $userInput = $DefaultValue 
            }
        } else {
            $userInput = (Read-Host $Prompt).Trim()
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

# Subnet Calculator Function
# Inspired by various PowerShell subnet calculator implementations from the community
# This function provides comprehensive subnet calculations for network planning
function Invoke-SubnetCalculator {
    param (
        [Parameter(Mandatory=$false)]
        [string]$IPAddress,
        
        [Parameter(Mandatory=$false)]
        [string]$SubnetMask,
        
        [Parameter(Mandatory=$false)]
        [int]$CIDR
    )
    
    Write-Host ""
    Write-Host ("="*70) -ForegroundColor Cyan
    Write-Host "Subnet Calculator" -ForegroundColor Cyan
    Write-Host ("="*70) -ForegroundColor Cyan
    Write-Host ""
    
    # Helper function to convert IP to binary
    function ConvertTo-Binary {
        param ([string]$IPAddress)
        $octets = $IPAddress -split '\.'
        $binary = ""
        foreach ($octet in $octets) {
            $binary += [Convert]::ToString([int]$octet, 2).PadLeft(8, '0')
        }
        return $binary
    }
    
    # Helper function to convert binary to IP
    function ConvertFrom-Binary {
        param ([string]$Binary)
        $ip = @()
        for ($i = 0; $i -lt 32; $i += 8) {
            $ip += [Convert]::ToInt32($Binary.Substring($i, 8), 2)
        }
        return $ip -join '.'
    }
    
    # Helper function to convert CIDR to subnet mask
    function ConvertTo-SubnetMask {
        param ([int]$CIDR)
        if ($CIDR -lt 0 -or $CIDR -gt 32) {
            throw "CIDR must be between 0 and 32"
        }
        $binary = ('1' * $CIDR).PadRight(32, '0')
        return ConvertFrom-Binary -Binary $binary
    }
    
    # Helper function to convert subnet mask to CIDR
    function ConvertTo-CIDR {
        param ([string]$SubnetMask)
        $binary = ConvertTo-Binary -IPAddress $SubnetMask
        return ($binary -replace '0', '').Length
    }
    
    # Interactive mode if parameters not provided
    if (-not $IPAddress) {
        $IPAddress = (Read-Host "Enter IP Address (e.g., 192.168.1.10)").Trim()
        # Validate IP address
        if (-not (Test-ValidIPAddress -IPAddress $IPAddress)) {
            Write-Host "Invalid IP address format. Please enter a valid IPv4 address." -ForegroundColor Red
            return
        }
    }
    
    if (-not $SubnetMask -and -not $CIDR) {
        $maskInput = (Read-Host "Enter Subnet Mask or CIDR (e.g., 255.255.255.0 or 24 or /24)").Trim()
        
        # Parse and validate input
        if ($maskInput -match "^/?([8-9]|[12][0-9]|3[0-2])$") {
            # CIDR notation with or without /
            $CIDR = [int]($maskInput -replace "/", "")
        } elseif ($maskInput -match "^\d+\.\d+\.\d+\.\d+$") {
            # Dotted decimal subnet mask
            if (Test-ValidSubnetMask -SubnetInput $maskInput) {
                $SubnetMask = $maskInput
            } else {
                Write-Host "Invalid subnet mask. Please enter a valid subnet mask (e.g., 255.255.255.0)." -ForegroundColor Red
                return
            }
        } else {
            Write-Host "Invalid format. Please enter a subnet mask (255.255.255.0) or CIDR notation (24 or /24)." -ForegroundColor Red
            return
        }
    }
    
    # Validate CIDR if provided
    if ($CIDR) {
        if ($CIDR -lt 8 -or $CIDR -gt 32) {
            Write-Host "Invalid CIDR value. CIDR must be between 8 and 32." -ForegroundColor Red
            return
        }
    }
    
    # Convert between CIDR and subnet mask if needed
    if ($CIDR -and -not $SubnetMask) {
        try {
            if ($CIDR -lt 8 -or $CIDR -gt 32) {
                Write-Host "Invalid CIDR value. CIDR must be between 8 and 32." -ForegroundColor Red
                return
            }
            $SubnetMask = ConvertTo-SubnetMask -CIDR $CIDR
        } catch {
            Write-Host "Error converting CIDR to subnet mask: $_" -ForegroundColor Red
            return
        }
    } elseif ($SubnetMask -and -not $CIDR) {
        try {
            if (-not (Test-ValidSubnetMask -SubnetInput $SubnetMask)) {
                Write-Host "Invalid subnet mask format. Please enter a valid subnet mask." -ForegroundColor Red
                return
            }
            $CIDR = ConvertTo-CIDR -SubnetMask $SubnetMask
        } catch {
            Write-Host "Error converting subnet mask to CIDR: $_" -ForegroundColor Red
            return
        }
    }
    
    # Calculate network information
    try {
        $ipBinary = ConvertTo-Binary -IPAddress $IPAddress
        $maskBinary = ConvertTo-Binary -IPAddress $SubnetMask
        
        # Calculate network address (IP AND Mask)
        $networkBinary = ""
        for ($i = 0; $i -lt 32; $i++) {
            if ($ipBinary[$i] -eq '1' -and $maskBinary[$i] -eq '1') {
                $networkBinary += '1'
            } else {
                $networkBinary += '0'
            }
        }
        $networkAddress = ConvertFrom-Binary -Binary $networkBinary
        
        # Calculate broadcast address (Network OR NOT Mask)
        $broadcastBinary = ""
        for ($i = 0; $i -lt 32; $i++) {
            if ($maskBinary[$i] -eq '0') {
                $broadcastBinary += '1'
            } else {
                $broadcastBinary += $networkBinary[$i]
            }
        }
        $broadcastAddress = ConvertFrom-Binary -Binary $broadcastBinary
        
        # Calculate wildcard mask (bitwise NOT of subnet mask)
        $wildcardBinary = $maskBinary -replace '1', 'X' -replace '0', '1' -replace 'X', '0'
        $wildcardMask = ConvertFrom-Binary -Binary $wildcardBinary
        
        # Calculate first and last usable IP
        $firstIPOctets = $networkAddress -split '\.'
        $firstIPOctets[3] = [string]([int]$firstIPOctets[3] + 1)
        $firstUsableIP = $firstIPOctets -join '.'
        
        $lastIPOctets = $broadcastAddress -split '\.'
        $lastIPOctets[3] = [string]([int]$lastIPOctets[3] - 1)
        $lastUsableIP = $lastIPOctets -join '.'
        
        # Calculate total hosts
        $hostBits = 32 - $CIDR
        $totalHosts = [Math]::Pow(2, $hostBits)
        $usableHosts = if ($CIDR -eq 32) { 1 } elseif ($CIDR -eq 31) { 2 } else { $totalHosts - 2 }
        
        # Determine network class
        $firstOctet = [int]($IPAddress -split '\.')[0]
        $networkClass = if ($firstOctet -ge 1 -and $firstOctet -le 126) { "A" }
                       elseif ($firstOctet -ge 128 -and $firstOctet -le 191) { "B" }
                       elseif ($firstOctet -ge 192 -and $firstOctet -le 223) { "C" }
                       elseif ($firstOctet -ge 224 -and $firstOctet -le 239) { "D (Multicast)" }
                       elseif ($firstOctet -ge 240 -and $firstOctet -le 255) { "E (Reserved)" }
                       else { "Invalid" }
        
        # Check if private IP
        $isPrivate = ($IPAddress -match '^10\.') -or 
                     ($IPAddress -match '^172\.(1[6-9]|2[0-9]|3[0-1])\.') -or 
                     ($IPAddress -match '^192\.168\.')
        
        # Display results
        Write-Host "Network Information:" -ForegroundColor Green
        Write-Host ("-"*70) -ForegroundColor Gray
        Write-Host ("IP Address:".PadRight(25)) -NoNewline -ForegroundColor Yellow
        Write-Host "$IPAddress" -ForegroundColor White
        Write-Host ("Subnet Mask:".PadRight(25)) -NoNewline -ForegroundColor Yellow
        Write-Host "$SubnetMask" -ForegroundColor White
        Write-Host ("CIDR Notation:".PadRight(25)) -NoNewline -ForegroundColor Yellow
        Write-Host "/$CIDR" -ForegroundColor White
        Write-Host ("Wildcard Mask:".PadRight(25)) -NoNewline -ForegroundColor Yellow
        Write-Host "$wildcardMask" -ForegroundColor White
        Write-Host ""
        
        Write-Host ("Network Address:".PadRight(25)) -NoNewline -ForegroundColor Yellow
        Write-Host "$networkAddress" -ForegroundColor Cyan
        Write-Host ("Broadcast Address:".PadRight(25)) -NoNewline -ForegroundColor Yellow
        Write-Host "$broadcastAddress" -ForegroundColor Cyan
        Write-Host ("First Usable IP:".PadRight(25)) -NoNewline -ForegroundColor Yellow
        Write-Host "$firstUsableIP" -ForegroundColor White
        Write-Host ("Last Usable IP:".PadRight(25)) -NoNewline -ForegroundColor Yellow
        Write-Host "$lastUsableIP" -ForegroundColor White
        Write-Host ""
        
        Write-Host ("Total Hosts:".PadRight(25)) -NoNewline -ForegroundColor Yellow
        Write-Host "$totalHosts" -ForegroundColor White
        Write-Host ("Usable Hosts:".PadRight(25)) -NoNewline -ForegroundColor Yellow
        Write-Host "$usableHosts" -ForegroundColor White
        Write-Host ""
        
        Write-Host ("Network Class:".PadRight(25)) -NoNewline -ForegroundColor Yellow
        Write-Host "$networkClass" -ForegroundColor White
        Write-Host ("IP Type:".PadRight(25)) -NoNewline -ForegroundColor Yellow
        if ($isPrivate) {
            Write-Host "Private" -ForegroundColor Green
        } else {
            Write-Host "Public" -ForegroundColor Cyan
        }
        Write-Host ""
        
        # Binary representation section
        Write-Host "Binary Representation:" -ForegroundColor Green
        Write-Host ("-"*70) -ForegroundColor Gray
        Write-Host ("IP Address:".PadRight(25)) -NoNewline -ForegroundColor Yellow
        Write-Host "$($ipBinary.Substring(0,8)).$($ipBinary.Substring(8,8)).$($ipBinary.Substring(16,8)).$($ipBinary.Substring(24,8))" -ForegroundColor Gray
        Write-Host ("Subnet Mask:".PadRight(25)) -NoNewline -ForegroundColor Yellow
        Write-Host "$($maskBinary.Substring(0,8)).$($maskBinary.Substring(8,8)).$($maskBinary.Substring(16,8)).$($maskBinary.Substring(24,8))" -ForegroundColor Gray
        Write-Host ("Network Address:".PadRight(25)) -NoNewline -ForegroundColor Yellow
        Write-Host "$($networkBinary.Substring(0,8)).$($networkBinary.Substring(8,8)).$($networkBinary.Substring(16,8)).$($networkBinary.Substring(24,8))" -ForegroundColor Gray
        Write-Host ""
        
        # Subnetting guide
        if ($CIDR -lt 30) {
            Write-Host "Quick Subnetting Reference:" -ForegroundColor Green
            Write-Host ("-"*70) -ForegroundColor Gray
            Write-Host "To create smaller subnets, increase CIDR (fewer hosts per subnet)" -ForegroundColor White
            Write-Host "Examples for this network:" -ForegroundColor Yellow
            
            $suggestions = @(
                @{ CIDR = $CIDR + 1; Desc = "Split into 2 subnets" },
                @{ CIDR = $CIDR + 2; Desc = "Split into 4 subnets" },
                @{ CIDR = $CIDR + 3; Desc = "Split into 8 subnets" }
            )
            
            foreach ($suggestion in $suggestions) {
                if ($suggestion.CIDR -le 30) {
                    $newHosts = [Math]::Pow(2, (32 - $suggestion.CIDR)) - 2
                    Write-Host "  /$($suggestion.CIDR) - $($suggestion.Desc) with $newHosts usable hosts each" -ForegroundColor White
                }
            }
        }
        
        Write-Host ""
        Write-Host ("="*70) -ForegroundColor Cyan
        
        Write-LogMessage -Message "Subnet calculation performed: $IPAddress/$CIDR" -Level "INFO"
        
    } catch {
        Write-Host "Error during subnet calculation: $_" -ForegroundColor Red
        Write-LogMessage -Message "Error during subnet calculation: $_" -Level "ERROR"
    }
}

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
        $GatewayInput = (Read-Host "Enter Gateway [Enter=.1, 254=.254, or last octet, full IP, 'none' to skip]").Trim()

        $Gateway = $null
        switch ($GatewayInput.ToLower()) {
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
            $PrimaryDNSInput = (Read-Host "Enter Primary DNS (default: 1.1.1.1)").Trim()
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
                $SecondaryDNSInput = (Read-Host "Enter Secondary DNS [Enter to use suggested: $suggestedSecondary, type 'none' to skip]").Trim()
                if ($SecondaryDNSInput -eq "") {
                    $SecondaryDNS = $suggestedSecondary
                    Write-LogMessage -Message "Using suggested secondary DNS: $suggestedSecondary" -Level "INFO"
                    break
                } elseif ($SecondaryDNSInput.ToLower() -eq "none") {
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

        $confirmation = (Read-Host "`nProceed with this configuration? (y/n, default: y)").Trim()
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

    Write-Host "Configuring static IP..." -ForegroundColor Cyan
    Write-LogMessage -Message "Setting static IP configuration for interface: $InterfaceName" -Level "INFO"

    try {
        # Verify interface exists
        $null = Get-NetAdapter -Name $InterfaceName -ErrorAction Stop
        Write-LogMessage -Message "Interface verification successful: $InterfaceName" -Level "INFO"

        # Convert subnet mask to prefix length
        $prefixLength = Get-PrefixLength -SubnetInput $SubnetMask
        Write-LogMessage -Message "Subnet mask processed: $SubnetMask = /$prefixLength" -Level "INFO"

        # Check if the IP address is already configured on this interface
        Write-Host "  Checking existing configuration..." -ForegroundColor Gray
        $existingIPv4 = Get-NetIPAddress -InterfaceAlias $InterfaceName -AddressFamily IPv4 -ErrorAction SilentlyContinue
        $ipAlreadyConfigured = $false
        
        if ($existingIPv4) {
            # Check if the exact IP and prefix length match
            $matchingIP = $existingIPv4 | Where-Object { $_.IPAddress -eq $IPAddress -and $_.PrefixLength -eq $prefixLength }
            if ($matchingIP) {
                $ipAlreadyConfigured = $true
                Write-LogMessage -Message "IP address $IPAddress/$prefixLength is already configured on interface $InterfaceName. Skipping IP removal/addition." -Level "INFO"
            } else {
                # Remove existing IPv4 addresses only if different
                $existingIPv4 | Remove-NetIPAddress -Confirm:$false -ErrorAction Stop
                Write-LogMessage -Message "Removed existing IPv4 addresses from interface $InterfaceName" -Level "INFO"
            }
        }

        # Remove existing default route ONLY if no other adapters are using it
        Write-Host "  Managing gateway route..." -ForegroundColor Gray
        $existingRoute = Get-NetRoute -InterfaceAlias $InterfaceName -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue
        if ($existingRoute) {
            # Check if other adapters have the same default route
            $allDefaultRoutes = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue
            $otherAdapterRoutes = $allDefaultRoutes | Where-Object { $_.InterfaceAlias -ne $InterfaceName }
            
            if ($otherAdapterRoutes) {
                Write-LogMessage -Message "Default route exists on other adapters. Not removing route from $InterfaceName" -Level "INFO"
            } else {
                # Safe to remove - no other adapters use this route
                $existingRoute | Remove-NetRoute -Confirm:$false -ErrorAction Stop
                Write-LogMessage -Message "Removed default route from interface $InterfaceName" -Level "INFO"
            }
        }

        # Prepare new static IP parameters
        Write-Host "  Applying IP configuration..." -ForegroundColor Gray
        $params = @{
            InterfaceAlias = $InterfaceName
            IPAddress      = $IPAddress
            PrefixLength   = $prefixLength
        }
        if ($Gateway) {
            $params["DefaultGateway"] = $Gateway
        } else {
            Write-LogMessage -Message "No Gateway specified. Skipping Default Gateway configuration." -Level "WARN"
        }

        # Apply new static IP only if not already configured
        if (-not $ipAlreadyConfigured) {
            New-NetIPAddress @params -ErrorAction Stop > $null
            Write-LogMessage -Message "Applied new static IP configuration: $IPAddress/$prefixLength" -Level "INFO"
        } elseif ($Gateway) {
            # IP is already set, but we may need to update/add the gateway
            try {
                $existingGateway = Get-NetRoute -InterfaceAlias $InterfaceName -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue
                if (-not $existingGateway -or $existingGateway.NextHop -ne $Gateway) {
                    # Remove old gateway if it exists and is different
                    if ($existingGateway) {
                        $existingGateway | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
                    }
                    # Add new gateway
                    New-NetRoute -InterfaceAlias $InterfaceName -DestinationPrefix "0.0.0.0/0" -NextHop $Gateway -ErrorAction Stop > $null
                    Write-LogMessage -Message "Updated gateway to $Gateway" -Level "INFO"
                }
            } catch {
                Write-LogMessage -Message "Warning: Could not update gateway: $_" -Level "WARN"
            }
        }

        # Prepare DNS list
        Write-Host "  Configuring DNS..." -ForegroundColor Gray
        $dnsServers = @()
        if ($PrimaryDNS) { $dnsServers += $PrimaryDNS }
        if ($SecondaryDNS) { $dnsServers += $SecondaryDNS }

        if ($dnsServers.Count -gt 0) {
            Set-DnsClientServerAddress -InterfaceAlias $InterfaceName -ServerAddresses $dnsServers -ErrorAction Stop
            Write-LogMessage -Message "DNS servers configured: $($dnsServers -join ', ')" -Level "INFO"
        } else {
            Write-LogMessage -Message "No DNS servers specified. Skipping DNS configuration." -Level "WARN"
        }

        # Show summary
        Write-Host "`n[OK] Static IP configuration successful" -ForegroundColor Green
        $ipConfig = Get-NetIPConfiguration -InterfaceAlias $InterfaceName -ErrorAction Stop
        Write-Host "Current IP configuration for interface: $InterfaceName" -ForegroundColor Cyan
        Write-Host "IP Address: $($ipConfig.IPv4Address.IPAddress)" -ForegroundColor White
        Write-Host "Subnet Mask: /$($ipConfig.IPv4Address.PrefixLength)" -ForegroundColor White
        
        if ($ipConfig.IPv4DefaultGateway) {
            Write-Host "Default Gateway: $($ipConfig.IPv4DefaultGateway.NextHop)" -ForegroundColor White
        } else {
            Write-Host "Default Gateway: (not set)" -ForegroundColor DarkYellow
        }
        
        # Filter DNS servers to show only IPv4 addresses
        if ($ipConfig.DnsServer -and $ipConfig.DnsServer.ServerAddresses) {
            $ipv4DnsServers = $ipConfig.DnsServer.ServerAddresses | Where-Object { $_ -match "^\d+\.\d+\.\d+\.\d+$" }
            if ($ipv4DnsServers) {
                Write-Host "DNS Servers (IPv4): $($ipv4DnsServers -join ', ')" -ForegroundColor White
            } else {
                Write-Host "DNS Servers (IPv4): (none configured)" -ForegroundColor DarkYellow
            }
        } else {
            Write-Host "DNS Servers (IPv4): (none configured)" -ForegroundColor DarkYellow
        }
        
        Write-LogMessage -Message "Static IP configuration applied successfully." -Level "INFO"
    } catch {
        $errorMessage = "Error: Unable to set static IP configuration. $_"
        Write-Host ""
        Write-Host "[FAIL] Configuration failed: $errorMessage" -ForegroundColor Red
        Write-LogMessage -Message $errorMessage -Level "CRITICAL"
    }
}

# Function to set DHCP configuration (optimized for speed and robustness)
function Set-DHCP {
    param (
        [string]$InterfaceName,
        [int]$MaxRetries = 3,
        [int]$RetryDelaySeconds = 2
    )

    # Input validation
    if ([string]::IsNullOrWhiteSpace($InterfaceName)) {
        Write-Host "Error: No interface name provided." -ForegroundColor Red
        Write-LogMessage -Message "Error: No interface name provided for DHCP configuration." -Level "ERROR"
        return $false
    }

    Write-LogMessage -Message "Switching to DHCP for interface: $InterfaceName" -Level "INFO"

    # Validate interface exists and is operational
    try {
        $interface = Get-NetAdapter -Name $InterfaceName -ErrorAction Stop
        if ($interface.Status -ne "Up") {
            Write-Host "Warning: Interface '$InterfaceName' is not 'Up' (status: $($interface.Status))" -ForegroundColor Yellow
            Write-LogMessage -Message "Interface '$InterfaceName' status: $($interface.Status)" -Level "WARN"
        }
    } catch {
        Write-Host "Error: Interface '$InterfaceName' not found." -ForegroundColor Red
        Write-LogMessage -Message "Interface '$InterfaceName' not found: $_" -Level "ERROR"
        return $false
    }

    # Retry mechanism for DHCP configuration
    for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {
        try {
            if ($MaxRetries -gt 1) {
                Write-Host "Configuring DHCP (attempt $attempt/$MaxRetries)..." -ForegroundColor Cyan
            } else {
                Write-Host "Configuring DHCP..." -ForegroundColor Cyan
            }
            
            # Step 1: Clear existing IP configuration (parallel operations where possible)
            Write-Host "  Releasing existing configuration..." -ForegroundColor Gray
            
            # Remove existing IP addresses (IPv4 only for speed)
            $existingIPs = Get-NetIPAddress -InterfaceAlias $InterfaceName -AddressFamily IPv4 -ErrorAction SilentlyContinue
            if ($existingIPs) {
                $existingIPs | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
            }

            # Step 2: Enable DHCP and reset DNS in parallel
            Write-Host "  Enabling DHCP..." -ForegroundColor Gray
            
            # Use jobs for parallel execution
            $dhcpJob = Start-Job -ScriptBlock {
                Set-NetIPInterface -InterfaceAlias $using:InterfaceName -Dhcp Enabled -ErrorAction Stop
            }

            $dnsJob = Start-Job -ScriptBlock {
                Set-DnsClientServerAddress -InterfaceAlias $using:InterfaceName -ResetServerAddresses -ErrorAction Stop
            }

            # Wait for both jobs to complete
            Wait-Job $dhcpJob, $dnsJob | Out-Null
            
            # Check for errors in parallel jobs
            $null = Receive-Job $dhcpJob -ErrorAction SilentlyContinue
            $null = Receive-Job $dnsJob -ErrorAction SilentlyContinue
            
            Remove-Job $dhcpJob, $dnsJob -Force

            # Step 3: Trigger DHCP renewal without disconnecting (important for Wi-Fi)
            Write-Host "  Renewing DHCP lease..." -ForegroundColor Gray
            
            # Use ipconfig /renew which doesn't disconnect Wi-Fi adapters
            # Try interface-specific renewal first, then fall back to full renew
            try {
                $null = & ipconfig /renew $InterfaceName 2>&1
            } catch {
                # If that fails, try full renewal
                $null = & ipconfig /renew 2>&1
            }

            # Step 4: Wait for DHCP lease with adaptive timeout
            $maxWait = 10 # Maximum wait time in seconds
            $waitInterval = 0.5 # Check every 500ms
            $waitTime = 0
            $dhcpSuccess = $false

            Write-Host "  Waiting for DHCP lease (timeout: ${maxWait}s)" -NoNewline -ForegroundColor Gray

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
                    # Continue waiting - interface may not be ready yet
                    Write-LogMessage -Message "Waiting for DHCP address assignment: $_" -Level "DEBUG"
                }
                
                Write-Host "." -NoNewline -ForegroundColor Gray
            }
            Write-Host "" # New line after dots

            # Step 5: Verify and display results
            if ($dhcpSuccess) {
                $ipConfig = Get-NetIPConfiguration -InterfaceAlias $InterfaceName -ErrorAction Stop
                Write-Host "`n[OK] DHCP configuration successful" -ForegroundColor Green
                Write-Host "Current IP configuration for interface: $InterfaceName" -ForegroundColor Cyan
                Write-Host "IP Address: $($ipConfig.IPv4Address.IPAddress)" -ForegroundColor White
                Write-Host "Subnet Mask: /$($ipConfig.IPv4Address.PrefixLength)" -ForegroundColor White
                
                if ($ipConfig.IPv4DefaultGateway) {
                    Write-Host "Default Gateway: $($ipConfig.IPv4DefaultGateway.NextHop)" -ForegroundColor White
                } else {
                    Write-Host "Default Gateway: (not set)" -ForegroundColor DarkYellow
                }
                
                # Filter DNS servers to show only IPv4 addresses
                if ($ipConfig.DnsServer -and $ipConfig.DnsServer.ServerAddresses) {
                    $ipv4DnsServers = $ipConfig.DnsServer.ServerAddresses | Where-Object { $_ -match "^\d+\.\d+\.\d+\.\d+$" }
                    if ($ipv4DnsServers) {
                        Write-Host "DNS Servers (IPv4): $($ipv4DnsServers -join ', ')" -ForegroundColor White
                    } else {
                        Write-Host "DNS Servers (IPv4): (none configured)" -ForegroundColor DarkYellow
                    }
                } else {
                    Write-Host "DNS Servers (IPv4): (none configured)" -ForegroundColor DarkYellow
                }
                
                Write-LogMessage -Message "DHCP configuration applied successfully for $InterfaceName in attempt $attempt." -Level "INFO"
                
                # Clear DNS cache for immediate effect
                Clear-DnsClientCache -ErrorAction SilentlyContinue
                
                return $true
            } else {
                # Check if we got APIPA address
                $ipConfig = Get-NetIPConfiguration -InterfaceAlias $InterfaceName -ErrorAction SilentlyContinue
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
        [string]$InterfaceName,
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
    $pingCount = if ($QuickTest) { 2 } else { 3 }
    foreach ($dns in $publicDnsServers) {
        $dnsJobs += Start-Job -ScriptBlock {
            try {
                $result = Test-Connection -ComputerName $using:dns -Count $using:pingCount -ErrorAction Stop
                if ($result) {
                    $avg = [math]::Round(($result | Measure-Object -Property ResponseTime -Average).Average, 1)
                    return @{ Server = $using:dns; Status = "Success"; AvgResponseTime = $avg }
                }
            } catch {
                return @{ Server = $using:dns; Status = "Failed"; Error = $_.Exception.Message }
            }
            return @{ Server = $using:dns; Status = "Failed"; Error = "No response" }
        }
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
    param ([string]$InterfaceName)

    if (-not $InterfaceName) {
        Write-Host "No network interface selected. Please choose one using option 6." -ForegroundColor Red
        return
    }

    try {
        $config = Get-NetIPConfiguration -InterfaceAlias $InterfaceName -ErrorAction Stop
        $ipv4 = $config.IPv4Address
        $gateway = $config.IPv4DefaultGateway
        
        Write-Host "Current IP configuration for interface: $InterfaceName" -ForegroundColor Cyan
        
        if ($ipv4 -and $ipv4.IPAddress) {
            Write-Host "IP Address: $($ipv4.IPAddress)" -ForegroundColor White
            Write-Host "Subnet Mask: /$($ipv4.PrefixLength)" -ForegroundColor White
        } else {
            Write-Host "IP Address: (not configured)" -ForegroundColor DarkYellow
        }
        
        if ($gateway) {
            Write-Host "Default Gateway: $($gateway.NextHop)" -ForegroundColor White
        } else {
            Write-Host "Default Gateway: (not set)" -ForegroundColor DarkYellow
        }
        
        # Filter DNS servers to show only IPv4 addresses
        if ($config.DnsServer -and $config.DnsServer.ServerAddresses) {
            $ipv4DnsServers = $config.DnsServer.ServerAddresses | Where-Object { $_ -match "^\d+\.\d+\.\d+\.\d+$" }
            if ($ipv4DnsServers) {
                Write-Host "DNS Servers (IPv4): $($ipv4DnsServers -join ', ')" -ForegroundColor White
            } else {
                Write-Host "DNS Servers (IPv4): (none configured)" -ForegroundColor DarkYellow
            }
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
        Write-Host "Press 'n' to rename an interface."
        Write-Host "Press 'q' to quit interface selection."

        $userChoice = (Read-Host "Your choice").Trim()

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
            "n" {
                # Rename interface
                Write-Host "`nRename Network Interface" -ForegroundColor Cyan
                $interfaceIndex = (Read-Host "Enter the interface number to rename").Trim()
                
                if ($interfaceIndex -match "^\d+$") {
                    $targetInterface = $interfaces | Where-Object { $_.InterfaceIndex -eq [int]$interfaceIndex }
                    
                    if ($targetInterface) {
                        Write-Host "Current name: $($targetInterface.Name)" -ForegroundColor Yellow
                        $newName = (Read-Host "Enter new name for this interface").Trim()
                        
                        if ([string]::IsNullOrWhiteSpace($newName)) {
                            Write-Host "Error: Interface name cannot be empty." -ForegroundColor Red
                            continue
                        }
                        
                        # Check if name already exists
                        $existingInterface = Get-NetAdapter | Where-Object { $_.Name -eq $newName }
                        if ($existingInterface) {
                            Write-Host "Error: An interface with the name '$newName' already exists." -ForegroundColor Red
                            continue
                        }
                        
                        try {
                            Rename-NetAdapter -Name $targetInterface.Name -NewName $newName -ErrorAction Stop
                            Write-Host "Successfully renamed interface to: $newName" -ForegroundColor Green
                            Write-LogMessage -Message "Interface renamed from '$($targetInterface.Name)' to '$newName'" -Level "INFO"
                            
                            # Update saved interface if it was the renamed one
                            $savedInterface = Get-SavedInterface
                            if ($savedInterface -eq $targetInterface.Name) {
                                Save-SelectedInterface -InterfaceName $newName
                                Write-Host "Updated saved interface selection to new name." -ForegroundColor Green
                            }
                            
                            Start-Sleep -Seconds 1
                        } catch {
                            Write-Host "Error renaming interface: $_" -ForegroundColor Red
                            Write-LogMessage -Message "Error renaming interface: $_" -Level "ERROR"
                        }
                    } else {
                        Write-Host "Invalid interface number." -ForegroundColor Red
                    }
                } else {
                    Write-Host "Invalid input. Please enter a valid number." -ForegroundColor Red
                }
                continue
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
    $host.UI.RawUI.WindowTitle = "Network Configuration - $interfaceName"
    
    # Show what's actually happening during initialization
    Write-Host "Initializing Network Configuration..." -ForegroundColor Cyan
    
    # Step 1: Verify saved interface
    Write-Host -NoNewline "  [...] Verifying saved interface '$interfaceName'" -ForegroundColor Gray
    Start-Sleep -Milliseconds 150
    try {
        $null = Get-NetAdapter -Name $interfaceName -ErrorAction Stop
        Write-Host "`r  [OK] Verifying saved interface '$interfaceName'                    " -ForegroundColor Green
        Write-LogMessage -Message "Interface '$interfaceName' verified successfully" -Level "INFO"
        
        # Step 2: Check interface status
        Write-Host -NoNewline "  [...] Checking interface status" -ForegroundColor Gray
        Start-Sleep -Milliseconds 150
        $adapterStatus = (Get-NetAdapter -Name $interfaceName).Status
        Write-Host "`r  [OK] Checking interface status ($adapterStatus)                    " -ForegroundColor Green
        
        # Step 3: Load IP configuration
        Write-Host -NoNewline "  [...] Loading IP configuration" -ForegroundColor Gray
        Start-Sleep -Milliseconds 150
        $null = Get-NetIPAddress -InterfaceAlias $interfaceName -AddressFamily IPv4 -ErrorAction SilentlyContinue
        Write-Host "`r  [OK] Loading IP configuration                    " -ForegroundColor Green
        
    } catch {
        Write-Host "`r  [FAIL] Verifying saved interface '$interfaceName'                    " -ForegroundColor Red
        Write-Host "         Previously selected interface no longer exists." -ForegroundColor Yellow
        Write-Host "         Please select a new interface using option 6." -ForegroundColor Yellow
        Write-LogMessage -Message "Previously selected interface '$interfaceName' no longer exists: $_" -Level "ERROR"
        $interfaceName = $null
    }
} else {
    # Show what's actually happening during first-time setup
    Write-Host "Initializing Network Configuration..." -ForegroundColor Cyan
    
    Write-Host -NoNewline "  [...] Detecting network adapters" -ForegroundColor Gray
    Start-Sleep -Milliseconds 150
    $adapters = Get-NetAdapter | Where-Object { $_.Status -ne 'Disabled' }
    Write-Host "`r  [OK] Detecting network adapters (Found: $($adapters.Count))                    " -ForegroundColor Green
    
    Write-Host -NoNewline "  [...] Loading configuration environment" -ForegroundColor Gray
    Start-Sleep -Milliseconds 150
    Write-Host "`r  [OK] Loading configuration environment                    " -ForegroundColor Green
    
    Write-Host ""
    Write-Host "No interface configured. Select one using option 6 to get started." -ForegroundColor Yellow
    Write-LogMessage -Message "First time setup detected - no interface configured" -Level "INFO"
}

if (-not $interfaceName) {
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

# Live Interface Monitoring
function Start-LiveInterfaceMonitor {
    param ([string]$InterfaceName)
    
    if ([string]::IsNullOrWhiteSpace($InterfaceName)) {
        Write-Host "No interface selected. Please select an interface first (Option 6)." -ForegroundColor Red
        Read-Host "Press Enter to continue"
        return
    }
    
    Clear-Host
    Write-Host "===========================================================================" -ForegroundColor Cyan
    Write-Host "                  LIVE NETWORK MONITORING                                 " -ForegroundColor Cyan
    Write-Host "===========================================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Interface: " -NoNewline -ForegroundColor Yellow
    Write-Host $InterfaceName -ForegroundColor White
    Write-Host ""
    Write-Host "Controls: (press key, case-insensitive)" -ForegroundColor Yellow
    Write-Host "  Q / Esc  - Exit monitoring" -ForegroundColor Gray
    Write-Host "  D        - Run network diagnostics" -ForegroundColor Gray
    Write-Host "  S        - Show current status" -ForegroundColor Gray
    Write-Host "  C        - Clear event log" -ForegroundColor Gray
    Write-Host ""
    Write-Host "===========================================================================" -ForegroundColor Cyan
    Write-Host ""
    
    # Previous state tracking
    $prev = @{
        Status = $null
        IP = $null
        DHCP = $null
        Gateway = $null
        DNS = $null
        Speed = $null
        WiFiSignal = $null
        WiFiSSID = $null
        DHCPServer = $null
        DHCPExpires = $null
    }
    
    $running = $true
    $eventCount = 0
    $lastEventTime = Get-Date
    $lastHeartbeat = Get-Date
    
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Monitoring started..." -ForegroundColor Green
    Write-Host ""
    Write-LogMessage -Message "Started live monitoring for interface '$InterfaceName'" -Level "INFO"
    
    try {
        while ($running) {
            # Get current state
            try {
                $adapter = Get-NetAdapter -Name $InterfaceName -ErrorAction Stop
                $ip = (Get-NetIPAddress -InterfaceAlias $InterfaceName -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1).IPAddress
                $ipIf = Get-NetIPInterface -InterfaceAlias $InterfaceName -AddressFamily IPv4 -ErrorAction SilentlyContinue
                $gw = (Get-NetRoute -InterfaceAlias $InterfaceName -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue | Select-Object -First 1).NextHop
                $dns = (Get-DnsClientServerAddress -InterfaceAlias $InterfaceName -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses -join ", "
                
                # WiFi info
                $wifi = $null
                try {
                    $wifiOutput = netsh wlan show interfaces 2>$null | Out-String
                    if ($wifiOutput -match $InterfaceName) {
                        $ssid = if ($wifiOutput -match "SSID\s+:\s+(.+)") { $matches[1].Trim() } else { $null }
                        $signal = if ($wifiOutput -match "Signal\s+:\s+(\d+)%") { $matches[1] } else { $null }
                        if ($ssid) { $wifi = @{ SSID = $ssid; Signal = $signal } }
                    }
                } catch {
                    # Silently continue if netsh fails
                    $null
                }
                
                # DHCP info
                $dhcpServer = $null
                $dhcpExpires = $null
                $dhcpObtained = $null
                if ($ipIf.Dhcp -eq "Enabled") {
                    try {
                        $ipconfigOutput = ipconfig /all | Out-String
                        # Try to find the section for this interface
                        $sections = $ipconfigOutput -split "`r?`n`r?`n"
                        foreach ($section in $sections) {
                            if ($section -match [regex]::Escape($InterfaceName) -or $section -match "adapter $InterfaceName") {
                                if ($section -match "DHCP Server[.\s]*:\s*([\d.]+)") { 
                                    $dhcpServer = $matches[1].Trim() 
                                }
                                if ($section -match "Lease Obtained[.\s]*:\s*(.+?)\r?\n") { 
                                    $dhcpObtained = $matches[1].Trim() 
                                }
                                if ($section -match "Lease Expires[.\s]*:\s*(.+?)\r?\n") { 
                                    $dhcpExpires = $matches[1].Trim() 
                                }
                                if ($dhcpServer) { break }
                            }
                        }
                    } catch {
                        # Silently continue if ipconfig parsing fails
                        $null
                    }
                }
                
                # Clear IP/Gateway/DNS if adapter is disconnected (Windows caches them)
                if ($adapter.Status -eq 'Disconnected') {
                    $ip = $null
                    $gw = $null
                    $dns = $null
                }
                
                $curr = @{
                    Status = $adapter.Status
                    IP = $ip
                    DHCP = $ipIf.Dhcp
                    Gateway = $gw
                    DNS = $dns
                    Speed = $adapter.LinkSpeed
                    WiFiSignal = $wifi.Signal
                    WiFiSSID = $wifi.SSID
                    DHCPServer = $dhcpServer
                    DHCPExpires = $dhcpExpires
                }
                
                $ts = Get-Date -Format "HH:mm:ss"
                
                # Update window title with live status
                $statusIcon = if ($curr.Status -eq 'Up') { '[UP]' } else { '[DOWN]' }
                $ipDisplay = if ($curr.IP) { $curr.IP } else { 'No IP' }
                $configType = if ($curr.DHCP -eq 'Enabled') { 'DHCP' } else { 'Static' }
                $host.UI.RawUI.WindowTitle = "Monitor: $InterfaceName $statusIcon | $ipDisplay ($configType) | Events: $eventCount"
                
                # Detect changes
                if ($null -ne $prev.Status -and $prev.Status -ne $curr.Status) {
                    if ($curr.Status -eq 'Up') {
                        # Check if this is a WiFi adapter
                        $isWiFi = ($null -ne $curr.WiFiSSID) -or ($InterfaceName -match 'Wi-?Fi|Wireless|WLAN')
                        
                        Write-Host "[$ts] " -NoNewline -ForegroundColor Gray
                        if ($isWiFi) {
                            Write-Host "NETWORK CONNECTED" -NoNewline -ForegroundColor Green
                            Write-Host " - Link established" -ForegroundColor Green
                        } else {
                            Write-Host "CABLE PLUGGED IN" -NoNewline -ForegroundColor Green
                            Write-Host " - Link established" -ForegroundColor Green
                        }
                        # Show DHCP REQUEST if DHCP is enabled (even if IP already acquired)
                        if ($ipIf.Dhcp -eq "Enabled") {
                            Write-Host "[$ts] " -NoNewline -ForegroundColor Gray
                            Write-Host "DHCP REQUEST" -NoNewline -ForegroundColor Yellow
                            Write-Host " - Requesting IP address..." -ForegroundColor Yellow
                        }
                    } elseif ($curr.Status -eq 'Disconnected') {
                        # Check if this is a WiFi adapter
                        $isWiFi = ($null -ne $prev.WiFiSSID) -or ($InterfaceName -match 'Wi-?Fi|Wireless|WLAN')
                        
                        Write-Host "[$ts] " -NoNewline -ForegroundColor Gray
                        if ($isWiFi) {
                            Write-Host "NETWORK DISCONNECTED" -NoNewline -ForegroundColor Red
                            Write-Host " - No link detected" -ForegroundColor Red
                        } else {
                            Write-Host "CABLE UNPLUGGED" -NoNewline -ForegroundColor Red
                            Write-Host " - No link detected" -ForegroundColor Red
                        }
                        # Show IP loss using previous IP (current is already cleared)
                        if ($null -ne $prev.IP) {
                            Write-Host "[$ts] " -NoNewline -ForegroundColor Gray
                            Write-Host "IP ADDRESS LOST" -NoNewline -ForegroundColor Red
                            Write-Host " - Was $($prev.IP)" -ForegroundColor Red
                            Write-LogMessage -Message "Interface '$InterfaceName' lost IP due to disconnect: $(Hide-IPAddress $prev.IP)" -Level "WARN"
                        }
                        if ($null -ne $prev.Gateway) {
                            Write-LogMessage -Message "Interface '$InterfaceName' lost gateway due to disconnect: $(Hide-IPAddress $prev.Gateway)" -Level "WARN"
                        }
                        if (-not [string]::IsNullOrWhiteSpace($prev.DNS)) {
                            Write-LogMessage -Message "Interface '$InterfaceName' lost DNS servers due to disconnect" -Level "WARN"
                        }
                    } else {
                        Write-Host "[$ts] STATUS: " -NoNewline -ForegroundColor Gray
                        Write-Host "$($prev.Status) -> $($curr.Status)" -ForegroundColor Yellow
                    }
                    $eventCount++
                    $lastEventTime = Get-Date
                    Write-LogMessage -Message "Interface '$InterfaceName' status: $($prev.Status) -> $($curr.Status)" -Level "INFO"
                }
                
                # IP address lost (separate from cable unplug - for other scenarios like ipconfig /release)
                if ($null -ne $prev.IP -and $null -eq $curr.IP -and $curr.Status -ne 'Disconnected' -and $prev.Status -ne 'Disconnected') {
                    Write-Host "[$ts] " -NoNewline -ForegroundColor Gray
                    Write-Host "IP ADDRESS LOST" -NoNewline -ForegroundColor Red
                    Write-Host " - Was $($prev.IP)" -ForegroundColor Red
                    $eventCount++
                    $lastEventTime = Get-Date
                    Write-LogMessage -Message "Interface '$InterfaceName' lost IP: $(Hide-IPAddress $prev.IP)" -Level "WARN"
                }
                
                # IP address acquired/changed
                if ($null -ne $prev.IP -and $prev.IP -ne $curr.IP -and $null -ne $curr.IP) {
                    Write-Host "[$ts] IP ADDRESS CHANGED: " -NoNewline -ForegroundColor Gray
                    if ($curr.IP -match '^169\.254\.') {
                        Write-Host "$($curr.IP) " -NoNewline -ForegroundColor Red
                        Write-Host "(APIPA - No DHCP server)" -ForegroundColor Red
                        Write-LogMessage -Message "Interface '$InterfaceName' APIPA: $($curr.IP)" -Level "WARN"
                    } else {
                        Write-Host "$($prev.IP) -> $($curr.IP)" -ForegroundColor Cyan
                        Write-LogMessage -Message "Interface '$InterfaceName' IP: $(Hide-IPAddress $prev.IP) -> $(Hide-IPAddress $curr.IP)" -Level "INFO"
                    }
                    $eventCount++
                    $lastEventTime = Get-Date
                }
                
                # New IP acquired (only show if this is a real change, not initial state)
                if ($null -eq $prev.IP -and $null -ne $curr.IP -and $null -ne $prev.Status) {
                    Write-Host "[$ts] " -NoNewline -ForegroundColor Gray
                    Write-Host "IP ADDRESS ACQUIRED: " -NoNewline -ForegroundColor Green
                    if ($curr.IP -match '^169\.254\.') {
                        Write-Host "$($curr.IP) " -NoNewline -ForegroundColor Yellow
                        Write-Host "(APIPA)" -ForegroundColor Yellow
                    } else {
                        Write-Host "$($curr.IP)" -ForegroundColor Green
                    }
                    $eventCount++
                    $lastEventTime = Get-Date
                    Write-LogMessage -Message "Interface '$InterfaceName' acquired IP: $(Hide-IPAddress $curr.IP)" -Level "INFO"
                }
                
                if ($null -ne $prev.DHCP -and $prev.DHCP -ne $curr.DHCP) {
                    $type = if ($curr.DHCP -eq "Enabled") { "DHCP" } else { "Static IP" }
                    $color = if ($curr.DHCP -eq "Enabled") { "Yellow" } else { "Magenta" }
                    Write-Host "[$ts] CONFIG: " -NoNewline -ForegroundColor Gray
                    Write-Host "Changed to $type" -ForegroundColor $color
                    $eventCount++
                    $lastEventTime = Get-Date
                    Write-LogMessage -Message "Interface '$InterfaceName' config: $type" -Level "INFO"
                }
                
                # Only show DHCP acquired if this is a real change (not initial state)
                if ($null -eq $prev.DHCPServer -and $null -ne $curr.DHCPServer -and $null -ne $prev.Status) {
                    Write-Host "[$ts] DHCP: " -NoNewline -ForegroundColor Gray
                    Write-Host "Acquired from $($curr.DHCPServer)" -ForegroundColor Green
                    if ($curr.DHCPExpires) {
                        Write-Host "[$ts] DHCP LEASE: " -NoNewline -ForegroundColor Gray
                        Write-Host "Expires $($curr.DHCPExpires)" -ForegroundColor Green
                    }
                    $eventCount++
                    $lastEventTime = Get-Date
                    Write-LogMessage -Message "Interface '$InterfaceName' DHCP from $(Hide-IPAddress $curr.DHCPServer)" -Level "INFO"
                }
                
                if ($null -ne $prev.DHCPServer -and $prev.DHCPServer -ne $curr.DHCPServer -and $null -ne $curr.DHCPServer) {
                    Write-Host "[$ts] DHCP SERVER: " -NoNewline -ForegroundColor Gray
                    Write-Host "$($prev.DHCPServer) -> $($curr.DHCPServer)" -ForegroundColor Yellow
                    $eventCount++
                    $lastEventTime = Get-Date
                    Write-LogMessage -Message "Interface '$InterfaceName' DHCP server changed: $(Hide-IPAddress $prev.DHCPServer) -> $(Hide-IPAddress $curr.DHCPServer)" -Level "INFO"
                }
                
                # Only report DHCP renewal if the lease time changed significantly (more than 1 minute)
                # This prevents false positives from clock drift or sub-second variations
                if ($null -ne $prev.DHCPExpires -and $null -ne $curr.DHCPExpires) {
                    try {
                        $prevExpiry = [DateTime]::Parse($prev.DHCPExpires)
                        $currExpiry = [DateTime]::Parse($curr.DHCPExpires)
                        $timeDiff = ($currExpiry - $prevExpiry).TotalMinutes
                        
                        # Only trigger if lease time increased by more than 1 minute (actual renewal)
                        if ($timeDiff -gt 1) {
                            Write-Host "[$ts] DHCP RENEWED: " -NoNewline -ForegroundColor Gray
                            Write-Host "Expires $($curr.DHCPExpires)" -ForegroundColor Green
                            $eventCount++
                    $lastEventTime = Get-Date
                            Write-LogMessage -Message "Interface '$InterfaceName' DHCP lease renewed, expires: $($curr.DHCPExpires)" -Level "INFO"
                        }
                    } catch {
                        # If we can't parse dates, fall back to string comparison (rare case)
                        if ($prev.DHCPExpires -ne $curr.DHCPExpires) {
                            Write-Host "[$ts] DHCP RENEWED: " -NoNewline -ForegroundColor Gray
                            Write-Host "Expires $($curr.DHCPExpires)" -ForegroundColor Green
                            $eventCount++
                    $lastEventTime = Get-Date
                        }
                    }
                }
                
                if ($prev.Gateway -ne $curr.Gateway -and $null -ne $prev.Status) {
                    if ($null -eq $curr.Gateway -and $null -ne $prev.Gateway) {
                        Write-Host "[$ts] " -NoNewline -ForegroundColor Gray
                        Write-Host "GATEWAY LOST" -NoNewline -ForegroundColor Red
                        Write-Host " - Was $($prev.Gateway)" -ForegroundColor Red
                        $eventCount++
                    $lastEventTime = Get-Date
                    } elseif ($null -eq $prev.Gateway -and $null -ne $curr.Gateway) {
                        Write-Host "[$ts] " -NoNewline -ForegroundColor Gray
                        Write-Host "GATEWAY ACQUIRED: " -NoNewline -ForegroundColor Green
                        Write-Host "$($curr.Gateway)" -ForegroundColor Green
                        $eventCount++
                    $lastEventTime = Get-Date
                    } elseif ($null -ne $prev.Gateway -and $null -ne $curr.Gateway) {
                        Write-Host "[$ts] " -NoNewline -ForegroundColor Gray
                        Write-Host "GATEWAY CHANGED: " -NoNewline -ForegroundColor Yellow
                        Write-Host "$($prev.Gateway) -> $($curr.Gateway)" -ForegroundColor Yellow
                        $eventCount++
                    $lastEventTime = Get-Date
                    }
                }
                
                if ($prev.DNS -ne $curr.DNS -and $null -ne $prev.Status) {
                    if ([string]::IsNullOrWhiteSpace($curr.DNS) -and -not [string]::IsNullOrWhiteSpace($prev.DNS)) {
                        Write-Host "[$ts] " -NoNewline -ForegroundColor Gray
                        Write-Host "DNS SERVERS CLEARED" -NoNewline -ForegroundColor Red
                        Write-Host " - Was $($prev.DNS)" -ForegroundColor Red
                        $eventCount++
                    $lastEventTime = Get-Date
                    } elseif ([string]::IsNullOrWhiteSpace($prev.DNS) -and -not [string]::IsNullOrWhiteSpace($curr.DNS)) {
                        Write-Host "[$ts] " -NoNewline -ForegroundColor Gray
                        Write-Host "DNS SERVERS CONFIGURED: " -NoNewline -ForegroundColor Green
                        Write-Host "$($curr.DNS)" -ForegroundColor Green
                        $eventCount++
                    $lastEventTime = Get-Date
                    } elseif (-not [string]::IsNullOrWhiteSpace($prev.DNS) -and -not [string]::IsNullOrWhiteSpace($curr.DNS)) {
                        Write-Host "[$ts] " -NoNewline -ForegroundColor Gray
                        Write-Host "DNS SERVERS CHANGED: " -NoNewline -ForegroundColor Yellow
                        Write-Host "$($curr.DNS)" -ForegroundColor Yellow
                        $eventCount++
                    $lastEventTime = Get-Date
                    }
                }
                
                if ($null -ne $prev.Speed -and $prev.Speed -ne $curr.Speed -and $null -ne $prev.Status) {
                    Write-Host "[$ts] LINK SPEED CHANGED: " -NoNewline -ForegroundColor Gray
                    Write-Host "$($prev.Speed) -> $($curr.Speed)" -ForegroundColor Cyan
                    $eventCount++
                    $lastEventTime = Get-Date
                }
                
                if ($prev.WiFiSSID -ne $curr.WiFiSSID -and $null -ne $prev.Status) {
                    if ($null -eq $curr.WiFiSSID -and $null -ne $prev.WiFiSSID) {
                        Write-Host "[$ts] " -NoNewline -ForegroundColor Gray
                        Write-Host "WIFI DISCONNECTED" -NoNewline -ForegroundColor Red
                        Write-Host " - Was connected to $($prev.WiFiSSID)" -ForegroundColor Red
                    } elseif ($null -eq $prev.WiFiSSID -and $null -ne $curr.WiFiSSID) {
                        Write-Host "[$ts] " -NoNewline -ForegroundColor Gray
                        Write-Host "WIFI CONNECTED: " -NoNewline -ForegroundColor Green
                        Write-Host "$($curr.WiFiSSID)" -ForegroundColor Green
                    } elseif ($null -ne $prev.WiFiSSID -and $null -ne $curr.WiFiSSID) {
                        Write-Host "[$ts] " -NoNewline -ForegroundColor Gray
                        Write-Host "WIFI SWITCHED: " -NoNewline -ForegroundColor Yellow
                        Write-Host "$($prev.WiFiSSID) -> $($curr.WiFiSSID)" -ForegroundColor Yellow
                    }
                    $eventCount++
                    $lastEventTime = Get-Date
                }
                
                if ($null -ne $prev.WiFiSignal -and $null -ne $curr.WiFiSignal) {
                    $diff = [int]$curr.WiFiSignal - [int]$prev.WiFiSignal
                    if ([Math]::Abs($diff) -ge 15) {
                        $color = if ($diff -gt 0) { "Green" } else { "Yellow" }
                        $sign = if ($diff -gt 0) { "+" } else { "" }
                        Write-Host "[$ts] WIFI SIGNAL: " -NoNewline -ForegroundColor Gray
                        Write-Host "$($curr.WiFiSignal)% ($sign$diff%)" -ForegroundColor $color
                        $eventCount++
                    $lastEventTime = Get-Date
                        Write-LogMessage -Message "Interface '$InterfaceName' WiFi signal changed: $sign$diff% (now $($curr.WiFiSignal)%)" -Level "INFO"
                    }
                }
                
                $prev = $curr
                
                # Show heartbeat if no events for 60 seconds (only show every 60 seconds)
                $timeSinceLastEvent = (Get-Date) - $lastEventTime
                $timeSinceLastHeartbeat = (Get-Date) - $lastHeartbeat
                
                if ($timeSinceLastEvent.TotalSeconds -ge 60 -and $timeSinceLastHeartbeat.TotalSeconds -ge 60) {
                    $minutes = [Math]::Floor($timeSinceLastEvent.TotalMinutes)
                    if ($minutes -eq 1) {
                        Write-Host "  [Monitoring active - No events for 1 minute]" -ForegroundColor DarkGray
                    } else {
                        Write-Host "  [Monitoring active - No events for $minutes minutes]" -ForegroundColor DarkGray
                    }
                    $lastHeartbeat = Get-Date
                }
                
            } catch {
                Write-Host "[$(Get-Date -Format 'HH:mm:ss')] ERROR: $_" -ForegroundColor Red
                Write-LogMessage -Message "Monitor error for '$InterfaceName': $_" -Level "ERROR"
            }
            
            # Check for keypress
            $elapsed = 0
            while ($elapsed -lt 2 -and $running) {
                Start-Sleep -Milliseconds 100
                $elapsed += 0.1
                
                if ([Console]::KeyAvailable) {
                    $key = [Console]::ReadKey($true)
                    
                    if ($key.Key -eq 'Q' -or $key.Key -eq 'Escape') {
                        $running = $false
                    }
                    elseif ($key.Key -eq 'D') {
                        # Run diagnostics
                        Write-Host "`n" -NoNewline
                        Write-Host ("=" * 60) -ForegroundColor Cyan
                        Write-Host "NETWORK DIAGNOSTICS - [$(Get-Date -Format 'HH:mm:ss')]" -ForegroundColor Cyan
                        Write-Host ("=" * 60) -ForegroundColor Cyan
                        Write-Host ""
                        
                        # Check if adapter is up
                        if ($curr.Status -ne 'Up') {
                            Write-Host "Cannot run diagnostics - Interface is $($curr.Status)" -ForegroundColor Red
                            Write-Host ""
                            Write-Host ("=" * 60) -ForegroundColor Cyan
                            Write-Host ""
                        } else {
                        
                        # Gateway test
                        if ($gw) {
                            Write-Host "[1] Gateway Connectivity Test" -ForegroundColor Yellow
                            Write-Host "    Target: " -NoNewline -ForegroundColor Gray
                            Write-Host "$gw (Default Gateway)" -ForegroundColor White
                            Write-Host "    Test:   " -NoNewline -ForegroundColor Gray
                            $ping = Test-Connection -ComputerName $gw -Count 2 -ErrorAction SilentlyContinue
                            if ($ping) {
                                $avg = ($ping | Measure-Object -Property ResponseTime -Average).Average
                                $min = ($ping | Measure-Object -Property ResponseTime -Minimum).Minimum
                                $max = ($ping | Measure-Object -Property ResponseTime -Maximum).Maximum
                                $loss = ((2 - $ping.Count) / 2) * 100
                                Write-Host "PASSED" -ForegroundColor Green
                                Write-Host "    Result: Avg=${avg}ms, Min=${min}ms, Max=${max}ms, Loss=${loss}%" -ForegroundColor Green
                            } else {
                                Write-Host "FAILED" -ForegroundColor Red
                                Write-Host "    Result: Gateway unreachable (all packets lost)" -ForegroundColor Red
                            }
                            Write-Host ""
                        } else {
                            Write-Host "[1] Gateway Connectivity Test" -ForegroundColor Yellow
                            Write-Host "    Status: SKIPPED - No gateway configured" -ForegroundColor DarkGray
                            Write-Host ""
                        }
                        
                        # DNS test
                        if ($dns) {
                            $primaryDNS = ($dns -split ",")[0].Trim()
                            Write-Host "[2] DNS Resolution Test" -ForegroundColor Yellow
                            Write-Host "    Server: " -NoNewline -ForegroundColor Gray
                            Write-Host "$primaryDNS" -ForegroundColor White
                            Write-Host "    Domain: " -NoNewline -ForegroundColor Gray
                            Write-Host "google.com" -ForegroundColor White
                            Write-Host "    Test:   " -NoNewline -ForegroundColor Gray
                            try {
                                $dnsResult = Resolve-DnsName -Name "google.com" -Server $primaryDNS -Type A -ErrorAction Stop -DnsOnly
                                Write-Host "PASSED" -ForegroundColor Green
                                Write-Host "    Result: Resolved to $($dnsResult[0].IPAddress)" -ForegroundColor Green
                            } catch {
                                Write-Host "FAILED" -ForegroundColor Red
                                Write-Host "    Result: Cannot resolve google.com" -ForegroundColor Red
                            }
                            Write-Host ""
                        } else {
                            Write-Host "[2] DNS Resolution Test" -ForegroundColor Yellow
                            Write-Host "    Status: SKIPPED - No DNS servers configured" -ForegroundColor DarkGray
                            Write-Host ""
                        }
                        
                        # Internet test
                        Write-Host "[3] Internet Connectivity Test" -ForegroundColor Yellow
                        $internetTestTarget = "1.1.1.1"
                        Write-Host "    Target: " -NoNewline -ForegroundColor Gray
                        Write-Host "$internetTestTarget (Cloudflare DNS)" -ForegroundColor White
                        Write-Host "    Test:   " -NoNewline -ForegroundColor Gray
                        $inet = Test-Connection -ComputerName $internetTestTarget -Count 2 -ErrorAction SilentlyContinue
                        if ($inet) {
                            $avg = ($inet | Measure-Object -Property ResponseTime -Average).Average
                            $min = ($inet | Measure-Object -Property ResponseTime -Minimum).Minimum
                            $max = ($inet | Measure-Object -Property ResponseTime -Maximum).Maximum
                            $loss = ((2 - $inet.Count) / 2) * 100
                            Write-Host "PASSED" -ForegroundColor Green
                            Write-Host "    Result: Avg=${avg}ms, Min=${min}ms, Max=${max}ms, Loss=${loss}%" -ForegroundColor Green
                        } else {
                            Write-Host "FAILED" -ForegroundColor Red
                            Write-Host "    Result: No internet connectivity" -ForegroundColor Red
                        }
                        
                        Write-Host ""
                        Write-Host ("=" * 60) -ForegroundColor Cyan
                        Write-Host ""
                        }
                    }
                    elseif ($key.Key -eq 'S') {
                        # Show status
                        Write-Host "`n--- STATUS [$(Get-Date -Format 'HH:mm:ss')] ---" -ForegroundColor Cyan
                        Write-Host "Interface:  $InterfaceName"
                        Write-Host "MAC Address: $($adapter.MacAddress)" -ForegroundColor Gray
                        Write-Host "Status:     $($curr.Status)" -ForegroundColor $(if($curr.Status -eq 'Up'){'Green'}else{'Red'})
                        Write-Host "IP:         $(if($curr.IP){$curr.IP}else{'Not configured'})"
                        Write-Host "Config:     $(if($curr.DHCP -eq 'Enabled'){'DHCP'}else{'Static'})" -ForegroundColor $(if($curr.DHCP -eq 'Enabled'){'Yellow'}else{'Magenta'})
                        if ($curr.DHCPServer) {
                            Write-Host "DHCP Server: $($curr.DHCPServer)" -ForegroundColor White
                            if ($dhcpObtained) { 
                                Write-Host "Lease Obtained: $dhcpObtained" -ForegroundColor White
                            }
                            if ($curr.DHCPExpires) { 
                                Write-Host "Lease Expires:  $($curr.DHCPExpires)" -ForegroundColor White
                                try {
                                    # Try parsing the date (handles various formats)
                                    $expiryDate = [DateTime]::ParseExact($curr.DHCPExpires, 'dddd, d MMMM yyyy HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture)
                                    $timeSpan = $expiryDate - (Get-Date)
                                    if ($timeSpan.TotalSeconds -gt 0) {
                                        $days = [Math]::Floor($timeSpan.TotalDays)
                                        $hours = $timeSpan.Hours
                                        $minutes = $timeSpan.Minutes
                                        $seconds = $timeSpan.Seconds
                                        
                                        if ($days -gt 0) {
                                            $remaining = "{0}d {1:D2}h {2:D2}m" -f $days, $hours, $minutes
                                        } else {
                                            $remaining = "{0:D2}h {1:D2}m {2:D2}s" -f $hours, $minutes, $seconds
                                        }
                                        Write-Host "Time Remaining: $remaining" -ForegroundColor Green
                                    } else {
                                        Write-Host "Time Remaining: EXPIRED" -ForegroundColor Red
                                    }
                                } catch {
                                    # Fallback: try standard Parse
                                    try {
                                        $expiryDate = [DateTime]::Parse($curr.DHCPExpires)
                                        $timeSpan = $expiryDate - (Get-Date)
                                        if ($timeSpan.TotalSeconds -gt 0) {
                                            $hours = [Math]::Floor($timeSpan.TotalHours)
                                            $minutes = $timeSpan.Minutes
                                            $seconds = $timeSpan.Seconds
                                            $remaining = "{0:D2}h {1:D2}m {2:D2}s" -f $hours, $minutes, $seconds
                                            Write-Host "Time Remaining: $remaining" -ForegroundColor Green
                                        }
                                    } catch {
                                        # Silently continue if date parsing fails
                                        $null
                                    }
                                }
                            }
                        }
                        Write-Host "Gateway:    $(if($curr.Gateway){$curr.Gateway}else{'Not configured'})"
                        Write-Host "DNS:        $(if($curr.DNS){$curr.DNS}else{'Not configured'})"
                        Write-Host "Link Speed: $($curr.Speed)"
                        if ($curr.WiFiSSID) {
                            Write-Host "WiFi SSID:  $($curr.WiFiSSID)"
                            if ($curr.WiFiSignal) {
                                Write-Host "WiFi Signal: $($curr.WiFiSignal)%" -ForegroundColor $(if([int]$curr.WiFiSignal -ge 70){'Green'}elseif([int]$curr.WiFiSignal -ge 40){'Yellow'}else{'Red'})
                            }
                        }
                        Write-Host "--- END STATUS ---`n" -ForegroundColor Cyan
                    }
                    elseif ($key.Key -eq 'C') {
                        Clear-Host
                        Write-Host "===========================================================================" -ForegroundColor Cyan
                        Write-Host "                  LIVE NETWORK MONITORING                                 " -ForegroundColor Cyan
                        Write-Host "===========================================================================" -ForegroundColor Cyan
                        Write-Host ""
                        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Log cleared - monitoring continues..." -ForegroundColor Yellow
                        Write-Host ""
                        $eventCount = 0
                    }
                }
            }
        }
    } finally {
        # Reset window title to normal state
        if ($InterfaceName) {
            $host.UI.RawUI.WindowTitle = "Network Configuration - $InterfaceName"
        } else {
            $host.UI.RawUI.WindowTitle = "Network Configuration - No Interface"
        }
        
        Write-Host ""
        Write-Host "===========================================================================" -ForegroundColor Gray
        Write-Host "Monitoring stopped. Events detected: $eventCount" -ForegroundColor Yellow
        Write-LogMessage -Message "Stopped monitoring for interface '$InterfaceName'" -Level "INFO"
        Read-Host "`nPress Enter to return to main menu"
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
    Write-Host "9. Subnet Calculator" -ForegroundColor White
    Write-Host "10. Check for updates" -ForegroundColor White
    Write-Host "11. Privacy & Data Management (GDPR)" -ForegroundColor White
    Write-Host "12. Live Interface Monitoring" -ForegroundColor White
    Write-Host "0. Exit" -ForegroundColor White
    Write-Host ""
    Write-Host "Quick actions: 'q' = Quick DHCP, 't' = Quick test, 'c' = Clear screen, 'd' = DNS flush, 'i' = Interface info" -ForegroundColor DarkGray

    $choice = (Read-Host "Enter your choice").Trim()

    # Block actions that require a valid interface
    $requiresInterface = @("1","2","3","4","5","8","12","q","t","i")
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
                $result = Set-DHCP -InterfaceName $interfaceName
                if (-not $result) {
                    Write-Host "`nDHCP configuration failed. Please check:" -ForegroundColor Red
                    Write-Host "  - Network cable is connected (for Ethernet)" -ForegroundColor Yellow
                    Write-Host "  - Wi-Fi is connected to a network" -ForegroundColor Yellow
                    Write-Host "  - Router/DHCP server is functioning" -ForegroundColor Yellow
                    Write-Host "  - Check logs for more details (Option 7)" -ForegroundColor Yellow
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
                    Write-Host "IP Address: $($config.IPAddress)" -ForegroundColor White
                    Write-Host "Subnet Mask: $($config.SubnetMask)" -ForegroundColor White
                    Write-Host "Gateway: $(if($config.Gateway) { $config.Gateway } else { '(none)' })" -ForegroundColor White
                    Write-Host "Primary DNS: $($config.PrimaryDNS)" -ForegroundColor White
                    Write-Host "Secondary DNS: $(if($config.SecondaryDNS) { $config.SecondaryDNS } else { '(none)' })" -ForegroundColor White
                    
                    $confirmation = (Read-Host "`nApply this configuration? (y/n, default: n)").Trim()
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
                $quickTest = (Read-Host "Run quick test? (y/n, default: n)").Trim()
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
            try {
                # Subnet Calculator - no interface required
                Invoke-SubnetCalculator
            } catch {
                Write-Host "Error during subnet calculation: $_" -ForegroundColor Red
                Write-LogMessage -Message "Error during subnet calculation: $_" -Level "ERROR"
            }
        }
        "10" {
            Update-NetworkScript
        }
        "11" {
            # Privacy & Data Management (GDPR)
            Show-GDPRMenu
        }
        "12" {
            # Live Interface Monitoring
            Start-LiveInterfaceMonitor -InterfaceName $interfaceName
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
        "t" {
            # Quick network test
            Write-Host "Quick network test..." -ForegroundColor Cyan
            try {
                $null = Test-NetworkConnectivity -InterfaceName $interfaceName -QuickTest $true
            } catch {
                Write-Host "Error during quick test: $_" -ForegroundColor Red
            }
        }
        "c" {
            # Clear screen
            Clear-Host
            continue
        }
        "d" {
            # DNS flush
            Write-Host "Flushing DNS cache..." -ForegroundColor Cyan
            try {
                $result = & ipconfig /flushdns 2>&1
                if ($LASTEXITCODE -eq 0) {
                    Write-Host "DNS cache successfully flushed." -ForegroundColor Green
                    Write-LogMessage -Message "DNS cache flushed successfully" -Level "INFO"
                } else {
                    Write-Host "Failed to flush DNS cache." -ForegroundColor Red
                    Write-LogMessage -Message "DNS flush failed: $result" -Level "ERROR"
                }
            } catch {
                Write-Host "Error flushing DNS: $_" -ForegroundColor Red
                Write-LogMessage -Message "Error flushing DNS: $_" -Level "ERROR"
            }
        }
        "i" {
            # Interface info
            Write-Host "Interface Information..." -ForegroundColor Cyan
            try {
                $adapter = Get-NetAdapter -Name $interfaceName -ErrorAction Stop
                Write-Host ""
                Write-Host "=== Interface Details ===" -ForegroundColor Yellow
                Write-Host "Name:          $($adapter.Name)" -ForegroundColor White
                Write-Host "Description:   $($adapter.InterfaceDescription)" -ForegroundColor White
                Write-Host "Status:        $($adapter.Status)" -ForegroundColor $(if ($adapter.Status -eq 'Up') { 'Green' } else { 'Red' })
                Write-Host "MAC Address:   $($adapter.MacAddress)" -ForegroundColor White
                Write-Host "Link Speed:    $($adapter.LinkSpeed)" -ForegroundColor White
                Write-Host "Media Type:    $($adapter.MediaType)" -ForegroundColor White
                Write-Host "Interface ID:  $($adapter.InterfaceIndex)" -ForegroundColor White
                Write-Host ""
                Write-LogMessage -Message "Interface info displayed for '$interfaceName'" -Level "INFO"
            } catch {
                Write-Host "Error getting interface info: $_" -ForegroundColor Red
                Write-LogMessage -Message "Error getting interface info: $_" -Level "ERROR"
            }
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
