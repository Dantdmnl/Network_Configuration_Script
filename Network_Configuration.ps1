# Version: 2.8
#Requires -Version 5.1
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

# Set console colors for better visibility
if ($Host.UI.SupportsVirtualTerminal -or $Host.Name -eq 'ConsoleHost') {
    try {
        $Host.UI.RawUI.BackgroundColor = 'Black'
        $Host.UI.RawUI.ForegroundColor = 'Gray'
        Clear-Host
    } catch {
        Write-Verbose "Console colors could not be set: $_"
    }
}

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
$script:ProfilesDirName = 'Profiles'
$script:BackupsDirName = 'Backups'
$script:ConfigPath = Join-Path $script:AppDataDir $script:ConfigFile
$script:LogPath = Join-Path $script:AppDataDir $script:LogFileName
$script:VersionPath = Join-Path $script:AppDataDir $script:VersionFile
$script:InterfacePath = Join-Path $script:AppDataDir $script:InterfaceFile
$script:ConsentPath = Join-Path $script:AppDataDir $script:ConsentFile
$script:ProfilesPath = Join-Path $script:AppDataDir $script:ProfilesDirName
$script:BackupsPath = Join-Path $script:AppDataDir $script:BackupsDirName
foreach ($directory in @($script:ProfilesPath, $script:BackupsPath)) {
    if (-not (Test-Path $directory)) {
        New-Item -Path $directory -ItemType Directory | Out-Null
    }
}
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

# Extract version dynamically from the script header before any consent or logging metadata is written
$script:ScriptVersion = "Unknown"
try {
    $scriptContent = Get-Content -Path $MyInvocation.MyCommand.Path -TotalCount 5 -ErrorAction SilentlyContinue
    $versionLine = $scriptContent | Where-Object { $_ -match "^# Version:" } | Select-Object -First 1
    if ($versionLine) {
        $script:ScriptVersion = ($versionLine -replace "^# Version:\s*", "").Trim()
    }
} catch {
    Write-Verbose "Could not extract script version from header: $_"
}

# Check for elevation and re-run as administrator if needed
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host ""
    Write-Host "Administrator privileges are required to change network adapter settings." -ForegroundColor Yellow
    Write-Host "A User Account Control prompt will open. Choose Yes to continue." -ForegroundColor Gray
    Write-Host ""

    try {
        $scriptPath = $MyInvocation.MyCommand.Definition
        $launchArgs = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""
        Start-Process -FilePath "powershell.exe" -ArgumentList $launchArgs -Verb RunAs -WorkingDirectory $scriptDir -ErrorAction Stop | Out-Null
        exit
    } catch {
        Write-Host "[ERROR] The script was not started as administrator." -ForegroundColor Red
        Write-Host "Network configuration changes cannot continue without elevation." -ForegroundColor Yellow
        Write-Host "Start PowerShell as Administrator, or rerun the script and accept the UAC prompt." -ForegroundColor Gray
        Write-Host ""
        Read-Host "Press Enter to exit"
        exit 1
    }
}


#region Logging Settings
$script:MaxLogSizeMB = 5      # Max log file size (MB) before rotation
$script:MaxLogArchives = 5    # Number of rotated log files to keep
$script:MaxLogAgeDays = 30    # Remove rotated logs older than this many days
$script:MaxBackupArchives = 5 # Number of script/network backup files to keep per backup type
$script:MaxBackupAgeDays = 30 # Remove backups older than this many days
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

function Read-YesNo {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Prompt,

        [bool]$Default = $false
    )

    $suffix = if ($Default) { " (Y/n)" } else { " (y/N)" }
    while ($true) {
        $response = (Read-Host "$Prompt$suffix").Trim().ToLower()
        if ([string]::IsNullOrWhiteSpace($response)) {
            return $Default
        }

        switch ($response) {
            "y" { return $true }
            "yes" { return $true }
            "n" { return $false }
            "no" { return $false }
            default {
                Write-Host "Please answer y or n." -ForegroundColor Yellow
            }
        }
    }
}

function Remove-OldFiles {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$Path,

        [Parameter(Mandatory=$true)]
        [string]$Filter,

        [ValidateRange(1,1000)]
        [int]$KeepNewest = 5,

        [ValidateRange(1,3650)]
        [int]$MaxAgeDays = 30
    )

    if (-not (Test-Path $Path)) { return 0 }

    $deletedCount = 0
    $cutoff = (Get-Date).AddDays(-$MaxAgeDays)
    $files = @(Get-ChildItem -Path $Path -Filter $Filter -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)

    foreach ($oldFile in ($files | Where-Object { $_.LastWriteTime -lt $cutoff })) {
        try {
            Remove-Item -LiteralPath $oldFile.FullName -Force -ErrorAction Stop
            $deletedCount++
        } catch {
            Write-Verbose "Could not remove old file '$($oldFile.FullName)': $_"
        }
    }

    $remainingFiles = @(Get-ChildItem -Path $Path -Filter $Filter -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
    foreach ($extraFile in ($remainingFiles | Select-Object -Skip $KeepNewest)) {
        try {
            Remove-Item -LiteralPath $extraFile.FullName -Force -ErrorAction Stop
            $deletedCount++
        } catch {
            Write-Verbose "Could not remove extra file '$($extraFile.FullName)': $_"
        }
    }

    return $deletedCount
}

function Remove-LocalItemSafe {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Path,

        [string]$DisplayName = $null,

        [switch]$Recurse
    )

    if (-not (Test-Path $Path)) { return $false }

    if ([string]::IsNullOrWhiteSpace($DisplayName)) {
        $DisplayName = Split-Path $Path -Leaf
    }

    try {
        if ($Recurse) {
            Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
        } else {
            Remove-Item -LiteralPath $Path -Force -ErrorAction Stop
        }

        Write-Host "  [OK] Deleted $DisplayName" -ForegroundColor Green
        return $true
    } catch {
        Write-Host "  [WARN] Could not delete ${DisplayName}: $_" -ForegroundColor Yellow
        return $false
    }
}

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
    Write-Host "  - Saved profiles and backups may contain full IP settings" -ForegroundColor White
    Write-Host "  - Script actions and errors" -ForegroundColor White
    Write-Host "  - Timestamps of operations" -ForegroundColor White
    Write-Host ""
    Write-Host "Data Protection:" -ForegroundColor Green
    Write-Host "  [OK] All data is stored locally on your computer" -ForegroundColor Gray
    Write-Host "  [OK] No data is sent to external servers" -ForegroundColor Gray
    Write-Host "  [OK] IP addresses are pseudonymized (last octet hidden)" -ForegroundColor Gray
    Write-Host "  [OK] You can delete logs or all local data at any time" -ForegroundColor Gray
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
    
    if (Read-YesNo -Prompt "Do you consent to logging with data pseudonymization?" -Default $false) {
        $script:LoggingConsent = $true
        $consentData = @{
            LoggingConsent = $true
            PseudonymizeData = $true
            ConsentDate = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
            Version = $script:ScriptVersion
        }
        $consentData | ConvertTo-Json | Set-Content -Path $script:ConsentPath -Encoding UTF8
        Write-Host ""
        Write-Host "[OK] Thank you. Logging enabled with data pseudonymization." -ForegroundColor Green
        Write-Host "  You can manage your data via the 'Privacy & Data' menu option." -ForegroundColor Gray
    } else {
        $script:LoggingConsent = $false
        $consentData = @{
            LoggingConsent = $false
            PseudonymizeData = $true
            ConsentDate = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
            Version = $script:ScriptVersion
        }
        $consentData | ConvertTo-Json | Set-Content -Path $script:ConsentPath -Encoding UTF8
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
    Write-Host "  Log Retention: $script:MaxLogArchives archive(s), $script:MaxLogAgeDays day(s)" -ForegroundColor Gray
    Write-Host "  Backup Retention: $script:MaxBackupArchives per type, $script:MaxBackupAgeDays day(s)" -ForegroundColor Gray
    Write-Host ""
    
    Write-Host "Options:" -ForegroundColor Cyan
    Write-Host "  [1] View Privacy Notice" -ForegroundColor White
    Write-Host "  [2] View Current Logs" -ForegroundColor White
    Write-Host "  [3] Delete Logs Only" -ForegroundColor White
    Write-Host "  [4] Delete All Local Data" -ForegroundColor Yellow
    Write-Host "  [5] Change Logging Consent" -ForegroundColor White
    Write-Host "  [6] Export Data (Data Portability)" -ForegroundColor White
    Write-Host "  [b] Back to Main Menu" -ForegroundColor White
    Write-Host ""
    
    $choice = (Read-Host "Select an option").Trim().ToLower()
    
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
            Remove-AllLocalData
            Read-Host "`nPress Enter to continue"
            Show-GDPRMenu
        }
        "5" {
            Update-GDPRConsent
            Read-Host "`nPress Enter to continue"
            Show-GDPRMenu
        }
        "6" {
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
    Write-Host "   - Saved IP profiles and managed backup snapshots" -ForegroundColor White
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
    Write-Host "   - Log retention: rotated after $script:MaxLogSizeMB MB; keeping $script:MaxLogArchives archive(s) for up to $script:MaxLogAgeDays day(s)" -ForegroundColor White
    Write-Host "   - Backup retention: keeping $script:MaxBackupArchives backup(s) per type for up to $script:MaxBackupAgeDays day(s)" -ForegroundColor White
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
    Write-Host "   - Log IP addresses are pseudonymized (last octet replaced with 'xxx')" -ForegroundColor White
    Write-Host "   - Profiles and backups may store full IP settings so they remain usable" -ForegroundColor White
    Write-Host "   - Logs stored with restricted file permissions" -ForegroundColor White
    Write-Host "   - Automatic log and backup cleanup to prevent excessive data retention" -ForegroundColor White
    Write-Host ""
    Write-Host "9. CONTACT" -ForegroundColor Yellow
    Write-Host "   This is an open-source tool. For questions, visit:" -ForegroundColor White
    Write-Host "   https://github.com/Dantdmnl/Network_Configuration_Script" -ForegroundColor Cyan
}

# Function to delete logs and consent record without removing saved profiles or backups
function Remove-AllLogs {
    Write-Host ""
    Write-Host "=== Delete Logs Only ===" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "This will permanently delete:" -ForegroundColor Yellow
    Write-Host "  - All log files" -ForegroundColor White
    Write-Host "  - All rotated log archives" -ForegroundColor White
    Write-Host "  - Consent record (you will be asked again)" -ForegroundColor White
    Write-Host ""
    Write-Host "Note: Configuration files (IP settings, interface) will NOT be deleted." -ForegroundColor Gray
    Write-Host ""
    
    if (Read-YesNo -Prompt "Delete logs and consent record?" -Default $false) {
        $deletedCount = 0
        
        # Delete main log file
        if (Remove-LocalItemSafe -Path $script:LogFile -DisplayName "main log file") {
            $deletedCount++
        }
        
        # Delete rotated logs
        $logArchivePattern = "$($script:LogFileName).*"
        foreach ($archiveLog in @(Get-ChildItem -Path $script:AppDataDir -Filter $logArchivePattern -File -ErrorAction SilentlyContinue)) {
            if (Remove-LocalItemSafe -Path $archiveLog.FullName -DisplayName "log archive $($archiveLog.Name)") {
                $deletedCount++
            }
        }
        
        # Delete consent file
        if (Remove-LocalItemSafe -Path $script:ConsentPath -DisplayName "consent record") {
            $deletedCount++
        }
        
        $script:LoggingConsent = $false
        
        Write-Host ""
        Write-Host "[OK] Successfully deleted $deletedCount log file(s)" -ForegroundColor Green
        Write-Host "  Your data has been erased." -ForegroundColor Green
    } else {
        Write-Host "[X] Deletion cancelled" -ForegroundColor Yellow
    }
}

function Remove-AllLocalData {
    Write-Host ""
    Write-Host "=== Delete All Local Data ===" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "This will permanently delete local data stored by this script:" -ForegroundColor Yellow
    Write-Host "  - Logs and rotated log archives" -ForegroundColor White
    Write-Host "  - GDPR consent record" -ForegroundColor White
    Write-Host "  - Selected adapter and legacy configuration files" -ForegroundColor White
    Write-Host "  - Saved IP profiles" -ForegroundColor White
    Write-Host "  - Managed backup files" -ForegroundColor White
    Write-Host ""
    Write-Host "The script file itself will not be deleted." -ForegroundColor Gray
    Write-Host ""

    $confirmation = (Read-Host "Type DELETE to permanently remove all local data").Trim()
    if ($confirmation -ne "DELETE") {
        Write-Host "[X] Local data deletion cancelled" -ForegroundColor Yellow
        return
    }

    $deletedCount = 0
    $pathsToDelete = @(
        $script:LogFile,
        $script:ConfigPath,
        $script:VersionPath,
        $script:InterfacePath,
        $script:ConsentPath
    )

    foreach ($path in $pathsToDelete) {
        if (Remove-LocalItemSafe -Path $path) {
            $deletedCount++
        }
    }

    foreach ($filter in @("$($script:LogFileName).*")) {
        foreach ($file in @(Get-ChildItem -Path $script:AppDataDir -Filter $filter -File -ErrorAction SilentlyContinue)) {
            if (Remove-LocalItemSafe -Path $file.FullName -DisplayName $file.Name) {
                $deletedCount++
            }
        }
    }

    foreach ($directory in @($script:ProfilesPath, $script:BackupsPath)) {
        if (Remove-LocalItemSafe -Path $directory -Recurse) {
            $deletedCount++
        }
    }

    foreach ($directory in @($script:ProfilesPath, $script:BackupsPath)) {
        if (-not (Test-Path $directory)) {
            New-Item -Path $directory -ItemType Directory -Force | Out-Null
        }
    }

    $script:LoggingConsent = $false
    $script:PseudonymizeData = $true

    Write-Host ""
    Write-Host "[OK] Deleted $deletedCount local data item(s)" -ForegroundColor Green
    Write-Host "  You will be asked for privacy consent again next time." -ForegroundColor Gray
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
    
    $script:LoggingConsent = Read-YesNo -Prompt "Enable logging?" -Default $script:LoggingConsent
    
    $consentData = @{
        LoggingConsent = $script:LoggingConsent
        PseudonymizeData = $true
        ConsentDate = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        Version = $script:ScriptVersion
    }
    $consentData | ConvertTo-Json | Set-Content -Path $script:ConsentPath -Encoding UTF8
    
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

        # Copy modern JSON profiles
        if (Test-Path $script:ProfilesPath) {
            $profilesExportDir = Join-Path $tempDir "profiles"
            New-Item -Path $profilesExportDir -ItemType Directory -Force | Out-Null
            Copy-Item -Path (Join-Path $script:ProfilesPath "*.json") -Destination $profilesExportDir -Force -ErrorAction SilentlyContinue
        }

        # Copy managed backups
        if (Test-Path $script:BackupsPath) {
            $backupsExportDir = Join-Path $tempDir "backups"
            New-Item -Path $backupsExportDir -ItemType Directory -Force | Out-Null
            Copy-Item -Path (Join-Path $script:BackupsPath "*") -Destination $backupsExportDir -Force -ErrorAction SilentlyContinue
        }
        
        # Create README
        $readme = @"
NETWORK CONFIGURATION SCRIPT - DATA EXPORT
Export Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Script Version: $script:ScriptVersion

This archive contains all data collected by the Network Configuration Script.

CONTENTS:
- logs/           : All log files (current and rotated)
- config/         : Network configuration files
- profiles/       : Saved JSON IP profiles
- backups/        : Managed update and network configuration backups
- consent/        : GDPR consent record

DATA FORMAT:
- Logs are in JSON format
- Profiles are in JSON format
- Legacy configuration files are in XML format
- Logs pseudonymize IP addresses when pseudonymization is enabled
- Profiles and backups may contain full IP settings so they can be reused or restored

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
        
        if (Read-YesNo -Prompt "Open export location?" -Default $false) {
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

    $null = Remove-OldFiles -Path $script:AppDataDir `
                             -Filter "$($script:LogFileName).*" `
                             -KeepNewest $script:MaxLogArchives `
                             -MaxAgeDays $script:MaxLogAgeDays
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
    $logEntry = [ordered]@{
        timestamp = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        level = $Level
        message = $Message
    } | ConvertTo-Json -Compress
    $logEntry = $logEntry -replace '\\u0027', "'" -replace '\\u003c', '<' -replace '\\u003e', '>' -replace '\\u0026', '&'
    $logEntry | Out-File -FilePath $script:LogFile -Append -Encoding UTF8
}
#endregion

function Invoke-BackupRetention {
    [CmdletBinding()]
    param (
        [string]$Filter = "*"
    )

    $removed = Remove-OldFiles -Path $script:BackupsPath `
                               -Filter $Filter `
                               -KeepNewest $script:MaxBackupArchives `
                               -MaxAgeDays $script:MaxBackupAgeDays

    if ($removed -gt 0) {
        Write-LogMessage -Message "Backup retention removed $removed old backup file(s) matching '$Filter'." -Level "INFO"
    }
}

function New-ManagedBackupPath {
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$BaseName,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Extension
    )

    if (-not (Test-Path $script:BackupsPath)) {
        New-Item -Path $script:BackupsPath -ItemType Directory -Force | Out-Null
    }

    $safeBaseName = $BaseName -replace '[\\/:*?"<>|]', '_'
    $safeExtension = $Extension.TrimStart('.')
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    return (Join-Path $script:BackupsPath "$safeBaseName`_$timestamp.$safeExtension")
}

function Invoke-StartupHousekeeping {
    $null = Remove-OldFiles -Path $script:AppDataDir `
                             -Filter "$($script:LogFileName).*" `
                             -KeepNewest $script:MaxLogArchives `
                             -MaxAgeDays $script:MaxLogAgeDays

    $null = Remove-OldFiles -Path $script:BackupsPath `
                             -Filter "*" `
                             -KeepNewest ($script:MaxBackupArchives * 4) `
                             -MaxAgeDays $script:MaxBackupAgeDays
}

Invoke-StartupHousekeeping
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

    $currentVersion = if ($script:ScriptVersion -and $script:ScriptVersion -ne "Unknown") {
        $script:ScriptVersion
    } else {
        (Get-Content $versionFilePath -ErrorAction SilentlyContinue).Trim()
    }

    try {
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        } catch {
            Write-LogMessage -Message "Could not enable TLS 1.2 for update check: $_" -Level "DEBUG"
        }

        # Fetch the remote script content
        $RemoteScriptContent = Invoke-WebRequest -Uri $RemoteScriptURL -UseBasicParsing
        if (-not $RemoteScriptContent -or -not $RemoteScriptContent.Content) {
            Write-Host "Failed to fetch the remote script. Please check the URL." -ForegroundColor Red
            Write-LogMessage -Message "Failed to fetch the remote script. Please check the URL." -Level "ERROR"
            return
        }

        # Validate the downloaded script parses before offering to replace the local copy
        $tokens = $null
        $parseErrors = $null
        $null = [System.Management.Automation.Language.Parser]::ParseInput($RemoteScriptContent.Content, [ref]$tokens, [ref]$parseErrors)
        if ($parseErrors -and $parseErrors.Count -gt 0) {
            Write-Host "Downloaded update did not pass PowerShell parser validation. Update cancelled." -ForegroundColor Red
            Write-LogMessage -Message "Remote update parser validation failed: $($parseErrors[0].Message)" -Level "CRITICAL"
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
                if (Read-YesNo -Prompt "Would you like to update to the latest version?" -Default $false) {
                    # Backup the current script in the managed backup folder.
                    $BackupPath = New-ManagedBackupPath -BaseName "script_update" -Extension "ps1"
                    Copy-Item -Path $CurrentScriptPath -Destination $BackupPath -Force
                    Invoke-BackupRetention -Filter "script_update_*.ps1"
                    Write-Host "A backup of the current script has been saved as $BackupPath." -ForegroundColor Yellow
                    Write-LogMessage -Message "A backup of the current script has been saved as $BackupPath." -Level "INFO"

                    # Update the script using UTF-8 without BOM for consistent source encoding
                    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
                    [System.IO.File]::WriteAllText($CurrentScriptPath, $RemoteScriptContent.Content, $utf8NoBom)
                    Set-Content -Path $versionFilePath -Value $RemoteVersion
                    Write-Host "The script has been updated successfully to version $RemoteVersion. Rerun the script to apply the update." -ForegroundColor Green
                    Write-LogMessage -Message "The script has been updated successfully to version $RemoteVersion." -Level "INFO"
                } else {
                    Write-Host "The script was not updated." -ForegroundColor Yellow
                    Write-LogMessage -Message "Update skipped by user." -Level "INFO"
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

# Menu input function with ESC support
function Read-MenuChoice {
    <#
    .SYNOPSIS
        Reads menu input with ESC support and handles multi-digit options
    #>
    param(
        [switch]$AllowEscape
    )
    
    # Check if we're in a true console that supports ReadKey
    $supportsReadKey = $false
    try {
        if ($null -ne [Console]::KeyAvailable) {
            $supportsReadKey = $true
        }
    } catch {
        Write-Verbose "Console ReadKey support could not be detected: $_"
    }
    
    if ($supportsReadKey) {
        # Build input character by character
        $userInput = ""
        while ($true) {
            try {
                $key = [Console]::ReadKey($true)
                
                # Handle ESC
                if ($AllowEscape -and $key.Key -eq [ConsoleKey]::Escape) {
                    Write-Host ""
                    return [char]27
                }
                
                # Handle Enter - submit input
                if ($key.Key -eq [ConsoleKey]::Enter) {
                    Write-Host ""
                    return $userInput.Trim()
                }
                
                # Handle Backspace
                if ($key.Key -eq [ConsoleKey]::Backspace) {
                    if ($userInput.Length -gt 0) {
                        $userInput = $userInput.Substring(0, $userInput.Length - 1)
                        Write-Host "`b `b" -NoNewline
                    }
                    continue
                }
                
                # Handle regular characters
                if ($key.KeyChar -match '[0-9a-zA-Z]') {
                    $userInput += $key.KeyChar
                    Write-Host $key.KeyChar -NoNewline -ForegroundColor Cyan
                }
            } catch {
                break
            }
        }
        return $userInput.Trim()
    } else {
        # Fallback to Read-Host for ISE/VS Code
        $userInput = Read-Host
        return $userInput.Trim()
    }
}

# Input validation functions for enhanced robustness
function Test-ValidIPAddress {
    <#
    .SYNOPSIS
        Validates if a string is a valid IPv4 address.
    
    .PARAMETER IPAddress
        The IP address string to validate.
    
    .OUTPUTS
        Boolean indicating if the IP is valid.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory=$true)]
        [AllowEmptyString()]
        [string]$IPAddress
    )
    
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
    <#
    .SYNOPSIS
        Validates if a string is a valid subnet mask.
    
    .PARAMETER SubnetInput
        The subnet mask to validate (supports dotted decimal, CIDR, or /CIDR notation).
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory=$true)]
        [AllowEmptyString()]
        [string]$SubnetInput
    )
    
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
    <#
    .SYNOPSIS
        Validates if a network interface name exists.
    
    .PARAMETER InterfaceName
        The interface name to validate.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory=$true)]
        [AllowEmptyString()]
        [string]$InterfaceName
    )
    
    if ([string]::IsNullOrWhiteSpace($InterfaceName)) { return $false }
    
    return ($null -ne (Get-NetworkAdapterSafe -InterfaceName $InterfaceName))
}

function Get-NetworkAdapterSafe {
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$InterfaceName,

        [switch]$RequireUp
    )

    try {
        $adapter = Get-NetAdapter -Name $InterfaceName -ErrorAction Stop
        if ($RequireUp -and $adapter.Status -ne "Up") {
            return $null
        }

        return $adapter
    } catch {
        return $null
    }
}

function Test-ValidDNSServer {
    <#
    .SYNOPSIS
        Validates if a string is a valid IPv4 DNS server address.
    
    .PARAMETER DNSServer
        The DNS server IPv4 address to validate.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory=$true)]
        [AllowEmptyString()]
        [string]$DNSServer
    )

    if ([string]::IsNullOrWhiteSpace($DNSServer)) { return $false }

    return (Test-ValidIPAddress -IPAddress $DNSServer)
}

function Test-DNSConnectivity {
    <#
    .SYNOPSIS
        Tests if a DNS server is reachable and can resolve names.
    
    .PARAMETER DNSServer
        The DNS server IP address to test.
    
    .PARAMETER TestDomains
        Domains to try for resolution tests.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory=$true)]
        [string]$DNSServer,
        
        [string[]]$TestDomains = @("dns.msftncsi.com", "www.msftconnecttest.com", "one.one.one.one"),

        [ValidateRange(1,3)]
        [int]$Attempts = 2
    )

    for ($attempt = 1; $attempt -le $Attempts; $attempt++) {
        foreach ($domain in $TestDomains) {
            try {
                $result = Resolve-DnsName -Name $domain -Server $DNSServer -Type A -QuickTimeout -ErrorAction Stop
                if ($result) { return $true }
            } catch {
                Write-LogMessage -Message "DNS connectivity test failed for $DNSServer resolving ${domain} (attempt $attempt/$Attempts): $($_.Exception.Message)" -Level "DEBUG"
            }
        }

        if ($attempt -lt $Attempts) {
            Start-Sleep -Milliseconds 500
        }
    }

    return $false
}

function Test-SystemDNSResolution {
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [string[]]$TestDomains = @("dns.msftncsi.com", "www.msftconnecttest.com", "one.one.one.one")
    )

    foreach ($domain in $TestDomains) {
        try {
            $result = Resolve-DnsName -Name $domain -Type A -QuickTimeout -ErrorAction Stop
            if ($result) { return $true }
        } catch {
            Write-LogMessage -Message "System DNS resolution test failed for ${domain}: $($_.Exception.Message)" -Level "DEBUG"
        }
    }

    return $false
}

function Test-MTUSize {
    <#
    .SYNOPSIS
        Detects optimal MTU size for a network connection.
    
    .PARAMETER Target
        Target host to test against (default: 8.8.8.8).
    
    .PARAMETER InterfaceAlias
        Network interface to test (optional).
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param (
        [string]$Target = "8.8.8.8",
        [string]$InterfaceAlias = $null
    )
    
    $maxMTU = 1500
    $minMTU = 576
    
    Write-LogMessage -Message "Testing MTU size to $Target" -Level "DEBUG"
    
    $sourceAddress = $null
    if ($InterfaceAlias) {
        try {
            $sourceAddress = (Get-NetIPAddress -InterfaceAlias $InterfaceAlias -AddressFamily IPv4 -ErrorAction Stop |
                Where-Object { $_.IPAddress -notlike "169.254.*" } |
                Select-Object -First 1).IPAddress
        } catch {
            Write-LogMessage -Message "Could not determine source address for MTU test on ${InterfaceAlias}: $($_.Exception.Message)" -Level "DEBUG"
        }
    }

    # Windows PowerShell 5.1 Test-Connection does not support -DontFragment/-TargetName.
    # Use ping.exe so MTU detection remains compatible with the built-in Windows PowerShell.
    for ($mtu = $maxMTU; $mtu -ge $minMTU; $mtu -= 8) {
        try {
            $payloadSize = $mtu - 28  # Account for IPv4 + ICMP headers
            $pingArgs = @("-n", "1", "-f", "-l", $payloadSize)

            if ($sourceAddress) {
                $pingArgs += @("-S", $sourceAddress)
            }

            $pingArgs += $Target
            $null = & ping.exe @pingArgs 2>&1

            if ($LASTEXITCODE -eq 0) {
                Write-LogMessage -Message "Optimal MTU detected: $mtu bytes" -Level "INFO"
                return $mtu
            }
        } catch {
            continue
        }
    }
    
    Write-LogMessage -Message "Using minimum MTU: $minMTU bytes" -Level "WARN"
    return $minMTU
}

function Test-IPConflict {
    <#
    .SYNOPSIS
        Detects if an IP address is already in use using gratuitous ARP and multiple detection methods.
    
    .PARAMETER IPAddress
        The IP address to check for conflicts.
    
    .PARAMETER InterfaceName
        The network interface name to exclude from conflict check.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory=$true)]
        [string]$IPAddress,
        
        [Parameter(Mandatory=$true)]
        [string]$InterfaceName
    )
    
    try {
        # Get all current IPs on this interface
        $currentIPs = (Get-NetIPAddress -InterfaceAlias $InterfaceName -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress
        
        # If we're checking an IP that's already configured on THIS interface, skip conflict check
        if ($currentIPs -contains $IPAddress) {
            Write-LogMessage -Message "IP $IPAddress already configured on this interface - skipping conflict check" -Level "DEBUG"
            return $false
        }
        
        Write-Host "    Scanning: " -NoNewline -ForegroundColor Gray
        Write-LogMessage -Message "Starting comprehensive IP conflict detection for $IPAddress..." -Level "DEBUG"
        
        # Method 1: NetBIOS Name Query (nbtstat) - Works for Windows clients
        # Run with short timeout to avoid hanging
        Write-Host "[NBT]" -NoNewline -ForegroundColor DarkGray
        try {
            $nbtJob = Start-Job -ScriptBlock { & nbtstat -A $using:IPAddress 2>&1 | Out-String }
            $nbtstatOutput = Wait-Job $nbtJob -Timeout 1 | Receive-Job
            Remove-Job $nbtJob -Force -ErrorAction SilentlyContinue
            
            if ($nbtstatOutput -and $nbtstatOutput -notmatch "Host not found" -and ($nbtstatOutput -match "MAC Address" -or $nbtstatOutput -match "<00>")) {
                $computerName = "Unknown"
                if ($nbtstatOutput -match "([A-Z0-9-]+)\s+<00>\s+UNIQUE") {
                    $computerName = $matches[1]
                }
                
                $macAddress = "Unknown"
                if ($nbtstatOutput -match "MAC Address = ([0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2})") {
                    $macAddress = $matches[1]
                }
                
                Write-Host "`r    [!] CONFLICT: $computerName ($macAddress)" -ForegroundColor Red
                Write-LogMessage -Message "IP conflict detected via NetBIOS: $IPAddress in use by $computerName ($macAddress)" -Level "WARN"
                return $true
            }
        } catch {
            Write-LogMessage -Message "NetBIOS conflict probe failed for ${IPAddress}: $_" -Level "DEBUG"
        }
        
        # Method 2: Gratuitous ARP using arp command
        Write-Host " [ARP]" -NoNewline -ForegroundColor DarkGray
        try {
            # Clear old entry first
            $null = & arp -d $IPAddress 2>&1
            
            # Send ARP request (gratuitous ARP probe)
            $pingResult = Test-Connection -ComputerName $IPAddress -Count 1 -Quiet -ErrorAction SilentlyContinue
            Start-Sleep -Milliseconds 100
            
            # Check if ARP table was populated
            $arpCheck = & arp -a $IPAddress 2>&1
            if ($arpCheck -match $IPAddress -and $arpCheck -notmatch "No ARP Entries") {
                $macMatch = [regex]::Match($arpCheck, '([0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2})')
                if ($macMatch.Success) {
                    Write-Host "`r    [!] CONFLICT: MAC $($macMatch.Value)" -ForegroundColor Red
                    Write-LogMessage -Message "IP conflict detected via ARP: $IPAddress has MAC $($macMatch.Value)" -Level "WARN"
                    return $true
                }
            }
        } catch {
            Write-LogMessage -Message "ARP conflict probe failed for ${IPAddress}: $_" -Level "DEBUG"
        }
        
        # Method 3: ICMP Ping
        Write-Host " [PING]" -NoNewline -ForegroundColor DarkGray
        $pingResult = Test-Connection -ComputerName $IPAddress -Count 1 -Quiet -ErrorAction SilentlyContinue
        if ($pingResult) {
            Write-Host "`r    [!] CONFLICT: Host responds to ping" -ForegroundColor Red
            Write-LogMessage -Message "IP conflict detected: $IPAddress responds to ICMP" -Level "WARN"
            return $true
        }
        
        # Method 4: PowerShell ARP cache
        Write-Host " [CACHE]" -NoNewline -ForegroundColor DarkGray
        Start-Sleep -Milliseconds 100
        $arpEntry = Get-NetNeighbor -IPAddress $IPAddress -ErrorAction SilentlyContinue | 
            Where-Object { $_.State -in @('Reachable', 'Stale', 'Delay', 'Probe', 'Permanent') }
        
        if ($arpEntry) {
            Write-Host "`r    [!] CONFLICT: MAC $($arpEntry.LinkLayerAddress)" -ForegroundColor Red
            Write-LogMessage -Message "IP conflict detected in ARP cache: $IPAddress ($($arpEntry.LinkLayerAddress))" -Level "WARN"
            return $true
        }
        
        # Method 5: TCP port scan (Windows services)
        Write-Host " [TCP]" -NoNewline -ForegroundColor DarkGray
        $commonPorts = @(445, 139)
        foreach ($port in $commonPorts) {
            try {
                $tcpClient = New-Object System.Net.Sockets.TcpClient
                $connectTask = $tcpClient.ConnectAsync($IPAddress, $port)
                if ($connectTask.Wait(100)) {
                    if ($tcpClient.Connected) {
                        $tcpClient.Close()
                        Write-Host "`r    [!] CONFLICT: Port $port open" -ForegroundColor Red
                        Write-LogMessage -Message "IP conflict detected: $IPAddress responds on TCP port $port" -Level "WARN"
                        $tcpClient.Dispose()
                        return $true
                    }
                }
                $tcpClient.Dispose()
            } catch {
                Write-LogMessage -Message "TCP conflict probe failed for ${IPAddress} on port ${port}: $_" -Level "DEBUG"
            }
        }
        
        # Method 6: Final comprehensive check
        Write-Host " [FINAL]" -NoNewline -ForegroundColor DarkGray
        Start-Sleep -Milliseconds 100
        $finalArpCheck = & arp -a | Select-String $IPAddress
        if ($finalArpCheck -and $finalArpCheck -notmatch "incomplete") {
            Write-Host "`r    [!] CONFLICT: Found in final ARP check" -ForegroundColor Red
            Write-LogMessage -Message "IP conflict detected in final check for $IPAddress" -Level "WARN"
            return $true
        }
        
        Write-Host "`r    No conflict detected. " -NoNewline -ForegroundColor Green
        Write-Host "[$IPAddress is available]" -NoNewline -ForegroundColor Green
        Write-Host (" " * 30)  # Clear remaining characters from progress line
        Write-LogMessage -Message "No IP conflict detected for $IPAddress after comprehensive scan" -Level "DEBUG"
        return $false
        
    } catch {
        Write-Host "`r    Error during conflict detection: $_" -ForegroundColor Red
        Write-LogMessage -Message "Error checking IP conflict for $IPAddress - $($_.Exception.Message)" -Level "DEBUG"
        return $false
    }
}

function Backup-NetworkConfiguration {
    <#
    .SYNOPSIS
        Creates a backup snapshot of network configuration.
    
    .PARAMETER InterfaceName
        The network interface to backup.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param (
        [Parameter(Mandatory=$true)]
        [string]$InterfaceName
    )
    
    try {
        $backup = @{
            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Interface = $InterfaceName
            IPv4Address = Get-NetIPAddress -InterfaceAlias $InterfaceName -AddressFamily IPv4 -ErrorAction SilentlyContinue
            IPv4Routes = Get-NetRoute -InterfaceAlias $InterfaceName -AddressFamily IPv4 -ErrorAction SilentlyContinue
            DNSServers = (Get-DnsClientServerAddress -InterfaceAlias $InterfaceName -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses
            DHCPEnabled = (Get-NetIPInterface -InterfaceAlias $InterfaceName -AddressFamily IPv4 -ErrorAction SilentlyContinue).Dhcp
        }

        try {
            $safeInterfaceName = $InterfaceName -replace '[\\/:*?"<>|]', '_'
            $backupPath = New-ManagedBackupPath -BaseName "network_$safeInterfaceName" -Extension "json"
            $backupFile = [ordered]@{
                FormatVersion = 1
                ScriptVersion = $script:ScriptVersion
                Timestamp = $backup.Timestamp
                Interface = $backup.Interface
                DHCPEnabled = [string]$backup.DHCPEnabled
                DNSServers = @($backup.DNSServers)
                IPv4Addresses = @(
                    $backup.IPv4Address | ForEach-Object {
                        [ordered]@{
                            IPAddress = $_.IPAddress
                            PrefixLength = $_.PrefixLength
                            PrefixOrigin = [string]$_.PrefixOrigin
                            SuffixOrigin = [string]$_.SuffixOrigin
                            AddressState = [string]$_.AddressState
                        }
                    }
                )
                IPv4Routes = @(
                    $backup.IPv4Routes | ForEach-Object {
                        [ordered]@{
                            DestinationPrefix = $_.DestinationPrefix
                            NextHop = $_.NextHop
                            RouteMetric = $_.RouteMetric
                            Protocol = [string]$_.Protocol
                        }
                    }
                )
            }
            $backupFile | ConvertTo-Json -Depth 5 | Set-Content -Path $backupPath -Encoding UTF8
            Invoke-BackupRetention -Filter "network_$safeInterfaceName`_*.json"
        } catch {
            Write-LogMessage -Message "Could not write managed network backup for ${InterfaceName}: $_" -Level "WARN"
        }
        
        Write-LogMessage -Message "Network configuration backup created for $InterfaceName" -Level "INFO"
        return $backup
    } catch {
        Write-LogMessage -Message "Failed to backup network configuration: $_" -Level "ERROR"
        return $null
    }
}

function Show-IPv4ConfigurationSummary {
    param (
        [Parameter(Mandatory=$true)]
        [string]$InterfaceName,

        [object]$IPConfig = $null,

        [object]$IPv4Address = $null,

        [string]$DHCPStatus = $null
    )

    if (-not $IPConfig) {
        $IPConfig = Get-NetIPConfiguration -InterfaceAlias $InterfaceName -ErrorAction SilentlyContinue
    }

    if (-not $IPv4Address -and $IPConfig -and $IPConfig.IPv4Address) {
        $IPv4Address = if ($IPConfig.IPv4Address -is [array]) {
            $IPConfig.IPv4Address | Select-Object -First 1
        } else {
            $IPConfig.IPv4Address
        }
    }

    if (-not $DHCPStatus) {
        $DHCPStatus = (Get-NetIPInterface -InterfaceAlias $InterfaceName -AddressFamily IPv4 -ErrorAction SilentlyContinue).Dhcp
    }

    Write-Host "`nCurrent IP configuration for interface: $InterfaceName" -ForegroundColor Cyan

    if ($IPv4Address -and $IPv4Address.IPAddress) {
        Write-Host "IP Address: $($IPv4Address.IPAddress)" -ForegroundColor White
        Write-Host "Subnet Mask: /$($IPv4Address.PrefixLength)" -ForegroundColor White
    } else {
        Write-Host "IP Address: (not configured)" -ForegroundColor DarkYellow
        Write-Host "Subnet Mask: (not configured)" -ForegroundColor DarkYellow
    }

    if ($IPConfig -and $IPConfig.IPv4DefaultGateway) {
        Write-Host "Default Gateway: $($IPConfig.IPv4DefaultGateway.NextHop)" -ForegroundColor White
    } else {
        Write-Host "Default Gateway: (not set)" -ForegroundColor DarkYellow
    }

    if ($IPConfig -and $IPConfig.DnsServer -and $IPConfig.DnsServer.ServerAddresses) {
        $ipv4DnsServers = $IPConfig.DnsServer.ServerAddresses | Where-Object { $_ -match "^\d+\.\d+\.\d+\.\d+$" }
        if ($ipv4DnsServers) {
            Write-Host "DNS Servers (IPv4): $($ipv4DnsServers -join ', ')" -ForegroundColor White
        } else {
            Write-Host "DNS Servers (IPv4): (none configured)" -ForegroundColor DarkYellow
        }
    } else {
        Write-Host "DNS Servers (IPv4): (none configured)" -ForegroundColor DarkYellow
    }

    if ($DHCPStatus) {
        $dhcpColor = if ($DHCPStatus -eq 'Disabled') { 'White' } else { 'Yellow' }
        Write-Host "DHCP Status: $DHCPStatus" -ForegroundColor $dhcpColor
    }
}

function Remove-IPv4AddressSafe {
    param (
        [Parameter(Mandatory=$true)]
        [string]$InterfaceName,

        [Parameter(Mandatory=$true)]
        [string]$IPAddress,

        [string]$PrefixLength = $null,

        [switch]$Quiet
    )

    try {
        Remove-NetIPAddress -IPAddress $IPAddress -InterfaceAlias $InterfaceName -Confirm:$false -ErrorAction Stop
        if (-not $Quiet) {
            $suffix = if ($PrefixLength) { "/$PrefixLength" } else { "" }
            Write-LogMessage -Message "Removed IPv4 address from ${InterfaceName}: $IPAddress$suffix" -Level "DEBUG"
        }
        return $true
    } catch {
        if (-not $Quiet) {
            Write-LogMessage -Message "Warning: Could not remove IPv4 address $IPAddress from ${InterfaceName}: $_" -Level "WARN"
        }
        return $false
    }
}

function Set-IPv4DefaultGatewaySafe {
    param (
        [Parameter(Mandatory=$true)]
        [string]$InterfaceName,

        [Parameter(Mandatory=$true)]
        [string]$Gateway
    )

    try {
        $existingGateway = Get-NetRoute -InterfaceAlias $InterfaceName -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue
        if ($existingGateway -and ($existingGateway | Where-Object { $_.NextHop -eq $Gateway })) {
            return $true
        }

        if ($existingGateway) {
            $existingGateway | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
        }

        New-NetRoute -InterfaceAlias $InterfaceName -DestinationPrefix "0.0.0.0/0" -NextHop $Gateway -ErrorAction Stop | Out-Null
        Write-LogMessage -Message "Updated gateway to $Gateway" -Level "INFO"
        return $true
    } catch {
        Write-LogMessage -Message "Warning: Could not update gateway: $_" -Level "WARN"
        return $false
    }
}

function Set-IPv4DnsServersSafe {
    param (
        [Parameter(Mandatory=$true)]
        [string]$InterfaceName,

        [Parameter(Mandatory=$true)]
        [string[]]$DNSServers
    )

    try {
        Set-DnsClientServerAddress -InterfaceAlias $InterfaceName -ServerAddresses $DNSServers -ErrorAction Stop
        Start-Sleep -Milliseconds 500
        $verifyDNS = (Get-DnsClientServerAddress -InterfaceAlias $InterfaceName -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses
        foreach ($dnsServer in $DNSServers) {
            if (-not ($verifyDNS -contains $dnsServer)) {
                return $false
            }
        }

        return $true
    } catch {
        Write-LogMessage -Message "Attempt to set DNS failed: $_" -Level "WARN"
        return $false
    }
}

function Reset-IPv4DnsServersSafe {
    param (
        [Parameter(Mandatory=$true)]
        [string]$InterfaceName,

        [switch]$Quiet
    )

    try {
        Set-DnsClientServerAddress -InterfaceAlias $InterfaceName -ResetServerAddresses -ErrorAction Stop
        if (-not $Quiet) {
            Write-LogMessage -Message "Reset IPv4 DNS server addresses for $InterfaceName" -Level "DEBUG"
        }
        return $true
    } catch {
        if (-not $Quiet) {
            Write-LogMessage -Message "Could not reset IPv4 DNS server addresses for ${InterfaceName}: $_" -Level "WARN"
        }
        return $false
    }
}

function Restore-DHCPConfiguration {
    param (
        [Parameter(Mandatory=$true)]
        [string]$InterfaceName
    )

    try {
        $partialIP = Get-NetIPAddress -InterfaceAlias $InterfaceName -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.PrefixOrigin -ne 'Dhcp' }
        foreach ($ip in @($partialIP)) {
            $null = Remove-IPv4AddressSafe -InterfaceName $InterfaceName -IPAddress $ip.IPAddress -Quiet
        }

        Set-NetIPInterface -InterfaceAlias $InterfaceName -AddressFamily IPv4 -Dhcp Enabled -ErrorAction Stop
        $null = Reset-IPv4DnsServersSafe -InterfaceName $InterfaceName -Quiet

        $null = & ipconfig /renew $InterfaceName 2>&1
        Write-LogMessage -Message "Successfully rolled back to DHCP after static IP failure" -Level "INFO"
        return $true
    } catch {
        Write-LogMessage -Message "Rollback to DHCP failed: $_" -Level "ERROR"
        return $false
    }
}

function Get-NetworkProfile {
    <#
    .SYNOPSIS
        Gets the network profile/category for an interface.
    
    .PARAMETER InterfaceAlias
        The network interface name.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory=$true)]
        [string]$InterfaceAlias
    )
    
    try {
        $adapter = Get-NetAdapter -Name $InterfaceAlias -ErrorAction Stop
        $netProfile = Get-NetConnectionProfile -InterfaceIndex $adapter.ifIndex -ErrorAction Stop
        return $netProfile.NetworkCategory
    } catch {
        Write-LogMessage -Message "Failed to get network profile for $InterfaceAlias - $($_.Exception.Message)" -Level "DEBUG"
        return "Unknown"
    }
}

function Get-NetworkPerformance {
    <#
    .SYNOPSIS
        Gets network performance statistics for an interface.
    
    .PARAMETER InterfaceName
        The network interface name.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param (
        [Parameter(Mandatory=$true)]
        [string]$InterfaceName
    )
    
    try {
        $adapter = Get-NetAdapter -Name $InterfaceName -ErrorAction Stop
        $stats = Get-NetAdapterStatistics -Name $InterfaceName -ErrorAction Stop
        
        return @{
            BytesSent = $stats.SentBytes
            BytesReceived = $stats.ReceivedBytes
            PacketsSent = $stats.SentUnicastPackets
            PacketsReceived = $stats.ReceivedUnicastPackets
            Errors = $stats.OutboundErrors + $stats.InboundErrors
            Discards = $stats.OutboundDiscardedPackets + $stats.InboundDiscardedPackets
            LinkSpeed = $adapter.LinkSpeed
            Timestamp = Get-Date
        }
    } catch {
        Write-LogMessage -Message "Failed to get network performance for $InterfaceName - $($_.Exception.Message)" -Level "DEBUG"
        return $null
    }
}

function Get-MACVendor {
    <#
    .SYNOPSIS
        Looks up the manufacturer/vendor of a network device by MAC address.
    
    .PARAMETER MACAddress
        The MAC address to lookup (any format: XX:XX:XX:XX:XX:XX, XX-XX-XX-XX-XX-XX, or XXXXXXXXXXXX).
    
    .PARAMETER UseCache
        Use cached results to avoid repeated API calls (default: true).
    
    .EXAMPLE
        Get-MACVendor -MACAddress "00:1A:2B:3C:4D:5E"
        Returns vendor information for the specified MAC address.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory=$true)]
        [string]$MACAddress,
        
        [Parameter(Mandatory=$false)]
        [bool]$UseCache = $true
    )
    
    # Initialize cache at script level if not exists
    if (-not $script:MACVendorCache) {
        $script:MACVendorCache = @{}
    }
    
    try {
        # Validate and normalize MAC address
        if ([string]::IsNullOrWhiteSpace($MACAddress)) {
            Write-LogMessage -Message "Empty MAC address provided" -Level "DEBUG"
            return "Invalid MAC"
        }
        
        # Normalize MAC address (remove separators, uppercase)
        $normalizedMAC = ($MACAddress -replace '[:\-\.\s]', '').ToUpper()
        
        # Validate length (should be 12 hex characters)
        if ($normalizedMAC.Length -ne 12) {
            Write-LogMessage -Message "Invalid MAC address length: $MACAddress (expected 12 hex digits)" -Level "DEBUG"
            return "Invalid MAC"
        }
        
        # Validate hex characters only
        if ($normalizedMAC -notmatch '^[0-9A-F]{12}$') {
            Write-LogMessage -Message "Invalid MAC address format: $MACAddress (must contain only hex digits)" -Level "DEBUG"
            return "Invalid MAC"
        }
        
        # Extract OUI (first 6 characters)
        $oui = $normalizedMAC.Substring(0, 6)
        
        # Check cache first
        if ($UseCache -and $script:MACVendorCache.ContainsKey($oui)) {
            return $script:MACVendorCache[$oui]
        }
        
        # Query API with timeout
        $apiUrl = "https://api.macvendors.com/$oui"
        $vendor = $null
        
        try {
            # Create web request with timeout
            $request = [System.Net.WebRequest]::Create($apiUrl)
            $request.Timeout = 2000  # 2 second timeout
            $response = $request.GetResponse()
            $stream = $response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($stream)
            $vendor = $reader.ReadToEnd()
            $reader.Close()
            $response.Close()
            
            # Cache the result
            if ($vendor -and $vendor -notmatch "error|not found") {
                $script:MACVendorCache[$oui] = $vendor
                Write-LogMessage -Message "MAC vendor lookup: $oui -> $vendor" -Level "DEBUG"
                return $vendor
            } else {
                # Don't cache - might be a temporary API issue
                return "Unknown Vendor"
            }
        } catch {
            # API failed or timeout - don't cache failures so we can retry when online
            if ($_.Exception.Message -match "404") {
                return "Unknown Vendor"
            } else {
                return "Lookup Failed"
            }
        }
        
    } catch {
        Write-LogMessage -Message "MAC vendor lookup error for $MACAddress - $($_.Exception.Message)" -Level "DEBUG"
        return "Unknown"
    }
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
    <#
    .SYNOPSIS
        Converts a subnet mask to CIDR prefix length.
    
    .PARAMETER SubnetInput
        Subnet mask in dotted decimal (e.g., 255.255.255.0), CIDR (24), or /CIDR (/24) notation.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$SubnetInput
    )

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

function ConvertTo-IPv4UInt32 {
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$IPAddress
    )

    $bytes = [System.Net.IPAddress]::Parse($IPAddress).GetAddressBytes()
    return ([uint64]$bytes[0] * 16777216) + ([uint64]$bytes[1] * 65536) + ([uint64]$bytes[2] * 256) + [uint64]$bytes[3]
}

function ConvertFrom-IPv4UInt32 {
    param (
        [Parameter(Mandatory=$true)]
        [uint64]$Address
    )

    $octet1 = [int]([math]::Floor($Address / 16777216) % 256)
    $octet2 = [int]([math]::Floor($Address / 65536) % 256)
    $octet3 = [int]([math]::Floor($Address / 256) % 256)
    $octet4 = [int]($Address % 256)

    return "$octet1.$octet2.$octet3.$octet4"
}

function Get-IPv4NetworkDetails {
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$IPAddress,

        [Parameter(Mandatory=$true)]
        [ValidateRange(0,32)]
        [int]$PrefixLength
    )

    $ipValue = ConvertTo-IPv4UInt32 -IPAddress $IPAddress
    $hostBits = 32 - $PrefixLength
    $blockSize = [uint64][math]::Pow(2, $hostBits)
    $networkValue = if ($PrefixLength -eq 0) { [uint64]0 } else { [uint64]([math]::Floor($ipValue / $blockSize) * $blockSize) }
    $broadcastValue = if ($PrefixLength -eq 32) { $networkValue } else { $networkValue + $blockSize - 1 }

    return @{
        NetworkAddress = ConvertFrom-IPv4UInt32 -Address $networkValue
        BroadcastAddress = ConvertFrom-IPv4UInt32 -Address $broadcastValue
        NetworkValue = $networkValue
        BroadcastValue = $broadcastValue
        IPValue = $ipValue
    }
}

# Function to suggest a default gateway based on IP address and subnet
function Get-SuggestedGateway {
    param (
        [string]$IPAddress,
        [int]$PrefixLength = 24  # Default to /24 if not specified
    )

    $ipParts = $IPAddress -split '\.'
    if ($ipParts.Count -ne 4) {
        throw "Invalid IP address format."
    }

    # For /24 or smaller subnets, suggest .1 and .254 in the same octet
    if ($PrefixLength -ge 24) {
        $base = "$($ipParts[0]).$($ipParts[1]).$($ipParts[2])"
        $gw1 = "$base.1"
        $gw254 = "$base.254"
        return @($gw1, $gw254)
    }
    
    # For larger subnets (e.g., /22, /23), calculate network boundaries
    # Create subnet mask from prefix length
    $maskBinary = ('1' * $PrefixLength).PadRight(32, '0')
    $maskBytes = @()
    for ($i = 0; $i -lt 32; $i += 8) {
        $maskBytes += [Convert]::ToInt32($maskBinary.Substring($i, 8), 2)
    }
    
    # Calculate network address
    $ipBytes = [System.Net.IPAddress]::Parse($IPAddress).GetAddressBytes()
    $networkBytes = @()
    for ($i = 0; $i -lt 4; $i++) {
        $networkBytes += $ipBytes[$i] -band $maskBytes[$i]
    }
    
    # Calculate broadcast address (all host bits set to 1)
    $broadcastBytes = @()
    for ($i = 0; $i -lt 4; $i++) {
        $broadcastBytes += $networkBytes[$i] -bor (255 -bxor $maskBytes[$i])
    }
    
    # Suggest .1 as first usable address (network + 1)
    $gw1Bytes = @($networkBytes[0], $networkBytes[1], $networkBytes[2], $networkBytes[3])
    $gw1Bytes[3] += 1
    $gw1 = $gw1Bytes -join '.'
    
    # Suggest last-1 as last usable address (broadcast - 1)
    $gw254Bytes = @($broadcastBytes[0], $broadcastBytes[1], $broadcastBytes[2], $broadcastBytes[3])
    $gw254Bytes[3] -= 1
    $gw254 = $gw254Bytes -join '.'
    
    return @($gw1, $gw254)
}

# Subnet Calculator Function
# Inspired by various PowerShell subnet calculator implementations from the community
# This function provides comprehensive subnet calculations for network planning
function Invoke-SubnetCalculator {
    [CmdletBinding()]
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
        $binary = ($octets | ForEach-Object {
            [Convert]::ToString([int]$_, 2).PadLeft(8, '0')
        }) -join ''
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
        for ($attempt = 1; $attempt -le 3; $attempt++) {
            $IPAddress = (Read-Host "Enter IP Address (blank to cancel, e.g., 192.168.1.10)").Trim()
            if ([string]::IsNullOrWhiteSpace($IPAddress)) {
                Write-Host "Subnet calculation cancelled." -ForegroundColor Yellow
                return
            }

            if (Test-ValidIPAddress -IPAddress $IPAddress) {
                break
            }

            Write-Host "Invalid IP address. Please enter a valid IPv4 address." -ForegroundColor Red
            if ($attempt -eq 3) {
                Write-Host "Maximum attempts reached. Returning to main menu." -ForegroundColor Yellow
                return
            }
        }
    } elseif (-not (Test-ValidIPAddress -IPAddress $IPAddress)) {
        Write-Host "Invalid IP address. Please enter a valid IPv4 address." -ForegroundColor Red
        return
    }

    if ($CIDR -ne 0) {
        if ($CIDR -lt 8 -or $CIDR -gt 32) {
            Write-Host "Invalid CIDR value. CIDR must be between 8 and 32." -ForegroundColor Red
            return
        }
    }
    
    if (-not $SubnetMask -and -not $CIDR) {
        for ($attempt = 1; $attempt -le 3; $attempt++) {
            $maskInput = (Read-Host "Enter Subnet Mask or CIDR (blank to cancel, e.g., 255.255.255.0 or 24 or /24)").Trim()
            if ([string]::IsNullOrWhiteSpace($maskInput)) {
                Write-Host "Subnet calculation cancelled." -ForegroundColor Yellow
                return
            }

            # Parse and validate input
            if ($maskInput -match "^/?([8-9]|[12][0-9]|3[0-2])$") {
                # CIDR notation with or without /
                $CIDR = [int]($maskInput -replace "/", "")
                break
            } elseif ($maskInput -match "^\d+\.\d+\.\d+\.\d+$") {
                # Dotted decimal subnet mask
                if (Test-ValidSubnetMask -SubnetInput $maskInput) {
                    $SubnetMask = $maskInput
                    break
                } else {
                    Write-Host "Invalid subnet mask. Please enter a valid subnet mask (e.g., 255.255.255.0)." -ForegroundColor Red
                }
            } else {
                Write-Host "Invalid format. Please enter a subnet mask (255.255.255.0) or CIDR notation (24 or /24)." -ForegroundColor Red
            }

            if ($attempt -eq 3) {
                Write-Host "Maximum attempts reached. Returning to main menu." -ForegroundColor Yellow
                return
            }
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
        
        # Calculate total hosts
        $hostBits = 32 - $CIDR
        $totalHosts = [Math]::Pow(2, $hostBits)
        $usableHosts = if ($CIDR -eq 32) { 1 } elseif ($CIDR -eq 31) { 2 } else { $totalHosts - 2 }

        # Calculate first and last usable IP
        if ($CIDR -eq 32) {
            $firstUsableIP = $IPAddress
            $lastUsableIP = $IPAddress
        } elseif ($CIDR -eq 31) {
            $firstUsableIP = $networkAddress
            $lastUsableIP = $broadcastAddress
        } else {
            $firstIPOctets = $networkAddress -split '\.'
            $firstIPOctets[3] = [string]([int]$firstIPOctets[3] + 1)
            $firstUsableIP = $firstIPOctets -join '.'

            $lastIPOctets = $broadcastAddress -split '\.'
            $lastIPOctets[3] = [string]([int]$lastIPOctets[3] - 1)
            $lastUsableIP = $lastIPOctets -join '.'
        }
        
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
$profilesPath = $script:ProfilesPath
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

function Get-SafeProfileFileName {
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name
    )

    $safeName = $Name.Trim()
    foreach ($char in [System.IO.Path]::GetInvalidFileNameChars()) {
        $safeName = $safeName.Replace($char, '-')
    }

    $safeName = $safeName -replace '\s+', '-'
    $safeName = $safeName -replace '[^a-zA-Z0-9_.-]', '-'
    $safeName = $safeName.Trim('-', '.', '_')

    if ([string]::IsNullOrWhiteSpace($safeName)) {
        $safeName = "profile"
    }

    return $safeName.ToLower()
}

function Get-IPProfiles {
    if (-not (Test-Path $profilesPath)) {
        return @()
    }

    $profiles = @()
    $profileFiles = Get-ChildItem -Path $profilesPath -Filter "*.json" -ErrorAction SilentlyContinue
    foreach ($file in $profileFiles) {
        try {
            $profileData = Get-Content -Path $file.FullName -Raw -ErrorAction Stop | ConvertFrom-Json
            $profiles += [pscustomobject]@{
                Name = $profileData.Name
                Environment = $profileData.Environment
                Description = $profileData.Description
                InterfaceName = $profileData.InterfaceName
                IPAddress = $profileData.IPAddress
                SubnetMask = $profileData.SubnetMask
                Gateway = $profileData.Gateway
                PrimaryDNS = $profileData.PrimaryDNS
                SecondaryDNS = $profileData.SecondaryDNS
                UpdatedAt = $profileData.UpdatedAt
                Path = $file.FullName
            }
        } catch {
            Write-LogMessage -Message "Could not read profile '$($file.FullName)': $_" -Level "WARN"
        }
    }

    return @($profiles | Sort-Object Environment, Name)
}

function Get-CurrentIPProfileSettings {
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$InterfaceName
    )

    try {
        $ipConfig = Get-NetIPConfiguration -InterfaceAlias $InterfaceName -ErrorAction Stop
        $ipInterface = Get-NetIPInterface -InterfaceAlias $InterfaceName -AddressFamily IPv4 -ErrorAction Stop
        $ipv4Address = $ipConfig.IPv4Address |
            Where-Object { $_.IPAddress -and $_.IPAddress -notlike "169.254.*" } |
            Select-Object -First 1

        if (-not $ipv4Address) {
            Write-Host "No usable IPv4 address found on $InterfaceName." -ForegroundColor Yellow
            return $null
        }

        if ($ipInterface.Dhcp -eq "Enabled") {
            Write-Host "This adapter is currently using DHCP. Static IP profiles save fixed IPv4 settings only." -ForegroundColor Yellow
            return $null
        }

        $dnsServers = @()
        if ($ipConfig.DnsServer -and $ipConfig.DnsServer.ServerAddresses) {
            $dnsServers = @($ipConfig.DnsServer.ServerAddresses | Where-Object { Test-ValidDNSServer -DNSServer $_ })
        }

        if ($dnsServers.Count -eq 0) {
            Write-Host "No IPv4 DNS server is configured on $InterfaceName." -ForegroundColor Yellow
            return $null
        }

        return @{
            IPAddress = $ipv4Address.IPAddress
            SubnetMask = [string]$ipv4Address.PrefixLength
            Gateway = if ($ipConfig.IPv4DefaultGateway) { $ipConfig.IPv4DefaultGateway.NextHop } else { $null }
            PrimaryDNS = $dnsServers[0]
            SecondaryDNS = if ($dnsServers.Count -gt 1) { $dnsServers[1] } else { $null }
        }
    } catch {
        Write-Host "Could not read current adapter configuration: $_" -ForegroundColor Red
        Write-LogMessage -Message "Could not read current adapter configuration for profile save: $_" -Level "ERROR"
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
        [string]$SecondaryDNS = $null,
        [string]$InterfaceName = $null
    )

    if (-not (Test-Path $profilesPath)) {
        New-Item -Path $profilesPath -ItemType Directory -Force | Out-Null
    }

    Write-Host ""
    Write-Host "=== Save IP Profile ===" -ForegroundColor Cyan
    Write-Host ""

    $defaultName = if ($InterfaceName) { "$InterfaceName-$IPAddress" } else { "Profile-$IPAddress" }
    $profileName = (Read-Host "Profile name (default: $defaultName)").Trim()
    if ([string]::IsNullOrWhiteSpace($profileName)) {
        $profileName = $defaultName
    }

    $environment = (Read-Host "Environment/group (home, work, lab; optional)").Trim()
    if ([string]::IsNullOrWhiteSpace($environment)) {
        $environment = "General"
    }

    $description = (Read-Host "Short note (optional)").Trim()
    $safeName = Get-SafeProfileFileName -Name "$environment-$profileName"
    $profilePath = Join-Path $profilesPath "$safeName.json"
    $now = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

    $createdAt = $now
    if (Test-Path $profilePath) {
        try {
            $existingProfile = Get-Content -Path $profilePath -Raw -ErrorAction Stop | ConvertFrom-Json
            if ($existingProfile.CreatedAt) {
                $createdAt = $existingProfile.CreatedAt
            }
        } catch {
            Write-LogMessage -Message "Existing profile metadata could not be read before overwrite: $_" -Level "WARN"
        }
    }

    $profileRecord = [ordered]@{
        FormatVersion = 1
        Name = $profileName
        Environment = $environment
        Description = $description
        InterfaceName = $InterfaceName
        IPAddress = $IPAddress
        SubnetMask = $SubnetMask
        Gateway = $Gateway
        PrimaryDNS = $PrimaryDNS
        SecondaryDNS = $SecondaryDNS
        CreatedAt = $createdAt
        UpdatedAt = $now
        ScriptVersion = $script:ScriptVersion
    }

    $profileRecord | ConvertTo-Json -Depth 4 | Set-Content -Path $profilePath -Encoding UTF8

    Write-LogMessage -Message "IP profile saved: $profileName ($environment)" -Level "INFO"
    Write-Host "[OK] Profile saved: $profileName" -ForegroundColor Green
    Write-Host "  Group: $environment" -ForegroundColor Gray
    Write-Host "  File : $profilePath" -ForegroundColor Gray
}

# Function to load static IP configuration
function Get-SavedIPConfig {
    $profiles = @(Get-IPProfiles)
    if ($profiles.Count -gt 0) {
        Write-Host ""
        Write-Host "=== IP Profiles ===" -ForegroundColor Cyan
        Write-Host ""

        for ($i = 0; $i -lt $profiles.Count; $i++) {
            $profileEntry = $profiles[$i]
            $number = $i + 1
            $group = if ($profileEntry.Environment) { $profileEntry.Environment } else { "General" }
            $note = if ($profileEntry.Description) { " - $($profileEntry.Description)" } else { "" }
            Write-Host ("  [{0}] " -f $number) -NoNewline -ForegroundColor Cyan
            Write-Host "$($profileEntry.Name)" -NoNewline -ForegroundColor White
            Write-Host "  ($group)" -NoNewline -ForegroundColor DarkGray
            Write-Host $note -ForegroundColor Gray
            Write-Host "      $($profileEntry.IPAddress)/$($profileEntry.SubnetMask)  GW: $(if($profileEntry.Gateway){$profileEntry.Gateway}else{'none'})  DNS: $($profileEntry.PrimaryDNS)$(if($profileEntry.SecondaryDNS){', ' + $profileEntry.SecondaryDNS}else{''})" -ForegroundColor DarkGray
        }

        Write-Host ""
        Write-Host "  [D] Delete a profile" -ForegroundColor Yellow
        Write-Host "  [B] Back" -ForegroundColor DarkGray
        Write-Host ""

        $selection = (Read-Host "Select profile").Trim().ToLower()
        if ($selection -eq "b" -or [string]::IsNullOrWhiteSpace($selection)) {
            return $null
        }

        if ($selection -eq "d") {
            $deleteSelection = (Read-Host "Profile number to delete").Trim()
            $deleteIndex = 0
            if ([int]::TryParse($deleteSelection, [ref]$deleteIndex) -and $deleteIndex -ge 1 -and $deleteIndex -le $profiles.Count) {
                $profileToDelete = $profiles[$deleteIndex - 1]
                if (Read-YesNo -Prompt "Delete '$($profileToDelete.Name)'?" -Default $false) {
                    if (Remove-LocalItemSafe -Path $profileToDelete.Path -DisplayName "profile '$($profileToDelete.Name)'") {
                        Write-LogMessage -Message "IP profile deleted: $($profileToDelete.Name)" -Level "INFO"
                    }
                } else {
                    Write-Host "Delete cancelled." -ForegroundColor Yellow
                }
            } else {
                Write-Host "Invalid profile number." -ForegroundColor Red
            }
            return $null
        }

        $selectedIndex = 0
        if ([int]::TryParse($selection, [ref]$selectedIndex) -and $selectedIndex -ge 1 -and $selectedIndex -le $profiles.Count) {
            $selectedProfile = $profiles[$selectedIndex - 1]
            return @{
                Name = $selectedProfile.Name
                Environment = $selectedProfile.Environment
                Description = $selectedProfile.Description
                InterfaceName = $selectedProfile.InterfaceName
                IPAddress = $selectedProfile.IPAddress
                SubnetMask = $selectedProfile.SubnetMask
                Gateway = $selectedProfile.Gateway
                PrimaryDNS = $selectedProfile.PrimaryDNS
                SecondaryDNS = $selectedProfile.SecondaryDNS
            }
        }

        Write-Host "Invalid profile selection." -ForegroundColor Red
        return $null
    }

    if (Test-Path $configPath) {
        $config = Import-Clixml -Path $configPath

        Write-Host "Using legacy XML profile. Save it again to convert it to the modern JSON profile format." -ForegroundColor Yellow
        return @{
            Name          = "Legacy XML Profile"
            Environment   = "Legacy"
            IPAddress     = $config.IPAddress
            SubnetMask    = $config.SubnetMask
            Gateway       = $config.Gateway       # May be $null
            PrimaryDNS    = $config.PrimaryDNS
            SecondaryDNS  = $config.SecondaryDNS  # May be $null
        }
    } else {
        Write-Host "No saved configuration found." -ForegroundColor Yellow
        Write-LogMessage -Message "No saved IP profile found." -Level "INFO"
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
                Write-LogMessage -Message "Static IP configuration cancelled: invalid IP address entered after all attempts." -Level "INFO"
                return $null
            }

        # Get and validate Subnet Mask
        $SubnetMask = Get-ValidatedInput -Prompt "Enter Subnet Mask (e.g., 255.255.255.0 or 24)" `
                                        -ValidationFunction { param($mask) Test-ValidSubnetMask -SubnetInput $mask } `
                                        -ErrorMessage "Invalid subnet mask. Please enter a valid subnet mask (e.g., 255.255.255.0) or prefix length (e.g., 24)."

        # Calculate prefix length for gateway suggestions
        $prefixLengthForGateway = Get-PrefixLength -SubnetInput $SubnetMask
        
        # Suggest and validate Gateway
        $suggestedGateways = Get-SuggestedGateway -IPAddress $IPAddress -PrefixLength $prefixLengthForGateway
        $defaultGateway = $suggestedGateways[0]
        Write-Host "Suggested Gateways: $($suggestedGateways -join ', ')" -ForegroundColor Yellow

        $Gateway = $null
        for ($attempt = 1; $attempt -le 3; $attempt++) {
            $GatewayInput = (Read-Host "Enter Gateway [Enter=$defaultGateway, 254=last suggested, full IP, 'none' to skip]").Trim()

            if ([string]::IsNullOrWhiteSpace($GatewayInput)) {
                $Gateway = $defaultGateway
                Write-LogMessage -Message "Using suggested gateway: $Gateway" -Level "INFO"
                break
            } elseif ($GatewayInput.ToLower() -eq "none") {
                $Gateway = $null
                Write-LogMessage -Message "User chose to skip gateway configuration." -Level "INFO"
                break
            } elseif ($GatewayInput -eq "254" -or $GatewayInput -eq ".254") {
                $Gateway = $suggestedGateways[-1]
                Write-LogMessage -Message "User selected alternate suggested gateway: $Gateway" -Level "INFO"
                break
            } elseif (Test-ValidIPAddress -IPAddress $GatewayInput) {
                $Gateway = $GatewayInput
                Write-LogMessage -Message "User provided full gateway IP: $GatewayInput" -Level "INFO"
                break
            } else {
                Write-Host "Invalid gateway. Enter a full IPv4 address, 254, none, or press Enter for $defaultGateway." -ForegroundColor Red
                Write-LogMessage -Message "Invalid gateway provided by user: $GatewayInput. Re-prompting." -Level "WARN"
                if ($attempt -eq 3) {
                    Write-Host "Maximum attempts reached. Gateway will be skipped." -ForegroundColor Yellow
                    $Gateway = $null
                    Write-LogMessage -Message "Maximum attempts reached for gateway. Skipping gateway." -Level "WARN"
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
                Write-Host "Invalid DNS server. Please enter a valid IPv4 address." -ForegroundColor Red
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
                    Write-Host "Invalid secondary DNS server. Please enter a valid IPv4 address." -ForegroundColor Red
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

        Write-Host ""
        if (-not (Read-YesNo -Prompt "Proceed with this configuration?" -Default $true)) {
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
    <#
    .SYNOPSIS
        Configures a static IP address on a network interface.
    
    .DESCRIPTION
        Sets a static IP configuration including IP address, subnet mask, gateway, and DNS servers
        with extensive validation, retry logic, and rollback capability.
    
    .PARAMETER InterfaceName
        The name of the network interface to configure.
    
    .PARAMETER IPAddress
        The static IP address to assign.
    
    .PARAMETER SubnetMask
        The subnet mask in dotted decimal or CIDR notation (e.g., 255.255.255.0 or 24).
    
    .PARAMETER Gateway
        The default gateway IP address (optional).
    
    .PARAMETER PrimaryDNS
        The primary DNS server IP address.
    
    .PARAMETER SecondaryDNS
        The secondary DNS server IP address (optional).
    
    .PARAMETER MaxRetries
        Maximum number of retry attempts for each operation (default: 2).
    
    .PARAMETER RetryDelaySeconds
        Delay in seconds between retry attempts (default: 3).
    
    .EXAMPLE
        Set-StaticIP -InterfaceName "Ethernet0" -IPAddress "192.168.1.100" -SubnetMask "24" -Gateway "192.168.1.1" -PrimaryDNS "1.1.1.1"
    
    .NOTES
        Requires administrative privileges.
    #>
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$InterfaceName,
        
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$IPAddress,
        
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$SubnetMask,
        
        [string]$Gateway = $null,
        
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$PrimaryDNS,
        
        [string]$SecondaryDNS = $null,
        
        [ValidateRange(1,10)]
        [int]$MaxRetries = 2,
        
        [ValidateRange(1,30)]
        [int]$RetryDelaySeconds = 3
    )

    Write-Host "Configuring static IP..." -ForegroundColor Cyan
    Write-LogMessage -Message "Setting static IP configuration for interface: $InterfaceName" -Level "INFO"
    
    # Backup current configuration for rollback capability
    $backupConfig = $null

    try {
        # === PRE-FLIGHT VALIDATION ===
        Write-Host "  Running pre-flight checks..." -ForegroundColor Gray
        
        # 1. Parameter validation
        if ([string]::IsNullOrWhiteSpace($InterfaceName)) {
            throw "Interface name cannot be empty"
        }
        if ([string]::IsNullOrWhiteSpace($IPAddress)) {
            throw "IP address cannot be empty"
        }
        if ([string]::IsNullOrWhiteSpace($SubnetMask)) {
            throw "Subnet mask cannot be empty"
        }
        if ([string]::IsNullOrWhiteSpace($PrimaryDNS)) {
            throw "Primary DNS cannot be empty"
        }
        
        # 2. Validate IP address values
        if (-not (Test-ValidIPAddress -IPAddress $IPAddress)) {
            throw "Invalid IP address: $IPAddress"
        }
        
        # 3. Validate DNS values
        if (-not (Test-ValidDNSServer -DNSServer $PrimaryDNS)) {
            throw "Invalid Primary DNS address: $PrimaryDNS"
        }
        if ($SecondaryDNS -and -not (Test-ValidDNSServer -DNSServer $SecondaryDNS)) {
            throw "Invalid Secondary DNS address: $SecondaryDNS"
        }
        
        # 4. Validate Gateway value if provided
        if ($Gateway -and -not (Test-ValidIPAddress -IPAddress $Gateway)) {
            throw "Invalid Gateway address: $Gateway"
        }
        
        Write-LogMessage -Message "Parameter validation passed" -Level "DEBUG"
        
        # 5. Verify interface exists and is operational
        $adapter = Get-NetworkAdapterSafe -InterfaceName $InterfaceName
        if (-not $adapter) {
            throw "Interface '$InterfaceName' not found"
        }
        Write-LogMessage -Message "Interface verification successful: $InterfaceName" -Level "INFO"
        
        # 6. Check adapter status
        if ($adapter.Status -ne "Up") {
            Write-Host "  [WARN] Interface '$InterfaceName' status is: $($adapter.Status)" -ForegroundColor Yellow
            Write-Host "  Configuration may fail if the adapter is not connected" -ForegroundColor Yellow
            Write-LogMessage -Message "Warning: Interface status is $($adapter.Status), not Up" -Level "WARN"
        }

        if (-not $PSCmdlet.ShouldProcess($InterfaceName, "Configure static IPv4 address $IPAddress/$SubnetMask")) {
            Write-Host "Static IP configuration cancelled." -ForegroundColor Yellow
            Write-LogMessage -Message "Static IP configuration cancelled by ShouldProcess for $InterfaceName" -Level "WARN"
            return $false
        }
        
        # 7. Check for IP conflicts
        Write-Host "  Checking for IP conflicts..." -ForegroundColor Gray
        if (Test-IPConflict -IPAddress $IPAddress -InterfaceName $InterfaceName) {
            Write-Host "  [WARNING] IP address $IPAddress may already be in use." -ForegroundColor Yellow
            if (-not (Read-YesNo -Prompt "Continue anyway?" -Default $false)) {
                Write-Host "  Configuration cancelled by user due to IP conflict" -ForegroundColor Yellow
                Write-LogMessage -Message "Configuration cancelled by user after IP conflict was detected for $IPAddress" -Level "INFO"
                return
            }
        }
        
        # Backup current configuration for potential rollback
        Write-Host "  Creating configuration backup..." -ForegroundColor Gray
        $backupConfig = Backup-NetworkConfiguration -InterfaceName $InterfaceName
        if ($backupConfig) {
            Write-LogMessage -Message "Current configuration backed up successfully" -Level "DEBUG"
        } else {
            Write-LogMessage -Message "Warning: Could not backup current configuration for $InterfaceName" -Level "WARN"
        }

        # Convert subnet mask to prefix length
        $prefixLength = Get-PrefixLength -SubnetInput $SubnetMask
        Write-LogMessage -Message "Subnet mask processed: $SubnetMask = /$prefixLength" -Level "INFO"
        
        # 7. Validate Gateway is in same subnet as IP (critical check!)
        $ipDetails = Get-IPv4NetworkDetails -IPAddress $IPAddress -PrefixLength $prefixLength
        if ($Gateway) {
            Write-Host "  Validating gateway subnet..." -ForegroundColor Gray
            
            $gwDetails = Get-IPv4NetworkDetails -IPAddress $Gateway -PrefixLength $prefixLength
            
            # Compare networks
            if ($ipDetails.NetworkAddress -ne $gwDetails.NetworkAddress) {
                Write-Host "`n[ERROR] Gateway $Gateway is not in the same subnet as IP $IPAddress/$prefixLength" -ForegroundColor Red
                Write-Host "  IP Network: $($ipDetails.NetworkAddress)/$prefixLength" -ForegroundColor Yellow
                Write-Host "  Gateway Network: $($gwDetails.NetworkAddress)/$prefixLength" -ForegroundColor Yellow
                Write-LogMessage -Message "Gateway validation failed: Gateway $Gateway not in same subnet as IP $IPAddress (IP network: $($ipDetails.NetworkAddress), Gateway network: $($gwDetails.NetworkAddress))" -Level "ERROR"
                throw "Gateway must be in the same subnet as the IP address"
            }
            
            Write-LogMessage -Message "Gateway $Gateway validated successfully (network: $($ipDetails.NetworkAddress)/$prefixLength)" -Level "DEBUG"
        }

        # Validate IP is not gateway, broadcast, or network address
        Write-Host "  Validating IP configuration..." -ForegroundColor Gray
        
        $ipOctets = $IPAddress -split '\.'
        $base = ($ipOctets[0..2] -join '.')
        
        # Check if IP matches gateway
        if ($Gateway -and $IPAddress -eq $Gateway) {
            Write-Host "`n[ERROR] Cannot set IP address to the gateway address ($Gateway)" -ForegroundColor Red
            Write-LogMessage -Message "Invalid configuration: IP address ($IPAddress) matches gateway address ($Gateway)" -Level "ERROR"
            return
        }
        
        # Check if IP is the network address for this subnet
        if ($prefixLength -lt 31 -and $ipDetails.IPValue -eq $ipDetails.NetworkValue) {
            Write-Host "`n[ERROR] Cannot set IP to network address ($($ipDetails.NetworkAddress)/$prefixLength)" -ForegroundColor Red
            Write-LogMessage -Message "Invalid configuration: IP address ($IPAddress) is the network address for /$prefixLength" -Level "ERROR"
            return
        }
        
        # Check if IP is the broadcast address for this subnet
        if ($prefixLength -lt 31 -and $ipDetails.IPValue -eq $ipDetails.BroadcastValue) {
            Write-Host "`n[ERROR] Cannot set IP to broadcast address ($($ipDetails.BroadcastAddress)/$prefixLength)" -ForegroundColor Red
            Write-LogMessage -Message "Invalid configuration: IP address ($IPAddress) is the broadcast address for /$prefixLength" -Level "ERROR"
            return
        }
        
        # Check if IP is .1 when it shouldn't be (common mistake - user enters gateway by accident)
        $lastOctet = [int]$ipOctets[3]
        if ($lastOctet -eq 1 -and $Gateway -and $Gateway -ne "$base.1") {
            Write-Host "`n[WARN] IP ends in .1 but gateway is $Gateway - is this intentional?" -ForegroundColor Yellow
            if (-not (Read-YesNo -Prompt "Continue with IP $IPAddress and gateway $Gateway?" -Default $false)) {
                Write-Host "`n[ABORT] Configuration cancelled by user" -ForegroundColor Yellow
                Write-LogMessage -Message "Configuration cancelled by user after .1 IP confirmation prompt for $IPAddress" -Level "INFO"
                return
            }
        }

        # Check if the IP address is already configured on this interface
        Write-Host "  Checking existing configuration..." -ForegroundColor Gray
        $existingIPv4 = Get-NetIPAddress -InterfaceAlias $InterfaceName -AddressFamily IPv4 -ErrorAction SilentlyContinue
        $ipAlreadyConfigured = $false
        
        if ($existingIPv4) {
            # Check if the exact IP, prefix length AND it's already static (not DHCP)
            $dhcpEnabled = (Get-NetIPInterface -InterfaceAlias $InterfaceName -AddressFamily IPv4 -ErrorAction SilentlyContinue).Dhcp
            $matchingIP = $existingIPv4 | Where-Object { $_.IPAddress -eq $IPAddress -and $_.PrefixLength -eq $prefixLength }
            
            if ($matchingIP -and $dhcpEnabled -eq 'Disabled' -and $existingIPv4.Count -eq 1) {
                # Same IP and prefix, already static, and ONLY one IP - can skip
                $ipAlreadyConfigured = $true
                Write-LogMessage -Message "IP address $IPAddress/$prefixLength is already configured as static on interface $InterfaceName. Skipping IP removal/addition." -Level "INFO"
            } else {
                # Remove ALL existing IPv4 addresses (handles multiple IPs, APIPA, etc.)
                if ($dhcpEnabled -eq 'Enabled') {
                    Write-LogMessage -Message "Removing DHCP-assigned IP addresses to configure static IP" -Level "INFO"
                }
                
                # Remove each IP individually to ensure complete cleanup
                $removedIpCount = 0
                foreach ($ip in $existingIPv4) {
                    if (Remove-IPv4AddressSafe -InterfaceName $InterfaceName -IPAddress $ip.IPAddress -PrefixLength $ip.PrefixLength) {
                        $removedIpCount++
                    }
                }
                Write-LogMessage -Message "Removed $removedIpCount existing IPv4 address(es) from interface $InterfaceName" -Level "INFO"
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

        # Prepare new static IP parameters with robust application process
        Write-Host "  Applying IP configuration..." -ForegroundColor Gray
        
        # CRITICAL STEP 1: Disable DHCP and DNS autoconfiguration to avoid PolicyStore conflicts
        $dhcpDisabled = $false
        $maxDhcpRetries = 3
        
        for ($dhcpAttempt = 1; $dhcpAttempt -le $maxDhcpRetries; $dhcpAttempt++) {
            try {
                Write-LogMessage -Message "Disabling DHCP for interface $InterfaceName (attempt $dhcpAttempt/$maxDhcpRetries)" -Level "INFO"
                
                # Disable both DHCP for IP and DNS
                Set-NetIPInterface -InterfaceAlias $InterfaceName -AddressFamily IPv4 -Dhcp Disabled -ErrorAction Stop
                
                # Wait briefly and verify DHCP is actually disabled
                Start-Sleep -Milliseconds 500
                
                $dhcpStatus = (Get-NetIPInterface -InterfaceAlias $InterfaceName -AddressFamily IPv4).Dhcp
                if ($dhcpStatus -eq 'Disabled') {
                    $dhcpDisabled = $true
                    Write-LogMessage -Message "DHCP disabled and verified for $InterfaceName" -Level "INFO"
                    break
                } else {
                    Write-LogMessage -Message "DHCP status check returned: $dhcpStatus (expected: Disabled)" -Level "WARN"
                    if ($dhcpAttempt -lt $maxDhcpRetries) {
                        Start-Sleep -Seconds 1
                    }
                }
            } catch {
                Write-LogMessage -Message "Attempt $dhcpAttempt to disable DHCP failed: $_" -Level "WARN"
                if ($dhcpAttempt -lt $maxDhcpRetries) {
                    Start-Sleep -Seconds 1
                }
            }
        }
        
        if (-not $dhcpDisabled) {
            throw "Failed to disable DHCP after $maxDhcpRetries attempts. Cannot proceed with static IP configuration."
        }
        
        # CRITICAL STEP 2: Apply static IP configuration with retry mechanism
        $params = @{
            InterfaceAlias = $InterfaceName
            IPAddress      = $IPAddress
            PrefixLength   = $prefixLength
        }
        if ($Gateway) {
            $params["DefaultGateway"] = $Gateway
        } else {
            Write-LogMessage -Message "No gateway specified for this profile; skipping default route configuration." -Level "INFO"
        }

        # Apply new static IP only if not already configured
        if (-not $ipAlreadyConfigured) {
            $ipConfigured = $false
            
            for ($ipAttempt = 1; $ipAttempt -le $MaxRetries; $ipAttempt++) {
                try {
                    Write-LogMessage -Message "Applying static IP configuration (attempt $ipAttempt/$MaxRetries)" -Level "INFO"
                    
                    New-NetIPAddress @params -ErrorAction Stop | Out-Null
                    
                    # Verify IP was actually set
                    Start-Sleep -Milliseconds 500
                    $verifyIP = Get-NetIPAddress -InterfaceAlias $InterfaceName -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -eq $IPAddress }
                    
                    if ($verifyIP) {
                        $ipConfigured = $true
                        Write-LogMessage -Message "Applied and verified static IP configuration: $IPAddress/$prefixLength" -Level "INFO"
                        break
                    } else {
                        Write-LogMessage -Message "IP verification failed on attempt $ipAttempt" -Level "WARN"
                        if ($ipAttempt -lt $MaxRetries) {
                            Start-Sleep -Seconds $RetryDelaySeconds
                        }
                    }
                } catch {
                    Write-LogMessage -Message "Attempt $ipAttempt to set IP failed: $_" -Level "ERROR"
                    Write-Host "    [ERROR] $_" -ForegroundColor Red
                    if ($ipAttempt -lt $MaxRetries) {
                        Start-Sleep -Seconds $RetryDelaySeconds
                    } else {
                        throw "Failed to set static IP after $MaxRetries attempts: $_"
                    }
                }
            }
            
            if (-not $ipConfigured) {
                throw "Failed to verify static IP configuration after $MaxRetries attempts"
            }
        } else {
            # IP was already configured correctly, mark as success
            $ipConfigured = $true
        }
        
        # Handle gateway configuration regardless of whether IP was just set or already existed
        if ($Gateway) {
            $null = Set-IPv4DefaultGatewaySafe -InterfaceName $InterfaceName -Gateway $Gateway
        }

        # CRITICAL STEP 3: Configure DNS with retry mechanism
        Write-Host "  Configuring DNS..." -ForegroundColor Gray
        $dnsServers = @()
        if ($PrimaryDNS) { $dnsServers += $PrimaryDNS }
        if ($SecondaryDNS) { $dnsServers += $SecondaryDNS }

        if ($dnsServers.Count -gt 0) {
            $dnsConfigured = $false
            
            for ($dnsAttempt = 1; $dnsAttempt -le $MaxRetries; $dnsAttempt++) {
                try {
                    Write-LogMessage -Message "Configuring DNS servers (attempt $dnsAttempt/$MaxRetries)" -Level "INFO"
                    
                    if (Set-IPv4DnsServersSafe -InterfaceName $InterfaceName -DNSServers $dnsServers) {
                        $dnsConfigured = $true
                        Write-LogMessage -Message "DNS servers configured and verified: $($dnsServers -join ', ')" -Level "INFO"
                        break
                    } else {
                        Write-LogMessage -Message "DNS verification failed on attempt $dnsAttempt" -Level "WARN"
                        if ($dnsAttempt -lt $MaxRetries) {
                            Start-Sleep -Seconds 1
                        }
                    }
                } catch {
                    Write-LogMessage -Message "Attempt $dnsAttempt to set DNS failed: $_" -Level "WARN"
                    if ($dnsAttempt -lt $MaxRetries) {
                        Start-Sleep -Seconds 1
                    }
                }
            }
            
            if (-not $dnsConfigured) {
                Write-LogMessage -Message "Warning: DNS configuration may not have been applied correctly" -Level "WARN"
                Write-Host "  [WARN] DNS configuration may need manual verification" -ForegroundColor Yellow
            }
        } else {
            Write-LogMessage -Message "No DNS servers specified. Skipping DNS configuration." -Level "WARN"
        }

        # Clear DNS cache for immediate effect
        Write-Host "  Clearing DNS cache..." -ForegroundColor Gray
        try {
            Clear-DnsClientCache -ErrorAction SilentlyContinue
            Write-LogMessage -Message "DNS cache cleared successfully" -Level "DEBUG"
        } catch {
            Write-LogMessage -Message "Could not clear DNS cache: $_" -Level "DEBUG"
        }
        
        # === FINAL STATE VERIFICATION ===
        Write-Host "  Performing final state verification..." -ForegroundColor Gray
        Start-Sleep -Milliseconds 1500  # Give Windows time to settle (increased from 1000ms)
        
        $ipConfig = Get-NetIPConfiguration -InterfaceAlias $InterfaceName -ErrorAction Stop
        $verificationPassed = $true
        $verificationIssues = @()
        
        # Get IPv4Address (handle array or single object)
        $ipv4Info = if ($ipConfig.IPv4Address -is [array]) { 
            $ipConfig.IPv4Address | Where-Object { $_.IPAddress -eq $IPAddress } | Select-Object -First 1
        } else { 
            $ipConfig.IPv4Address 
        }
        
        # If we didn't find it by matching IP, try getting any IPv4 address
        if (-not $ipv4Info -and $ipConfig.IPv4Address) {
            $ipv4Info = if ($ipConfig.IPv4Address -is [array]) {
                $ipConfig.IPv4Address | Select-Object -First 1
            } else {
                $ipConfig.IPv4Address
            }
        }
        
        # Verify IP address
        if (-not $ipv4Info -or $ipv4Info.IPAddress -ne $IPAddress) {
            $actualIP = if ($ipv4Info) { $ipv4Info.IPAddress } else { "(none)" }
            $verificationIssues += "IP address mismatch (expected: $IPAddress, actual: $actualIP)"
            $verificationPassed = $false
        }
        
        # Verify prefix length
        if (-not $ipv4Info -or $ipv4Info.PrefixLength -ne $prefixLength) {
            $actualPrefix = if ($ipv4Info) { $ipv4Info.PrefixLength } else { "(none)" }
            $verificationIssues += "Prefix length mismatch (expected: /$prefixLength, actual: /$actualPrefix)"
            $verificationPassed = $false
        }
        
        # Verify gateway (if specified)
        if ($Gateway) {
            if (-not $ipConfig.IPv4DefaultGateway -or $ipConfig.IPv4DefaultGateway.NextHop -ne $Gateway) {
                $actualGw = if ($ipConfig.IPv4DefaultGateway) { $ipConfig.IPv4DefaultGateway.NextHop } else { "(none)" }
                $verificationIssues += "Gateway mismatch (expected: $Gateway, actual: $actualGw)"
                $verificationPassed = $false
            }
        }
        
        # Verify DNS
        $currentDNS = (Get-DnsClientServerAddress -InterfaceAlias $InterfaceName -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses
        if (-not ($currentDNS -contains $PrimaryDNS)) {
            $verificationIssues += "Primary DNS not found in configuration"
            $verificationPassed = $false
        }
        
        # Verify DHCP is disabled
        $dhcpStatus = (Get-NetIPInterface -InterfaceAlias $InterfaceName -AddressFamily IPv4).Dhcp
        if ($dhcpStatus -ne 'Disabled') {
            $verificationIssues += "DHCP is still enabled (status: $dhcpStatus)"
            $verificationPassed = $false
        }
        
        if (-not $verificationPassed) {
            Write-Host "`n[WARN] Configuration completed but verification found issues:" -ForegroundColor Yellow
            foreach ($issue in $verificationIssues) {
                Write-Host "  - $issue" -ForegroundColor Yellow
                Write-LogMessage -Message "Verification issue: $issue" -Level "WARN"
            }
        }

        # Keep DNS reachability as a quiet diagnostic; the apply step verifies configuration state.
        if ($verificationPassed -and $Gateway -and $currentDNS) {
            $reachableDns = @()
            foreach ($dnsServer in ($currentDNS | Where-Object { Test-ValidDNSServer -DNSServer $_ })) {
                if (Test-DNSConnectivity -DNSServer $dnsServer) {
                    $reachableDns += $dnsServer
                }
            }

            if ($reachableDns.Count -gt 0) {
                Write-LogMessage -Message "Post-configuration DNS diagnostic passed for: $($reachableDns -join ', ')" -Level "DEBUG"
            } elseif (Test-SystemDNSResolution) {
                Write-LogMessage -Message "Post-configuration DNS diagnostic passed via system resolver using configured DNS settings." -Level "DEBUG"
            } else {
                Write-LogMessage -Message "Post-configuration DNS diagnostic could not confirm reachability for configured DNS servers: $($currentDNS -join ', ')" -Level "DEBUG"
            }
        } elseif (-not $Gateway) {
            Write-LogMessage -Message "Skipped DNS reachability test because no gateway is configured" -Level "DEBUG"
        }
        
        # Clean up any stray APIPA or duplicate IP addresses after static IP is applied
        Start-Sleep -Milliseconds 500
        $allIPs = Get-NetIPAddress -InterfaceAlias $InterfaceName -AddressFamily IPv4 -ErrorAction SilentlyContinue
        if ($allIPs -and $allIPs.Count -gt 1) {
            foreach ($ip in $allIPs) {
                # Remove APIPA addresses or any IP that isn't our configured static IP
                if ($ip.IPAddress -like "169.254.*" -or ($ip.IPAddress -ne $IPAddress)) {
                    if (Remove-IPv4AddressSafe -InterfaceName $InterfaceName -IPAddress $ip.IPAddress -Quiet) {
                        Write-LogMessage -Message "Removed stray IP address after static config: $($ip.IPAddress)" -Level "DEBUG"
                    }
                }
            }
            
            # Re-fetch clean config
            Start-Sleep -Milliseconds 300
            $ipConfig = Get-NetIPConfiguration -InterfaceAlias $InterfaceName -ErrorAction SilentlyContinue
            $ipv4Info = Get-NetIPAddress -InterfaceAlias $InterfaceName -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -eq $IPAddress }
        }
        
        # Show summary
        Write-Host "`n[OK] Static IP configuration successful" -ForegroundColor Green
        if ($verificationPassed) {
            Write-Host "  All parameters verified successfully" -ForegroundColor Green
        }
        
        Show-IPv4ConfigurationSummary -InterfaceName $InterfaceName -IPConfig $ipConfig -IPv4Address $ipv4Info -DHCPStatus $dhcpStatus
        
        Write-LogMessage -Message "Static IP configuration verified for ${InterfaceName}: $IPAddress/$prefixLength, gateway=$(if($Gateway){$Gateway}else{'none'}), dns=$($dnsServers -join ', ')" -Level "INFO"
    } catch {
        $errorMessage = "Error: Unable to set static IP configuration. $_"
        Write-Host ""
        Write-Host "[FAIL] Configuration failed: $errorMessage" -ForegroundColor Red
        Write-LogMessage -Message $errorMessage -Level "CRITICAL"
        
        # Attempt rollback to previous configuration if available
        if ($backupConfig -and $backupConfig.DHCPEnabled -eq 'Enabled') {
            Write-Host "`nAttempting to restore previous DHCP configuration..." -ForegroundColor Yellow
            Write-LogMessage -Message "Attempting rollback to DHCP after failed static IP configuration" -Level "WARN"
            
            if (Restore-DHCPConfiguration -InterfaceName $InterfaceName) {
                Write-Host "[OK] Rolled back to DHCP configuration" -ForegroundColor Green
            } else {
                Write-Host "[WARN] Rollback failed" -ForegroundColor Red
                Write-Host "You may need to manually reconfigure the network adapter." -ForegroundColor Yellow
            }
        } else {
            Write-Host "`nNo automatic rollback available. Manual intervention may be required." -ForegroundColor Yellow
        }
    }
}

# Function to set DHCP configuration (optimized for speed and robustness)
function Set-DHCP {
    <#
    .SYNOPSIS
        Enables DHCP configuration on a network interface.
    
    .DESCRIPTION
        Switches a network interface to DHCP mode with automatic IP address assignment,
        including retry logic and validation.
    
    .PARAMETER InterfaceName
        The name of the network interface to configure.
    
    .PARAMETER MaxRetries
        Maximum number of retry attempts (default: 3).
    
    .PARAMETER RetryDelaySeconds
        Delay in seconds between retry attempts (default: 2).
    
    .EXAMPLE
        Set-DHCP -InterfaceName "Ethernet0"
    
    .NOTES
        Requires administrative privileges.
    #>
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$InterfaceName,
        
        [ValidateRange(1,10)]
        [int]$MaxRetries = 3,
        
        [ValidateRange(1,30)]
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
        $interface = Get-NetworkAdapterSafe -InterfaceName $InterfaceName
        if (-not $interface) {
            throw "Interface '$InterfaceName' not found"
        }
        if ($interface.Status -ne "Up") {
            Write-Host "Warning: Interface '$InterfaceName' is not 'Up' (status: $($interface.Status))" -ForegroundColor Yellow
            Write-LogMessage -Message "Interface '$InterfaceName' status: $($interface.Status)" -Level "WARN"
        }
    } catch {
        Write-Host "Error: Interface '$InterfaceName' not found." -ForegroundColor Red
        Write-LogMessage -Message "Interface '$InterfaceName' not found: $_" -Level "ERROR"
        return $false
    }

    if (-not $PSCmdlet.ShouldProcess($InterfaceName, "Enable DHCP and reset IPv4 DNS server addresses")) {
        Write-Host "DHCP configuration cancelled." -ForegroundColor Yellow
        Write-LogMessage -Message "DHCP configuration cancelled by ShouldProcess for $InterfaceName" -Level "WARN"
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
            
            # Remove ALL existing IP addresses (IPv4 only for speed)
            # This ensures we clear both static IPs and APIPA addresses (169.254.x.x) left from previous configs
            $existingIPs = Get-NetIPAddress -InterfaceAlias $InterfaceName -AddressFamily IPv4 -ErrorAction SilentlyContinue
            if ($existingIPs) {
                foreach ($ip in $existingIPs) {
                    $null = Remove-IPv4AddressSafe -InterfaceName $InterfaceName -IPAddress $ip.IPAddress -PrefixLength $ip.PrefixLength
                }
            }

            # Step 2: Enable DHCP and reset DNS
            Write-Host "  Enabling DHCP..." -ForegroundColor Gray

            Set-NetIPInterface -InterfaceAlias $InterfaceName -AddressFamily IPv4 -Dhcp Enabled -ErrorAction Stop
            if (-not (Reset-IPv4DnsServersSafe -InterfaceName $InterfaceName)) {
                throw "Failed to reset DNS server addresses"
            }

            Start-Sleep -Milliseconds 500
            $dhcpStatus = (Get-NetIPInterface -InterfaceAlias $InterfaceName -AddressFamily IPv4 -ErrorAction Stop).Dhcp
            if ($dhcpStatus -ne "Enabled") {
                throw "DHCP enable verification failed. Current DHCP status: $dhcpStatus"
            }

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

            # Step 5: Clean up any APIPA addresses that may have been assigned during DHCP wait
            if ($dhcpSuccess) {
                # Remove any APIPA (169.254.x.x) or other stray IP addresses
                $allIPs = Get-NetIPAddress -InterfaceAlias $InterfaceName -AddressFamily IPv4 -ErrorAction SilentlyContinue
                foreach ($ip in $allIPs) {
                    # Remove APIPA addresses or multiple IPs, keeping only the DHCP-assigned one
                    if ($ip.IPAddress -like "169.254.*" -or ($allIPs.Count -gt 1 -and $ip.PrefixOrigin -eq "WellKnown")) {
                        if (Remove-IPv4AddressSafe -InterfaceName $InterfaceName -IPAddress $ip.IPAddress -Quiet) {
                            Write-LogMessage -Message "Removed stray IP address: $($ip.IPAddress)" -Level "DEBUG"
                        }
                    }
                }
                
                # Re-fetch clean config
                Start-Sleep -Milliseconds 500
                $ipConfig = Get-NetIPConfiguration -InterfaceAlias $InterfaceName -ErrorAction Stop
                $dhcpStatus = (Get-NetIPInterface -InterfaceAlias $InterfaceName -AddressFamily IPv4 -ErrorAction SilentlyContinue).Dhcp
                
                Write-Host "`n[OK] DHCP configuration successful" -ForegroundColor Green
                Show-IPv4ConfigurationSummary -InterfaceName $InterfaceName -IPConfig $ipConfig -DHCPStatus $dhcpStatus
                
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
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$InterfaceName,
        
        [bool]$QuickTest = $false,
        
        [ValidateRange(5,120)]
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
    
    # MTU Detection (if gateway test passed)
    if (-not $QuickTest -and $testResults.Gateway -and $testResults.Gateway.Status -eq "Success") {
        Write-Host ""
        Write-Host "MTU Detection: " -NoNewline
        try {
            $mtu = Test-MTUSize -Target $testResults.Gateway.IP -InterfaceAlias $InterfaceName
            Write-Host "$mtu bytes" -ForegroundColor Green
            Write-LogMessage -Message "Optimal MTU for ${InterfaceName}: $mtu bytes" -Level "INFO"
        } catch {
            Write-Host "Unable to detect" -ForegroundColor Gray
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

function Invoke-DNSLookup {
    [CmdletBinding()]
    param ()

    Write-Host ""
    Write-Host "=== DNS Lookup ===" -ForegroundColor Cyan
    Write-Host ""

    $hostName = (Read-Host "Enter hostname or IP to resolve").Trim()
    if ([string]::IsNullOrWhiteSpace($hostName)) {
        Write-Host "DNS lookup cancelled: no host entered." -ForegroundColor Yellow
        return
    }

    $recordInput = (Read-Host "Record type (A, AAAA, CNAME, MX, NS, PTR, TXT; default: A)").Trim().ToUpper()
    if ([string]::IsNullOrWhiteSpace($recordInput)) {
        $recordInput = "A"
    }

    $validTypes = @("A", "AAAA", "CNAME", "MX", "NS", "PTR", "TXT")
    if ($recordInput -notin $validTypes) {
        Write-Host "Invalid record type '$recordInput'. Using A." -ForegroundColor Yellow
        $recordInput = "A"
    }

    $serverInput = (Read-Host "DNS server [Enter=system default, or IPv4 address]").Trim()

    try {
        $params = @{
            Name = $hostName
            Type = $recordInput
            ErrorAction = "Stop"
        }

        if (-not [string]::IsNullOrWhiteSpace($serverInput)) {
            if (-not (Test-ValidDNSServer -DNSServer $serverInput)) {
                Write-Host "Invalid DNS server IPv4 address: $serverInput" -ForegroundColor Red
                return
            }
            $params["Server"] = $serverInput
        }

        Write-Host ""
        Write-Host "Resolving $hostName ($recordInput)..." -ForegroundColor Yellow
        $results = Resolve-DnsName @params

        if (-not $results) {
            Write-Host "No DNS records returned." -ForegroundColor Yellow
            return
        }

        $results |
            Select-Object Name, Type, TTL, IPAddress, NameHost, NameExchange, Preference, Strings |
            Format-Table -AutoSize

        Write-LogMessage -Message "DNS lookup completed for $hostName ($recordInput)" -Level "INFO"
    } catch {
        Write-Host "DNS lookup failed: $_" -ForegroundColor Red
        Write-LogMessage -Message "DNS lookup failed for ${hostName}: $_" -Level "ERROR"
    }
}

function Invoke-Traceroute {
    [CmdletBinding()]
    param ()

    Write-Host ""
    Write-Host "=== Traceroute ===" -ForegroundColor Cyan
    Write-Host ""

    $target = (Read-Host "Enter hostname or IP to trace").Trim()
    if ([string]::IsNullOrWhiteSpace($target)) {
        Write-Host "Traceroute cancelled: no target entered." -ForegroundColor Yellow
        return
    }

    $maxHopsInput = (Read-Host "Maximum hops (default: 30)").Trim()
    $maxHops = 30
    if (-not [string]::IsNullOrWhiteSpace($maxHopsInput)) {
        if (-not [int]::TryParse($maxHopsInput, [ref]$maxHops) -or $maxHops -lt 1 -or $maxHops -gt 255) {
            Write-Host "Invalid maximum hops. Using 30." -ForegroundColor Yellow
            $maxHops = 30
        }
    }

    $resolveInput = (Read-Host "Resolve hop hostnames? (y/n, default: n)").Trim().ToLower()
    $tracertArgs = @("-h", $maxHops.ToString())
    if ($resolveInput -ne "y") {
        $tracertArgs += "-d"
    }
    $tracertArgs += $target

    try {
        Write-Host ""
        Write-Host "Tracing route to $target..." -ForegroundColor Yellow
        Write-LogMessage -Message "Traceroute started for $target with max hops $maxHops" -Level "INFO"
        & tracert.exe @tracertArgs
        Write-LogMessage -Message "Traceroute completed for $target" -Level "INFO"
    } catch {
        Write-Host "Traceroute failed: $_" -ForegroundColor Red
        Write-LogMessage -Message "Traceroute failed for ${target}: $_" -Level "ERROR"
    }
}

function Test-TcpPort {
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName,

        [Parameter(Mandatory=$true)]
        [ValidateRange(1,65535)]
        [int]$Port,

        [ValidateRange(100,30000)]
        [int]$TimeoutMs = 2000
    )

    $tcpClient = New-Object System.Net.Sockets.TcpClient
    try {
        $connectTask = $tcpClient.ConnectAsync($ComputerName, $Port)
        if (-not $connectTask.Wait($TimeoutMs)) {
            return $false
        }

        return $tcpClient.Connected
    } catch {
        return $false
    } finally {
        $tcpClient.Close()
        $tcpClient.Dispose()
    }
}

function Invoke-PortCheck {
    [CmdletBinding()]
    param ()

    Write-Host ""
    Write-Host "=== TCP Port Check ===" -ForegroundColor Cyan
    Write-Host ""

    $target = (Read-Host "Enter hostname or IP").Trim()
    if ([string]::IsNullOrWhiteSpace($target)) {
        Write-Host "Port check cancelled: no target entered." -ForegroundColor Yellow
        return
    }

    $portsInput = (Read-Host "Ports (comma-separated, default: 22,80,443,3389)").Trim()
    if ([string]::IsNullOrWhiteSpace($portsInput)) {
        $portsInput = "22,80,443,3389"
    }

    $ports = @()
    foreach ($portText in ($portsInput -split ",")) {
        $port = 0
        if ([int]::TryParse($portText.Trim(), [ref]$port) -and $port -ge 1 -and $port -le 65535) {
            $ports += $port
        } else {
            Write-Host "Skipping invalid port: $portText" -ForegroundColor Yellow
        }
    }

    if ($ports.Count -eq 0) {
        Write-Host "No valid ports entered." -ForegroundColor Red
        return
    }

    Write-Host ""
    Write-Host "Checking TCP ports on $target..." -ForegroundColor Yellow
    foreach ($port in ($ports | Sort-Object -Unique)) {
        $isOpen = Test-TcpPort -ComputerName $target -Port $port -TimeoutMs 2000
        if ($isOpen) {
            Write-Host "[OPEN]   $target`:$port" -ForegroundColor Green
        } else {
            Write-Host "[CLOSED] $target`:$port" -ForegroundColor Red
        }
    }

    Write-LogMessage -Message "TCP port check completed for $target ($($ports -join ', '))" -Level "INFO"
}

function Show-ARPTable {
    [CmdletBinding()]
    param (
        [string]$InterfaceName = $null
    )

    Write-Host ""
    Write-Host "=== ARP / Neighbor Table ===" -ForegroundColor Cyan
    Write-Host ""

    try {
        $neighbors = Get-NetNeighbor -AddressFamily IPv4 -ErrorAction Stop |
            Where-Object {
                $_.IPAddress -notlike "224.*" -and
                $_.IPAddress -ne "255.255.255.255" -and
                -not [string]::IsNullOrWhiteSpace($_.LinkLayerAddress)
            }

        if ($InterfaceName) {
            $neighbors = $neighbors | Where-Object { $_.InterfaceAlias -eq $InterfaceName }
            Write-Host "Interface: $InterfaceName" -ForegroundColor Yellow
            Write-Host ""
        }

        if (-not $neighbors) {
            Write-Host "No IPv4 neighbor entries found." -ForegroundColor Yellow
            return
        }

        $neighbors |
            Sort-Object InterfaceAlias, IPAddress |
            Select-Object InterfaceAlias, IPAddress, LinkLayerAddress, State |
            Format-Table -AutoSize

        $scopeText = if ($InterfaceName) { " for $InterfaceName" } else { "" }
        Write-LogMessage -Message "ARP table displayed$scopeText" -Level "INFO"
    } catch {
        Write-Host "Failed to read ARP table: $_" -ForegroundColor Red
        Write-LogMessage -Message "Failed to read ARP table: $_" -Level "ERROR"
    }
}

function Invoke-MACVendorLookup {
    <#
    .SYNOPSIS
        Interactive MAC address vendor lookup tool.
    
    .DESCRIPTION
        Prompts user for a MAC address and displays manufacturer information.
        Includes comprehensive validation and error handling.
    #>
    [CmdletBinding()]
    param()
    
    Write-Host "`n" -NoNewline
    Write-Host ("="*60) -ForegroundColor Cyan
    Write-Host "MAC Address Vendor Lookup" -ForegroundColor Cyan
    Write-Host ("="*60) -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Supported formats:" -ForegroundColor Gray
    Write-Host "    - XX:XX:XX:XX:XX:XX  (colon separated)" -ForegroundColor DarkGray
    Write-Host "    - XX-XX-XX-XX-XX-XX  (dash separated)" -ForegroundColor DarkGray
    Write-Host "    - XXXXXXXXXXXX       (no separators)" -ForegroundColor DarkGray
    Write-Host ""
    
    $attempts = 0
    $maxAttempts = 3
    
    while ($attempts -lt $maxAttempts) {
        $macInput = Read-Host "  Enter MAC address (or 'q' to cancel)"
        
        # Check for cancel
        if ($macInput.ToLower() -eq 'q') {
            Write-Host "`n[CANCELLED] MAC lookup cancelled" -ForegroundColor Yellow
            Write-LogMessage -Message "MAC vendor lookup cancelled by user" -Level "DEBUG"
            return
        }
        
        # Validate format
        $normalizedMAC = $macInput -replace '[:\-\.\s]', ''
        
        if ([string]::IsNullOrWhiteSpace($macInput)) {
            Write-Host "`n[ERROR] MAC address cannot be empty" -ForegroundColor Red
            $attempts++
            continue
        }
        
        if ($normalizedMAC.Length -ne 12) {
            Write-Host "`n[ERROR] Invalid MAC address length" -ForegroundColor Red
            Write-Host "  Expected: 12 hex digits (6 bytes)" -ForegroundColor Yellow
            Write-Host "  Received: $($normalizedMAC.Length) characters" -ForegroundColor Yellow
            $attempts++
            continue
        }
        
        if ($normalizedMAC -notmatch '^[0-9A-Fa-f]{12}$') {
            Write-Host "`n[ERROR] Invalid characters in MAC address" -ForegroundColor Red
            Write-Host "  Only hexadecimal digits (0-9, A-F) are allowed" -ForegroundColor Yellow
            $attempts++
            continue
        }
        
        # Valid MAC - proceed with lookup
        Write-Host ""
        Write-Host "  Normalized MAC: " -NoNewline -ForegroundColor Gray
        $formattedMAC = ($normalizedMAC.ToUpper() -split '(.{2})' | Where-Object { $_ }) -join ':'
        Write-Host "$formattedMAC" -ForegroundColor White
        Write-Host ""
        Write-Host "  Looking up vendor information..." -NoNewline -ForegroundColor Cyan
        
        try {
            $vendor = Get-MACVendor -MACAddress $macInput
            
            Write-Host "`r                                    `r" -NoNewline  # Clear the line
            
            if ($vendor -in @("Unknown", "Lookup Failed", "Invalid MAC", "Unknown Vendor")) {
                Write-Host "  [!] " -NoNewline -ForegroundColor Yellow
                Write-Host "Vendor: " -NoNewline -ForegroundColor Gray
                
                switch ($vendor) {
                    "Unknown Vendor" { 
                        Write-Host "Not found in database" -ForegroundColor Yellow 
                        Write-Host "  The OUI ($($normalizedMAC.Substring(0,6).ToUpper())) may be unregistered or recently assigned" -ForegroundColor DarkGray
                    }
                    "Lookup Failed" { 
                        Write-Host "API request failed" -ForegroundColor Red 
                        Write-Host "  Please check internet connectivity" -ForegroundColor DarkGray
                    }
                    "Invalid MAC" { 
                        Write-Host "Invalid format" -ForegroundColor Red 
                    }
                    default { 
                        Write-Host "Unknown" -ForegroundColor Gray 
                    }
                }
            } else {
                Write-Host "  [OK] " -NoNewline -ForegroundColor Green
                Write-Host "Vendor: " -NoNewline -ForegroundColor Gray
                Write-Host "$vendor" -ForegroundColor Cyan
                
                # Show OUI info
                $oui = $normalizedMAC.Substring(0, 6).ToUpper()
                Write-Host "  OUI: $($oui.Insert(2,':').Insert(5,':'))" -ForegroundColor DarkGray
            }
            
            Write-Host ""
            Write-LogMessage -Message "MAC vendor lookup: $macInput -> $vendor" -Level "INFO"
            return
            
        } catch {
            Write-Host "`r" -NoNewline
            Write-Host "`n[ERROR] Unexpected error during lookup" -ForegroundColor Red
            Write-Host "  $($_.Exception.Message)" -ForegroundColor Yellow
            Write-LogMessage -Message "MAC vendor lookup error: $($_.Exception.Message)" -Level "ERROR"
            return
        }
    }
    
    # Max attempts reached
    Write-Host "`n[ERROR] Maximum attempts ($maxAttempts) exceeded" -ForegroundColor Red
    Write-Host "  Returning to main menu" -ForegroundColor Yellow
    Write-LogMessage -Message "MAC vendor lookup failed: max attempts exceeded" -Level "WARN"
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
        $adapter = Get-NetAdapter -Name $InterfaceName -ErrorAction Stop
        $ipv4 = $config.IPv4Address
        $gateway = $config.IPv4DefaultGateway
        
        Write-Host "Current IP configuration for interface: $InterfaceName" -ForegroundColor Cyan
        Write-Host ("="*60) -ForegroundColor Gray
        
        # Show adapter status and type
        Write-Host "Status: " -NoNewline -ForegroundColor Gray
        $statusColor = if ($adapter.Status -eq 'Up') { 'Green' } else { 'Yellow' }
        Write-Host "$($adapter.Status)" -ForegroundColor $statusColor
        
        if ($adapter.LinkSpeed -and $adapter.Status -eq 'Up') {
            Write-Host "Link Speed: $($adapter.LinkSpeed)" -ForegroundColor White
        }
        
        # Show network profile (Public/Private/Domain)
        $netProfile = Get-NetworkProfile -InterfaceAlias $InterfaceName
        if ($netProfile -ne "Unknown") {
            $profileColor = switch ($netProfile) {
                'Public' { 'Yellow' }
                'Private' { 'Green' }
                'DomainAuthenticated' { 'Cyan' }
                default { 'Gray' }
            }
            Write-Host "Network Profile: " -NoNewline -ForegroundColor Gray
            Write-Host "$netProfile" -ForegroundColor $profileColor
        }
        
        # Show MAC address and vendor
        if ($adapter.MacAddress) {
            Write-Host "MAC Address: " -NoNewline -ForegroundColor Gray
            Write-Host "$($adapter.MacAddress)" -NoNewline -ForegroundColor White
            
            # Lookup vendor
            $vendor = Get-MACVendor -MACAddress $adapter.MacAddress
            if ($vendor -and $vendor -notin @("Unknown", "Lookup Failed", "Invalid MAC", "Unknown Vendor")) {
                Write-Host " ($vendor)" -ForegroundColor DarkCyan
            } else {
                Write-Host ""
            }
        }
        
        Write-Host ("="*60) -ForegroundColor Gray
        
        if ($ipv4 -and $ipv4.IPAddress) {
            # Handle case where multiple IPs exist - show only the primary (non-APIPA) one
            $displayIP = if ($ipv4.IPAddress -is [array]) {
                ($ipv4 | Where-Object { $_.IPAddress -notlike "169.254.*" } | Select-Object -First 1).IPAddress
            } else {
                $ipv4.IPAddress
            }
            
            $displayPrefix = if ($ipv4.PrefixLength -is [array]) {
                ($ipv4 | Where-Object { $_.IPAddress -notlike "169.254.*" } | Select-Object -First 1).PrefixLength
            } else {
                $ipv4.PrefixLength
            }
            
            Write-Host "IP Address: $displayIP" -ForegroundColor White
            Write-Host "Subnet Mask: /$displayPrefix" -ForegroundColor White
            
            # Show DHCP status
            $dhcpStatus = (Get-NetIPInterface -InterfaceAlias $InterfaceName -AddressFamily IPv4 -ErrorAction SilentlyContinue).Dhcp
            Write-Host "DHCP: " -NoNewline -ForegroundColor Gray
            if ($dhcpStatus -eq 'Enabled') {
                Write-Host "Enabled" -ForegroundColor Green
            } else {
                Write-Host "Disabled (Static)" -ForegroundColor Cyan
            }
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
        if ($config.DnsServer -and $config.DnsServer.ServerAddresses) {
            $ipv6DnsServers = $config.DnsServer.ServerAddresses | Where-Object { $_ -notmatch "^\d+\.\d+\.\d+\.\d+$" -and $_ -ne "" }
            if ($ipv6DnsServers) {
                Write-Host "DNS Servers (IPv6): $($ipv6DnsServers -join ', ')" -ForegroundColor Gray
            }
        }
        
        # Show MTU if available
        if ($adapter.MtuSize) {
            Write-Host "MTU Size: $($adapter.MtuSize) bytes" -ForegroundColor Gray
        }
        
        # Enhanced Wi-Fi information
        if ($adapter.InterfaceDescription -match 'Wireless' -or $adapter.InterfaceDescription -match '802.11') {
            Write-Host ("="*60) -ForegroundColor Gray
            Write-Host "Wi-Fi Information:" -ForegroundColor Cyan
            
            try {
                $wifiOutput = netsh wlan show interfaces | Out-String
                
                if ($wifiOutput -match $InterfaceName -or $wifiOutput -match 'State\s+:\s+connected') {
                    if ($wifiOutput -match 'SSID\s+:\s+(.+)') { 
                        $ssid = $matches[1].Trim()
                        Write-Host "  SSID: $ssid" -ForegroundColor White
                    }
                    
                    if ($wifiOutput -match 'Signal\s+:\s+(\d+)%') { 
                        $signal = [int]$matches[1]
                        $signalColor = if ($signal -ge 70) { 'Green' } elseif ($signal -ge 50) { 'Yellow' } else { 'Red' }
                        Write-Host "  Signal Strength: " -NoNewline -ForegroundColor Gray
                        Write-Host "$signal%" -ForegroundColor $signalColor
                        
                        # Signal quality indicator
                        $bars = [math]::Floor($signal / 20)
                        $signalBars = "|" * [math]::Max(1, $bars)
                        Write-Host "  Signal Quality: $signalBars" -ForegroundColor $signalColor
                    }
                    
                    if ($wifiOutput -match 'Authentication\s+:\s+(.+)') { 
                        $auth = $matches[1].Trim()
                        Write-Host "  Security: $auth" -ForegroundColor Gray
                    }
                    
                    if ($wifiOutput -match 'Radio type\s+:\s+(.+)') { 
                        $radioType = $matches[1].Trim()
                        Write-Host "  Radio Type: $radioType" -ForegroundColor Gray
                    }
                    
                    if ($wifiOutput -match 'Channel\s+:\s+(\d+)') { 
                        $channel = $matches[1].Trim()
                        Write-Host "  Channel: $channel" -ForegroundColor Gray
                    }
                } else {
                    Write-Host "  Status: Not connected to any network" -ForegroundColor Yellow
                }
            } catch {
                Write-Host "  Unable to retrieve Wi-Fi details" -ForegroundColor DarkGray
            }
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
        # Filter interfaces based on the toggle - exclude virtual/loopback adapters
        if ($showDownInterfaces) {
            $interfaces = Get-NetAdapter | Where-Object { 
                $_.InterfaceDescription -notmatch '(Hyper-V|WSL|Loopback|Teredo|6to4|VirtualBox|VMware)' -and
                $_.Virtual -eq $false
            }
        } else {
            $interfaces = Get-NetAdapter | Where-Object { 
                $_.Status -eq "Up" -and
                $_.InterfaceDescription -notmatch '(Hyper-V|WSL|Loopback|Teredo|6to4|VirtualBox|VMware)' -and
                $_.Virtual -eq $false
            }
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
        # Get adapter info
        $adapter = Get-NetworkAdapterSafe -InterfaceName $InterfaceName
        if (-not $adapter) {
            return "Status: Not found"
        }
        
        # Get IP and DHCP status
        $ipAddress = (Get-NetIPAddress -InterfaceAlias $InterfaceName -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1).IPAddress
        if ($ipAddress) {
            $dhcpEnabled = (Get-NetIPInterface -InterfaceAlias $InterfaceName -AddressFamily IPv4 -ErrorAction SilentlyContinue).Dhcp
            $configType = if ($dhcpEnabled -eq "Enabled") { "DHCP" } else { "Static" }
            
            # Get link speed and state
            $linkSpeed = $adapter.LinkSpeed
            $state = $adapter.Status
            
            return "$state | $linkSpeed | IP: $ipAddress | Type: $configType"
        } else {
            $state = $adapter.Status
            return "$state | No IP configured"
        }
    } catch {
        return "Status: Unknown"
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
                    elseif ($key.Key -eq 'P') {
                        # Show performance statistics
                        Write-Host "
" -NoNewline
                        Write-Host ("=" * 60) -ForegroundColor Cyan
                        Write-Host "PERFORMANCE STATISTICS - [$(Get-Date -Format 'HH:mm:ss')]" -ForegroundColor Cyan
                        Write-Host ("=" * 60) -ForegroundColor Cyan
                        Write-Host ""
                        
                        $currentPerf = Get-NetworkPerformance -InterfaceName $InterfaceName
                        
                        if ($currentPerf -and $initialPerf) {
                            # Calculate deltas
                            $bytesSentDelta = $currentPerf.BytesSent - $initialPerf.BytesSent
                            $bytesRecvDelta = $currentPerf.BytesReceived - $initialPerf.BytesReceived
                            $packetsSentDelta = $currentPerf.PacketsSent - $initialPerf.PacketsSent
                            $packetsRecvDelta = $currentPerf.PacketsReceived - $initialPerf.PacketsReceived
                            
                            # Format bytes
                            function Format-Bytes([long]$bytes) {
                                if ($bytes -gt 1GB) { return "{0:N2} GB" -f ($bytes / 1GB) }
                                elseif ($bytes -gt 1MB) { return "{0:N2} MB" -f ($bytes / 1MB) }
                                elseif ($bytes -gt 1KB) { return "{0:N2} KB" -f ($bytes / 1KB) }
                                else { return "$bytes bytes" }
                            }
                            
                            Write-Host "Link Speed: " -NoNewline -ForegroundColor Gray
                            Write-Host "$($currentPerf.LinkSpeed)" -ForegroundColor White
                            Write-Host ""
                            
                            Write-Host "Since Monitor Start:" -ForegroundColor Yellow
                            Write-Host "  Sent:     " -NoNewline -ForegroundColor Gray
                            Write-Host "$(Format-Bytes $bytesSentDelta) ($packetsSentDelta packets)" -ForegroundColor Green
                            Write-Host "  Received: " -NoNewline -ForegroundColor Gray
                            Write-Host "$(Format-Bytes $bytesRecvDelta) ($packetsRecvDelta packets)" -ForegroundColor Green
                            Write-Host "  Total:    " -NoNewline -ForegroundColor Gray
                            Write-Host "$(Format-Bytes ($bytesSentDelta + $bytesRecvDelta))" -ForegroundColor Cyan
                            
                            if ($currentPerf.Errors -gt 0 -or $currentPerf.Discards -gt 0) {
                                Write-Host ""
                                Write-Host "Errors: " -NoNewline -ForegroundColor Yellow
                                Write-Host "$($currentPerf.Errors)" -ForegroundColor Red
                                Write-Host "Discards: " -NoNewline -ForegroundColor Yellow
                                Write-Host "$($currentPerf.Discards)" -ForegroundColor Red
                            }
                        } else {
                            Write-Host "Unable to retrieve performance data" -ForegroundColor Red
                        }
                        
                        Write-Host ""
                        Write-Host ("=" * 60) -ForegroundColor Cyan
                        Write-Host ""
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

function Write-MenuOption {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Key,

        [Parameter(Mandatory=$true)]
        [string]$Label,

        [string]$Color = "Cyan",

        [int]$Width = 26
    )

    $text = $Label
    if ($text.Length -gt $Width) {
        $text = $text.Substring(0, $Width - 1)
    }

    Write-Host "  [" -NoNewline -ForegroundColor DarkGray
    Write-Host $Key.ToUpper() -NoNewline -ForegroundColor $Color
    Write-Host "] " -NoNewline -ForegroundColor DarkGray
    Write-Host $text.PadRight($Width) -NoNewline -ForegroundColor Gray
}

function Write-MenuSection {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Title,

        [Parameter(Mandatory=$true)]
        [object[]]$Rows
    )

    Write-Host ""
    Write-Host "  $Title" -ForegroundColor DarkCyan
    Write-Host "  $("." * $Title.Length)" -ForegroundColor DarkGray

    foreach ($row in $Rows) {
        foreach ($item in $row) {
            Write-MenuOption -Key $item.Key -Label $item.Label -Color $item.Color
        }
        Write-Host ""
    }
}

function Show-MainMenu {
    param (
        [string]$InterfaceName
    )

    $statusInfo = Get-InterfaceStatus -InterfaceName $InterfaceName
    $adapterText = if ($InterfaceName) { $InterfaceName } else { "No adapter selected" }
    $adapterColor = if ($InterfaceName) { "Cyan" } else { "Yellow" }
    $logText = if ($script:LoggingConsent) { "Logging on" } else { "Logging off" }
    $logColor = if ($script:LoggingConsent) { "Green" } else { "Yellow" }

    Write-Host ""
    Write-Host "  ========================================================================" -ForegroundColor DarkCyan
    Write-Host "  NETWORK CONFIGURATION" -NoNewline -ForegroundColor White
    Write-Host "  v$script:ScriptVersion" -ForegroundColor DarkGray
    Write-Host "  ========================================================================" -ForegroundColor DarkCyan
    Write-Host "  Adapter: " -NoNewline -ForegroundColor DarkGray
    Write-Host $adapterText -NoNewline -ForegroundColor $adapterColor
    Write-Host "    Privacy: " -NoNewline -ForegroundColor DarkGray
    Write-Host $logText -ForegroundColor $logColor
    Write-Host "  Status : " -NoNewline -ForegroundColor DarkGray
    Write-Host $statusInfo -ForegroundColor Yellow
    if (-not $InterfaceName) {
        Write-Host "  Tip    : Select an adapter with [6] before configuring IPv4 or running adapter tests." -ForegroundColor DarkYellow
    }

    Write-MenuSection -Title "Configuration" -Rows @(
        @(
            @{ Key = "1"; Label = "Set static IPv4"; Color = "Cyan" },
            @{ Key = "2"; Label = "Enable DHCP"; Color = "Green" },
            @{ Key = "3"; Label = "View config"; Color = "White" }
        ),
        @(
            @{ Key = "4"; Label = "Save IP profile"; Color = "Cyan" },
            @{ Key = "5"; Label = "IP profiles"; Color = "Cyan" },
            @{ Key = "6"; Label = "Switch adapter"; Color = "Yellow" }
        )
    )

    Write-MenuSection -Title "Diagnostics" -Rows @(
        @(
            @{ Key = "T"; Label = "Connectivity test"; Color = "Green" },
            @{ Key = "N"; Label = "DNS lookup"; Color = "Cyan" },
            @{ Key = "R"; Label = "Traceroute"; Color = "Cyan" }
        ),
        @(
            @{ Key = "O"; Label = "TCP port check"; Color = "Magenta" },
            @{ Key = "A"; Label = "ARP table"; Color = "White" },
            @{ Key = "S"; Label = "Subnet calculator"; Color = "Cyan" }
        )
    )

    Write-MenuSection -Title "Tools" -Rows @(
        @(
            @{ Key = "M"; Label = "Live monitor"; Color = "Yellow" },
            @{ Key = "I"; Label = "Adapter details"; Color = "White" },
            @{ Key = "V"; Label = "MAC vendor lookup"; Color = "Magenta" }
        ),
        @(
            @{ Key = "Q"; Label = "Quick DHCP"; Color = "Green" },
            @{ Key = "D"; Label = "Flush DNS"; Color = "Yellow" },
            @{ Key = "L"; Label = "View log"; Color = "White" }
        ),
        @(
            @{ Key = "P"; Label = "Privacy"; Color = "Cyan" },
            @{ Key = "U"; Label = "Updates"; Color = "White" },
            @{ Key = "C"; Label = "Refresh"; Color = "White" }
        )
    )

    Write-Host ""
    Write-Host "  [0] Exit" -ForegroundColor Red
    Write-Host ""
    Write-Host "  Choice (Esc refresh): " -NoNewline -ForegroundColor Cyan
}

while ($true) {
    Clear-Host

    Show-MainMenu -InterfaceName $interfaceName
    
    $choice = Read-MenuChoice -AllowEscape
    if ($choice -eq [char]27) { continue }  # ESC pressed
    $choice = $choice.ToLower()
    if ([string]::IsNullOrWhiteSpace($choice)) { continue }

    # Block actions that require a valid interface
    $requiresInterface = @("1","2","3","4","5","t","m","q","i")
    if ($requiresInterface -contains $choice -and -not $interfaceName) {
        Write-Host "`n[ERROR] No network adapter selected" -ForegroundColor Red
        Write-Host "  Please select an adapter using option 6 first" -ForegroundColor Yellow
        Start-Sleep -Seconds 2
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
                    Write-Host "`n[WARN] Configuration cancelled by user" -ForegroundColor Yellow
                }
            } catch {
                Write-Host "Error during static IP configuration: $_" -ForegroundColor Red
                Write-LogMessage -Message "Error during static IP configuration: $_" -Level "ERROR"
            }
            Read-Host "`nPress Enter to continue"
        }
        "2" {
            try {
                $result = Set-DHCP -InterfaceName $interfaceName
                if (-not $result) {
                    Write-Host "`n[FAIL] DHCP configuration failed" -ForegroundColor Red
                    Write-Host "  Please verify:" -ForegroundColor Yellow
                    Write-Host "    - Network cable is connected (Ethernet)" -ForegroundColor Gray
                    Write-Host "    - Wi-Fi is connected to a network" -ForegroundColor Gray
                    Write-Host "    - Router/DHCP server is functioning" -ForegroundColor Gray
                    Write-Host "    - Check logs for details (L)" -ForegroundColor Gray
                }
            } catch {
                Write-Host "Error during DHCP configuration: $_" -ForegroundColor Red
                Write-LogMessage -Message "Error during DHCP configuration: $_" -Level "ERROR"
            }
            Read-Host "`nPress Enter to continue"
        }
        "3" {
            try {
                Show-IPInfo -InterfaceName $interfaceName
            } catch {
                Write-Host "Error displaying IP information: $_" -ForegroundColor Red
                Write-LogMessage -Message "Error displaying IP information: $_" -Level "ERROR"
            }
            Read-Host "`nPress Enter to continue"
        }
        "4" {
            try {
                $settings = $null
                if (Read-YesNo -Prompt "Save current static adapter configuration?" -Default $true) {
                    $settings = Get-CurrentIPProfileSettings -InterfaceName $interfaceName
                    if (-not $settings) {
                        if (Read-YesNo -Prompt "Enter profile settings manually instead?" -Default $false) {
                            $settings = Read-IPConfigurationSettings -InterfaceName $interfaceName
                        }
                    }
                } else {
                    $settings = Read-IPConfigurationSettings -InterfaceName $interfaceName
                }

                if ($settings) {
                    Save-StaticIPConfig -IPAddress $settings.IPAddress `
                                        -SubnetMask $settings.SubnetMask `
                                        -Gateway $settings.Gateway `
                                        -PrimaryDNS $settings.PrimaryDNS `
                                        -SecondaryDNS $settings.SecondaryDNS `
                                        -InterfaceName $interfaceName
                } else {
                    Write-Host "`n[WARN] Save operation cancelled" -ForegroundColor Yellow
                }
            } catch {
                Write-Host "Error saving static IP configuration: $_" -ForegroundColor Red
                Write-LogMessage -Message "Error saving static IP configuration: $_" -Level "ERROR"
            }
            Read-Host "`nPress Enter to continue"
        }
        "5" {
            try {
                $config = Get-SavedIPConfig
                if ($config) {
                    Write-Host "Loaded Profile:" -ForegroundColor Green
                    if ($config.Name) {
                        Write-Host "Name: $($config.Name)" -ForegroundColor White
                    }
                    if ($config.Environment) {
                        Write-Host "Group: $($config.Environment)" -ForegroundColor White
                    }
                    if ($config.Description) {
                        Write-Host "Note: $($config.Description)" -ForegroundColor Gray
                    }
                    Write-Host "IP Address: $($config.IPAddress)" -ForegroundColor White
                    Write-Host "Subnet Mask: $($config.SubnetMask)" -ForegroundColor White
                    Write-Host "Gateway: $(if($config.Gateway) { $config.Gateway } else { '(none)' })" -ForegroundColor White
                    Write-Host "Primary DNS: $($config.PrimaryDNS)" -ForegroundColor White
                    Write-Host "Secondary DNS: $(if($config.SecondaryDNS) { $config.SecondaryDNS } else { '(none)' })" -ForegroundColor White

                    if ($config.InterfaceName -and $config.InterfaceName -ne $interfaceName) {
                        Write-Host ""
                        Write-Host "[WARN] This profile was saved from adapter '$($config.InterfaceName)', but the selected adapter is '$interfaceName'." -ForegroundColor Yellow
                    }
                    
                    Write-Host ""
                    if (Read-YesNo -Prompt "Apply this configuration?" -Default $false) {
                        Set-StaticIP -InterfaceName $interfaceName `
                                     -IPAddress $config.IPAddress `
                                     -SubnetMask $config.SubnetMask `
                                     -Gateway $config.Gateway `
                                     -PrimaryDNS $config.PrimaryDNS `
                                     -SecondaryDNS $config.SecondaryDNS
                    } else {
                        Write-Host "`n[WARN] Configuration not applied" -ForegroundColor Yellow
                    }
                }
            } catch {
                Write-Host "Error loading static IP configuration: $_" -ForegroundColor Red
                Write-LogMessage -Message "Error loading static IP configuration: $_" -Level "ERROR"
            }
            Read-Host "`nPress Enter to continue"
        }
        "6" {
            try {
                $newInterface = Select-NetworkInterface
                if ($newInterface) {
                    $interfaceName = $newInterface
                    $host.UI.RawUI.WindowTitle = "Network Configuration - $interfaceName"
                    Write-Host "`n[OK] Network adapter switched successfully" -ForegroundColor Green
                    Write-Host "  Active adapter: $interfaceName" -ForegroundColor Cyan
                } else {
                    Write-Host "`n[WARN] No adapter selected - keeping current adapter" -ForegroundColor Yellow
                }
            } catch {
                Write-Host "Error selecting network interface: $_" -ForegroundColor Red
                Write-LogMessage -Message "Error selecting network interface: $_" -Level "ERROR"
            }
            Read-Host "`nPress Enter to continue"
        }
        "t" {
            try {
                $isQuickTest = Read-YesNo -Prompt "Run quick test?" -Default $false
                
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
            Read-Host "`nPress Enter to continue"
        }
        "s" {
            try {
                # Subnet Calculator - no interface required
                Invoke-SubnetCalculator
            } catch {
                Write-Host "Error during subnet calculation: $_" -ForegroundColor Red
                Write-LogMessage -Message "Error during subnet calculation: $_" -Level "ERROR"
            }
            Read-Host "`nPress Enter to continue"
        }
        "n" {
            try {
                Invoke-DNSLookup
            } catch {
                Write-Host "Error during DNS lookup: $_" -ForegroundColor Red
                Write-LogMessage -Message "Error during DNS lookup: $_" -Level "ERROR"
            }
            Read-Host "`nPress Enter to continue"
        }
        "r" {
            try {
                Invoke-Traceroute
            } catch {
                Write-Host "Error during traceroute: $_" -ForegroundColor Red
                Write-LogMessage -Message "Error during traceroute: $_" -Level "ERROR"
            }
            Read-Host "`nPress Enter to continue"
        }
        "o" {
            try {
                Invoke-PortCheck
            } catch {
                Write-Host "Error during port check: $_" -ForegroundColor Red
                Write-LogMessage -Message "Error during port check: $_" -Level "ERROR"
            }
            Read-Host "`nPress Enter to continue"
        }
        "a" {
            try {
                Show-ARPTable -InterfaceName $interfaceName
            } catch {
                Write-Host "Error displaying ARP table: $_" -ForegroundColor Red
                Write-LogMessage -Message "Error displaying ARP table: $_" -Level "ERROR"
            }
            Read-Host "`nPress Enter to continue"
        }
        "m" {
            # Live Interface Monitoring
            Start-LiveInterfaceMonitor -InterfaceName $interfaceName
        }
        "p" {
            # Privacy & Data Management (GDPR)
            Show-GDPRMenu
        }
        "l" {
            # Open log file
            try {
                Open-LogFile
            } catch {
                Write-Host "Error opening log file: $_" -ForegroundColor Red
                Write-LogMessage -Message "Error opening log file: $_" -Level "ERROR"
            }
            Start-Sleep -Seconds 1
            Read-Host "`nPress Enter to continue"
        }
        "u" {
            # Check for updates
            Update-NetworkScript
            Read-Host "`nPress Enter to continue"
        }
        "v" {
            # MAC Vendor Lookup
            try {
                Invoke-MACVendorLookup
            } catch {
                Write-Host "`nError during MAC vendor lookup: $_" -ForegroundColor Red
                Write-LogMessage -Message "Error during MAC vendor lookup: $_" -Level "ERROR"
            }
            Read-Host "`nPress Enter to continue"
        }
        "q" {
            # Quick DHCP configuration
            Write-Host "`n[>] Enabling DHCP (Quick Mode)..." -ForegroundColor Cyan
            try {
                $result = Set-DHCP -InterfaceName $interfaceName -MaxRetries 2
                if ($result) {
                    Write-Host "  [OK] DHCP enabled successfully" -ForegroundColor Green
                } else {
                    Write-Host "  [FAIL] DHCP setup failed" -ForegroundColor Red
                }
            } catch {
                Write-Host "Error during quick DHCP: $_" -ForegroundColor Red
            }
            Read-Host "`nPress Enter to continue"
        }
        "c" {
            # Clear screen
            Clear-Host
            continue
        }
        "d" {
            # DNS flush
            Write-Host "`n[>] Flushing DNS cache..." -ForegroundColor Cyan
            try {
                $result = & ipconfig /flushdns 2>&1
                if ($LASTEXITCODE -eq 0) {
                    Write-Host "  [OK] DNS cache flushed successfully" -ForegroundColor Green
                    Write-LogMessage -Message "DNS cache flushed successfully" -Level "INFO"
                } else {
                    Write-Host "  [FAIL] Failed to flush DNS cache" -ForegroundColor Red
                    Write-LogMessage -Message "DNS flush failed: $result" -Level "ERROR"
                }
            } catch {
                Write-Host "Error flushing DNS: $_" -ForegroundColor Red
                Write-LogMessage -Message "Error flushing DNS: $_" -Level "ERROR"
            }
            Read-Host "`nPress Enter to continue"
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
            Read-Host "`nPress Enter to continue"
        }
        "0" {
            Write-Host "`n[OK] Exiting Network Configuration Manager..." -ForegroundColor Cyan
            Write-Host "  Thank you for using this tool!" -ForegroundColor Gray
            Write-LogMessage "Script exited by user."
            
            # Pause if launched from context menu (Run with PowerShell)
            if ($Host.Name -eq 'ConsoleHost') {
                Read-Host "`nPress Enter to close"
            }
            exit
        }
        default {
            Write-Host "`n[ERROR] Invalid option: '$choice'" -ForegroundColor Red
            Write-Host "  Please select a valid option" -ForegroundColor Yellow
            Start-Sleep -Seconds 2
        }
    }
}
