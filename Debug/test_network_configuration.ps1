#Requires -Version 5.1
. (Join-Path $PSScriptRoot 'NetworkTestHarness.ps1')
# Exercise the actual conflict checker before replacing it for deterministic transaction tests.
Reset-TestState
Assert-True (-not (Test-IPConflict -InterfaceName Ethernet -IPAddress '192.168.1.50')) 'Self-address reported as conflict'
$script:addresses += [pscustomobject]@{ InterfaceAlias = 'Wi-Fi'; InterfaceIndex = 8; IPAddress = '192.168.1.25'; AddressState = 'Preferred'; Store = 'ActiveStore' }
Assert-True (Test-IPConflict -InterfaceName Ethernet -IPAddress '192.168.1.25') 'Other local adapter ownership missed'
function New-Object {
    param($TypeName)
    Assert-True ($TypeName -eq 'System.Net.NetworkInformation.Ping') 'Unexpected object construction in conflict test'
    $probe = [pscustomobject]@{}
    $probe | Add-Member -MemberType ScriptMethod -Name Send -Value { param($Address, $Timeout) }
    $probe | Add-Member -MemberType ScriptMethod -Name Dispose -Value { }
    return $probe
}
Reset-TestState
$script:neighbors = @(
    [pscustomobject]@{ InterfaceIndex = 7; IPAddress = '192.168.1.250'; State = 'Reachable'; LinkLayerAddress = '00-11-22-33-44-55' },
    [pscustomobject]@{ InterfaceIndex = 8; IPAddress = '192.168.1.25'; State = 'Reachable'; LinkLayerAddress = '00-11-22-33-44-55' }
)
Assert-True (-not (Test-IPConflict -InterfaceName Ethernet -IPAddress '192.168.1.25')) 'Unrelated IP or other-interface neighbor reported as conflict'
$script:neighbors += [pscustomobject]@{ InterfaceIndex = 7; IPAddress = '192.168.1.25'; State = 'Incomplete'; LinkLayerAddress = '00-00-00-00-00-00' }
Assert-True (-not (Test-IPConflict -InterfaceName Ethernet -IPAddress '192.168.1.25')) 'Incomplete neighbor reported as conflict'
$script:neighbors += [pscustomobject]@{ InterfaceIndex = 7; IPAddress = '192.168.1.25'; State = 'Reachable'; LinkLayerAddress = '00-11-22-33-44-55' }
Assert-True (Test-IPConflict -InterfaceName Ethernet -IPAddress '192.168.1.25') 'Exact neighbor conflict missed'
Remove-Item Function:\New-Object
function Test-IPConflict { param($InterfaceName, $IPAddress) return $false }

Reset-TestState
Assert-True (Set-StaticIP @settings) 'Static apply failed with other adapter and existing persistent gateway'
Assert-True (@($script:routes | Where-Object { $_.InterfaceAlias -eq 'Wi-Fi' }).Count -eq 2) 'Other adapter routes changed'
Assert-True (@($script:routes | Where-Object DestinationPrefix -eq '10.0.0.0/8').Count -eq 2) 'Custom route removed'
Assert-True (@($script:addresses | Where-Object IPAddress -eq '192.168.1.25').Count -eq 2) 'New address not persisted'
Assert-True (Set-StaticIP @settings) 'Reapplying same configuration failed'
$noGateway = $settings.Clone(); $noGateway.Gateway = $null
Assert-True (Set-StaticIP @noGateway) 'Gateway-free apply failed'
Assert-True (-not ($script:routes | Where-Object { $_.InterfaceAlias -eq 'Ethernet' -and $_.DestinationPrefix -eq '0.0.0.0/0' })) 'Gateway-free profile retained gateway'

foreach ($failure in @('partialAdd', 'duplicate', 'dnsFailure', 'routeFailure', 'backupFailure', 'finalMismatch')) {
    Reset-TestState
    Set-Variable -Name $failure -Value $true -Scope Script
    $result = Set-StaticIP @settings
    if ($failure -eq 'partialAdd') {
        Assert-True $result 'Partial successful address creation was not reconciled on retry'
    } else {
        Assert-True (-not $result) "Failure $failure reported success"
        Assert-True (@($script:addresses | Where-Object IPAddress -eq '192.168.1.50').Count -eq 2) "Failure $failure did not restore old static address"
        Assert-True (($script:dns -join ',') -eq '9.9.9.9') "Failure $failure did not restore DNS"
        Assert-True (@($script:routes | Where-Object { $_.InterfaceAlias -eq 'Ethernet' -and $_.NextHop -eq '192.168.1.254' -and $_.RouteMetric -eq 42 }).Count -eq 2) "Failure $failure did not restore gateway metrics"
        if ($failure -eq 'backupFailure') { Assert-True ($script:mutations -eq 0) 'Modified adapter without backup' }
    }
}
Reset-TestState
$script:addresses[1].PrefixLength = 25; $script:addresses[1].SkipAsSource = $true
$script:addresses += [pscustomobject]@{ InterfaceAlias = 'Ethernet'; InterfaceIndex = 7; IPAddress = '192.168.1.99'; PrefixLength = 32; PrefixOrigin = 'Manual'; AddressState = 'Invalid'; SkipAsSource = $true; Store = 'PersistentStore' }
$script:routeFailure = $true
Assert-True (-not (Set-StaticIP @settings)) 'Route failure with asymmetric address stores reported success'
Assert-True (@($script:addresses | Where-Object { $_.IPAddress -eq '192.168.1.50' -and $_.Store -eq 'ActiveStore' -and $_.PrefixLength -eq 24 -and -not $_.SkipAsSource }).Count -eq 1) 'Original active address was not restored'
Assert-True (@($script:addresses | Where-Object { $_.IPAddress -eq '192.168.1.50' -and $_.Store -eq 'PersistentStore' -and $_.PrefixLength -eq 25 -and $_.SkipAsSource }).Count -eq 1) 'Original persistent address was not restored'
Assert-True (@($script:addresses | Where-Object IPAddress -eq '192.168.1.99').Count -eq 1 -and ($script:addresses | Where-Object IPAddress -eq '192.168.1.99').Store -eq 'PersistentStore') 'Saved-only address was not restored'
Reset-TestState
$sameAddress = $settings.Clone(); $sameAddress.IPAddress = '192.168.1.50'; $sameAddress.SubnetMask = '25'
Assert-True (Set-StaticIP @sameAddress) 'Changing prefix on same address failed'
Assert-True (@($script:addresses | Where-Object { $_.IPAddress -eq '192.168.1.50' -and $_.PrefixLength -eq 25 }).Count -eq 2) 'New prefix not persisted'
Reset-TestState
$script:addresses = @($script:addresses | Where-Object Store -eq 'ActiveStore')
$existing = $settings.Clone(); $existing.IPAddress = '192.168.1.50'
Assert-True (Set-StaticIP @existing) 'Active-only existing address was not made persistent'
Reset-TestState
$script:addresses[0].AddressState = 'Tentative'
try { Wait-IPv4AddressReady -InterfaceName Ethernet -IPAddress '192.168.1.50' -PrefixLength 24 -TimeoutSeconds 0; throw 'Tentative address accepted' } catch { if ($_.Exception.Message -eq 'Tentative address accepted') { throw } }
Reset-TestState
Assert-True (-not (Set-StaticIP @settings -WhatIf)) 'WhatIf reported applied'
Assert-True ($script:mutations -eq 0) 'WhatIf modified adapter'
$invalid = $settings.Clone(); $invalid.Gateway = '10.0.0.1'
Assert-True (-not (Set-StaticIP @invalid)) 'Invalid gateway was accepted'
Assert-True ($script:mutations -eq 0) 'Validation failure modified adapter'
Reset-TestState
Assert-True (-not (Set-DHCP -InterfaceName Ethernet -MaxRetries 1 -Confirm:$false)) 'Failed DHCP renewal reported success'
Assert-True (@($script:addresses | Where-Object IPAddress -eq '192.168.1.50').Count -eq 2) 'DHCP failure lost old static address'
Reset-TestState
$script:renewSuccess = $true
Assert-True (Set-DHCP -InterfaceName Ethernet -MaxRetries 1 -Confirm:$false) 'Successful DHCP lease was rejected'
Assert-True ($script:dhcp -eq 'Enabled') 'DHCP not enabled'
Assert-True (-not ($script:routes | Where-Object { $_.InterfaceAlias -eq 'Ethernet' -and $_.DestinationPrefix -eq '0.0.0.0/0' })) 'Static gateway retained after DHCP'
$script:releaseDhcpOnDisable = $true; $script:noMatchesError = $true
Assert-True (Set-StaticIP @settings) 'DHCP-to-static failed when disabling DHCP removed its lease and CIM reported no matches'
Assert-True ($script:dhcp -eq 'Disabled' -and @($script:addresses | Where-Object IPAddress -eq '192.168.1.25').Count -eq 2) 'DHCP-to-static did not apply and persist the target address'
Reset-TestState
$script:renewSuccess = $true; $script:acknowledgedNoLease = $true
Assert-True (-not (Set-DHCP -InterfaceName Ethernet -MaxRetries 1 -Confirm:$false)) 'CIM success without a Preferred lease reported success'
Assert-True (@($script:addresses | Where-Object IPAddress -eq '192.168.1.50').Count -eq 2) 'Missing DHCP lease lost the previous static settings'
Reset-TestState
$script:renewSuccess = $true; $script:routeFailure = $true; $script:dhcp = 'Enabled'
$script:releaseDhcpOnDisable = $true; $script:noMatchesError = $true
$script:addresses = @($script:addresses | Where-Object Store -eq 'ActiveStore')
$script:addresses[0].PrefixOrigin = 'Dhcp'
$script:renewDelayQueries = 3
Assert-True (-not (Set-StaticIP @settings)) 'Failed DHCP-to-static gateway apply reported success'
Assert-True ($script:dhcp -eq 'Enabled') 'DHCP-to-static failure did not restore DHCP'
Assert-True (-not ($script:addresses | Where-Object IPAddress -eq '192.168.1.25')) 'Partial static address remained after DHCP rollback'
Assert-True (($script:dns -join ',') -eq '9.9.9.9') 'DHCP rollback lost static DNS override'
Reset-TestState
$script:addresses = @(); $script:noMatchesError = $true
Assert-True (@(Get-IPv4StoreState -InterfaceName Ethernet -Kind Address).Count -eq 0) 'CIM no-match was not treated as an empty address store'
try {
    Wait-IPv4AddressReady -InterfaceName Ethernet -IPAddress '192.168.1.25' -PrefixLength 24 -TimeoutSeconds 0
    throw 'Missing address passed readiness check'
} catch {
    Assert-True ($_.Exception.Message -like '*did not become Preferred*') 'Readiness failed on CIM no-match instead of its bounded timeout'
}
Reset-TestState
$script:readFailure = $true
try { $null = Get-IPv4StoreState -InterfaceName Ethernet -Kind Route; throw 'Read failure swallowed' } catch { if ($_.Exception.Message -eq 'Read failure swallowed') { throw } }
foreach ($failure in @('cimLookupFailure', 'cimIdentityMismatch', 'cimEmpty', 'cimTimeout', 'cimMissingResult')) {
    Reset-TestState
    Set-Variable -Name $failure -Value $true -Scope Script
    try { Invoke-InterfaceDHCPRenewal -InterfaceName Ethernet; throw 'CIM failure was accepted' } catch { if ($_.Exception.Message -eq 'CIM failure was accepted') { throw } }
    if ($failure -in @('cimLookupFailure', 'cimIdentityMismatch', 'cimEmpty')) { Assert-True ($script:cimCalls -eq 0) 'Renewed DHCP after identity lookup failed' }
}
foreach ($code in @(1, 64, 82, 91, 100, [uint32]::MaxValue)) {
    Reset-TestState
    $script:cimReturnCode = $code
    try { Invoke-InterfaceDHCPRenewal -InterfaceName Ethernet; throw 'Non-ready CIM result was accepted' } catch { if ($_.Exception.Message -eq 'Non-ready CIM result was accepted') { throw } }
}

# Test the real snapshot function and its versioned disk representation with mocked reads.
Reset-TestState
$definition = $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) | Where-Object Name -eq 'Backup-NetworkConfiguration' | Select-Object -First 1
. ([scriptblock]::Create($definition.Extent.Text))
$script:snapshotPath = Join-Path $PSScriptRoot ('network_snapshot_test_' + [guid]::NewGuid().ToString('N') + '.json')
function New-ManagedBackupPath { param($BaseName, $Extension) return $script:snapshotPath }
function Invoke-BackupRetention { param($Filter) }
function Get-ItemProperty { [CmdletBinding()]param($LiteralPath) [pscustomobject]@{ NameServer = $script:dnsOverride } }
try {
    $script:dnsOverride = '9.9.9.9'
    $backup = Backup-NetworkConfiguration -InterfaceName Ethernet
    Assert-True ($backup -and -not $backup.DNSAutomatic) 'Snapshot lost explicit DNS mode'
    $record = Get-Content -LiteralPath $script:snapshotPath -Raw | ConvertFrom-Json
    Assert-True ($record.FormatVersion -eq 2 -and $record.PersistentAddresses.Count -eq 1 -and $record.PersistentRoutes.Count -eq 2) 'Disk backup missing policy-store information'
    $script:dnsOverride = ''
    Assert-True ((Backup-NetworkConfiguration -InterfaceName Ethernet).DNSAutomatic) 'Automatic DNS mode not captured'
    $script:readFailure = $true
    Assert-True (-not (Backup-NetworkConfiguration -InterfaceName Ethernet)) 'Snapshot accepted failed network reads'
} finally { if (Test-Path -LiteralPath $script:snapshotPath) { Remove-Item -LiteralPath $script:snapshotPath -Force } }

# Adapter selection must include a virtual NIC and return when no adapters exist.
function Get-NetAdapter { [CmdletBinding()]param($Name) $script:selectableAdapters }
function Read-Host { return '7' }
function Save-SelectedInterface { param($InterfaceName) }
$script:selectableAdapters = @([pscustomobject]@{ Name = 'Ethernet'; InterfaceIndex = 7; Status = 'Up'; Virtual = $true; InterfaceDescription = 'VMware Virtual Ethernet Adapter'; MacAddress = '00-11-22-33-44-55' })
Assert-True ((Select-NetworkInterface) -eq 'Ethernet') 'Virtual NIC was excluded from selection'
$script:selectableAdapters = @()
Assert-True (-not (Select-NetworkInterface)) 'Empty adapter inventory did not return'
Write-Host 'Network configuration regression tests passed.' -ForegroundColor Green
