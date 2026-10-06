#Requires -Version 5.1
param([string]$TestLibraryPath)
# Isolated stateful regression tests. Never dot-source the application startup or call live networking cmdlets.
$ErrorActionPreference = 'Stop'
$sourcePath = Join-Path $PSScriptRoot '..\Network_Configuration.ps1'
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($sourcePath, [ref]$null, [ref]$errors)
if ($errors) { throw ($errors | Out-String) }
$names = @('Set-StaticIP', 'Set-DHCP', 'Get-IPv4StoreState', 'Restore-NetworkConfiguration', 'Wait-IPv4AddressReady', 'Invoke-InterfaceDHCPRenewal',
    'Set-IPv4DefaultGatewaySafe', 'Remove-IPv4AddressSafe', 'Set-IPv4DnsServersSafe', 'Reset-IPv4DnsServersSafe',
    'Test-ValidIPAddress', 'Test-ValidDNSServer', 'Test-ValidSubnetMask', 'Get-PrefixLength',
    'ConvertTo-IPv4UInt32', 'ConvertFrom-IPv4UInt32', 'Get-IPv4NetworkDetails', 'Test-IPConflict', 'Select-NetworkInterface')
if ($TestLibraryPath) { . $TestLibraryPath }
else { foreach ($name in $names) {
    $definition = $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) |
        Where-Object Name -eq $name | Select-Object -First 1
    if (-not $definition) { throw "Missing function $name" }
    Set-Item -Path ("Function:script:" + $name) -Value $definition.Body.GetScriptBlock()
} }
function Assert-True($Condition, $Message) { if (-not $Condition) { throw $Message } }
function Register-TestOperation {
    param($Name, $Target, $Store)
    $script:operations += [pscustomobject]@{ Name = $Name; Target = $Target; Store = $Store }
    if ($script:failOperation -eq $Name -and $script:failCount -gt 0 -and
        (-not $script:failTarget -or $script:failTarget -eq $Target)) {
        $script:failCount--
        throw "Injected $Name failure for $Target"
    }
}
function Write-LogMessage { param($Message, $Level) }
function Start-Sleep { param($Milliseconds, $Seconds) }
function Show-IPv4ConfigurationSummary { param($InterfaceName, $IPConfig, $IPv4Address, $DHCPStatus) }
function Test-DNSConnectivity { param($DNSServer) return $true }
function Test-SystemDNSResolution { return $true }
function Clear-DnsClientCache { [CmdletBinding()]param() }
function Read-YesNo { param($Prompt, $Default) return $true }
function Get-NetAdapter { [CmdletBinding()]param($Name) [pscustomobject]@{ Name = 'Ethernet'; Status = 'Up'; ifIndex = 7; InterfaceGuid = '11111111-1111-1111-1111-111111111111' } }
function Get-NetworkAdapterSafe { param($InterfaceName) Get-NetAdapter -Name $InterfaceName }
function Get-NetIPInterface { [CmdletBinding()]param($InterfaceAlias, $AddressFamily) [pscustomobject]@{ Dhcp = $script:dhcp } }
function Set-NetIPInterface {
    [CmdletBinding()]param($InterfaceAlias, $AddressFamily, $Dhcp)
    Register-TestOperation -Name SetDhcp -Target $Dhcp
    if ($Dhcp -eq 'Disabled' -and $script:dhcp -eq 'Enabled' -and $script:releaseDhcpOnDisable) {
        $script:addresses = @($script:addresses | Where-Object { $_.InterfaceAlias -ne $InterfaceAlias -or $_.PrefixOrigin -ne 'Dhcp' })
        $script:routes = @($script:routes | Where-Object { $_.InterfaceAlias -ne $InterfaceAlias -or $_.Protocol -ne 'Dhcp' })
    }
    $script:dhcp = $Dhcp; $script:mutations++
}
function Get-NetIPAddress {
    [CmdletBinding()]param($InterfaceAlias, $AddressFamily, $PolicyStore = 'ActiveStore')
    Register-TestOperation -Name ReadAddress -Target $InterfaceAlias -Store $PolicyStore
    if ($script:readFailure) { throw 'Injected read failure' }
    if ($script:leaseDelayQueries -gt 0) {
        $script:leaseDelayQueries--
        if ($script:leaseDelayQueries -eq 0) {
            foreach ($address in @($script:addresses | Where-Object PrefixOrigin -eq 'Dhcp')) { $address.AddressState = 'Preferred' }
        }
    }
    $result = @($script:addresses | Where-Object { $_.Store -eq $PolicyStore -and (-not $InterfaceAlias -or $_.InterfaceAlias -eq $InterfaceAlias) })
    if ($script:noMatchesError -and $result.Count -eq 0) {
        $PSCmdlet.WriteError([System.Management.Automation.ErrorRecord]::new(
            [Exception]::new('No matching MSFT_NetIPAddress objects found by CIM query'),
            'CmdletizationQuery_NotFound', [System.Management.Automation.ErrorCategory]::ObjectNotFound, $InterfaceAlias))
    }
    $result
}
function New-NetIPAddress {
    [CmdletBinding()]param($InterfaceAlias, $AddressFamily, $IPAddress, $PrefixLength, $DefaultGateway, $PolicyStore, $SkipAsSource = $false, $ValidLifetime, $PreferredLifetime)
    Assert-True (-not $DefaultGateway) 'Address creation attempted to create a gateway'
    Assert-True ($PolicyStore -ne 'PersistentStore') 'Used unsupported explicit PersistentStore address creation'
    Register-TestOperation -Name NewAddress -Target $IPAddress -Store $PolicyStore
    $stores = if ($PolicyStore) { @($PolicyStore) } else { @('ActiveStore', 'PersistentStore') }
    foreach ($store in $stores) {
        Assert-True (-not ($script:addresses | Where-Object { $_.InterfaceAlias -eq $InterfaceAlias -and $_.IPAddress -eq $IPAddress -and $_.Store -eq $store })) 'Duplicate address creation'
        $state = if ($script:duplicate -and $IPAddress -eq '192.168.1.25') { 'Duplicate' } else { 'Preferred' }
        $script:addresses += [pscustomobject]@{ InterfaceAlias = $InterfaceAlias; InterfaceIndex = 7; IPAddress = $IPAddress; PrefixLength = $PrefixLength; PrefixOrigin = 'Manual'; AddressState = $state; SkipAsSource = $SkipAsSource; Store = $store }
    }
    $script:mutations++
    if ($script:partialAdd) { $script:partialAdd = $false; throw 'Injected error after successful address creation' }
}
function Remove-NetIPAddress {
    [CmdletBinding(SupportsShouldProcess)]param($InterfaceAlias, $IPAddress, $AddressFamily, $PolicyStore)
    Register-TestOperation -Name RemoveAddress -Target $IPAddress -Store $PolicyStore
    if ($script:removeFailure) { throw 'Injected address removal failure' }
    $script:addresses = @($script:addresses | Where-Object { $_.InterfaceAlias -ne $InterfaceAlias -or $_.IPAddress -ne $IPAddress -or ($PolicyStore -and $_.Store -ne $PolicyStore) })
    $script:mutations++
}
function Set-NetIPAddress {
    [CmdletBinding()]param($InterfaceAlias, $AddressFamily, $IPAddress, $SkipAsSource, $PrefixLength, $PolicyStore)
    Assert-True ($PolicyStore -ne 'PersistentStore') 'Used unsupported explicit PersistentStore address mutation'
    Register-TestOperation -Name SetAddress -Target $IPAddress -Store $PolicyStore
    foreach ($address in @($script:addresses | Where-Object { $_.InterfaceAlias -eq $InterfaceAlias -and $_.IPAddress -eq $IPAddress -and (-not $PolicyStore -or $_.Store -eq $PolicyStore) })) {
        if ($PSBoundParameters.ContainsKey('PrefixLength')) { $address.PrefixLength = $PrefixLength }
        if ($PSBoundParameters.ContainsKey('SkipAsSource')) { $address.SkipAsSource = $SkipAsSource }
    }
    $script:mutations++
}
function Get-NetRoute {
    [CmdletBinding()]param($InterfaceAlias, $AddressFamily, $PolicyStore = 'ActiveStore')
    Register-TestOperation -Name ReadRoute -Target $InterfaceAlias -Store $PolicyStore
    if ($script:readFailure) { throw 'Injected route read failure' }
    $script:routes | Where-Object { $_.InterfaceAlias -eq $InterfaceAlias -and $_.Store -eq $PolicyStore }
}
function Remove-NetRoute {
    [CmdletBinding(SupportsShouldProcess)]param($InterfaceAlias, $AddressFamily, $DestinationPrefix, $NextHop, $PolicyStore)
    Assert-True ($InterfaceAlias -eq 'Ethernet') 'Touched another adapter route'
    Register-TestOperation -Name RemoveRoute -Target $NextHop -Store $PolicyStore
    $script:routes = @($script:routes | Where-Object { $_.InterfaceAlias -ne $InterfaceAlias -or $_.DestinationPrefix -ne $DestinationPrefix -or $_.NextHop -ne $NextHop -or $_.Store -ne $PolicyStore })
    $script:mutations++
}
function New-NetRoute {
    [CmdletBinding()]param($InterfaceAlias, $AddressFamily, $DestinationPrefix, $NextHop, $PolicyStore, $RouteMetric = 256)
    Register-TestOperation -Name NewRoute -Target $NextHop -Store $PolicyStore
    if ($PolicyStore -eq 'PersistentStore') { throw 'New-NetRoute cannot explicitly create in PersistentStore' }
    if ($script:routeFailure -and $NextHop -eq '192.168.1.1') { throw 'Injected gateway failure' }
    Assert-True (-not ($script:routes | Where-Object { $_.InterfaceAlias -eq $InterfaceAlias -and $_.DestinationPrefix -eq $DestinationPrefix -and $_.NextHop -eq $NextHop -and $_.Store -eq $PolicyStore })) 'Duplicate route creation'
    $stores = if ($PolicyStore) { @($PolicyStore) } else { @('ActiveStore', 'PersistentStore') }
    foreach ($targetStore in $stores) {
        Assert-True (-not ($script:routes | Where-Object { $_.InterfaceAlias -eq $InterfaceAlias -and $_.DestinationPrefix -eq $DestinationPrefix -and $_.NextHop -eq $NextHop -and $_.Store -eq $targetStore })) 'Duplicate route creation'
        $script:routes += [pscustomobject]@{ InterfaceAlias = $InterfaceAlias; DestinationPrefix = $DestinationPrefix; NextHop = $NextHop; Store = $targetStore; Protocol = 'NetMgmt'; RouteMetric = $RouteMetric }
    }
    $script:mutations++
}
function Set-NetRoute {
    [CmdletBinding()]param($InterfaceAlias, $AddressFamily, $DestinationPrefix, $NextHop, $PolicyStore, $RouteMetric)
    Assert-True ($InterfaceAlias -eq 'Ethernet') 'Changed another adapter route metric'
    foreach ($route in @($script:routes | Where-Object { $_.InterfaceAlias -eq $InterfaceAlias -and $_.DestinationPrefix -eq $DestinationPrefix -and $_.NextHop -eq $NextHop -and $_.Store -eq $PolicyStore })) {
        $route.RouteMetric = $RouteMetric
    }
    $script:mutations++
}
function Get-DnsClientServerAddress { [CmdletBinding()]param($InterfaceAlias, $AddressFamily) Register-TestOperation -Name ReadDNS -Target $InterfaceAlias; [pscustomobject]@{ ServerAddresses = @($script:dns); AddressFamily = 2 } }
function Set-DnsClientServerAddress {
    [CmdletBinding()]param([Parameter(ValueFromPipeline)]$InputObject, $ServerAddresses, [switch]$ResetServerAddresses)
    process {
        $operation = if ($ResetServerAddresses) { 'ResetDNS' } else { 'SetDNS' }
        Register-TestOperation -Name $operation -Target ($ServerAddresses -join ',')
        Assert-True ($InputObject.AddressFamily -eq 2) 'DNS update was not scoped to IPv4'
        if ($script:dnsFailure -and $ServerAddresses -contains '1.1.1.1') { throw 'Injected DNS failure' }
        $script:dns = if ($ResetServerAddresses) { @('192.168.1.1') } else { @($ServerAddresses) }
        $script:mutations++
    }
}
function Get-NetIPConfiguration {
    [CmdletBinding()]param($InterfaceAlias)
    $addresses = @(Get-NetIPAddress -InterfaceAlias $InterfaceAlias)
    if ($script:finalMismatch) { $addresses = @() }
    [pscustomobject]@{ IPv4Address = $addresses; IPv4DefaultGateway = @(Get-NetRoute -InterfaceAlias $InterfaceAlias | Where-Object DestinationPrefix -eq '0.0.0.0/0') }
}
function Get-NetNeighbor { [CmdletBinding()]param($InterfaceIndex, $AddressFamily) $script:neighbors | Where-Object InterfaceIndex -eq $InterfaceIndex }
function ipconfig { throw 'Unexpected native DHCP command' }
function Get-CimInstance {
    [CmdletBinding()]param($Namespace, $ClassName, $Filter, $OperationTimeoutSec)
    Assert-True ($ClassName -eq 'Win32_NetworkAdapterConfiguration' -and $Namespace -eq 'root/cimv2') 'Unexpected CIM query'
    Assert-True ($Filter -eq 'InterfaceIndex = 7' -and $OperationTimeoutSec -gt 0) 'Unscoped or untimed DHCP lookup'
    if ($script:cimLookupFailure) { throw 'Injected CIM lookup failure' }
    if ($script:cimEmpty) { return }
    $id = if ($script:cimIdentityMismatch) { '22222222-2222-2222-2222-222222222222' } else { '11111111-1111-1111-1111-111111111111' }
    [pscustomobject]@{ InterfaceIndex = 7; SettingID = $id }
}
function Invoke-CimMethod {
    [CmdletBinding()]param($InputObject, $MethodName, $OperationTimeoutSec)
    Assert-True ($InputObject.InterfaceIndex -eq 7 -and $MethodName -eq 'RenewDHCPLease' -and $OperationTimeoutSec -gt 0) 'Renewal not scoped to one adapter with timeout'
    $script:cimCalls++
    if ($script:cimTimeout) { throw 'Injected CIM operation timeout' }
    if ($script:cimMissingResult) { return [pscustomobject]@{} }
    $code = if ($null -ne $script:cimReturnCode) { $script:cimReturnCode } elseif ($script:renewSuccess) { 0 } else { 82 }
    if ($code -eq 0 -and -not $script:acknowledgedNoLease) {
        $script:leaseDelayQueries = $script:renewDelayQueries
        $leaseState = if ($script:leaseDelayQueries -gt 0) { 'Tentative' } else { 'Preferred' }
        $script:addresses += [pscustomobject]@{ InterfaceAlias = 'Ethernet'; InterfaceIndex = 7; IPAddress = '192.168.1.100'; PrefixLength = 24; PrefixOrigin = 'Dhcp'; AddressState = $leaseState; SkipAsSource = $false; Store = 'ActiveStore' }
    }
    [pscustomobject]@{ ReturnValue = $code }
}
function Backup-NetworkConfiguration {
    param($InterfaceName)
    if ($script:backupFailure) { return $null }
    @{ Interface = $InterfaceName; IPv4Address = @(Get-IPv4StoreState -InterfaceName $InterfaceName -Kind Address); PersistentAddresses = @(Get-IPv4StoreState -InterfaceName $InterfaceName -Kind Address -PolicyStore PersistentStore);
       IPv4Routes = @(Get-IPv4StoreState -InterfaceName $InterfaceName -Kind Route); PersistentRoutes = @(Get-IPv4StoreState -InterfaceName $InterfaceName -Kind Route -PolicyStore PersistentStore);
       DNSServers = @($script:dns); DHCPEnabled = $script:dhcp; DNSAutomatic = $false }
}
function Reset-TestState {
    $script:operations = @(); $script:failOperation = ''; $script:failTarget = ''; $script:failCount = 0
    $script:addresses = @()
    $script:routes = @()
    $script:neighbors = @()
    $script:dhcp = 'Disabled'; $script:dns = @('9.9.9.9'); $script:mutations = 0
    $script:duplicate = $false; $script:partialAdd = $false; $script:dnsFailure = $false
    $script:routeFailure = $false; $script:readFailure = $false; $script:backupFailure = $false; $script:removeFailure = $false
    $script:finalMismatch = $false; $script:renewSuccess = $false
    $script:cimLookupFailure = $false; $script:cimIdentityMismatch = $false; $script:cimEmpty = $false
    $script:cimTimeout = $false; $script:cimReturnCode = $null; $script:cimMissingResult = $false
    $script:acknowledgedNoLease = $false; $script:cimCalls = 0
    $script:leaseDelayQueries = 0; $script:renewDelayQueries = 0
    $script:releaseDhcpOnDisable = $false; $script:noMatchesError = $false
    New-NetIPAddress -InterfaceAlias Ethernet -IPAddress '192.168.1.50' -PrefixLength 24
    New-NetRoute -InterfaceAlias Ethernet -DestinationPrefix '0.0.0.0/0' -NextHop '192.168.1.254' -RouteMetric 42
    New-NetRoute -InterfaceAlias Ethernet -DestinationPrefix '10.0.0.0/8' -NextHop '192.168.1.254'
    foreach ($store in @('ActiveStore', 'PersistentStore')) {
        $script:routes += [pscustomobject]@{ InterfaceAlias = 'Wi-Fi'; DestinationPrefix = '0.0.0.0/0'; NextHop = '192.168.1.1'; Store = $store; Protocol = 'NetMgmt'; RouteMetric = 99 }
    }
    $script:mutations = 0
    $script:operations = @()
}
$settings = @{ InterfaceName = 'Ethernet'; IPAddress = '192.168.1.25'; SubnetMask = '24'; Gateway = '192.168.1.1'; PrimaryDNS = '1.1.1.1'; SecondaryDNS = '1.0.0.1'; Confirm = $false }
