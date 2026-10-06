#Requires -Version 5.1
param([string]$TestLibraryPath)
. (Join-Path $PSScriptRoot 'NetworkTestHarness.ps1') -TestLibraryPath $TestLibraryPath

function Set-TestStartingMode {
    param($Mode)
    Reset-TestState
    $script:renewSuccess = $true
    $script:releaseDhcpOnDisable = $true
    $script:noMatchesError = $true
    switch ($Mode) {
        DHCP {
            $script:dhcp = 'Enabled'
            $script:addresses = @($script:addresses | Where-Object Store -eq 'ActiveStore')
            $script:addresses[0].PrefixOrigin = 'Dhcp'
        }
        APIPA {
            $script:dhcp = 'Enabled'
            $script:addresses = @($script:addresses | Where-Object Store -eq 'ActiveStore')
            $script:addresses[0].IPAddress = '169.254.5.10'; $script:addresses[0].PrefixOrigin = 'WellKnown'
        }
        Empty { $script:addresses = @() }
        ActiveOnly { $script:addresses = @($script:addresses | Where-Object Store -eq 'ActiveStore') }
        SavedOnly { $script:addresses = @($script:addresses | Where-Object Store -eq 'PersistentStore') }
        Multiple {
            New-NetIPAddress -InterfaceAlias Ethernet -IPAddress '192.168.1.60' -PrefixLength 24 -SkipAsSource $true
        }
        StalePersistentRoute {
            foreach ($route in @($script:routes | Where-Object { $_.InterfaceAlias -eq 'Ethernet' -and $_.DestinationPrefix -eq '0.0.0.0/0' -and $_.Store -eq 'PersistentStore' })) { $route.NextHop = '192.168.1.253' }
        }
    }
    $script:mutations = 0; $script:operations = @()
}
function Get-ManualAddressFingerprint {
    @($script:addresses | Where-Object PrefixOrigin -eq 'Manual' | ForEach-Object { "$($_.InterfaceAlias)|$($_.Store)|$($_.IPAddress)|$($_.PrefixLength)|$($_.SkipAsSource)" } | Sort-Object) -join ';'
}
function Get-RouteFingerprint {
    @($script:routes | Where-Object Protocol -eq 'NetMgmt' | ForEach-Object { "$($_.InterfaceAlias)|$($_.Store)|$($_.DestinationPrefix)|$($_.NextHop)|$($_.RouteMetric)" } | Sort-Object) -join ';'
}
$modes = @('Static', 'DHCP', 'APIPA', 'Empty', 'ActiveOnly', 'SavedOnly', 'Multiple', 'StalePersistentRoute')
$successCases = @($modes | ForEach-Object { @{ Mode = $_ } })
$failureCases = @(foreach ($mode in $modes) { foreach ($failure in @('Address', 'Gateway', 'DNS', 'FinalState')) { @{ Mode = $mode; Failure = $failure } } })

Describe 'IPv4 transaction state matrix' {
    BeforeEach {
        Mock Write-Host { }
        Mock Out-Host { }
        Mock Test-IPConflict { return $false }
    }
    It 'applies and persists static configuration from <Mode>' -TestCases $successCases {
        param($Mode)
        Set-TestStartingMode $Mode
        $otherRoutes = @($script:routes | Where-Object InterfaceAlias -eq 'Wi-Fi' | ConvertTo-Json -Compress)
        (Set-StaticIP @settings) | Should Be $true
        @($script:addresses | Where-Object IPAddress -eq '192.168.1.25').Count | Should Be 2
        @($script:addresses | Where-Object InterfaceAlias -eq 'Ethernet').Count | Should Be 2
        @($script:routes | Where-Object { $_.InterfaceAlias -eq 'Ethernet' -and $_.DestinationPrefix -eq '0.0.0.0/0' -and $_.NextHop -eq '192.168.1.1' }).Count | Should Be 2
        (@($script:routes | Where-Object InterfaceAlias -eq 'Wi-Fi' | ConvertTo-Json -Compress) -join '') | Should Be ($otherRoutes -join '')
        ($script:dns -join ',') | Should Be '1.1.1.1,1.0.0.1'
        $script:dhcp | Should Be 'Disabled'
    }
    It 'restores <Mode> state after <Failure> failure' -TestCases $failureCases {
        param($Mode, $Failure)
        Set-TestStartingMode $Mode
        $addressesBefore = Get-ManualAddressFingerprint
        $routesBefore = Get-RouteFingerprint
        $dhcpBefore = $script:dhcp
        switch ($Failure) {
            Address { $script:failOperation = 'NewAddress'; $script:failTarget = '192.168.1.25'; $script:failCount = 2 }
            Gateway { $script:routeFailure = $true }
            DNS { $script:dnsFailure = $true }
            FinalState { $script:finalMismatch = $true }
        }
        (Set-StaticIP @settings) | Should Be $false
        (Get-ManualAddressFingerprint) | Should Be $addressesBefore
        (Get-RouteFingerprint) | Should Be $routesBefore
        $script:dhcp | Should Be $dhcpBefore
        ($script:dns -join ',') | Should Be '9.9.9.9'
    }
    It 'creates the replacement address before deleting a different working address' {
        Set-TestStartingMode Static
        (Set-StaticIP @settings) | Should Be $true
        $newIndex = -1; $removeIndex = -1
        for ($i = 0; $i -lt $script:operations.Count; $i++) {
            if ($newIndex -lt 0 -and $script:operations[$i].Name -eq 'NewAddress') { $newIndex = $i }
            if ($removeIndex -lt 0 -and $script:operations[$i].Name -eq 'RemoveAddress' -and $script:operations[$i].Target -eq '192.168.1.50') { $removeIndex = $i }
        }
        ($newIndex -ge 0 -and $removeIndex -gt $newIndex) | Should Be $true
    }
    $routeStoreCases = @(@{ Store = 'ActiveStore' }, @{ Store = 'PersistentStore' }, @{ Store = 'Neither' })
    It 'creates a durable gateway when the requested route initially exists in <Store>' -TestCases $routeStoreCases {
        param($Store)
        Set-TestStartingMode DHCP
        $script:routes = @($script:routes | Where-Object { $_.InterfaceAlias -ne 'Ethernet' -or $_.DestinationPrefix -ne '0.0.0.0/0' })
        if ($Store -ne 'Neither') {
            $script:routes += [pscustomobject]@{ InterfaceAlias = 'Ethernet'; DestinationPrefix = '0.0.0.0/0'; NextHop = '192.168.1.1'; Store = $Store; Protocol = 'NetMgmt'; RouteMetric = 42 }
        }
        (Set-StaticIP @settings) | Should Be $true
        @($script:routes | Where-Object { $_.InterfaceAlias -eq 'Ethernet' -and $_.DestinationPrefix -eq '0.0.0.0/0' }).Count | Should Be 2
        @($script:operations | Where-Object { $_.Name -eq 'NewRoute' -and $_.Store -eq 'PersistentStore' }).Count | Should Be 0
    }
    $recoveryRouteCases = @(@{ Store = 'ActiveStore' }, @{ Store = 'PersistentStore' }, @{ Store = 'DifferentMetrics' })
    It 'restores original route stores and metrics after DNS failure from <Store>' -TestCases $recoveryRouteCases {
        param($Store)
        Set-TestStartingMode Static
        if ($Store -eq 'DifferentMetrics') {
            foreach ($route in @($script:routes | Where-Object { $_.InterfaceAlias -eq 'Ethernet' -and $_.Store -eq 'ActiveStore' })) { $route.RouteMetric = 73 }
        } else {
            $script:routes = @($script:routes | Where-Object { $_.InterfaceAlias -ne 'Ethernet' -or $_.Store -eq $Store })
        }
        $original = Get-RouteFingerprint
        $script:dnsFailure = $true
        (Set-StaticIP @settings) | Should Be $false
        (Get-RouteFingerprint) | Should Be $original
    }
    It 'shows the underlying gateway provider failure on the console' {
        Set-TestStartingMode DHCP
        $script:routeFailure = $true
        (Set-StaticIP @settings) | Should Be $false
        Assert-MockCalled Write-Host -Scope It -Times 1 -Exactly -ParameterFilter { $Object -like '*[[]ERROR[]] Gateway*Injected gateway failure*' }
    }
    It 'does not create addresses or routes when reapplying identical durable settings' {
        Set-TestStartingMode Static
        (Set-StaticIP @settings) | Should Be $true
        $script:operations = @()
        (Set-StaticIP @settings) | Should Be $true
        @($script:operations | Where-Object { $_.Name -in @('NewAddress', 'NewRoute', 'RemoveAddress', 'RemoveRoute') }).Count | Should Be 0
    }
    It 'recovers from a transient address creation failure with exactly two attempts' {
        Set-TestStartingMode Static
        $script:failOperation = 'NewAddress'; $script:failTarget = '192.168.1.25'; $script:failCount = 1
        (Set-StaticIP @settings) | Should Be $true
        @($script:operations | Where-Object { $_.Name -eq 'NewAddress' -and $_.Target -eq '192.168.1.25' }).Count | Should Be 2
    }
    It 'removes both default-route stores when a profile requests no gateway' {
        Set-TestStartingMode StalePersistentRoute
        $request = $settings.Clone(); $request.Gateway = $null
        (Set-StaticIP @request) | Should Be $true
        @($script:routes | Where-Object { $_.InterfaceAlias -eq 'Ethernet' -and $_.DestinationPrefix -eq '0.0.0.0/0' }).Count | Should Be 0
        @($script:routes | Where-Object DestinationPrefix -eq '10.0.0.0/8').Count | Should Be 2
    }
    It 'returns false and reports failed recovery instead of success when recovery also fails' {
        Set-TestStartingMode Static
        $script:routeFailure = $true; $script:removeFailure = $true
        (Set-StaticIP @settings) | Should Be $false
        Assert-MockCalled Write-Host -Times 1 -Exactly -Scope It -ParameterFilter { $Object -like '*Recovery incomplete*' }
    }
    It 'does not mutate an adapter under WhatIf' {
        Set-TestStartingMode Static
        (Set-StaticIP @settings -WhatIf) | Should Be $false
        $script:mutations | Should Be 0
        (Set-DHCP -InterfaceName Ethernet -WhatIf) | Should Be $false
        $script:mutations | Should Be 0
    }
    It 'does not mutate without a usable snapshot' {
        Set-TestStartingMode Static
        $script:backupFailure = $true
        (Set-StaticIP @settings) | Should Be $false
        (Set-DHCP -InterfaceName Ethernet -Confirm:$false) | Should Be $false
        $script:mutations | Should Be 0
    }
    It 'cancels a reported conflict without touching configuration' {
        Set-TestStartingMode Static
        Mock Test-IPConflict { return $true }
        Mock Read-YesNo { return $false }
        $null = Set-StaticIP @settings
        $script:mutations | Should Be 0
    }
}

$invalidCases = @(
    @{ Field = 'IPAddress'; Value = '192.168.1.256' }, @{ Field = 'IPAddress'; Value = '192.168.1.0' },
    @{ Field = 'IPAddress'; Value = '192.168.1.255' }, @{ Field = 'IPAddress'; Value = '192.168.1.1' },
    @{ Field = 'SubnetMask'; Value = '255.0.255.0' }, @{ Field = 'SubnetMask'; Value = '33' },
    @{ Field = 'Gateway'; Value = '10.0.0.1' }, @{ Field = 'Gateway'; Value = '192.168.1.0' },
    @{ Field = 'Gateway'; Value = '192.168.1.255' }, @{ Field = 'PrimaryDNS'; Value = 'bad' },
    @{ Field = 'SecondaryDNS'; Value = '2001:db8::1' }
)
Describe 'Transaction validation boundaries' {
    BeforeEach { Mock Write-Host { }; Mock Test-IPConflict { return $false }; Set-TestStartingMode Static }
    It 'rejects <Field> value <Value> before mutation' -TestCases $invalidCases {
        param($Field, $Value)
        $request = $settings.Clone(); $request[$Field] = $Value
        $null = Set-StaticIP @request
        $script:mutations | Should Be 0
    }
    It 'accepts a /31 peer gateway' {
        $request = $settings.Clone(); $request.IPAddress = '192.168.1.10'; $request.SubnetMask = '31'; $request.Gateway = '192.168.1.11'
        (Set-StaticIP @request) | Should Be $true
    }
    It 'accepts a /32 address without a gateway' {
        $request = $settings.Clone(); $request.IPAddress = '192.168.1.10'; $request.SubnetMask = '32'; $request.Gateway = $null
        (Set-StaticIP @request) | Should Be $true
    }
}
