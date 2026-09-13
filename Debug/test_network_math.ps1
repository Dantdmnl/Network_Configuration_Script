#Requires -Version 5.1
# Validate address parsing and subnet suggestions without touching adapters.
$ErrorActionPreference = 'Stop'
$sourcePath = Join-Path $PSScriptRoot '..\Network_Configuration.ps1'
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($sourcePath, [ref]$null, [ref]$parseErrors)
if ($parseErrors) { throw 'Network script has parse errors.' }

foreach ($name in @('Test-ValidIPAddress', 'Test-ValidSubnetMask', 'Get-PrefixLength', 'ConvertTo-IPv4UInt32', 'ConvertFrom-IPv4UInt32', 'Get-IPv4NetworkDetails', 'Get-SuggestedGateway')) {
    $definition = $ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
    }, $true) | Where-Object Name -eq $name | Select-Object -First 1
    if (-not $definition) { throw "Missing function: $name" }
    . ([scriptblock]::Create($definition.Extent.Text))
}

foreach ($address in @('192.168.1', '10.1', '192.168.1.256', '192.168.001.1', '127.0.0.1', '2001:db8::1')) {
    if (Test-ValidIPAddress -IPAddress $address) { throw "Accepted invalid configuration address: $address" }
}
foreach ($address in @('192.168.1.1', '10.0.0.25')) {
    if (-not (Test-ValidIPAddress -IPAddress $address)) { throw "Rejected valid address: $address" }
}
foreach ($mask in @('7', '254.0.0.0', '33', '255.0.255.0')) {
    if (Test-ValidSubnetMask -SubnetInput $mask) { throw "Accepted invalid subnet mask: $mask" }
    try {
        $null = Get-PrefixLength -SubnetInput $mask
        throw "Converted invalid subnet mask: $mask"
    } catch {
        if ($_.Exception.Message -eq "Converted invalid subnet mask: $mask") { throw }
    }
}
if ((Get-PrefixLength -SubnetInput '255.255.255.128') -ne 25) { throw 'Dotted subnet mask conversion failed.' }

$cases = @(
    @{ Address = '192.168.1.25'; Prefix = 24; Expected = @('192.168.1.1', '192.168.1.254') },
    @{ Address = '192.168.1.200'; Prefix = 25; Expected = @('192.168.1.129', '192.168.1.254') },
    @{ Address = '192.168.1.25'; Prefix = 25; Expected = @('192.168.1.1', '192.168.1.126') },
    @{ Address = '192.168.1.1'; Prefix = 30; Expected = @('192.168.1.2') },
    @{ Address = '192.168.1.10'; Prefix = 31; Expected = @('192.168.1.11') },
    @{ Address = '192.168.1.10'; Prefix = 32; Expected = @() },
    @{ Address = '10.20.30.40'; Prefix = 8; Expected = @('10.0.0.1', '10.255.255.254') }
)
foreach ($case in $cases) {
    $actual = @(Get-SuggestedGateway -IPAddress $case.Address -PrefixLength $case.Prefix)
    if (($actual -join ',') -ne ($case.Expected -join ',')) {
        throw "Wrong gateways for $($case.Address)/$($case.Prefix): $($actual -join ',')"
    }
}
Write-Host 'Network address tests passed.' -ForegroundColor Green
