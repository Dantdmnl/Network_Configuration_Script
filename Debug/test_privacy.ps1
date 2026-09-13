#Requires -Version 5.1
# Exercise the privacy helpers without running the interactive script or changing network settings.
$ErrorActionPreference = 'Stop'
$scriptPath = Join-Path $PSScriptRoot '..\Network_Configuration.ps1'
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$parseErrors)
if ($parseErrors) { throw "Network script has parse errors." }

foreach ($name in @('Get-GDPRConsent', 'Hide-IPAddress', 'Write-LogMessage')) {
    $definition = $ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
    }, $true) | Where-Object Name -eq $name | Select-Object -First 1
    if (-not $definition) { throw "Missing function: $name" }
    . ([scriptblock]::Create($definition.Extent.Text))
}

# Keep the test isolated from user logs and skip rotation, which is unrelated here.
function Invoke-LogRotation {}
$script:LoggingConsent = $true
$script:PseudonymizeData = $true
$script:MinLogLevel = 'INFO'
$script:LogLevels = @{ DEBUG = 1; INFO = 2; WARN = 3; ERROR = 4; CRITICAL = 5 }
$script:LogFile = Join-Path ([System.IO.Path]::GetTempPath()) ("network_privacy_test_{0}.log" -f [guid]::NewGuid())
$script:ConsentPath = Join-Path ([System.IO.Path]::GetTempPath()) ("network_consent_test_{0}.json" -f [guid]::NewGuid())

try {
    '{"LoggingConsent":true,"PseudonymizeData":false}' | Set-Content -LiteralPath $script:ConsentPath
    Get-GDPRConsent
    if (-not $script:PseudonymizeData) { throw 'Stored consent disabled log pseudonymization.' }

    $cases = @(
        @{ Input = '2001:db8:abcd:1234:5678:9abc:def0:1234'; Masked = '2001:db8:abcd:1234:xxxx:xxxx:xxxx:xxxx' },
        @{ Input = 'fe80::1234:5678'; Masked = 'fe80:0:0:0:xxxx:xxxx:xxxx:xxxx' },
        @{ Input = '::1'; Masked = '0:0:0:0:xxxx:xxxx:xxxx:xxxx' },
        @{ Input = '::ffff:192.0.2.42'; Masked = '0:0:0:0:xxxx:xxxx:xxxx:xxxx' }
    )
    foreach ($case in $cases) {
        $actual = Hide-IPAddress -IPAddress $case.Input
        if ($actual -ne $case.Masked) { throw "Mask mismatch for $($case.Input): $actual" }
        Write-LogMessage -Message "Address $($case.Input)" -Level INFO
    }
    Write-LogMessage -Message 'Address 192.168.1.42' -Level INFO
    $entries = @(Get-Content $script:LogFile | ForEach-Object { $_ | ConvertFrom-Json })
    for ($i = 0; $i -lt $cases.Count; $i++) {
        if ($entries[$i].message -ne "Address $($cases[$i].Masked)") {
            throw "Log did not mask $($cases[$i].Input): $($entries[$i].message)"
        }
    }
    if ($entries[-1].message -ne 'Address 192.168.1.xxx') { throw 'IPv4 log masking regressed.' }

    $script:LoggingConsent = $false
    Write-LogMessage -Message 'Address 10.0.0.1' -Level INFO
    if (@(Get-Content $script:LogFile).Count -ne $entries.Count) { throw 'Logging continued without consent.' }
    Write-Host 'Privacy masking tests passed.' -ForegroundColor Green
} finally {
    Remove-Item -LiteralPath $script:LogFile -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $script:ConsentPath -Force -ErrorAction SilentlyContinue
}
