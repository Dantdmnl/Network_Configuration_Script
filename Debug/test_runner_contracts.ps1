#Requires -Version 5.1
# Exercise reporting failure paths with owned disposable child processes and files.
$ErrorActionPreference = 'Stop'
$root = Join-Path $PSScriptRoot ('test-results/runner_contract_' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root -Force | Out-Null
$windowsPowerShell = Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe'
$runner = Join-Path $PSScriptRoot 'test_regression.ps1'
$contractsPassed = $false
try {
    'throw "Intentional fixture failure"' | Set-Content -LiteralPath (Join-Path $root 'failure.ps1')
    '# Deliberately empty Pester suite' | Set-Content -LiteralPath (Join-Path $root 'empty.Tests.ps1')
    'Start-Sleep -Seconds 90' | Set-Content -LiteralPath (Join-Path $root 'timeout.ps1')
    'exit 0' | Set-Content -LiteralPath (Join-Path $root 'success.ps1')
    $cases = @(
        @{ File = 'failure.ps1'; Failed = 1 }, @{ File = 'missing.ps1'; Failed = 1 },
        @{ File = 'empty.Tests.ps1'; Failed = 1 }, @{ File = 'timeout.ps1'; Failed = 1 },
        @{ File = 'success.ps1'; Failed = 0 }
    )
    foreach ($case in $cases) {
        $suite = 'test-results/' + (Split-Path $root -Leaf) + '/' + $case.File
        $output = Join-Path $root ($case.File + '_report')
        $previousPreference = $ErrorActionPreference
        $timeout = 10
        if ($case.File -eq 'empty.Tests.ps1') { $timeout = 60 }
        try {
            $ErrorActionPreference = 'Continue'
            $null = & $windowsPowerShell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $runner `
                -Suites $suite -OutputDirectory $output -SuiteTimeoutSeconds $timeout 2>&1
        } finally { $ErrorActionPreference = $previousPreference }
        $code = $LASTEXITCODE
        if (($case.Failed -gt 0 -and $code -eq 0) -or ($case.Failed -eq 0 -and $code -ne 0)) { throw "Incorrect runner exit status for $($case.File): $code" }
        $summary = Get-Content -LiteralPath (Join-Path $output 'summary.json') -Raw | ConvertFrom-Json
        if ($summary.FailedSuites -ne $case.Failed -or @($summary.Suites).Count -ne 1) { throw "Incorrect runner summary for $($case.File)" }
        if ($case.File -eq 'empty.Tests.ps1') {
            $report = Get-Content -LiteralPath (Join-Path $output 'empty.Tests.json') -Raw | ConvertFrom-Json
            if ($report.Total -ne 0) { throw 'Empty suite was not recognized as empty' }
        }
    }
    Write-Host 'Runner contracts passed: crash, missing suite, empty Pester suite, timeout, and success.' -ForegroundColor Green
    $contractsPassed = $true
} finally {
    $resolved = [IO.Path]::GetFullPath($root)
    $allowed = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'test-results')).TrimEnd('\') + '\'
    if (-not $resolved.StartsWith($allowed, [StringComparison]::OrdinalIgnoreCase)) { throw 'Cleanup path outside test results' }
    if ($contractsPassed) { Remove-Item -LiteralPath $resolved -Recurse -Force }
    else { Write-Host "Failed runner fixtures retained: $resolved" }
}
