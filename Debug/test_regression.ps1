#Requires -Version 5.1
<#
.SYNOPSIS
    Runs all automated checks in separate Windows PowerShell 5.1 processes.
.DESCRIPTION
    Aggregates failures, rejects empty/Pending/Skipped Pester runs, and saves JSON,
    JUnit XML, command coverage, and per-suite logs. No application startup is executed.
#>
param(
    [string]$OutputDirectory = (Join-Path $PSScriptRoot 'test-results'),
    [ValidateRange(10,1800)][int]$SuiteTimeoutSeconds = 300,
    [string[]]$Suites = @('test_privacy.ps1', 'test_update.ps1', 'test_network_math.ps1', 'test_network_configuration.ps1',
        'test_export.ps1', 'test_profiles.ps1', 'test_log_query.ps1', 'Network_Core.Tests.ps1', 'Network_Transactions.Tests.ps1', 'test_syntax.ps1', 'test_runner_contracts.ps1')
)
$ErrorActionPreference = 'Stop'
$windowsPowerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
if (-not (Test-Path -LiteralPath $windowsPowerShell)) { throw 'Windows PowerShell 5.1 is required.' }
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$OutputDirectory = (Resolve-Path -LiteralPath $OutputDirectory).Path
if ($Suites.Count -eq 0) { throw 'At least one suite is required.' }
$results = @()
foreach ($suite in $suites) {
    $suitePath = Join-Path $PSScriptRoot $suite
    $base = [IO.Path]::GetFileNameWithoutExtension($suite)
    $logPath = Join-Path $OutputDirectory ($base + '.log')
    $errorPath = Join-Path $OutputDirectory ($base + '.stderr.log')
    $resultPath = Join-Path $OutputDirectory ($base + '.json')
    if (Test-Path -LiteralPath $resultPath) { Remove-Item -LiteralPath $resultPath -Force }
    $arguments = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File')
    if ($suite -like '*.Tests.ps1') {
        $arguments += @((Join-Path $PSScriptRoot 'invoke_pester_suite.ps1'), '-TestsPath', $suitePath, '-ResultPath', $resultPath)
    } else {
        $arguments += $suitePath
        if ($suite -eq 'test_syntax.ps1') { $arguments += '-RequireAnalyzer' }
    }
    # Start-Process joins arguments on Windows; all paths are quoted as literal values.
    $quotedArguments = @($arguments | ForEach-Object { '"' + $_.Replace('"', '\"') + '"' })
    $started = Get-Date
    Write-Host "Running $suite..." -ForegroundColor Cyan
    try {
        if (-not (Test-Path -LiteralPath $suitePath)) { throw "Missing suite $suite" }
        $process = Start-Process -FilePath $windowsPowerShell -ArgumentList $quotedArguments -WindowStyle Hidden `
            -RedirectStandardOutput $logPath -RedirectStandardError $errorPath -PassThru
        $null = $process.Handle # Retain the handle so Windows PowerShell can read ExitCode after a fast child exits.
        $completed = $process.WaitForExit($SuiteTimeoutSeconds * 1000)
        if (-not $completed) { $process.Kill(); $process.WaitForExit(); throw "Suite timed out after $SuiteTimeoutSeconds seconds" }
        $process.Refresh()
        $exitCode = $process.ExitCode
        if ($null -eq $exitCode) { throw 'Child process did not report an exit code' }
        $record = [ordered]@{ Suite = $suite; ExitCode = $exitCode; Status = $(if ($exitCode -eq 0) { 'Passed' } else { 'Failed' }); DurationSeconds = [math]::Round(((Get-Date) - $started).TotalSeconds, 2) }
        if ($suite -like '*.Tests.ps1' -and (Test-Path -LiteralPath $resultPath)) {
            $named = Get-Content -LiteralPath $resultPath -Raw | ConvertFrom-Json
            $record.Total = $named.Total; $record.Passed = $named.Passed; $record.Failed = $named.Failed
            if ($named.Total -eq 0 -or $named.Failed -gt 0 -or $named.Skipped -gt 0 -or $named.Pending -gt 0) {
                $record.Status = 'Failed'; $record.ExitCode = 1
            }
        }
        elseif ($suite -like '*.Tests.ps1') { throw 'Pester child did not produce a result report' }
        if ($exitCode -ne 0) {
            Get-Content -LiteralPath $logPath -Tail 30 | Out-Host
            Get-Content -LiteralPath $errorPath -Tail 20 | Out-Host
        }
        $results += [pscustomobject]$record
        Write-Host "  $($record.Status) ($($record.DurationSeconds)s)"
    } catch {
        $results += [pscustomobject]@{ Suite = $suite; ExitCode = 1; Status = 'Failed'; Error = $_.Exception.Message }
        Write-Host "  Failed: $_" -ForegroundColor Red
    }
}
$summary = [ordered]@{
    Timestamp = (Get-Date).ToString('o'); HostVersion = [string]$PSVersionTable.PSVersion
    Suites = $results; FailedSuites = @($results | Where-Object Status -ne 'Passed').Count
    NamedTests = ($results | Where-Object { $_.PSObject.Properties['Total'] } | Measure-Object Total -Sum).Sum
}
$summary | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'summary.json') -Encoding UTF8
$results | Format-Table Suite, Status, Total, DurationSeconds -AutoSize | Out-Host
Write-Host "Reports: $OutputDirectory"
if ($summary.FailedSuites -gt 0) { exit 1 }
exit 0
