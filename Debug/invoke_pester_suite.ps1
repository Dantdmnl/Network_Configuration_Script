#Requires -Version 5.1
param(
    [Parameter(Mandatory=$true)][string]$TestsPath,
    [Parameter(Mandatory=$true)][string]$ResultPath
)
$ErrorActionPreference = 'Stop'
try {
    $module = Get-Module -ListAvailable Pester | Where-Object { $_.Version -ge [version]'3.4' -and $_.Version.Major -lt 5 } |
        Sort-Object Version -Descending | Select-Object -First 1
    if (-not $module) { throw 'Pester 3.4 or 4.x is required; no tests were run.' }
    Import-Module $module.Path -Force
    $sourcePath = Join-Path $PSScriptRoot '..\Network_Configuration.ps1'
    $sourceErrors = $null
    $sourceAst = [System.Management.Automation.Language.Parser]::ParseFile($sourcePath, [ref]$null, [ref]$sourceErrors)
    if ($sourceErrors) { throw 'Application source does not parse.' }
    # Compile a physical function-only library. Dynamic AST body imports retain a
    # filename but do not reliably trigger Pester's file breakpoints (false 0% coverage).
    # Preserve original line numbers and omit every startup/menu-loop statement.
    $sourceLines = [regex]::Split([IO.File]::ReadAllText($sourcePath), '\r?\n')
    $libraryLines = New-Object 'string[]' $sourceLines.Count
    foreach ($definition in @($sourceAst.EndBlock.Statements | Where-Object { $_ -is [System.Management.Automation.Language.FunctionDefinitionAst] })) {
        for ($line = $definition.Extent.StartLineNumber; $line -le $definition.Extent.EndLineNumber; $line++) {
            $libraryLines[$line - 1] = $sourceLines[$line - 1]
        }
    }
    $libraryPath = [IO.Path]::ChangeExtension($ResultPath, '.library.ps1')
    [IO.File]::WriteAllLines($libraryPath, $libraryLines, [Text.UTF8Encoding]::new($false))
    $libraryPath = (Resolve-Path -LiteralPath $libraryPath).Path
    $pesterScript = @{ Path = (Resolve-Path -LiteralPath $TestsPath).Path; Parameters = @{ TestLibraryPath = $libraryPath } }
    $result = Invoke-Pester -Script $pesterScript -PassThru -Quiet -Strict -CodeCoverage $libraryPath
    $summary = [ordered]@{
        PesterVersion = [string]$module.Version
        Total = $result.TotalCount; Passed = $result.PassedCount; Failed = $result.FailedCount
        Skipped = $result.SkippedCount; Pending = $result.PendingCount
        Tests = @($result.TestResult | Select-Object Describe, Context, Name, Result, FailureMessage)
        Coverage = $result.CodeCoverage
        CoverageSource = (Resolve-Path -LiteralPath $sourcePath).Path
    }
    $summary | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $ResultPath -Encoding UTF8
    # Pester 3's NUnit writer queries Win32_OperatingSystem via CIM. Generate JUnit
    # directly so reporting requires no machine/WMI access and escapes test text safely.
    $xmlSettings = New-Object System.Xml.XmlWriterSettings
    $xmlSettings.Indent = $true
    $writer = [System.Xml.XmlWriter]::Create([IO.Path]::ChangeExtension($ResultPath, '.xml'), $xmlSettings)
    try {
        $writer.WriteStartDocument(); $writer.WriteStartElement('testsuite')
        $writer.WriteAttributeString('name', (Split-Path $TestsPath -Leaf))
        $writer.WriteAttributeString('tests', [string]$summary.Total)
        $writer.WriteAttributeString('failures', [string]$summary.Failed)
        foreach ($test in $summary.Tests) {
            $writer.WriteStartElement('testcase'); $writer.WriteAttributeString('name', $test.Name)
            $writer.WriteAttributeString('classname', ($test.Describe + '.' + $test.Context))
            if ($test.Result -ne 'Passed') {
                $writer.WriteStartElement('failure'); $writer.WriteAttributeString('message', [string]$test.FailureMessage)
                $writer.WriteEndElement()
            }
            $writer.WriteEndElement()
        }
        $writer.WriteEndElement(); $writer.WriteEndDocument()
    } finally { $writer.Dispose() }
    Write-Host ("{0}: {1} tests, {2} passed, {3} failed" -f (Split-Path $TestsPath -Leaf), $summary.Total, $summary.Passed, $summary.Failed)
    foreach ($failure in @($summary.Tests | Where-Object Result -ne 'Passed')) { Write-Host ("  {0}: {1}" -f $failure.Name, $failure.FailureMessage) -ForegroundColor Red }
    if ($summary.Total -eq 0 -or $summary.Failed -gt 0 -or $summary.Skipped -gt 0 -or $summary.Pending -gt 0) { exit 1 }
    exit 0
} catch {
    @{ Total = 0; Passed = 0; Failed = 1; Error = $_.Exception.Message } | ConvertTo-Json | Set-Content -LiteralPath $ResultPath -Encoding UTF8
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1
}
