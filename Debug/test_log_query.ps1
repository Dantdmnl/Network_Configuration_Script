#Requires -Version 5.1
# Query disposable JSON-line logs without starting the interactive script.
$ErrorActionPreference = 'Stop'
$sourcePath = Join-Path $PSScriptRoot '..\Network_Configuration.ps1'
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($sourcePath, [ref]$null, [ref]$parseErrors)
if ($parseErrors) { throw 'Network script has parse errors.' }
$definition = $ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
}, $true) | Where-Object Name -eq 'Get-NetworkLogEntries' | Select-Object -First 1
if (-not $definition) { throw 'Missing Get-NetworkLogEntries function.' }
. ([scriptblock]::Create($definition.Extent.Text))
$viewerDefinition = $ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
}, $true) | Where-Object Name -eq 'Show-LogViewer' | Select-Object -First 1
if (-not $viewerDefinition) { throw 'Missing Show-LogViewer function.' }
. ([scriptblock]::Create($viewerDefinition.Extent.Text))

$testRoot = Join-Path $PSScriptRoot ("log_query_test_{0}" -f [guid]::NewGuid().ToString('N'))
$logPath = Join-Path $testRoot 'network_config.log'
try {
    New-Item -ItemType Directory -Path $testRoot -Force | Out-Null
    [pscustomobject]@{ timestamp = '2026-09-13 10:00:00'; level = 'INFO'; message = 'Adapter[1] ready' } |
        ConvertTo-Json -Compress | Set-Content -LiteralPath $logPath -Encoding UTF8
    [pscustomobject]@{ timestamp = '2026-09-12 09:00:00'; level = 'ERROR'; message = 'Link LOST' } |
        ConvertTo-Json -Compress | Set-Content -LiteralPath "$logPath.1.log" -Encoding UTF8
    '{not valid JSON' | Add-Content -LiteralPath "$logPath.1.log" -Encoding UTF8
    [pscustomobject]@{ timestamp = 'invalid'; level = 'INFO'; message = 'Bad date' } |
        ConvertTo-Json -Compress | Add-Content -LiteralPath "$logPath.1.log" -Encoding UTF8
    [pscustomobject]@{ timestamp = '2026-09-10 08:00:00'; level = 'WARN'; message = 'Link recovered' } |
        ConvertTo-Json -Compress | Set-Content -LiteralPath "$logPath.2.log" -Encoding UTF8

    $script:LoggingConsent = $false
    $all = @(Get-NetworkLogEntries -LogPath $logPath -MaxArchives 2)
    if ($all.Count -ne 3 -or $all[0].Message -ne 'Adapter[1] ready' -or
        $all[1].Source -ne 'network_config.log.1.log') {
        throw 'Query did not combine, sort, or identify archived entries.'
    }
    $errors = @(Get-NetworkLogEntries -LogPath $logPath -MaxArchives 2 -Level ERROR)
    if ($errors.Count -ne 1 -or $errors[0].Message -ne 'Link LOST') { throw 'Severity filter failed.' }
    $dateMatches = @(Get-NetworkLogEntries -LogPath $logPath -MaxArchives 2 `
        -From ([datetime]'2026-09-12') -Until ([datetime]'2026-09-13'))
    if ($dateMatches.Count -ne 1 -or $dateMatches[0].Level -ne 'ERROR') { throw 'Date filter failed.' }
    $literalMatches = @(Get-NetworkLogEntries -LogPath $logPath -MaxArchives 2 -SearchText '[1]')
    if ($literalMatches.Count -ne 1 -or $literalMatches[0].Level -ne 'INFO') { throw 'Literal search failed.' }
    $caseMatches = @(Get-NetworkLogEntries -LogPath $logPath -MaxArchives 2 -SearchText 'link')
    if ($caseMatches.Count -ne 2) { throw 'Case-insensitive search failed.' }
    if (@(Get-NetworkLogEntries -LogPath $logPath -MaxArchives 2 -MaxResults 1).Count -ne 1) {
        throw 'Result limit failed.'
    }
    if (@(Get-NetworkLogEntries -LogPath (Join-Path $testRoot 'missing.log') -MaxArchives 2).Count -ne 0) {
        throw 'Missing logs did not return an empty result.'
    }

    function Clear-Host {}
    function Read-Host {
        if ($script:InputIndex -ge $script:ViewerInputs.Count) { throw 'Log viewer requested unexpected input.' }
        $answer = $script:ViewerInputs[$script:InputIndex]
        $script:InputIndex++
        return $answer
    }
    $script:LogFile = $logPath
    $script:MaxLogArchives = 2
    $script:ViewerInputs = @('2', 'ERROR', 'link', '2026-09-12', '2026-09-12', '10', 'b', 'b')
    $script:InputIndex = 0
    Show-LogViewer
    if ($script:InputIndex -ne $script:ViewerInputs.Count) { throw 'Log viewer did not complete the query flow.' }
    Write-Host 'Log query tests passed.' -ForegroundColor Green
} finally {
    $resolvedRoot = [System.IO.Path]::GetFullPath($testRoot)
    $resolvedDebug = [System.IO.Path]::GetFullPath($PSScriptRoot).TrimEnd('\') + '\'
    if ($resolvedRoot.StartsWith($resolvedDebug, [System.StringComparison]::OrdinalIgnoreCase) -and (Test-Path -LiteralPath $resolvedRoot)) {
        Remove-Item -LiteralPath $resolvedRoot -Recurse -Force
    }
}
