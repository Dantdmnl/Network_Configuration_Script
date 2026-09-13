#Requires -Version 5.1
# Exercise archive creation and failure cleanup using only disposable local data.
$ErrorActionPreference = 'Stop'
$sourcePath = Join-Path $PSScriptRoot '..\Network_Configuration.ps1'
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($sourcePath, [ref]$null, [ref]$parseErrors)
if ($parseErrors) { throw 'Network script has parse errors.' }
$definition = $ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
}, $true) | Where-Object Name -eq 'Export-UserData' | Select-Object -First 1
if (-not $definition) { throw 'Missing Export-UserData function.' }
. ([scriptblock]::Create($definition.Extent.Text))
function Read-YesNo { return $false }

$testRoot = Join-Path $PSScriptRoot ("export_test_{0}" -f [guid]::NewGuid().ToString('N'))
$script:ProfilesPath = Join-Path $testRoot 'Profiles'
$script:BackupsPath = Join-Path $testRoot 'Backups'
$script:LogFile = Join-Path $testRoot 'network_config.log'
$script:ConfigPath = Join-Path $testRoot 'IPConfiguration.xml'
$script:ConsentPath = Join-Path $testRoot 'gdpr_consent.txt'
$script:InterfacePath = Join-Path $testRoot 'selected_interface.txt'
$script:MaxLogArchives = 5
$script:ScriptVersion = '2.9'

try {
    New-Item -ItemType Directory -Path $script:ProfilesPath -Force | Out-Null
    New-Item -ItemType Directory -Path $script:BackupsPath -Force | Out-Null
    Set-Content -LiteralPath $script:LogFile -Value 'sample log'
    Set-Content -LiteralPath "$script:LogFile.1.log" -Value 'older log'
    Set-Content -LiteralPath (Join-Path $script:ProfilesPath 'site.json') -Value '{}'
    Set-Content -LiteralPath (Join-Path $script:BackupsPath 'snapshot.json') -Value '{}'

    Export-UserData -ExportDirectory $testRoot -TemporaryRoot $testRoot
    $archives = @(Get-ChildItem -LiteralPath $testRoot -Filter 'NetworkScript_DataExport_*.zip')
    if ($archives.Count -ne 1) { throw 'Export archive was not created.' }
    $expanded = Join-Path $testRoot 'expanded'
    Expand-Archive -LiteralPath $archives[0].FullName -DestinationPath $expanded -ErrorAction Stop
    foreach ($path in @('logs\network_config.log', 'logs\network_config.1.log', 'profiles\site.json', 'backups\snapshot.json')) {
        if (-not (Test-Path -LiteralPath (Join-Path $expanded $path))) { throw "Export omitted $path" }
    }
    if (@(Get-ChildItem -LiteralPath $testRoot -Directory -Filter 'NetworkScript_Export_*').Count -ne 0) {
        throw 'Temporary export data remained after success.'
    }

    function Compress-Archive { $script:CompressionWasAttempted = $true; throw 'Simulated ZIP failure.' }
    $script:CompressionWasAttempted = $false
    Export-UserData -ExportDirectory $testRoot -TemporaryRoot $testRoot
    if (-not $script:CompressionWasAttempted) { throw 'Failure path was not exercised.' }
    if (@(Get-ChildItem -LiteralPath $testRoot -Directory -Filter 'NetworkScript_Export_*').Count -ne 0) {
        throw 'Temporary export data remained after failure.'
    }
    if (@(Get-ChildItem -LiteralPath $testRoot -Filter 'NetworkScript_DataExport_*.zip').Count -ne 1) {
        throw 'Failed export left an extra archive.'
    }
    Write-Host 'Export tests passed.' -ForegroundColor Green
} finally {
    $resolvedRoot = [System.IO.Path]::GetFullPath($testRoot)
    $resolvedDebug = [System.IO.Path]::GetFullPath($PSScriptRoot).TrimEnd('\') + '\'
    if ($resolvedRoot.StartsWith($resolvedDebug, [System.StringComparison]::OrdinalIgnoreCase) -and (Test-Path -LiteralPath $resolvedRoot)) {
        Remove-Item -LiteralPath $resolvedRoot -Recurse -Force
    }
}
