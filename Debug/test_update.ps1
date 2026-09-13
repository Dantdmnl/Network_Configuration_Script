#Requires -Version 5.1
# Test the updater with local files and a mocked download; no network or adapter changes.
$ErrorActionPreference = 'Stop'
$sourcePath = Join-Path $PSScriptRoot '..\Network_Configuration.ps1'
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($sourcePath, [ref]$null, [ref]$parseErrors)
if ($parseErrors) { throw 'Network script has parse errors.' }

foreach ($name in @('New-ManagedBackupPath', 'Install-ValidatedScriptUpdate', 'Update-NetworkScript')) {
    $definition = $ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
    }, $true) | Where-Object Name -eq $name | Select-Object -First 1
    if (-not $definition) { throw "Missing function: $name" }
    . ([scriptblock]::Create($definition.Extent.Text))
}

function Invoke-WebRequest { return [pscustomobject]@{ Content = $script:MockDownload } }
function Read-YesNo { return $true }
function Write-LogMessage {}
function Invoke-BackupRetention {}

$testRoot = Join-Path $PSScriptRoot ("update_test_{0}" -f [guid]::NewGuid().ToString('N'))
$script:BackupsPath = Join-Path $testRoot 'Backups'
$script:VersionPath = Join-Path $testRoot 'version.txt'
$script:ScriptVersion = '1.0'
$currentPath = Join-Path $testRoot 'Network_Configuration.ps1'
$oldContent = "# Version: 1.0`nWrite-Output 'old'`n"
$newContent = "# Version: 1.1`nWrite-Output 'new'`n"

try {
    New-Item -ItemType Directory -Path $script:BackupsPath -Force | Out-Null
    [System.IO.File]::WriteAllText($currentPath, $oldContent)
    Set-Content -LiteralPath $script:VersionPath -Value '1.0'
    $script:MockDownload = $newContent
    Update-NetworkScript -CurrentScriptPath $currentPath

    if ((Get-Content -LiteralPath $currentPath -Raw) -ne $newContent) { throw 'Valid update did not replace the script.' }
    if ((Get-Content -LiteralPath $script:VersionPath -Raw).Trim() -ne '1.1') { throw 'Version file did not update.' }
    $backups = @(Get-ChildItem -LiteralPath $script:BackupsPath -Filter 'script_update_*.ps1')
    if ($backups.Count -ne 1 -or (Get-Content -LiteralPath $backups[0].FullName -Raw) -ne $oldContent) {
        throw 'Updater did not retain the original script.'
    }

    $script:MockDownload = "# Version: 3.0`nfunction Broken {`n"
    Update-NetworkScript -CurrentScriptPath $currentPath
    if ((Get-Content -LiteralPath $currentPath -Raw) -ne $newContent) { throw 'Invalid update changed the script.' }

    $badBackup = Join-Path $testRoot 'missing\backup.ps1'
    try {
        Install-ValidatedScriptUpdate -CurrentScriptPath $currentPath -Content "# Version: 3.0`nWrite-Output 'bad'`n" -BackupPath $badBackup
        throw 'Missing backup directory did not fail.'
    } catch {
        if ($_.Exception.Message -eq 'Missing backup directory did not fail.') { throw }
    }
    if ((Get-Content -LiteralPath $currentPath -Raw) -ne $newContent) { throw 'Backup failure changed the script.' }
    if (@(Get-ChildItem -LiteralPath $testRoot -Filter '*.update' -Force).Count -ne 0) { throw 'Staged update was not cleaned up.' }

    Write-Host 'Updater tests passed.' -ForegroundColor Green
} finally {
    $resolvedRoot = [System.IO.Path]::GetFullPath($testRoot)
    $resolvedDebug = [System.IO.Path]::GetFullPath($PSScriptRoot).TrimEnd('\') + '\'
    if ($resolvedRoot.StartsWith($resolvedDebug, [System.StringComparison]::OrdinalIgnoreCase) -and (Test-Path -LiteralPath $resolvedRoot)) {
        Remove-Item -LiteralPath $resolvedRoot -Recurse -Force
    }
}
