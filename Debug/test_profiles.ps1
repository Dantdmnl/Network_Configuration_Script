#Requires -Version 5.1
# Check profile writes, replacement prompts, and sanitized filename collisions.
$ErrorActionPreference = 'Stop'
$sourcePath = Join-Path $PSScriptRoot '..\Network_Configuration.ps1'
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($sourcePath, [ref]$null, [ref]$parseErrors)
if ($parseErrors) { throw 'Network script has parse errors.' }

foreach ($name in @('Get-SafeProfileFileName', 'Write-IPProfileFile', 'Save-StaticIPConfig')) {
    $definition = $ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
    }, $true) | Where-Object Name -eq $name | Select-Object -First 1
    if (-not $definition) { throw "Missing function: $name" }
    . ([scriptblock]::Create($definition.Extent.Text))
}

function Read-Host {
    $answer = $script:PromptAnswers[$script:PromptIndex]
    $script:PromptIndex++
    return $answer
}
function Read-YesNo { return $script:AllowReplace }
function Write-LogMessage {}

$testRoot = Join-Path $PSScriptRoot ("profile_test_{0}" -f [guid]::NewGuid().ToString('N'))
$profilesPath = $testRoot
$script:ScriptVersion = '2.9'

try {
    New-Item -ItemType Directory -Path $testRoot -Force | Out-Null
    $script:PromptAnswers = @('Lab Site', 'Lab', 'first')
    $script:PromptIndex = 0
    $script:AllowReplace = $false
    Save-StaticIPConfig -IPAddress '192.168.1.10' -SubnetMask '24' -PrimaryDNS '1.1.1.1'
    $profilePath = Join-Path $testRoot 'lab-lab-site.json'
    $first = Get-Content -LiteralPath $profilePath -Raw | ConvertFrom-Json
    if ($first.IPAddress -ne '192.168.1.10') { throw 'Initial profile save failed.' }

    $script:PromptAnswers = @('Lab Site', 'Lab', 'second')
    $script:PromptIndex = 0
    Save-StaticIPConfig -IPAddress '192.168.1.20' -SubnetMask '24' -PrimaryDNS '1.1.1.1'
    if ((Get-Content -LiteralPath $profilePath -Raw | ConvertFrom-Json).IPAddress -ne '192.168.1.10') {
        throw 'Declined replacement changed the profile.'
    }

    $script:AllowReplace = $true
    $script:PromptIndex = 0
    Save-StaticIPConfig -IPAddress '192.168.1.20' -SubnetMask '24' -PrimaryDNS '1.1.1.1'
    $updated = Get-Content -LiteralPath $profilePath -Raw | ConvertFrom-Json
    if ($updated.IPAddress -ne '192.168.1.20' -or $updated.CreatedAt -ne $first.CreatedAt) {
        throw 'Approved replacement failed or changed creation time.'
    }

    $script:PromptAnswers = @('Lab-Site', 'Lab', 'collision')
    $script:PromptIndex = 0
    Save-StaticIPConfig -IPAddress '192.168.1.30' -SubnetMask '24' -PrimaryDNS '1.1.1.1'
    if ((Get-Content -LiteralPath $profilePath -Raw | ConvertFrom-Json).IPAddress -ne '192.168.1.20') {
        throw 'Filename collision overwrote a different profile.'
    }

    try {
        Write-IPProfileFile -Path $profilePath -Json '{invalid json'
        throw 'Malformed JSON did not fail.'
    } catch {
        if ($_.Exception.Message -eq 'Malformed JSON did not fail.') { throw }
    }
    if ((Get-Content -LiteralPath $profilePath -Raw | ConvertFrom-Json).IPAddress -ne '192.168.1.20') {
        throw 'Failed profile write changed the existing file.'
    }
    if (@(Get-ChildItem -LiteralPath $testRoot -Force -Filter '.*.tmp').Count -ne 0) {
        throw 'Staged profile file was not cleaned up.'
    }
    Write-Host 'Profile tests passed.' -ForegroundColor Green
} finally {
    $resolvedRoot = [System.IO.Path]::GetFullPath($testRoot)
    $resolvedDebug = [System.IO.Path]::GetFullPath($PSScriptRoot).TrimEnd('\') + '\'
    if ($resolvedRoot.StartsWith($resolvedDebug, [System.StringComparison]::OrdinalIgnoreCase) -and (Test-Path -LiteralPath $resolvedRoot)) {
        Remove-Item -LiteralPath $resolvedRoot -Recurse -Force
    }
}
