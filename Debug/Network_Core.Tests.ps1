#Requires -Version 5.1
param([string]$TestLibraryPath)
# Load only function bodies, preserving their source locations for Pester coverage.
$sourcePath = Join-Path $PSScriptRoot '..\Network_Configuration.ps1'
$parseErrors = $null
$sourceAst = [System.Management.Automation.Language.Parser]::ParseFile($sourcePath, [ref]$null, [ref]$parseErrors)
if ($parseErrors) { throw 'Application source does not parse.' }
$functionNames = @('Read-YesNo', 'Get-ValidatedInput', 'Read-IPConfigurationSettings', 'Test-ValidIPAddress',
    'Test-ValidSubnetMask', 'Test-ValidDNSServer', 'Get-PrefixLength', 'ConvertTo-IPv4UInt32', 'ConvertFrom-IPv4UInt32',
    'Get-IPv4NetworkDetails', 'Get-SuggestedGateway', 'Remove-OldFiles', 'Remove-LocalItemSafe', 'New-ManagedBackupPath',
    'Write-IPProfileFile', 'Get-IPProfiles', 'Get-SavedIPConfig', 'Save-SelectedInterface', 'Get-SavedInterface',
    'Get-NetworkLogEntries', 'Hide-IPAddress', 'Get-GDPRConsent', 'Get-MACVendor', 'Invoke-DNSLookup',
    'Invoke-Traceroute', 'Invoke-PortCheck', 'Test-TcpPort', 'Install-ValidatedScriptUpdate', 'Get-SafeProfileFileName',
    'Write-MenuOption', 'Write-MenuSection', 'Show-MainMenu', 'Get-InterfaceStatus', 'Start-LiveInterfaceMonitor', 'Remove-AllLogs', 'Update-NetworkScript')
if ($TestLibraryPath) { . $TestLibraryPath }
else { foreach ($name in $functionNames) {
    $definition = $sourceAst.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) |
        Where-Object Name -eq $name | Select-Object -First 1
    if (-not $definition) { throw "Missing function $name" }
    Set-Item -Path ('Function:script:' + $name) -Value $definition.Body.GetScriptBlock()
} }
function Write-LogMessage { param($Message, $Level) }
function Resolve-DnsName { [CmdletBinding()]param($Name, $Type, $Server) throw 'Unmocked DNS boundary' }
function tracert.exe { param([Parameter(ValueFromRemainingArguments)]$Arguments) }
function Get-TestReply {
    if ($script:replyIndex -ge $script:replies.Count) { throw 'Unexpected prompt: fixture exhausted' }
    $reply = $script:replies[$script:replyIndex]; $script:replyIndex++; return $reply
}
$script:fixtureParent = Join-Path $PSScriptRoot 'test-results'
New-Item -ItemType Directory -Path $script:fixtureParent -Force | Out-Null

Describe 'Core helpers and user flows' {
    BeforeEach {
        $script:caseRoot = Join-Path $script:fixtureParent ('core_' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $script:caseRoot | Out-Null
        Mock Write-Host { }
        Mock Clear-Host { }
        Mock Start-Sleep { }
        Mock Read-Host { Get-TestReply }
        $script:replies = @(); $script:replyIndex = 0
        $script:LoggingConsent = $false; $script:MACVendorCache = @{}
    }
    AfterEach {
        $resolved = [IO.Path]::GetFullPath($script:caseRoot)
        $allowed = [IO.Path]::GetFullPath($script:fixtureParent).TrimEnd('\') + '\'
        if (-not $resolved.StartsWith($allowed, [StringComparison]::OrdinalIgnoreCase)) { throw 'Fixture cleanup outside test results' }
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
    Context 'Confirmation and input cancellation' {
        $confirmationCases = @(
            @{ Text = 'y'; Expected = $true }, @{ Text = ' YES '; Expected = $true },
            @{ Text = 'n'; Expected = $false }, @{ Text = ' No '; Expected = $false }
        )
        It 'interprets confirmation <Text>' -TestCases $confirmationCases {
            param($Text, $Expected)
            $script:replies = @($Text)
            (Read-YesNo -Prompt 'Apply?') | Should Be $Expected
            $script:replyIndex | Should Be 1
        }
        It 'uses both defaults only after blank input' {
            $script:replies = @('', '')
            (Read-YesNo -Prompt 'Apply?' -Default $true) | Should Be $true
            (Read-YesNo -Prompt 'Delete?' -Default $false) | Should Be $false
        }
        It 'reprompts invalid confirmation without treating it as approval' {
            $script:replies = @('perhaps', 'n')
            (Read-YesNo -Prompt 'Apply?') | Should Be $false
            $script:replyIndex | Should Be 2
        }
        It 'bounds invalid input retries' {
            $script:replies = @('bad', 'bad', 'bad')
            { Get-ValidatedInput -Prompt 'IP' -ValidationFunction { param($Value) Test-ValidIPAddress $Value } -MaxAttempts 3 } | Should Throw
            $script:replyIndex | Should Be 3
        }
        It 'returns a validated default and trims user input' {
            $script:replies = @('', ' 192.168.1.25 ')
            (Get-ValidatedInput -Prompt 'IP' -DefaultValue '192.168.1.25' -ValidationFunction { param($Value) Test-ValidIPAddress $Value }) | Should Be '192.168.1.25'
            (Get-ValidatedInput -Prompt 'IP' -ValidationFunction { param($Value) Test-ValidIPAddress $Value }) | Should Be '192.168.1.25'
        }
        It 'does not prompt without an adapter' {
            (Read-IPConfigurationSettings -InterfaceName '') | Should BeNullOrEmpty
            $script:replyIndex | Should Be 0
        }
        It 'captures default gateway and DNS settings' {
            $script:replies = @('192.168.1.25', '24', '', '', '', 'y')
            $settings = Read-IPConfigurationSettings -InterfaceName Ethernet
            $settings.Gateway | Should Be '192.168.1.1'
            $settings.PrimaryDNS | Should Be '1.1.1.1'
            $settings.SecondaryDNS | Should Be '1.0.0.1'
        }
        It 'captures gateway-free and secondary-DNS-free settings' {
            $script:replies = @('192.168.1.25', '24', 'none', '9.9.9.9', 'none', 'y')
            $settings = Read-IPConfigurationSettings -InterfaceName Ethernet
            $settings.Gateway | Should BeNullOrEmpty
            $settings.SecondaryDNS | Should BeNullOrEmpty
            $settings.PrimaryDNS | Should Be '9.9.9.9'
        }
        It 'uses the alternate gateway inside a narrow subnet' {
            $script:replies = @('192.168.1.200', '25', 'last', '', '', 'y')
            (Read-IPConfigurationSettings -InterfaceName Ethernet).Gateway | Should Be '192.168.1.254'
        }
        It 'returns no settings when review is declined' {
            $script:replies = @('192.168.1.25', '24', '', '', '', 'n')
            (Read-IPConfigurationSettings -InterfaceName Ethernet) | Should BeNullOrEmpty
        }
        It 'stops after invalid address retries without prompting for later fields' {
            $script:replies = @('bad', 'bad', 'bad')
            (Read-IPConfigurationSettings -InterfaceName Ethernet) | Should BeNullOrEmpty
            $script:replyIndex | Should Be 3
        }
    }
    Context 'Independent address arithmetic and boundaries' {
        $badAddresses = @('192.168.1', '192.168.001.1', '256.1.1.1', '0.1.2.3', '127.0.0.1', '224.0.0.1', '255.255.255.255', '2001:db8::1', '1e2.1.1.1', '192.168.1.1;exit')
        It 'rejects malformed or reserved address <Address>' -TestCases @($badAddresses | ForEach-Object { @{ Address = $_ } }) {
            param($Address) (Test-ValidIPAddress $Address) | Should Be $false
        }
        It 'round-trips 64 seeded IPv4 values and bounds each subnet independently' {
            $random = New-Object System.Random(300)
            for ($i = 0; $i -lt 64; $i++) {
                $octets = @(10, $random.Next(256), $random.Next(256), $random.Next(256))
                $ip = $octets -join '.'
                $number = [uint64]$octets[0] * 16777216 + [uint64]$octets[1] * 65536 + [uint64]$octets[2] * 256 + [uint64]$octets[3]
                (ConvertTo-IPv4UInt32 $ip) | Should Be $number
                (ConvertFrom-IPv4UInt32 $number) | Should Be $ip
                $prefix = $random.Next(8, 33)
                $block = [uint64][math]::Pow(2, (32 - $prefix))
                $network = [uint64]([math]::Floor($number / $block) * $block)
                $details = Get-IPv4NetworkDetails -IPAddress $ip -PrefixLength $prefix
                $details.NetworkValue | Should Be $network
                $details.BroadcastValue | Should Be ($network + $block - 1)
                foreach ($gateway in @(Get-SuggestedGateway -IPAddress $ip -PrefixLength $prefix)) {
                    $gw = ConvertTo-IPv4UInt32 $gateway
                    ($gw -ge $network -and $gw -le ($network + $block - 1) -and $gateway -ne $ip) | Should Be $true
                }
            }
        }
        It 'accepts every supported dotted mask and rejects holes in its bits' {
            for ($prefix = 8; $prefix -le 32; $prefix++) {
                $bits = ('1' * $prefix).PadRight(32, '0')
                $mask = @(0..3 | ForEach-Object { [Convert]::ToInt32($bits.Substring($_ * 8, 8), 2) }) -join '.'
                (Get-PrefixLength $mask) | Should Be $prefix
                (Get-PrefixLength ("/$prefix")) | Should Be $prefix
            }
            foreach ($mask in @('255.0.255.0', '255.255.255.1', '7', '33', '-1')) { { Get-PrefixLength $mask } | Should Throw }
        }
        It 'handles zero and maximum unsigned IPv4 boundaries' {
            (ConvertFrom-IPv4UInt32 0) | Should Be '0.0.0.0'
            (ConvertFrom-IPv4UInt32 4294967295) | Should Be '255.255.255.255'
        }
    }
    Context 'Profiles and saved adapter state' {
        BeforeEach {
            $profilesPath = Join-Path $script:caseRoot 'profiles'; New-Item -ItemType Directory -Path $profilesPath -Force | Out-Null
            $configPath = Join-Path $script:caseRoot 'legacy.xml'
            $interfacePath = Join-Path $script:caseRoot 'adapter.txt'
        }
        It 'ignores corrupt profiles and sorts valid profiles by group and name' {
            @{ Name = 'Z'; Environment = 'work'; IPAddress = '10.0.0.2' } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $profilesPath 'z.json')
            @{ Name = 'A'; Environment = 'home'; IPAddress = '10.0.0.3' } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $profilesPath 'a.json')
            '{broken' | Set-Content -LiteralPath (Join-Path $profilesPath 'bad.json')
            $profiles = @(Get-IPProfiles)
            $profiles.Count | Should Be 2
            $profiles[0].Name | Should Be 'A'
        }
        It 'keeps the existing profile on malformed replacement and removes temporary files' {
            $path = Join-Path $profilesPath 'profile.json'
            Write-IPProfileFile -Path $path -Json '{"Name":"original"}'
            { Write-IPProfileFile -Path $path -Json '{invalid' } | Should Throw
            (Get-Content -LiteralPath $path -Raw | ConvertFrom-Json).Name | Should Be 'original'
            @(Get-ChildItem -LiteralPath $profilesPath -Force | Where-Object Name -like '.*').Count | Should Be 0
        }
        It 'loads legacy XML only when no modern profiles exist' {
            @{ IPAddress = '192.168.1.25'; SubnetMask = '24'; PrimaryDNS = '1.1.1.1' } | Export-Clixml -LiteralPath $configPath
            (Get-SavedIPConfig).IPAddress | Should Be '192.168.1.25'
            @{ Name = 'modern'; IPAddress = '10.0.0.2'; Environment = 'lab' } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $profilesPath 'modern.json')
            $script:replies = @('1')
            (Get-SavedIPConfig).Name | Should Be 'modern'
        }
        It 'preserves a profile when deletion is declined' {
            $path = Join-Path $profilesPath 'site.json'; '{"Name":"site"}' | Set-Content -LiteralPath $path
            $script:replies = @('d', '1', 'n')
            $null = Get-SavedIPConfig
            (Test-Path -LiteralPath $path) | Should Be $true
        }
        It 'deletes only the selected profile after confirmation' {
            $path = Join-Path $profilesPath 'site.json'; '{"Name":"site"}' | Set-Content -LiteralPath $path
            $script:replies = @('d', '1', 'y')
            $null = Get-SavedIPConfig
            (Test-Path -LiteralPath $path) | Should Be $false
        }
        It 'rejects overflow and out-of-range profile selections without deleting anything' {
            '{"Name":"site"}' | Set-Content -LiteralPath (Join-Path $profilesPath 'site.json')
            foreach ($choice in @('0', '-1', '2147483648', '999999999999999999999')) {
                $script:replies = @($choice); $script:replyIndex = 0
                (Get-SavedIPConfig) | Should BeNullOrEmpty
            }
            @(Get-ChildItem -LiteralPath $profilesPath).Count | Should Be 1
        }
        It 'persists and reloads an adapter name containing spaces' {
            Save-SelectedInterface -InterfaceName 'Lab Ethernet'
            (Get-SavedInterface) | Should Be 'Lab Ethernet'
        }
    }
    Context 'Retention, backup naming, and log queries' {
        It 'retains newest files, removes expired files, and leaves unrelated files intact' {
            $root = Join-Path $script:caseRoot 'retention'; New-Item -ItemType Directory -Path $root | Out-Null
            foreach ($i in 1..5) {
                $path = Join-Path $root ("backup_$i.json"); '{}' | Set-Content -LiteralPath $path
                (Get-Item -LiteralPath $path).LastWriteTime = (Get-Date).AddDays(-$i)
            }
            $expired = Join-Path $root 'backup_old.json'; '{}' | Set-Content -LiteralPath $expired
            (Get-Item -LiteralPath $expired).LastWriteTime = (Get-Date).AddDays(-60)
            'keep' | Set-Content -LiteralPath (Join-Path $root 'unrelated.txt')
            (Remove-OldFiles -Path $root -Filter 'backup_*.json' -KeepNewest 2 -MaxAgeDays 30) | Should Be 4
            @(Get-ChildItem -LiteralPath $root -Filter 'backup_*.json').Count | Should Be 2
            (Test-Path -LiteralPath (Join-Path $root 'unrelated.txt')) | Should Be $true
        }
        It 'uses unique managed backup names even for rapid consecutive requests' {
            $script:BackupsPath = Join-Path $script:caseRoot 'backups'
            $names = @(1..100 | ForEach-Object { New-ManagedBackupPath -BaseName network -Extension json })
            @($names | Select-Object -Unique).Count | Should Be 100
        }
        It 'rejects reversed or identical log date ranges' {
            { Get-NetworkLogEntries -LogPath 'missing' -From ([datetime]'2026-01-02') -Until ([datetime]'2026-01-01') } | Should Throw
            { Get-NetworkLogEntries -LogPath 'missing' -From ([datetime]'2026-01-01') -Until ([datetime]'2026-01-01') } | Should Throw
        }
    }
    Context 'Privacy consent and vendor lookup' {
        It 'does not interpret a string false as logging consent' {
            $script:ConsentPath = Join-Path $script:caseRoot 'consent.json'
            '{"LoggingConsent":"false","PseudonymizeData":false}' | Set-Content -LiteralPath $script:ConsentPath
            $script:replies = @('n')
            Get-GDPRConsent
            ($script:LoggingConsent -is [bool] -and -not $script:LoggingConsent) | Should Be $true
        }
        It 'asks for consent again after corrupt consent data' {
            $script:ConsentPath = Join-Path $script:caseRoot 'consent.json'
            '{broken' | Set-Content -LiteralPath $script:ConsentPath
            $script:replies = @('n')
            Get-GDPRConsent
            $script:LoggingConsent | Should Be $false
            $script:replyIndex | Should Be 1
        }
        It 'rejects malformed MAC addresses without calling an external service' {
            foreach ($mac in @(' ', 'not-a-mac', '00112233445566', 'GG1122334455')) { (Get-MACVendor $mac) | Should Be 'Invalid MAC' }
        }
        It 'normalizes MAC formats and uses a vendor-prefix cache' {
            $script:MACVendorCache = @{ '001122' = 'Synthetic Vendor' }
            foreach ($mac in @('00:11:22:33:44:55', '00-11-22-33-44-66', '0011.2233.4477', '001122334488')) { (Get-MACVendor $mac) | Should Be 'Synthetic Vendor' }
        }
        It 'deletes only logs and consent after approval, preserving profiles and backups' {
            $script:AppDataDir = Join-Path $script:caseRoot 'privacy'; New-Item -ItemType Directory -Path $script:AppDataDir | Out-Null
            $script:LogFileName = 'network_config.log'; $script:LogFile = Join-Path $script:AppDataDir $script:LogFileName
            $script:ConsentPath = Join-Path $script:AppDataDir 'consent.json'
            $profile = Join-Path $script:AppDataDir 'profile.json'; $backup = Join-Path $script:AppDataDir 'backup.json'
            foreach ($path in @($script:LogFile, ($script:LogFile + '.1.log'), $script:ConsentPath, $profile, $backup)) { '{}' | Set-Content -LiteralPath $path }
            $script:replies = @('y'); $script:LoggingConsent = $true
            Remove-AllLogs
            (Test-Path -LiteralPath $script:LogFile) | Should Be $false
            (Test-Path -LiteralPath $script:ConsentPath) | Should Be $false
            (Test-Path -LiteralPath $profile) | Should Be $true
            (Test-Path -LiteralPath $backup) | Should Be $true
            $script:LoggingConsent | Should Be $false
        }
    }
    Context 'Diagnostic boundaries without real traffic' {
        It 'cancels blank DNS lookup without performing a query' {
            Mock Resolve-DnsName { throw 'Unexpected DNS query' }
            $script:replies = @('')
            $null = Invoke-DNSLookup
            Assert-MockCalled Resolve-DnsName -Times 0 -Exactly -Scope It
        }
        It 'validates DNS server input before querying' {
            Mock Resolve-DnsName { throw 'Unexpected DNS query' }
            $script:replies = @('example.test', 'A', 'not-an-ip')
            $null = Invoke-DNSLookup
            Assert-MockCalled Resolve-DnsName -Times 0 -Exactly -Scope It
        }
        It 'uses the requested DNS server and record type' {
            Mock Resolve-DnsName { return $null }
            $script:replies = @('example.test', 'AAAA', '9.9.9.9')
            $null = Invoke-DNSLookup
            Assert-MockCalled Resolve-DnsName -Times 1 -Exactly -Scope It -ParameterFilter { $Name -eq 'example.test' -and $Type -eq 'AAAA' -and $Server -eq '9.9.9.9' }
        }
        It 'falls back to A for unsupported DNS record types and reports query failure' {
            Mock Resolve-DnsName { throw 'Synthetic DNS failure' }
            $script:replies = @('example.test', 'INVALID', '')
            $null = Invoke-DNSLookup
            Assert-MockCalled Resolve-DnsName -Times 1 -Exactly -Scope It -ParameterFilter { $Type -eq 'A' }
            Assert-MockCalled Write-Host -Times 1 -Exactly -Scope It -ParameterFilter { $Object -like 'DNS lookup failed:*' }
        }
        It 'deduplicates valid TCP ports and skips invalid tokens' {
            Mock Test-TcpPort { return $false }
            $script:replies = @('example.test', '443,443,0,65536,bad,22')
            $null = Invoke-PortCheck
            Assert-MockCalled Test-TcpPort -Times 2 -Exactly -Scope It
            Assert-MockCalled Test-TcpPort -Times 0 -Exactly -Scope It -ParameterFilter { $Port -notin @(22, 443) }
        }
        It 'does not execute traceroute after blank target input' {
            Mock tracert.exe { throw 'Unexpected native traceroute' }
            $script:replies = @('')
            $null = Invoke-Traceroute
            Assert-MockCalled tracert.exe -Times 0 -Exactly -Scope It
        }
        It 'passes a target as a separate native argument with bounded hop input' {
            Mock tracert.exe { }
            $script:replies = @('example.test', '999', 'n')
            $null = Invoke-Traceroute
            Assert-MockCalled tracert.exe -Times 1 -Exactly -Scope It
        }
    }
    Context 'TCP client resource cleanup' {
        $socketCases = @(
            @{ Mode = 'Connected'; Expected = $true }, @{ Mode = 'Refused'; Expected = $false },
            @{ Mode = 'Timeout'; Expected = $false }, @{ Mode = 'Fault'; Expected = $false }
        )
        It 'disposes its TCP client after <Mode>' -TestCases $socketCases {
            param($Mode, $Expected)
            $socket = [pscustomobject]@{ Connected = ($Mode -eq 'Connected'); Mode = $Mode; Closed = $false; Disposed = $false }
            $socket | Add-Member ScriptMethod ConnectAsync {
                param($Computer, $Port)
                if ($this.Mode -eq 'Fault') { throw 'Synthetic connect failure' }
                $task = [pscustomobject]@{ Mode = $this.Mode }
                $task | Add-Member ScriptMethod Wait { param($Timeout) return ($this.Mode -ne 'Timeout') }
                return $task
            }
            $socket | Add-Member ScriptMethod Close { $this.Closed = $true }
            $socket | Add-Member ScriptMethod Dispose { $this.Disposed = $true }
            $global:NetworkTestSocket = $socket
            Mock New-Object { return $global:NetworkTestSocket } -ParameterFilter { $TypeName -eq 'System.Net.Sockets.TcpClient' }
            (Test-TcpPort -ComputerName example.test -Port 443) | Should Be $Expected
            $socket.Closed | Should Be $true
            $socket.Disposed | Should Be $true
            Remove-Variable NetworkTestSocket -Scope Global
        }
    }
    Context 'Updates and console rendering' {
        It 'does not update after a rejected upgrade' {
            $path = Join-Path $script:caseRoot 'Network.ps1'; $old = "# Version: 1.0`nWrite-Output 'old'"
            [IO.File]::WriteAllText($path, $old)
            $script:VersionPath = Join-Path $script:caseRoot 'version.txt'; '1.0' | Set-Content -LiteralPath $script:VersionPath
            $script:ScriptVersion = '1.0'
            Mock Invoke-WebRequest { [pscustomobject]@{ Content = "# Version: 2.0`nWrite-Output 'new'" } }
            Mock Install-ValidatedScriptUpdate { throw 'Unexpected replacement' }
            $script:replies = @('n')
            Update-NetworkScript -CurrentScriptPath $path
            ([IO.File]::ReadAllText($path)) | Should Be $old
            Assert-MockCalled Install-ValidatedScriptUpdate -Times 0 -Exactly -Scope It
        }
        $badDownloads = @(
            @{ Content = ''; Scenario = 'empty' }, @{ Content = 'Write-Output 1'; Scenario = 'missing header' },
            @{ Content = "# Version: nope`nWrite-Output 1"; Scenario = 'invalid version' },
            @{ Content = "# Version: 2.0`nfunction Broken {"; Scenario = 'invalid syntax' },
            @{ Content = "# Version: 1.0`nWrite-Output 1"; Scenario = 'same version' },
            @{ Content = "# Version: 0.5`nWrite-Output 1"; Scenario = 'older version' }
        )
        It 'keeps the script for an <Scenario> download' -TestCases $badDownloads {
            param($Content, $Scenario)
            $path = Join-Path $script:caseRoot 'Network.ps1'; $old = "# Version: 1.0`nWrite-Output 'old'"
            [IO.File]::WriteAllText($path, $old)
            $script:VersionPath = Join-Path $script:caseRoot 'version.txt'; '1.0' | Set-Content -LiteralPath $script:VersionPath
            $script:ScriptVersion = '1.0'; $script:download = $Content
            Mock Invoke-WebRequest { [pscustomobject]@{ Content = $script:download } }
            Mock Install-ValidatedScriptUpdate { throw 'Unexpected replacement' }
            Update-NetworkScript -CurrentScriptPath $path
            ([IO.File]::ReadAllText($path)) | Should Be $old
            Assert-MockCalled Install-ValidatedScriptUpdate -Times 0 -Exactly -Scope It
        }
        It 'renders all menu sections and a no-adapter hint without network reads' {
            Mock Get-InterfaceStatus { return 'No adapter' }
            $script:ScriptVersion = '3.0'
            Show-MainMenu -InterfaceName ''
            Assert-MockCalled Write-Host -Times 1 -Exactly -Scope It -ParameterFilter { ([string]$Object).Contains('Select an adapter with [6]') }
            Assert-MockCalled Write-Host -Times 1 -Exactly -Scope It -ParameterFilter { $Object -eq 'Logging off' }
        }
        It 'returns from monitoring when no adapter is selected' {
            $script:replies = @('')
            Start-LiveInterfaceMonitor -InterfaceName ''
            $script:replyIndex | Should Be 1
        }
    }
}
