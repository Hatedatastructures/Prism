[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../../..')).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Failures = [System.Collections.Generic.List[string]]::new()

function Add-Failure {
    param([string]$Message)

    [void]$Failures.Add($Message)
}

function ConvertFrom-YamlScalar {
    param([AllowNull()][string]$Value)

    if ($null -eq $Value) {
        return $null
    }

    $Text = $Value.Trim()
    if ($Text -match '^([^\s]+)\s+#') {
        $Text = $Matches[1]
    }
    if ($Text.Length -ge 2 -and
        (($Text.StartsWith('"') -and $Text.EndsWith('"')) -or
         ($Text.StartsWith("'") -and $Text.EndsWith("'")))) {
        return $Text.Substring(1, $Text.Length - 2)
    }
    if ($Text -eq 'true') {
        return $true
    }
    if ($Text -eq 'false') {
        return $false
    }
    if ($Text -eq 'null' -or $Text -eq '~') {
        return $null
    }
    return $Text
}

function Get-Indent {
    param([string]$Line)

    return ($Line.Length - $Line.TrimStart().Length)
}

function Get-SectionRange {
    param(
        [string[]]$Lines,
        [string]$Section
    )

    $HeaderPattern = '^{0}:\s*$' -f [regex]::Escape($Section)
    $Start = -1
    for ($Index = 0; $Index -lt $Lines.Count; $Index++) {
        if ($Lines[$Index] -match $HeaderPattern) {
            $Start = $Index + 1
            break
        }
    }
    if ($Start -lt 0) {
        throw "YAML section '$Section' was not found."
    }

    $End = $Lines.Count
    for ($Index = $Start; $Index -lt $Lines.Count; $Index++) {
        if ($Lines[$Index] -match '^\S' -and $Lines[$Index] -notmatch '^\s*#') {
            $End = $Index
            break
        }
    }
    return [pscustomobject]@{ Start = $Start; End = $End }
}

function Get-ProxyRecords {
    param([string[]]$Lines)

    $Range = Get-SectionRange -Lines $Lines -Section 'proxies'
    $Records = [System.Collections.Generic.List[object]]::new()
    $Current = $null

    for ($Index = $Range.Start; $Index -lt $Range.End; $Index++) {
        $Line = $Lines[$Index]
        if ($Line -match '^\s{2}-\s+name:\s*(?<name>"[^"]*"|\S+)(?:\s+#\s*status:\s*(?<status>.*))?\s*$') {
            if ($null -ne $Current) {
                [void]$Records.Add($Current)
            }
            $Current = [ordered]@{
                name = ConvertFrom-YamlScalar $Matches['name']
            }
            if ($Matches.ContainsKey('status') -and $Matches['status']) {
                $Current.status = ($Matches['status'] -split ';')[0].Trim()
            }
            continue
        }
        if ($null -eq $Current) {
            continue
        }
        if ($Line -match '^\s{4}(?<key>[A-Za-z0-9-]+):(?:\s+(?<value>.*?))?\s*(?:#.*)?$') {
            $Value = $null
            if ($Matches.ContainsKey('value') -and $Matches['value']) {
                $Value = ConvertFrom-YamlScalar $Matches['value']
            }
            $Current[$Matches['key']] = if ($null -eq $Value) { $true } else { $Value }
        }
    }
    if ($null -ne $Current) {
        [void]$Records.Add($Current)
    }
    return @($Records)
}

function Get-ProxyGroupRecords {
    param([string[]]$Lines)

    $Range = Get-SectionRange -Lines $Lines -Section 'proxy-groups'
    $Groups = [System.Collections.Generic.List[object]]::new()
    $Current = $null
    $ReadingProxies = $false

    for ($Index = $Range.Start; $Index -lt $Range.End; $Index++) {
        $Line = $Lines[$Index]
        if ($Line -match '^\s{2}-\s+name:\s*(?<name>"[^"]*"|\S+)\s*$') {
            if ($null -ne $Current) {
                [void]$Groups.Add($Current)
            }
            $Current = [ordered]@{
                name = ConvertFrom-YamlScalar $Matches['name']
                proxies = [System.Collections.Generic.List[string]]::new()
            }
            $ReadingProxies = $false
            continue
        }
        if ($null -eq $Current) {
            continue
        }
        if ($Line -match '^\s{4}proxies:\s*$') {
            $ReadingProxies = $true
            continue
        }
        if ($Line -match '^\s{4}[A-Za-z0-9-]+:') {
            $ReadingProxies = $false
            continue
        }
        if ($ReadingProxies -and $Line -match '^\s{6}-\s+(?<proxy>.*)\s*$') {
            [void]$Current.proxies.Add([string](ConvertFrom-YamlScalar $Matches['proxy']))
        }
    }
    if ($null -ne $Current) {
        [void]$Groups.Add($Current)
    }
    return @($Groups)
}

function Get-MatrixEntries {
    param([string[]]$Lines)

    $Range = Get-SectionRange -Lines $Lines -Section 'entries'
    $Entries = [System.Collections.Generic.List[object]]::new()
    $Current = $null

    for ($Index = $Range.Start; $Index -lt $Range.End; $Index++) {
        $Line = $Lines[$Index]
        if ($Line -match '^\s{2}-\s+name:\s*(?<name>"[^"]*"|\S+)\s*$') {
            if ($null -ne $Current) {
                [void]$Entries.Add($Current)
            }
            $Current = [ordered]@{
                name = ConvertFrom-YamlScalar $Matches['name']
            }
            continue
        }
        if ($null -ne $Current -and
            $Line -match '^\s{4}(?<key>[A-Za-z0-9-]+):(?:\s+(?<value>.*?))?\s*$') {
            $Value = $null
            if ($Matches.ContainsKey('value') -and $Matches['value']) {
                $Value = ConvertFrom-YamlScalar $Matches['value']
            }
            $Current[$Matches['key']] = if ($null -eq $Value) { $true } else { $Value }
        }
    }
    if ($null -ne $Current) {
        [void]$Entries.Add($Current)
    }
    return @($Entries)
}

function Get-YamlList {
    param(
        [string[]]$Lines,
        [string]$Key
    )

    $HeaderIndex = -1
    $HeaderIndent = 0
    $HeaderPattern = '^(?<indent>\s*){0}:\s*$' -f [regex]::Escape($Key)
    for ($Index = 0; $Index -lt $Lines.Count; $Index++) {
        if ($Lines[$Index] -match $HeaderPattern) {
            $HeaderIndex = $Index
            $HeaderIndent = Get-Indent $Lines[$Index]
            break
        }
    }
    if ($HeaderIndex -lt 0) {
        throw "YAML list '$Key' was not found."
    }

    $Values = [System.Collections.Generic.List[string]]::new()
    for ($Index = $HeaderIndex + 1; $Index -lt $Lines.Count; $Index++) {
        $Line = $Lines[$Index]
        if ([string]::IsNullOrWhiteSpace($Line) -or $Line.TrimStart().StartsWith('#')) {
            continue
        }
        $Indent = Get-Indent $Line
        if ($Indent -le $HeaderIndent) {
            break
        }
        if ($Line -match '^\s+-\s+(?<value>.*)\s*$') {
            [void]$Values.Add([string](ConvertFrom-YamlScalar $Matches['value']))
        }
    }
    return @($Values)
}

function Test-HasField {
    param(
        [System.Collections.IDictionary]$Record,
        [string]$Key
    )

    return $Record.Contains($Key)
}

function Get-Field {
    param(
        [System.Collections.IDictionary]$Record,
        [string]$Key,
        [AllowNull()]$Default = $null
    )

    if (Test-HasField $Record $Key) {
        return $Record[$Key]
    }
    return $Default
}

function Assert-Equal {
    param(
        [AllowNull()]$Actual,
        [AllowNull()]$Expected,
        [string]$Message
    )

    if ($Actual -ne $Expected) {
        $ActualText = if ($null -eq $Actual) { '<missing>' } else { [string]$Actual }
        $ExpectedText = if ($null -eq $Expected) { '<missing>' } else { [string]$Expected }
        Add-Failure "$Message (expected '$ExpectedText', got '$ActualText')"
    }
}

function Assert-True {
    param(
        [bool]$Condition,
        [string]$Message
    )

    if (-not $Condition) {
        Add-Failure $Message
    }
}

function ConvertTo-FlatArray {
    param([AllowNull()]$Values)

    $Flattened = [System.Collections.Generic.List[object]]::new()
    foreach ($Value in @($Values)) {
        if ($null -eq $Value) {
            continue
        }
        if ($Value -is [System.Collections.IEnumerable] -and
            $Value -isnot [string] -and
            $Value -isnot [System.Collections.IDictionary]) {
            foreach ($NestedValue in $Value) {
                [void]$Flattened.Add($NestedValue)
            }
        } else {
            [void]$Flattened.Add($Value)
        }
    }
    return @($Flattened)
}

function Assert-SetEqual {
    param(
        [AllowNull()][object[]]$Actual,
        [AllowNull()][object[]]$Expected,
        [string]$Message
    )

    $ActualSet = @(ConvertTo-FlatArray $Actual | ForEach-Object { [string]$_ } | Sort-Object -Unique)
    $ExpectedSet = @(ConvertTo-FlatArray $Expected | ForEach-Object { [string]$_ } | Sort-Object -Unique)
    $Missing = @($ExpectedSet | Where-Object { $_ -notin $ActualSet })
    $Unexpected = @($ActualSet | Where-Object { $_ -notin $ExpectedSet })
    if ($Missing.Count -gt 0 -or $Unexpected.Count -gt 0) {
        Add-Failure "$Message (missing: $($Missing -join ', '); unexpected: $($Unexpected -join ', '))"
    }
}

function Find-ByName {
    param(
        [object[]]$Records,
        [string]$Name,
        [string]$Kind
    )

    $Matches = @($Records | Where-Object { $_.name -eq $Name })
    Assert-Equal $Matches.Count 1 "$Kind '$Name' must occur exactly once"
    if ($Matches.Count -eq 1) {
        return $Matches[0]
    }
    return $null
}

$ConfigPath = Join-Path $RepositoryRoot 'PreviewConfigurationLan.json'
$ClientPath = Join-Path $RepositoryRoot 'PrismPreviewClient.yaml'
$MatrixPath = Join-Path $RepositoryRoot 'docs/clash/PreviewConfigurationMatrix.yaml'

$Lan = Get-Content -Raw -LiteralPath $ConfigPath | ConvertFrom-Json
$ClientLines = @(Get-Content -LiteralPath $ClientPath)
$MatrixLines = @(Get-Content -LiteralPath $MatrixPath)
$MatrixText = Get-Content -Raw -LiteralPath $MatrixPath

$ExpectedProtocols = @('http', 'socks5', 'vless', 'trojan', 'vmess', 'shadowsocks2022', 'anytls')
$ExpectedActive = @('Http', 'SOCKS5 TCP Cert', 'VLESS TCP', 'Trojan TCP', 'VMess TCP', 'SS2022 TCP')

Assert-Equal @($Lan.Protocols).Count $ExpectedProtocols.Count 'LAN JSON protocol count'
Assert-SetEqual @($Lan.Protocols | ForEach-Object { $_.Name }) $ExpectedProtocols 'LAN JSON protocol names'
Assert-Equal @($Lan.Listeners.Tcp).Count 1 'LAN JSON TCP listener count'
Assert-Equal @($Lan.Listeners.Udp).Count 0 'LAN JSON UDP listener count'
Assert-Equal @($Lan.Listeners.Quic).Count 0 'LAN JSON QUIC listener count'
Assert-Equal @($Lan.Carriers).Count 1 'LAN JSON carrier count'
Assert-Equal @($Lan.Runtime.RequiredCapabilities).Count 0 'LAN JSON required capability count'

$TcpListener = $Lan.Listeners.Tcp[0]
$Account = @($Lan.Accounts | Where-Object { $_.Id -eq 'local' })[0]
Assert-True ($null -ne $Account) "LAN JSON local account must exist"

$ProxyRecords = @(Get-ProxyRecords $ClientLines)
$ProxyGroups = @(Get-ProxyGroupRecords $ClientLines)
$MatrixEntries = @(Get-MatrixEntries $MatrixLines)
$ProxyByName = @{}
foreach ($Proxy in $ProxyRecords) {
    if ($ProxyByName.ContainsKey($Proxy.name)) {
        Add-Failure "Client proxy '$($Proxy.name)' is duplicated"
    } else {
        $ProxyByName[$Proxy.name] = $Proxy
    }
}

Assert-Equal $ProxyRecords.Count 74 'Client proxy node count'
Assert-Equal $MatrixEntries.Count 74 'Matrix entry count'
if ($MatrixText -match '(?m)^\s+proxy-node-count:\s*(\d+)\s*$') {
    Assert-Equal ([int]$Matches[1]) 74 'Matrix baseline proxy-node-count'
} else {
    Add-Failure 'Matrix baseline proxy-node-count is missing'
}
Assert-SetEqual (ConvertTo-FlatArray $ProxyByName.Keys) (ConvertTo-FlatArray ($MatrixEntries | ForEach-Object { $_.name })) 'Client and matrix node names'

$ActiveGroup = Find-ByName $ProxyGroups 'PrismPreview-Active' 'Client group'
$PendingGroup = Find-ByName $ProxyGroups 'PrismPreview-Pending' 'Client group'
$MatrixGroup = Find-ByName $ProxyGroups 'PrismPreview-ProtocolMatrix' 'Client group'
$HealthGroup = Find-ByName $ProxyGroups 'PrismPreview-Xiaomi-Health' 'Client group'
if ($null -ne $ActiveGroup) {
    Assert-SetEqual $ActiveGroup.proxies ($ExpectedActive + 'DIRECT') 'Active group entries'
}
if ($null -ne $PendingGroup) {
    Assert-True ($PendingGroup.proxies -notcontains 'DIRECT') 'Pending group must not contain DIRECT'
}
if ($null -ne $MatrixGroup) {
    Assert-SetEqual $MatrixGroup.proxies (ConvertTo-FlatArray $ProxyByName.Keys) 'Protocol matrix group entries'
}
if ($null -ne $HealthGroup) {
    Assert-SetEqual $HealthGroup.proxies $ExpectedActive 'Health group entries'
}

$DefaultRule = @($ClientLines | Where-Object { $_ -match '^\s*-\s+MATCH,PrismPreview-Active\s*$' })
Assert-Equal $DefaultRule.Count 1 'Default MATCH rule'

$MatrixActive = @($MatrixEntries | Where-Object { (Get-Field $_ 'status') -eq 'active' } | ForEach-Object { $_.name })
$MatrixPending = @($MatrixEntries | Where-Object { (Get-Field $_ 'status') -eq 'server-side pending' } | ForEach-Object { $_.name })
Assert-SetEqual $MatrixActive $ExpectedActive 'Matrix active entries'
Assert-SetEqual $MatrixPending (ConvertTo-FlatArray $ProxyByName.Keys | Where-Object { $_ -notin $ExpectedActive }) 'Matrix pending entries'
if ($null -ne $PendingGroup) {
    Assert-SetEqual $PendingGroup.proxies $MatrixPending 'Pending group entries'
}
Assert-SetEqual (@($MatrixEntries | ForEach-Object { $_.status }) | Where-Object { $_ -ne 'active' -and $_ -ne 'server-side pending' }) @() 'Matrix status values'

$StatusContractActive = @(Get-YamlList -Lines $MatrixLines -Key 'active')
Assert-SetEqual $StatusContractActive $ExpectedActive 'Matrix status-contract active entries'

$ActiveExpectations = @(
    @{ Name = 'Http'; Type = 'http'; Credential = $Account.Credentials.Http; CredentialField = 'password'; Username = 'local' },
    @{ Name = 'SOCKS5 TCP Cert'; Type = 'socks5'; Credential = $Account.Credentials.Socks5; CredentialField = 'password'; Username = 'local' },
    @{ Name = 'VLESS TCP'; Type = 'vless'; Credential = $Account.Credentials.Vless; CredentialField = 'uuid'; Username = $null },
    @{ Name = 'Trojan TCP'; Type = 'trojan'; Credential = $Account.Credentials.Trojan; CredentialField = 'password'; Username = $null },
    @{ Name = 'VMess TCP'; Type = 'vmess'; Credential = $Account.Credentials.Vmess; CredentialField = 'uuid'; Username = $null },
    @{ Name = 'SS2022 TCP'; Type = 'ss'; Credential = $Account.Credentials.Shadowsocks2022; CredentialField = 'password'; Username = $null }
)
$ForbiddenCarrierFields = @('sni', 'servername', 'skip-cert-verify', 'plugin', 'plugin-opts', 'reality-opts', 'smux')

foreach ($Expectation in $ActiveExpectations) {
    $Proxy = Find-ByName $ProxyRecords $Expectation.Name 'Client proxy'
    if ($null -eq $Proxy) {
        continue
    }
    Assert-Equal (Get-Field $Proxy 'status') 'active' "Client status for $($Expectation.Name)"
    Assert-Equal (Get-Field $Proxy 'type') $Expectation.Type "Client type for $($Expectation.Name)"
    Assert-Equal (Get-Field $Proxy 'server') $TcpListener.Address "Client server for $($Expectation.Name)"
    Assert-Equal ([int](Get-Field $Proxy 'port' 0)) ([int]$TcpListener.Port) "Client port for $($Expectation.Name)"
    Assert-Equal (Get-Field $Proxy 'network' 'tcp') 'tcp' "Client transport for $($Expectation.Name)"
    if ($Expectation.Name -eq 'Trojan TCP') {
        Assert-Equal (Get-Field $Proxy 'skip-cert-verify' $false) $true "Trojan NativeTls verification for $($Expectation.Name)"
    } else {
        Assert-Equal (Get-Field $Proxy 'tls' $false) $false "Client TLS for $($Expectation.Name)"
    }
    Assert-Equal (Get-Field $Proxy 'udp' $false) $false "Client UDP for $($Expectation.Name)"
    Assert-Equal (Get-Field $Proxy $Expectation.CredentialField) $Expectation.Credential "Client credential for $($Expectation.Name)"
    if ($null -ne $Expectation.Username) {
        Assert-Equal (Get-Field $Proxy 'username') $Expectation.Username "Client username for $($Expectation.Name)"
    }
    foreach ($Field in $ForbiddenCarrierFields) {
        if ($Expectation.Name -eq 'Trojan TCP' -and $Field -eq 'skip-cert-verify') {
            continue
        }
        Assert-True (-not (Test-HasField $Proxy $Field)) "Active node $($Expectation.Name) must not set '$Field'"
    }
}

foreach ($Entry in $MatrixEntries) {
    $Proxy = $ProxyByName[$Entry.name]
    Assert-Equal (Get-Field $Proxy 'status') (Get-Field $Entry 'status') "Client/matrix status for $($Entry.name)"
    if ((Get-Field $Entry 'status') -eq 'active') {
        Assert-Equal (Get-Field $Entry 'transport') 'tcp' "Matrix transport for $($Entry.name)"
        if ($Entry.name -eq 'Trojan TCP') {
            Assert-Equal (Get-Field $Entry 'tls') 'protocol-native' "Matrix TLS for $($Entry.name)"
        } else {
            Assert-Equal (Get-Field $Entry 'tls') $false "Matrix TLS for $($Entry.name)"
        }
        Assert-Equal (Get-Field $Entry 'udp') $false "Matrix UDP for $($Entry.name)"
    }
}

if ($Failures.Count -gt 0) {
    Write-Host "PREVIEW CONFIGURATION STATIC AUDIT FAILED ($($Failures.Count) failure(s))"
    foreach ($Failure in $Failures) {
        Write-Host "- $Failure"
    }
    exit 1
}

Write-Host 'PREVIEW CONFIGURATION STATIC AUDIT PASSED'
Write-Host "- server protocols: $($ExpectedProtocols -join ', ')"
Write-Host "- active nodes: $($ExpectedActive -join ', ')"
Write-Host "- matrix nodes: $($ProxyRecords.Count)"
Write-Host '- network requests: 0'
exit 0
