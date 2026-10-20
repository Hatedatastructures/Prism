#requires -Version 7.4
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$PrismTemplate,
    [Parameter(Mandatory = $true)][string]$MihomoTemplate,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9_.-]{1,48}$')]
    [string]$CaseDirectory,
    [ValidateRange(0, 65535)][int]$PrismPort = 0,
    [ValidateRange(0, 65535)][int]$TargetPort = 0,
    [ValidateRange(0, 65535)][int]$ProxyPort = 0,
    [ValidateRange(0, 65535)][int]$HandshakeBackendPort = 0,
    [string]$TlsCertificate = 'cert.pem',
    [string]$TlsPrivateKey = 'key.pem',
    [switch]$Tls12HandshakeBackend,
    [ValidatePattern('^$|^[A-Za-z0-9_. -]{1,128}$')][string]$ActiveProxy = '',
    [string]$MihomoExecutable = 'mihomo.exe',
    [string]$MihomoLogLevel = '',
    [ValidateSet('http', 'socks5', 'vless', 'trojan', 'vmess', 'shadowsocks', 'anytls')]
    [string]$ExpectedProtocol = '',
    [ValidatePattern('^127\.0\.0\.1$|^::1$')][string]$ServerAddress = '127.0.0.1',
    [ValidateRange(0, 65535)][int]$ControllerPort = 0,
    [ValidateRange(1, 2147483647)][int]$RepeatCount = 3,
    [ValidateRange(1, 32)][int]$ConcurrentRequests = 1
)

if ($PSVersionTable.PSVersion -lt [Version]'7.4') {
    throw 'Mihomo interop runners require PowerShell 7.4 or newer'
}
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'MihomoTestSupport.ps1')

function Write-Utf8NoBom {
    param([string]$Path, [string]$Content)

    $Path = Get-MihomoCaseArtifactPath $script:CaseDirectory $Path
    $Encoding = New-Object System.Text.UTF8Encoding -ArgumentList $false
    [System.IO.File]::WriteAllText($Path, $Content, $Encoding)
}

function Get-FreeLoopbackPort {
    param([int[]]$AvoidPorts = @())

    for ($Attempt = 0; $Attempt -lt 64; $Attempt++) {
        $Listener = [System.Net.Sockets.TcpListener]::new(
            [System.Net.IPAddress]::Loopback, 0)
        $Udp = $null
        try {
            $Listener.Start()
            $Port = ([System.Net.IPEndPoint]$Listener.LocalEndpoint).Port
            if ($Port -in $AvoidPorts) {
                continue
            }
            # Mihomo's mixed-port binds both TCP and UDP. Probe both protocols
            # before returning so a TCP-only free-port check cannot race it.
            $UdpEndpoint = [System.Net.IPEndPoint]::new(
                [System.Net.IPAddress]::Loopback, $Port)
            $Udp = [System.Net.Sockets.UdpClient]::new($UdpEndpoint)
            $UdpPort = ([System.Net.IPEndPoint]$Udp.Client.LocalEndPoint).Port
            if ($UdpPort -ne $Port) {
                throw 'UDP port probe bound an unexpected local port'
            }
            return $UdpPort
        }
        catch {
            if ($Attempt -eq 63) {
                throw
            }
        }
        finally {
            if ($null -ne $Udp) {
                $Udp.Dispose()
            }
            $Listener.Stop()
        }
    }
    throw 'Unable to reserve a loopback TCP/UDP port'
}

function Get-Sha256 {
    param([Parameter(Mandatory = $true)][string]$Path)

    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToUpperInvariant()
}

function Read-NewPrismLogEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$LogRoot,
        [Parameter(Mandatory = $true)][int]$MinimumSuccessCount,
        [AllowEmptyString()][string]$Protocol = ''
    )

    $DataPlanePattern = if ($Protocol -eq 'anytls') {
        'stage=mux outcome=success'
    }
    else {
        'stage=relay outcome=success'
    }
    $ProtocolPattern = if ([string]::IsNullOrWhiteSpace($Protocol)) {
        ''
    }
    else {
        '\[Protocol=' + [regex]::Escape($Protocol) + '\]'
    }
    $SuccessCount = 0
    $LastMatches = [System.Collections.Generic.List[string]]::new()
    $LastPath = ''
    foreach ($LogFile in @(Get-ChildItem -LiteralPath $LogRoot -File -ErrorAction SilentlyContinue)) {
        $Matches = @(Get-Content -LiteralPath $LogFile.FullName -ErrorAction SilentlyContinue |
            Where-Object {
                $_ -match $DataPlanePattern -and
                ([string]::IsNullOrEmpty($ProtocolPattern) -or $_ -match $ProtocolPattern)
            })
        if ($Matches.Count -gt 0) {
            $SuccessCount += $Matches.Count
            $LastMatches.AddRange([string[]]$Matches)
            $LastPath = $LogFile.FullName
        }
    }
    if ($SuccessCount -gt $MinimumSuccessCount) {
        return [pscustomobject]@{
            Observed = $true
            Path = $LastPath
            Excerpt = ($LastMatches | Select-Object -Last 3) -join "`n"
        }
    }
    return [pscustomobject]@{
        Observed = $false
        Path = ''
        Excerpt = ''
    }
}

if ([string]::IsNullOrWhiteSpace($ExpectedProtocol)) {
    $ExpectedProtocol = switch -Regex ($ActiveProxy) {
        '^Http' { 'http'; break }
        '^SOCKS5' { 'socks5'; break }
        '^VLESS' { 'vless'; break }
        '^Trojan' { 'trojan'; break }
        '^VMess' { 'vmess'; break }
        '^SS2022' { 'shadowsocks'; break }
        '^AnyTLS' { 'anytls'; break }
        default { '' }
    }
}
if ([string]::IsNullOrWhiteSpace($ExpectedProtocol)) {
    throw 'TCP Mihomo case requires an explicit supported expected protocol'
}

$RepositoryRoot = [System.IO.Path]::GetFullPath(
    (Join-Path $PSScriptRoot '..\..\..\..'))
Assert-MihomoLocalFixedDirectoryPath $RepositoryRoot
if ($PrismPort -eq 0) {
    $PrismPort = Get-FreeLoopbackPort
}
if ($TargetPort -eq 0) {
    $TargetPort = Get-FreeLoopbackPort @($PrismPort)
}
if ($ProxyPort -eq 0) {
    $ProxyPort = Get-FreeLoopbackPort @($PrismPort, $TargetPort)
}
if ($PrismPort -lt 1 -or $TargetPort -lt 1 -or $ProxyPort -lt 1 -or
    @($PrismPort, $TargetPort, $ProxyPort | Select-Object -Unique).Count -ne 3) {
    throw 'TCP case requires three distinct positive loopback port assignments'
}
$CaseDirectory = New-UniqueMihomoCaseDirectory $CaseDirectory
$TargetRoot = Join-Path $CaseDirectory 'target-root'
$PrismLogRoot = Join-Path $CaseDirectory 'prism-logs'
$PrismConfig = Join-Path $CaseDirectory 'prism.json'
$Started = [System.Collections.Generic.List[object]]::new()
$TemporaryDirectories = [System.Collections.Generic.List[string]]::new()
$PrismProcess = $null
$PrismProcessOwner = $null
$TargetProcess = $null
$TargetProcessOwner = $null
$TlsProcess = $null
$TlsProcessOwner = $null
$Results = [System.Collections.Generic.List[object]]::new()
$CleanupFailures = [System.Collections.Generic.List[string]]::new()
$SensitiveValues = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase)
try {
$PrismExecutable = Assert-MihomoLocalFixedFilePath (
    Join-Path $RepositoryRoot 'build/src/Prism.exe')
$MihomoExecutable = Resolve-MihomoExecutable $MihomoExecutable
$FileServerExecutable = Assert-MihomoLocalFixedFilePath (
    Join-Path $RepositoryRoot 'build/tests/PrismMatrixFileServer.exe')
$CurlExecutable = Resolve-MihomoExecutablePath 'curl.exe'
$PrismSha256 = Get-Sha256 $PrismExecutable
$MihomoSha256 = Get-Sha256 $MihomoExecutable
$TargetRoot = New-MihomoCaseSubdirectory $CaseDirectory 'target-root'
$PrismLogRoot = New-MihomoCaseSubdirectory $CaseDirectory 'prism-logs'
$TargetResponse = [byte[]]::new(65536)
for ($Index = 0; $Index -lt $TargetResponse.Length; $Index++) {
    $TargetResponse[$Index] = [byte]($Index % 251)
}
[System.IO.File]::WriteAllBytes(
    (Get-MihomoCaseArtifactPath $CaseDirectory (Join-Path $TargetRoot 'hello.txt')),
    $TargetResponse)

$PrismTemplatePath = Assert-MihomoLocalFixedFilePath $PrismTemplate
$PrismTemplateDirectory = Split-Path -Parent $PrismTemplatePath
$MihomoTemplatePath = Assert-MihomoLocalFixedFilePath $MihomoTemplate
$PrismObject = Read-MihomoCasePrismConfiguration $PrismTemplatePath
foreach ($SensitiveValue in @(Get-MihomoConfigurationSensitiveValues $PrismObject)) {
    [void]$SensitiveValues.Add($SensitiveValue)
}
Set-MihomoPrismCaseListeners $PrismObject 'tcp' $PrismPort 0 $ServerAddress
$PrismObject.Operations.WebDirectory = ''
Resolve-MihomoPrismLocalPaths $PrismObject $PrismTemplateDirectory
$TlsBackendCertificate = $null
$TlsBackendPrivateKey = $null
if ($HandshakeBackendPort -gt 0) {
    $TlsBackendCertificate = Assert-MihomoLocalFixedFilePath $TlsCertificate
    $TlsBackendPrivateKey = Assert-MihomoLocalFixedFilePath $TlsPrivateKey
}
Set-MihomoPrismDialCarrierBackend $PrismObject $HandshakeBackendPort
$PrismObject.Logging.Directory = $PrismLogRoot.Replace('\', '/')
$PrismObject.Logging.FileName = 'prism.log'
$ReservedPorts = @($PrismPort, $TargetPort, $ProxyPort)
if ($HandshakeBackendPort -gt 0) {
    $ReservedPorts += $HandshakeBackendPort
}
$PrismOperationsPort = Get-FreeLoopbackPort $ReservedPorts
$PrismObject.Operations.Enabled = $true
$PrismObject.Operations.Endpoint = "127.0.0.1:$PrismOperationsPort"
$ControllerAvoidPorts = @($ReservedPorts)
if ($PrismOperationsPort -gt 0) {
    $ControllerAvoidPorts += $PrismOperationsPort
}
if ($ControllerPort -gt 0 -and $ControllerPort -in $ControllerAvoidPorts) {
    throw 'ControllerPort must be distinct from every Prism, target, proxy, and operations port'
}
$ControllerPort = if ($ControllerPort -gt 0) {
    $ControllerPort
} else {
    Get-FreeLoopbackPort $ControllerAvoidPorts
}
$ControllerSecret = New-MihomoControllerSecret
$null = $SensitiveValues.Add($ControllerSecret)

$Yaml = Get-Content -LiteralPath $MihomoTemplatePath -Raw
Assert-MihomoYamlSupportedSyntax $Yaml
Assert-MihomoNoShortcutInbounds $Yaml
Assert-MihomoTemplateProxyEndpointsAreLoopback $Yaml
foreach ($SensitiveValue in @(Get-MihomoYamlSensitiveValues $Yaml)) {
    [void]$SensitiveValues.Add($SensitiveValue)
}
$Yaml = Remove-MihomoYamlComments $Yaml
if (Test-MihomoYamlContainsKey $Yaml @('proxy-providers', 'rule-providers')) {
    throw 'Mihomo templates using external providers are not supported by isolated cases'
}
$Yaml = if ([string]::IsNullOrWhiteSpace($MihomoLogLevel)) {
    $Yaml
} else {
    [regex]::Replace($Yaml, '(?m)^log-level:\s+.*$', "log-level: $MihomoLogLevel")
}
$Yaml = Remove-MihomoControllerSettings $Yaml
$Yaml = Normalize-MihomoCaseNetworkConfiguration $Yaml
$Yaml = Set-MihomoTopLevelScalar $Yaml 'bind-address' '127.0.0.1'
$Yaml = Set-MihomoTopLevelScalar $Yaml 'allow-lan' 'false'
$InboundConfiguration = Normalize-MihomoIsolatedInbound $Yaml 'tcp' $ProxyPort
$Yaml = $InboundConfiguration.Yaml
$ProxyPortKey = $InboundConfiguration.PortKey
$Yaml = Set-MihomoTopLevelScalar $Yaml 'mode' 'rule'
$Yaml = Set-MihomoTopLevelScalar $Yaml 'external-controller' "127.0.0.1:$ControllerPort"
$Yaml = Set-MihomoTopLevelScalar $Yaml 'secret' $ControllerSecret
$ControllerEntries = @(Get-MihomoYamlMappingEntries $Yaml | Where-Object {
        $_.Indent -eq 0 -and -not $_.IsSequence -and $_.Key -eq 'external-controller'
    })
if ($ControllerEntries.Count -ne 1 -or
    $ControllerEntries[0].Value -notmatch '^\s+127\.0\.0\.1:\d+\s*(?:#.*)?$' -or
    (Test-MihomoYamlContainsKey $Yaml @(
            'external-controller-pipe', 'external-controller-unix',
            'external-controller-tls', 'external-controller-cors', 'listeners'))) {
    throw 'Mihomo test controller must have only its isolated loopback endpoint'
}
Assert-MihomoRuleMode $Yaml
Assert-MihomoNoDnsListener $Yaml
Assert-MihomoNoShortcutInbounds $Yaml
Assert-MihomoIsolatedInboundPort $Yaml $ProxyPortKey $ProxyPort
# 强制本地回环目标经过隔离 Mihomo；主配置的回环直连规则不能进入这个测试模板。
$Yaml = [regex]::Replace(
    $Yaml,
    '(?m)^\s*-\s*IP-CIDR,127\.0\.0\.0/8,DIRECT\s*\r?\n',
    '')
if (-not [string]::IsNullOrWhiteSpace($ActiveProxy)) {
    $InitialMatchTargets = @(Get-MihomoMatchTargets $Yaml)
    if ($InitialMatchTargets.Count -ne 1 -or
        $InitialMatchTargets[0] -ne 'PrismPreview-Active') {
        throw 'Mihomo template must have one MATCH,PrismPreview-Active route marker'
    }
    $Yaml = [regex]::Replace(
        $Yaml,
        '(?m)^(\s*-\s*MATCH,)PrismPreview-Active\s*$',
        ('$1' + $ActiveProxy))
    Assert-MihomoRouteTarget $Yaml $ActiveProxy
}
elseif (@(Get-MihomoMatchTargets $Yaml | Where-Object { $_ -eq 'PrismPreview-Active' }).Count -gt 0) {
    throw 'ActiveProxy is required to resolve the PrismPreview-Active route marker'
}
$MatchTargets = @(Get-MihomoMatchTargets $Yaml)
if ($MatchTargets.Count -ne 1) {
    throw 'Mihomo template must have exactly one MATCH route for route evidence'
}
$ExpectedRoute = $MatchTargets[0]
Assert-MihomoRouteTarget $Yaml $ExpectedRoute
$Yaml = Set-MihomoIsolatedRouteClosure $Yaml $ExpectedRoute
$ExpectedRouteChain = @(Get-MihomoExpectedRouteChain $Yaml $ExpectedRoute)
$SelectedProxy = $ExpectedRouteChain[0]
Assert-MihomoProxyMatchesScenario $Yaml $SelectedProxy $ExpectedProtocol
Assert-MihomoPrismProxyCredentials `
    $PrismObject $ExpectedProtocol $Yaml $SelectedProxy
Assert-MihomoPrismProxyServerName `
    $PrismObject $ExpectedProtocol $Yaml $SelectedProxy
$OptionalMihomoUuid = if ($ExpectedProtocol -in @('vless', 'vmess')) {
    Get-MihomoOptionalProxyScalar $Yaml $SelectedProxy 'uuid'
}
else {
    $null
}
if ($null -ne $OptionalMihomoUuid) {
    $UuidCredentialName = @{ vless = 'Vless'; vmess = 'Vmess' }[$ExpectedProtocol]
    $UuidCredential = $PrismObject.Accounts[0].Credentials.PSObject.Properties[$UuidCredentialName]
    $ConfiguredCredential = if ($null -eq $UuidCredential) {
        ''
    }
    else {
        [string]$UuidCredential.Value
    }
    if (-not [string]::Equals([string]$ConfiguredCredential, $OptionalMihomoUuid,
            [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'Prism and Mihomo UUIDs do not match'
    }
}
$OptionalMihomoServerName = Get-MihomoOptionalProxyScalar $Yaml $SelectedProxy 'servername'
if ($null -ne $OptionalMihomoServerName) {
    Assert-MihomoPrismProxyServerName `
        $PrismObject $ExpectedProtocol $Yaml $SelectedProxy $OptionalMihomoServerName
}
else {
    $OptionalMihomoSni = Get-MihomoOptionalProxyScalar $Yaml $SelectedProxy 'sni'
    if ($null -ne $OptionalMihomoSni) {
        Assert-MihomoPrismProxyServerName `
            $PrismObject $ExpectedProtocol $Yaml $SelectedProxy $OptionalMihomoSni
        $OptionalMihomoServerName = $OptionalMihomoSni
    }
}
$Yaml = Set-MihomoProxyEndpoint $Yaml $SelectedProxy $ServerAddress $PrismPort
Assert-MihomoCaseNetworkIsolation $Yaml $true $ControllerPort $ControllerSecret
Assert-MihomoIsolatedRouteClosure $Yaml $ExpectedRoute $SelectedProxy $ServerAddress $PrismPort
$ChildEnvironment = New-MihomoIsolatedChildEnvironment

    Write-Utf8NoBom $PrismConfig ($PrismObject | ConvertTo-Json -Depth 100)
    $PrismReadback = Read-MihomoPrismConfigurationReadback $PrismConfig
    Assert-MihomoPrismLocalPaths $PrismReadback.Configuration
    Assert-MihomoPrismCaseLogging $PrismReadback.Configuration $CaseDirectory
    Assert-MihomoPrismDialCarrierBackend `
        $PrismReadback.Configuration $HandshakeBackendPort
    Assert-MihomoPrismConfigurationCase `
        -Configuration $PrismReadback.Configuration -Mode 'tcp' `
        -TcpPort $PrismPort -OperationsPort $PrismOperationsPort `
        -ListenerAddress $ServerAddress
    $PrismConfigSha256 = $PrismReadback.Sha256

    $TargetProcess = Start-Process -FilePath $FileServerExecutable `
        -ArgumentList @($TargetRoot, $TargetPort, '1') `
        -WorkingDirectory $RepositoryRoot -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput (Get-MihomoCaseArtifactPath $CaseDirectory `
            (Join-Path $CaseDirectory 'target.stdout.log')) `
        -RedirectStandardError (Get-MihomoCaseArtifactPath $CaseDirectory `
            (Join-Path $CaseDirectory 'target.stderr.log')) `
        -Environment $ChildEnvironment
    $TargetProcessOwner = Register-MihomoOwnedProcess $Started $TargetProcess $FileServerExecutable
    $TargetReady = $false
    for ($Index = 0; $Index -lt 40; $Index++) {
        if ($TargetProcess.HasExited) {
            throw "Target server exited with code $($TargetProcess.ExitCode)"
        }
        if (Test-MihomoOwnedTcpPort $TargetProcessOwner $TargetPort '127.0.0.1') {
            $TargetReady = $true
            break
        }
        Start-Sleep -Milliseconds 250
    }
    if (-not $TargetReady) {
        throw 'Target TCP endpoint is not exclusively owned on loopback'
    }

    if ($HandshakeBackendPort -gt 0) {
        $OpenSslExecutable = Resolve-MihomoExecutablePath 'openssl.exe'
        $TlsArguments = [System.Collections.Generic.List[string]]::new()
        foreach ($TlsArgument in @(
                's_server', '-accept', "127.0.0.1:$HandshakeBackendPort",
                '-cert', $TlsBackendCertificate,
                '-key', $TlsBackendPrivateKey,
                '-www', '-quiet') ) {
            [void]$TlsArguments.Add($TlsArgument)
        }
        if ($Tls12HandshakeBackend) {
            [void]$TlsArguments.Add('-tls1_2')
        }
        $TlsProcess = Start-Process -FilePath $OpenSslExecutable `
            -ArgumentList $TlsArguments `
            -WorkingDirectory $RepositoryRoot -WindowStyle Hidden -PassThru `
            -RedirectStandardOutput (Get-MihomoCaseArtifactPath $CaseDirectory `
                (Join-Path $CaseDirectory 'tls.stdout.log')) `
            -RedirectStandardError (Get-MihomoCaseArtifactPath $CaseDirectory `
                (Join-Path $CaseDirectory 'tls.stderr.log')) `
            -Environment $ChildEnvironment
        $TlsProcessOwner = Register-MihomoOwnedProcess $Started $TlsProcess $OpenSslExecutable
        $TlsReady = $false
        for ($Index = 0; $Index -lt 40; $Index++) {
            Start-Sleep -Milliseconds 250
            if ($TlsProcess.HasExited) {
                throw "TLS backend exited with code $($TlsProcess.ExitCode)"
            }
            if (Test-MihomoOwnedTcpPort $TlsProcessOwner $HandshakeBackendPort '127.0.0.1') {
                $TlsReady = $true
                break
            }
        }
        if (-not $TlsReady) {
            throw 'TLS backend readiness timeout'
        }
    }

    $PrismProcess = Start-Process -FilePath $PrismExecutable `
        -ArgumentList @($PrismConfig) `
        -WorkingDirectory $RepositoryRoot -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput (Get-MihomoCaseArtifactPath $CaseDirectory `
            (Join-Path $CaseDirectory 'prism.stdout.log')) `
        -RedirectStandardError (Get-MihomoCaseArtifactPath $CaseDirectory `
            (Join-Path $CaseDirectory 'prism.stderr.log')) `
        -Environment $ChildEnvironment
    $PrismProcessOwner = Register-MihomoOwnedProcess $Started $PrismProcess $PrismExecutable

    $PrismReady = $false
    for ($Index = 0; $Index -lt 40; $Index++) {
        Start-Sleep -Milliseconds 250
        if ($PrismProcess.HasExited) {
            throw "Prism exited with code $($PrismProcess.ExitCode)"
        }
        $ReadyLog = Join-Path $CaseDirectory 'prism.stdout.log'
        if ((Test-Path -LiteralPath $ReadyLog) -and
            (Get-Content -LiteralPath $ReadyLog -Raw) -match 'Prism READY') {
            if ((Test-MihomoOwnedTcpPort $PrismProcessOwner $PrismPort $ServerAddress) -and
                (Test-MihomoOwnedTcpPort $PrismProcessOwner $PrismOperationsPort '127.0.0.1')) {
                $PrismReady = $true
                break
            }
        }
    }
    if (-not $PrismReady) {
        throw 'Prism readiness timeout'
    }

    for ($Attempt = 1; $Attempt -le $RepeatCount; $Attempt++) {
        $AttemptResult = $null
        $MihomoProcess = $null
        $ServerEvidence = [pscustomobject]@{
            Observed = $false
            Path = ''
            Excerpt = ''
        }
        $AttemptProxyPort = if ($Attempt -eq 1) {
            $ProxyPort
        } else {
            Get-FreeLoopbackPort @($ControllerPort, $PrismOperationsPort, $PrismPort, $TargetPort)
        }
        $AttemptHome = Join-Path $CaseDirectory ("mihomo-home-{0}" -f $Attempt)
        $AttemptHome = New-MihomoCaseSubdirectory $CaseDirectory (Split-Path -Leaf $AttemptHome)
        [void]$TemporaryDirectories.Add($AttemptHome)
        $AttemptConfig = Join-Path $AttemptHome 'config.yaml'
        $MihomoOut = Get-MihomoCaseArtifactPath $CaseDirectory `
            (Join-Path $CaseDirectory ("mihomo-{0}.stdout.log" -f $Attempt))
        $MihomoErr = Get-MihomoCaseArtifactPath $CaseDirectory `
            (Join-Path $CaseDirectory ("mihomo-{0}.stderr.log" -f $Attempt))
        $AttemptYaml = Set-MihomoTopLevelScalar $Yaml $ProxyPortKey ([string]$AttemptProxyPort)
        Assert-MihomoNoDnsListener $AttemptYaml
        Assert-MihomoNoShortcutInbounds $AttemptYaml
        Assert-MihomoNoProbeGroups $AttemptYaml
        Assert-MihomoIsolatedInboundPort $AttemptYaml $ProxyPortKey $AttemptProxyPort
        Assert-MihomoCaseNetworkIsolation $AttemptYaml $true $ControllerPort $ControllerSecret
        Assert-MihomoIsolatedRouteClosure `
            $AttemptYaml $ExpectedRoute $SelectedProxy $ServerAddress $PrismPort
        Assert-MihomoProxyMatchesScenario $AttemptYaml $SelectedProxy $ExpectedProtocol
        Assert-MihomoPrismProxyCredentials `
            $PrismObject $ExpectedProtocol $AttemptYaml $SelectedProxy
        Assert-MihomoPrismProxyServerName `
            $PrismObject $ExpectedProtocol $AttemptYaml $SelectedProxy $OptionalMihomoServerName
        Write-Utf8NoBom $AttemptConfig $AttemptYaml
        $AttemptConfigReadback = Get-Content -LiteralPath $AttemptConfig -Raw
        Assert-MihomoNoDnsListener $AttemptConfigReadback
        Assert-MihomoNoShortcutInbounds $AttemptConfigReadback
        Assert-MihomoNoProbeGroups $AttemptConfigReadback
        Assert-MihomoIsolatedInboundPort `
            $AttemptConfigReadback $ProxyPortKey $AttemptProxyPort
        Assert-MihomoCaseNetworkIsolation $AttemptConfigReadback $true $ControllerPort $ControllerSecret
        Assert-MihomoIsolatedRouteClosure `
            $AttemptConfigReadback $ExpectedRoute $SelectedProxy $ServerAddress $PrismPort
        Assert-MihomoProxyMatchesScenario $AttemptConfigReadback $SelectedProxy $ExpectedProtocol
        Assert-MihomoPrismProxyCredentials `
            $PrismObject $ExpectedProtocol $AttemptConfigReadback $SelectedProxy
        Assert-MihomoPrismProxyServerName `
            $PrismObject $ExpectedProtocol $AttemptConfigReadback $SelectedProxy $OptionalMihomoServerName
        $PortLine = [regex]::Match($AttemptYaml, '(?m)^mixed-port:\s+(\d+)\s*$')
        if (-not $PortLine.Success -or [int]$PortLine.Groups[1].Value -ne $AttemptProxyPort) {
            throw "Mihomo config port mismatch: expected $AttemptProxyPort"
        }
        if (-not (Test-Path -LiteralPath $AttemptConfig)) {
            throw "Mihomo config was not written: $AttemptConfig"
        }
        $AttemptConfigSha256 = Get-Sha256 $AttemptConfig
        $MihomoArguments = "-d `"$AttemptHome`" -f `"$AttemptConfig`""
        $MihomoOwner = $null
        $MihomoProcess = Start-Process -FilePath $MihomoExecutable `
            -ArgumentList $MihomoArguments `
            -WorkingDirectory $AttemptHome -WindowStyle Hidden -PassThru `
            -RedirectStandardOutput (Get-MihomoCaseArtifactPath $CaseDirectory $MihomoOut) `
            -RedirectStandardError (Get-MihomoCaseArtifactPath $CaseDirectory $MihomoErr) `
            -Environment $ChildEnvironment
        $MihomoOwner = Register-MihomoOwnedProcess $Started $MihomoProcess $MihomoExecutable
        $MihomoExited = $false
        $ServerEvidence = [pscustomobject]@{ Observed = $false; Path = ''; Excerpt = '' }
        try {
            $MihomoIdentity = Get-CimInstance Win32_Process `
                    -Filter "ProcessId=$($MihomoProcess.Id)" `
                    -ErrorAction SilentlyContinue
            $CommandLine = if ($null -eq $MihomoIdentity) {
                ''
            }
            else {
                [string]$MihomoIdentity.CommandLine
            }
            if ($MihomoOwner.Stopped -or $null -eq $MihomoIdentity -or
                -not (Test-MihomoOwnedProcessIdentity $MihomoOwner) -or
                -not [string]::Equals([string]$MihomoIdentity.ExecutablePath,
                    $MihomoOwner.Path, [System.StringComparison]::OrdinalIgnoreCase) -or
                [string]::IsNullOrWhiteSpace($CommandLine) -or
                $CommandLine.IndexOf($AttemptConfig, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
                throw "Mihomo PID $($MihomoProcess.Id) did not receive the isolated config path"
            }
            $ProxyReady = $false
            for ($Index = 0; $Index -lt 40; $Index++) {
                Start-Sleep -Milliseconds 250
                if ($MihomoProcess.HasExited) {
                    throw "Mihomo exited with code $($MihomoProcess.ExitCode)"
                }
                Assert-MihomoNoUnexpectedDefaultProxyListener $MihomoOwner
                if ((Test-MihomoOwnedTcpPort $MihomoOwner $AttemptProxyPort '127.0.0.1') -and
                    (Test-MihomoOwnedUdpPort $MihomoOwner $AttemptProxyPort '127.0.0.1')) {
                    $ProxyReady = $true
                    break
                }
            }
            if (-not $ProxyReady) {
                throw 'Mihomo mixed-port ownership or loopback readiness timeout'
            }
            $ProxySelection = Get-MihomoSelectedProxyChainSnapshot `
                $ControllerPort $ControllerSecret $MihomoOwner $ExpectedRouteChain
            $ProxySelectionSha256 = [Convert]::ToHexString(
                [System.Security.Cryptography.SHA256]::HashData(
                    [System.Text.UTF8Encoding]::new($false).GetBytes(
                        ($ProxySelection | ConvertTo-Json -Depth 12 -Compress)))).ToUpperInvariant()
            $CredentialNames = @{
                http = 'Http'; socks5 = 'Socks5'; vless = 'Vless'; trojan = 'Trojan'
                vmess = 'Vmess'; shadowsocks = 'Shadowsocks2022'; anytls = 'AnyTls'
                hysteria2 = 'hysteria2'; tuic = 'Tuic'
            }
            $CredentialName = $CredentialNames[$ExpectedProtocol]
            $PrismCredentialText = ''
            if (-not [string]::IsNullOrWhiteSpace($CredentialName) -and
                $null -ne $PrismObject.Accounts -and @($PrismObject.Accounts).Count -eq 1) {
                $CredentialProperty = $PrismObject.Accounts[0].Credentials.PSObject.Properties[$CredentialName]
                if ($null -ne $CredentialProperty) {
                    $PrismCredentialText = [string]$CredentialProperty.Value
                }
            }
            if (-not [string]::IsNullOrEmpty($PrismCredentialText)) {
                [void]$SensitiveValues.Add($PrismCredentialText)
            }

            $DataPlanePattern = if ($ExpectedProtocol -eq 'anytls') {
                'stage=mux outcome=success'
            }
            else {
                'stage=relay outcome=success'
            }
            $ProtocolPattern = if ([string]::IsNullOrWhiteSpace($ExpectedProtocol)) {
                ''
            }
            else {
                '\[Protocol=' + [regex]::Escape($ExpectedProtocol) + '\]'
            }
            $PrismSuccessCount = 0
            foreach ($PrismLogFile in @(Get-ChildItem -LiteralPath $PrismLogRoot -File -ErrorAction SilentlyContinue)) {
                $PrismSuccessCount += @(Get-Content -LiteralPath $PrismLogFile.FullName -ErrorAction SilentlyContinue |
                    Where-Object {
                        $_ -match $DataPlanePattern -and
                        ([string]::IsNullOrEmpty($ProtocolPattern) -or $_ -match $ProtocolPattern)
                    }).Count
            }
            $StartedAt = Get-Date
            $Output = [System.Collections.Generic.List[string]]::new()
            $ExitCode = 0
            $ResponseBodyPaths = [System.Collections.Generic.List[string]]::new()
            $ResponseBodyMatched = $false
            $RouteEvidence = [pscustomobject]@{
                Observed = $false
                ApiResponded = $false
                SnapshotCount = 0
            }
            if ($ConcurrentRequests -eq 1) {
                $CurlStdoutPath = Join-Path $CaseDirectory ("curl-{0}-1.stdout.log" -f $Attempt)
                $CurlStderrPath = Join-Path $CaseDirectory ("curl-{0}-1.stderr.log" -f $Attempt)
                $CurlResponsePath = Join-Path $TargetRoot ("curl-response-{0}-1.bin" -f $Attempt)
                if (-not (Test-MihomoOwnedTcpPort $TargetProcessOwner $TargetPort '127.0.0.1') -or
                    -not (Test-MihomoOwnedTcpPort $PrismProcessOwner $PrismPort $ServerAddress) -or
                    -not (Test-MihomoOwnedTcpPort $PrismProcessOwner $PrismOperationsPort '127.0.0.1') -or
                    -not (Test-MihomoOwnedTcpPort $MihomoOwner $AttemptProxyPort '127.0.0.1') -or
                    -not (Test-MihomoOwnedUdpPort $MihomoOwner $AttemptProxyPort '127.0.0.1')) {
                    throw 'TCP request endpoints are not exclusively owned loopback sockets'
                }
                if ($HandshakeBackendPort -gt 0 -and
                    -not (Test-MihomoOwnedTcpPort $TlsProcessOwner $HandshakeBackendPort '127.0.0.1')) {
                    throw 'TLS handshake backend is not exclusively owned on loopback'
                }
                $CurlResponsePath = Get-MihomoCaseArtifactPath $CaseDirectory $CurlResponsePath
                $ResponseBodyPaths.Add($CurlResponsePath)
                $CurlArguments = ('-q --noproxy= --proxy=http://127.0.0.1:{0} --max-time 30 ' +
                    '--limit-rate 32k --silent --show-error --output "{1}" ' +
                    '--write-out "\nHTTP_CODE=%{{http_code}}\nTIME=%{{time_total}}\n" ' +
                    'http://127.0.0.1:{2}/hello.txt') -f $AttemptProxyPort, $CurlResponsePath, $TargetPort
                Assert-MihomoCurlArgumentsDisableDefaults $CurlArguments
                $CurlProcess = Start-Process -FilePath $CurlExecutable -ArgumentList $CurlArguments `
                    -WindowStyle Hidden -PassThru `
                    -RedirectStandardOutput (Get-MihomoCaseArtifactPath $CaseDirectory $CurlStdoutPath) `
                    -RedirectStandardError (Get-MihomoCaseArtifactPath $CaseDirectory $CurlStderrPath)
                [void](Register-MihomoOwnedProcess $Started $CurlProcess $CurlExecutable)
                $RouteEvidence = Wait-MihomoRouteEvidence @($CurlProcess) $MihomoOwner $ControllerPort `
                    $ControllerSecret '127.0.0.1' $TargetPort $AttemptProxyPort 'tcp' $ExpectedRoute `
                    $ExpectedRouteChain
                if (-not $CurlProcess.WaitForExit(35000)) {
                    throw "curl request did not exit: PID $($CurlProcess.Id)"
                }
                $ExitCode = $CurlProcess.ExitCode
                $SingleOutput = @()
                if (Test-Path -LiteralPath $CurlStdoutPath) {
                    $SingleOutput += @(Get-Content -LiteralPath $CurlStdoutPath)
                }
                if (Test-Path -LiteralPath $CurlStderrPath) {
                    $SingleOutput += @(Get-Content -LiteralPath $CurlStderrPath)
                }
                $SingleOutput = @($SingleOutput | ForEach-Object {
                    Protect-MihomoText ([string]$_) @($SensitiveValues)
                })
                $Output.AddRange([string[]]$SingleOutput)
            }
            else {
                $CurlProcesses = [System.Collections.Generic.List[System.Diagnostics.Process]]::new()
                $CurlStdout = [System.Collections.Generic.List[string]]::new()
                $CurlStderr = [System.Collections.Generic.List[string]]::new()
                for ($RequestIndex = 1; $RequestIndex -le $ConcurrentRequests; $RequestIndex++) {
                    $StdoutPath = Join-Path $CaseDirectory ("curl-{0}-{1}.stdout.log" -f $Attempt, $RequestIndex)
                    $StderrPath = Join-Path $CaseDirectory ("curl-{0}-{1}.stderr.log" -f $Attempt, $RequestIndex)
                    $ResponsePath = Join-Path $TargetRoot ("curl-response-{0}-{1}.bin" -f $Attempt, $RequestIndex)
                    if (-not (Test-MihomoOwnedTcpPort $TargetProcessOwner $TargetPort '127.0.0.1') -or
                        -not (Test-MihomoOwnedTcpPort $PrismProcessOwner $PrismPort $ServerAddress) -or
                        -not (Test-MihomoOwnedTcpPort $PrismProcessOwner $PrismOperationsPort '127.0.0.1') -or
                        -not (Test-MihomoOwnedTcpPort $MihomoOwner $AttemptProxyPort '127.0.0.1') -or
                        -not (Test-MihomoOwnedUdpPort $MihomoOwner $AttemptProxyPort '127.0.0.1')) {
                        throw 'Concurrent TCP request endpoints are not exclusively owned loopback sockets'
                    }
                    if ($HandshakeBackendPort -gt 0 -and
                        -not (Test-MihomoOwnedTcpPort $TlsProcessOwner $HandshakeBackendPort '127.0.0.1')) {
                        throw 'TLS handshake backend is not exclusively owned on loopback'
                    }
                    $ResponsePath = Get-MihomoCaseArtifactPath $CaseDirectory $ResponsePath
                    $ResponseBodyPaths.Add($ResponsePath)
                    $CurlStdout.Add($StdoutPath)
                    $CurlStderr.Add($StderrPath)
                    $CurlArguments = @(
                                '-q',
                                '--noproxy=',
                                ("--proxy=http://127.0.0.1:{0}" -f $AttemptProxyPort),
                                '--max-time', '30', '--limit-rate', '32k', '--silent', '--show-error',
                                '--output', ('"' + $ResponsePath + '"'),
                                '--write-out', '\nHTTP_CODE=%{http_code}\nTIME=%{time_total}\n',
                                ("http://127.0.0.1:{0}/hello.txt" -f $TargetPort))
                    Assert-MihomoCurlArgumentsDisableDefaults $CurlArguments
                    $CurlProcess = Start-Process -FilePath $CurlExecutable -ArgumentList $CurlArguments `
                            -WindowStyle Hidden -PassThru `
                            -RedirectStandardOutput (Get-MihomoCaseArtifactPath $CaseDirectory $StdoutPath) `
                            -RedirectStandardError (Get-MihomoCaseArtifactPath $CaseDirectory $StderrPath)
                    $CurlProcesses.Add($CurlProcess)
                    [void](Register-MihomoOwnedProcess $Started $CurlProcess $CurlExecutable)
                }
                $RouteEvidence = Wait-MihomoRouteEvidence @($CurlProcesses) $MihomoOwner $ControllerPort `
                    $ControllerSecret '127.0.0.1' $TargetPort $AttemptProxyPort 'tcp' $ExpectedRoute `
                    $ExpectedRouteChain
                foreach ($CurlProcess in $CurlProcesses) {
                    if (-not $CurlProcess.HasExited) {
                        [void]$CurlProcess.WaitForExit(35000)
                    }
                    if (-not $CurlProcess.HasExited) {
                        throw "curl concurrent request did not exit: PID $($CurlProcess.Id)"
                    }
                    if ($CurlProcess.ExitCode -ne 0) {
                        $ExitCode = 1
                    }
                }
                for ($RequestIndex = 0; $RequestIndex -lt $ConcurrentRequests; $RequestIndex++) {
                    if (Test-Path $CurlStdout[$RequestIndex]) {
                        $StdoutLines = @(Get-Content $CurlStdout[$RequestIndex])
                        if ($StdoutLines.Count -gt 0) {
                            $Output.AddRange([string[]]$StdoutLines)
                        }
                    }
                    if (Test-Path $CurlStderr[$RequestIndex]) {
                        $StderrLines = @(Get-Content $CurlStderr[$RequestIndex])
                        if ($StderrLines.Count -gt 0) {
                            $Output.AddRange([string[]]$StderrLines)
                        }
                    }
                }
            }
            $ResponseBodyMatched = $ResponseBodyPaths.Count -eq $ConcurrentRequests
            foreach ($ResponsePath in $ResponseBodyPaths) {
                try {
                    Assert-MihomoExactResponseBody `
                        -Actual ([IO.File]::ReadAllBytes($ResponsePath)) `
                        -Expected $TargetResponse
                }
                catch {
                    $ResponseBodyMatched = $false
                }
            }
            if (-not $ResponseBodyMatched) {
                $ExitCode = 1
                $Output.Add('HTTP_RESPONSE_BODY_MATCH=FAILED')
            }
            else {
                $Output.Add('HTTP_RESPONSE_BODY_MATCH=VERIFIED')
            }
            for ($Index = 0; $Index -lt $Output.Count; $Index++) {
                $Output[$Index] = Protect-MihomoText $Output[$Index] @($SensitiveValues)
            }
            $RouteEvidenceLine = if ($RouteEvidence.Observed) {
                $Evidence = $RouteEvidence.Evidence
                'MIHOMO_ROUTE_EVIDENCE=VERIFIED network={0} inboundPort={1} destination={2}:{3} rule={4} rulePayload={5} chains={6}' -f `
                    $Evidence.Network, $Evidence.InboundPort, $Evidence.DestinationAddress, $Evidence.DestinationPort,
                    $Evidence.Rule, $Evidence.RulePayload, ($Evidence.Chains -join ' -> ')
            } else {
                'MIHOMO_ROUTE_EVIDENCE=UNVERIFIED'
            }
            $Output.Add((Protect-MihomoText $RouteEvidenceLine @($SensitiveValues)))
            $HttpCode200Count = @($Output | Where-Object { $_ -match 'HTTP_CODE=200' }).Count
            # Mihomo keeps AnyTLS application-mux connections pooled after the
            # request. Close this task-owned client before waiting for the
            # server-side close/mux evidence, otherwise the evidence wait is
            # measuring the client's idle pool lifetime.
            [void](Stop-MihomoOwnedProcess $MihomoOwner)
            # AnyTLS 将并发请求复用到一个应用层 mux 会话；其服务端成功日志
            # 按物理会话计数，payload 数量仍由 HTTP 结果逐请求校验。
            $MinimumSuccessCount = if ($ExpectedProtocol -eq 'anytls') {
                $PrismSuccessCount
            }
            else {
                $PrismSuccessCount + $ConcurrentRequests - 1
            }
            for ($LogAttempt = 0; $LogAttempt -lt 450; $LogAttempt++) {
                $ServerEvidence = Read-NewPrismLogEvidence `
                    -LogRoot $PrismLogRoot `
                    -MinimumSuccessCount $MinimumSuccessCount `
                    -Protocol $ExpectedProtocol
                if ($ServerEvidence.Observed) {
                    break
                }
                Start-Sleep -Milliseconds 100
            }
            $AttemptResult = [ordered]@{
                    attempt = $Attempt
                    proxyPort = $AttemptProxyPort
                    mihomoPid = $MihomoProcess.Id
                    configPath = $AttemptConfig
                    configSha256 = $AttemptConfigSha256
                    commandLine = Protect-MihomoText $CommandLine @($SensitiveValues)
                    exitCode = $ExitCode
                    elapsedSeconds = ((Get-Date) - $StartedAt).TotalSeconds
                    output = ($Output -join "`n")
                    prismExecutable = $PrismExecutable
                    prismSha256 = $PrismSha256
                    prismConfig = $PrismConfig
                    prismConfigSha256 = $PrismConfigSha256
                    mihomoExecutable = $MihomoExecutable
                    mihomoSha256 = $MihomoSha256
                    expectedProtocol = $ExpectedProtocol
                    dnsSourceHandling = 'source template is read-only; dns section is removed from the case copy'
                    concurrentRequests = $ConcurrentRequests
                    httpCode200Count = $HttpCode200Count
                    responseBodyMatched = [bool]$ResponseBodyMatched
                    serverLogObserved = [bool]$ServerEvidence.Observed
                    serverLogPath = $ServerEvidence.Path
                    serverLogExcerpt = Protect-MihomoText $ServerEvidence.Excerpt @($SensitiveValues)
                    routeEvidenceObserved = [bool]$RouteEvidence.Observed
                    routeEvidenceApiResponded = [bool]$RouteEvidence.ApiResponded
                    routeEvidenceSnapshots = [int]$RouteEvidence.SnapshotCount
                    controllerProxiesApiResponded = $true
                    controllerSelectedChain = @($ExpectedRouteChain)
                    controllerProxiesSha256 = $ProxySelectionSha256
                    routeEvidence = if ($RouteEvidence.Observed) {
                        [ordered]@{
                            destinationAddress = Protect-MihomoText `
                                $RouteEvidence.Evidence.DestinationAddress @($SensitiveValues)
                            destinationPort = Protect-MihomoText `
                                ([string]$RouteEvidence.Evidence.DestinationPort) @($SensitiveValues)
                            inboundPort = Protect-MihomoText `
                                ([string]$RouteEvidence.Evidence.InboundPort) @($SensitiveValues)
                            network = Protect-MihomoText `
                                $RouteEvidence.Evidence.Network @($SensitiveValues)
                            rule = Protect-MihomoText $RouteEvidence.Evidence.Rule @($SensitiveValues)
                            rulePayload = Protect-MihomoText `
                                $RouteEvidence.Evidence.RulePayload @($SensitiveValues)
                            expectedRoute = Protect-MihomoText `
                                $RouteEvidence.Evidence.ExpectedRoute @($SensitiveValues)
                            chains = @($RouteEvidence.Evidence.Chains | ForEach-Object {
                                Protect-MihomoText ([string]$_) @($SensitiveValues)
                            })
                        }
                    } else { $null }
                    targetAddress = Protect-MihomoText $ServerAddress @($SensitiveValues)
                    controllerPort = $ControllerPort
                    prismOperationsPort = $PrismOperationsPort
                }
        }
        finally {
            $MihomoExited = Invoke-MihomoCleanupAction $CleanupFailures 'Mihomo process stop' {
                Stop-MihomoOwnedProcess $MihomoOwner
            }
            $ConfigRemoved = if ($MihomoExited) {
                Invoke-MihomoCleanupAction $CleanupFailures 'Mihomo config removal' {
                    Remove-MihomoCaseFile $CaseDirectory $AttemptConfig
                }
            }
            else {
                $false
            }
            $HomeRemoved = if ($MihomoExited) {
                Invoke-MihomoCleanupAction $CleanupFailures 'Mihomo home removal' {
                    Remove-MihomoCaseDirectory $CaseDirectory $AttemptHome
                }
            }
            else {
                $false
            }
            if ($null -eq $AttemptResult) {
                $AttemptResult = [ordered]@{
                    attempt = $Attempt
                    proxyPort = $AttemptProxyPort
                    mihomoPid = if ($null -eq $MihomoProcess) { 0 } else { $MihomoProcess.Id }
                    configPath = $AttemptConfig
                    configSha256 = $AttemptConfigSha256
                    prismExecutable = $PrismExecutable
                    prismSha256 = $PrismSha256
                    prismConfig = $PrismConfig
                    prismConfigSha256 = $PrismConfigSha256
                    mihomoExecutable = $MihomoExecutable
                    mihomoSha256 = $MihomoSha256
                    expectedProtocol = $ExpectedProtocol
                    serverLogObserved = [bool]$ServerEvidence.Observed
                    serverLogPath = $ServerEvidence.Path
                    serverLogExcerpt = Protect-MihomoText $ServerEvidence.Excerpt @($SensitiveValues)
                    responseBodyMatched = $false
                    targetAddress = Protect-MihomoText $ServerAddress @($SensitiveValues)
                    controllerPort = $ControllerPort
                    prismOperationsPort = $PrismOperationsPort
                    exitCode = 1
                    elapsedSeconds = 0
                    output = ''
                }
            }
            $AttemptResult['cleanup'] = [ordered]@{
                mihomoExited = [bool]$MihomoExited
                homeRemoved = [bool]$HomeRemoved
                configRemoved = [bool]$ConfigRemoved
                processesExited = $false
                cleanupFailures = @()
                cleanupSucceeded = $false
            }
            [void]$Results.Add($AttemptResult)
        }
    }
}
finally {
    $AllProcessesExited = $true
    foreach ($OwnedProcess in $Started) {
        if (-not (Invoke-MihomoCleanupAction $CleanupFailures 'owned process stop' {
                    Stop-MihomoOwnedProcess $OwnedProcess
                })) {
            $AllProcessesExited = $false
        }
    }
    if ($AllProcessesExited) {
        [void](Invoke-MihomoCleanupAction $CleanupFailures 'case log redaction' {
            Protect-MihomoCaseLogs $CaseDirectory @($SensitiveValues)
        })
        [void](Invoke-MihomoCleanupAction $CleanupFailures 'Prism config removal' {
            Remove-MihomoCaseFile $CaseDirectory $PrismConfig
        })
        foreach ($TemporaryDirectory in $TemporaryDirectories) {
            [void](Invoke-MihomoCleanupAction $CleanupFailures 'temporary Mihomo home removal' {
                Remove-MihomoCaseDirectory $CaseDirectory $TemporaryDirectory
            })
        }
        [void](Invoke-MihomoCleanupAction $CleanupFailures 'target fixture removal' {
            Remove-MihomoCaseDirectory $CaseDirectory $TargetRoot
        })
        if ($Results.Count -eq 0) {
            [void](Invoke-MihomoCleanupAction $CleanupFailures 'empty Prism log directory removal' {
                if (-not (Test-Path -LiteralPath $PrismLogRoot)) {
                    return $true
                }
                if (@(Get-ChildItem -LiteralPath $PrismLogRoot -Force -ErrorAction Stop).Count -gt 0) {
                    return $true
                }
                return (Remove-MihomoCaseDirectory $CaseDirectory $PrismLogRoot)
            })
        }
    }
    $PrismConfigRemoved = -not (Test-Path -LiteralPath $PrismConfig)
    foreach ($Result in $Results) {
        $Result['cleanup']['prismConfigRemoved'] = [bool]$PrismConfigRemoved
        $Result['cleanup']['processesExited'] = [bool]$AllProcessesExited
        $Result['cleanup']['cleanupFailures'] = @($CleanupFailures.ToArray())
        $Result['cleanup']['cleanupSucceeded'] = $CleanupFailures.Count -eq 0 -and $AllProcessesExited
        if (-not $AllProcessesExited -or $CleanupFailures.Count -gt 0) {
            $Result['exitCode'] = 1
            $CleanupMessage = if (-not $AllProcessesExited) {
                'cleanup could not verify every owned process; case configs and active logs were retained'
            } else {
                'cleanup item failed; see sanitized cleanupFailures'
            }
            $Result['output'] = (($Result['output'],
                $CleanupMessage) -join "`n")
        }
    }
    if ($CleanupFailures.Count -gt 0 -and $Results.Count -eq 0) {
        try {
            Write-Utf8NoBom (Join-Path $CaseDirectory 'cleanup-failures.log') `
                ($CleanupFailures -join "`n")
        }
        catch {
        }
    }
    foreach ($Result in $Results) {
        $AttemptConfigPath = [string]$Result['configPath']
        $Result['cleanup']['configRemoved'] = -not (Test-Path -LiteralPath $AttemptConfigPath)
        $Result['cleanup']['homeRemoved'] = -not (Test-Path -LiteralPath (Split-Path -Parent $AttemptConfigPath))
    }
}

if ($RepeatCount -lt 1 -or $Results.Count -ne $RepeatCount) {
    throw 'Mihomo TCP runner did not complete every requested attempt'
}
for ($Index = 0; $Index -lt $Results.Count; $Index++) {
    $ResultRouteChain = @($Results[$Index].controllerSelectedChain | ForEach-Object { [string]$_ })
    if ($ResultRouteChain.Count -lt 1 -or
        -not [string]::Equals([string]$Results[$Index].expectedProtocol, $ExpectedProtocol,
            [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'Mihomo TCP attempts do not share the validated case route or protocol'
    }
}
Protect-MihomoObjectInPlace $Results @($SensitiveValues)
$ResultJson = $Results | ConvertTo-Json -Depth 8
Write-Utf8NoBom (Join-Path $CaseDirectory 'results.json') $ResultJson
$ResultJson
if (@($Results | Where-Object {
        $_.exitCode -ne 0 -or $_.httpCode200Count -lt $_.concurrentRequests -or
        -not $_.responseBodyMatched -or -not $_.serverLogObserved -or
        -not $_.controllerProxiesApiResponded -or
        @($_.controllerSelectedChain).Count -ne @($ExpectedRouteChain).Count -or
        -not $_.routeEvidenceObserved -or
        -not $_.cleanup.cleanupSucceeded
    }).Count -gt 0) {
    exit 1
}
