#requires -Version 7.4
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$PrismTemplate,
    [Parameter(Mandatory = $true)][string]$MihomoTemplate,
    [string]$UdpEchoScript = '',
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9_.-]{1,48}$')]
    [string]$CaseDirectory,
    [ValidateRange(0, 65535)][int]$PrismPort = 0,
    [ValidateRange(0, 65535)][int]$PrismUdpPort = 0,
    [ValidateRange(0, 65535)][int]$TargetPort = 0,
    [ValidateRange(0, 65535)][int]$ProxyPort = 0,
    [switch]$UseUdpServerPort,
    [ValidatePattern('^$|^[A-Za-z0-9_. -]{1,128}$')][string]$ActiveProxy = '',
    [string]$MihomoExecutable = 'mihomo.exe',
    [ValidatePattern('^127\.0\.0\.1$|^::1$')][string]$ServerAddress = '127.0.0.1',
    [ValidateRange(0, 65535)][int]$ControllerPort = 0,
    [int]$WarmupSeconds = 0,
    [ValidateRange(1, 2147483647)][int]$RepeatCount = 3
)

if ($PSVersionTable.PSVersion -lt [Version]'7.4') {
    throw 'Mihomo interop runners require PowerShell 7.4 or newer'
}
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'MihomoTestSupport.ps1')
if ([string]::IsNullOrWhiteSpace($UdpEchoScript)) {
    $UdpEchoScript = Join-Path $PSScriptRoot 'RunUdpEchoServer.ps1'
}

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

function Get-FreeLoopbackPortPair {
    $First = Get-FreeLoopbackPort
    $Second = Get-FreeLoopbackPort @($First)
    return @($First, $Second)
}

$RepositoryRoot = [System.IO.Path]::GetFullPath(
    (Join-Path $PSScriptRoot '..\..\..\..'))
Assert-MihomoLocalFixedDirectoryPath $RepositoryRoot
if ($PrismPort -eq 0 -and $PrismUdpPort -eq 0) {
    $PrismPortPair = Get-FreeLoopbackPortPair
    $PrismPort = [int]$PrismPortPair[0]
    $PrismUdpPort = [int]$PrismPortPair[1]
}
elseif ($PrismPort -eq 0) {
    $PrismPort = Get-FreeLoopbackPort @($PrismUdpPort)
}
elseif ($PrismUdpPort -eq 0) {
    $PrismUdpPort = Get-FreeLoopbackPort @($PrismPort)
}
if ($PrismPort -lt 1 -or $PrismUdpPort -lt 1 -or $PrismPort -eq $PrismUdpPort) {
    throw 'UDP case requires distinct positive TCP and UDP Prism ports'
}
if ($TargetPort -eq 0) {
    $TargetPort = Get-FreeLoopbackPort @($PrismPort, $PrismUdpPort)
}
if ($ProxyPort -eq 0) {
    $ProxyPort = Get-FreeLoopbackPort @($PrismPort, $PrismUdpPort, $TargetPort)
}
if ($TargetPort -lt 1 -or $ProxyPort -lt 1 -or
    @($PrismPort, $PrismUdpPort, $TargetPort, $ProxyPort |
        Select-Object -Unique).Count -ne 4) {
    throw 'UDP case requires four distinct positive loopback port assignments'
}
$CaseDirectory = New-UniqueMihomoCaseDirectory $CaseDirectory
$PrismLogRoot = Join-Path $CaseDirectory 'prism-logs'
$PrismConfig = Join-Path $CaseDirectory 'prism.json'
$Started = [System.Collections.Generic.List[object]]::new()
$TemporaryDirectories = [System.Collections.Generic.List[string]]::new()
$EchoProcess = $null
$EchoProcessOwner = $null
$PrismProcess = $null
$PrismProcessOwner = $null
$Results = [System.Collections.Generic.List[object]]::new()
$CleanupFailures = [System.Collections.Generic.List[string]]::new()
$SensitiveValues = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase)
try {
$PrismExecutable = Assert-MihomoLocalFixedFilePath (
    Join-Path $RepositoryRoot 'build/src/Prism.exe')
$MihomoExecutable = Resolve-MihomoExecutable $MihomoExecutable
$PowerShellExecutable = Resolve-MihomoExecutablePath 'pwsh.exe'
$PrismSha256 = Get-Sha256 $PrismExecutable
$MihomoSha256 = Get-Sha256 $MihomoExecutable
$PrismTemplatePath = Assert-MihomoLocalFixedFilePath $PrismTemplate
$PrismTemplateDirectory = Split-Path -Parent $PrismTemplatePath
$MihomoTemplatePath = Assert-MihomoLocalFixedFilePath $MihomoTemplate
$UdpEchoScript = Assert-MihomoLocalFixedFilePath $UdpEchoScript
$PrismObject = Read-MihomoCasePrismConfiguration $PrismTemplatePath
foreach ($SensitiveValue in @(Get-MihomoConfigurationSensitiveValues $PrismObject)) {
    [void]$SensitiveValues.Add($SensitiveValue)
}
Set-MihomoPrismCaseListeners $PrismObject 'udp' $PrismPort $PrismUdpPort $ServerAddress
$PrismObject.Operations.WebDirectory = ''
Resolve-MihomoPrismLocalPaths $PrismObject $PrismTemplateDirectory
Set-MihomoPrismDialCarrierBackend $PrismObject 0
$PrismLogRoot = New-MihomoCaseSubdirectory $CaseDirectory 'prism-logs'
$PrismObject.Logging.Directory = $PrismLogRoot.Replace('\', '/')
$PrismObject.Logging.FileName = 'prism.log'
$ReservedPorts = @($PrismPort, $PrismUdpPort, $TargetPort, $ProxyPort)
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
$ReplacementPrismPort = if ($UseUdpServerPort) { $PrismUdpPort } else { $PrismPort }

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
$Yaml = Remove-MihomoControllerSettings $Yaml
$Yaml = Remove-MihomoNamedListenerSection $Yaml
$Yaml = Normalize-MihomoCaseNetworkConfiguration $Yaml
$Yaml = Set-MihomoTopLevelScalar $Yaml 'bind-address' '127.0.0.1'
$Yaml = Set-MihomoTopLevelScalar $Yaml 'allow-lan' 'false'
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
$InboundConfiguration = Normalize-MihomoIsolatedInbound $Yaml 'udp' $ProxyPort
$Yaml = $InboundConfiguration.Yaml
$ProxyPortKey = $InboundConfiguration.PortKey
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
$ExpectedProtocol = switch -Regex ($SelectedProxy) {
    '^Http' { 'http'; break }
    '^SOCKS5' { 'socks5'; break }
    '^VLESS' { 'vless'; break }
    '^Trojan' { 'trojan'; break }
    '^VMess' { 'vmess'; break }
    '^SS2022' { 'shadowsocks'; break }
    '^AnyTLS' { 'anytls'; break }
    '^Hysteria2' { 'hysteria2'; break }
    '^TUIC' { 'tuic'; break }
    default { '' }
}
if ([string]::IsNullOrWhiteSpace($ExpectedProtocol)) {
    throw 'UDP Mihomo case requires a supported selected protocol'
}
Assert-MihomoProxyMatchesScenario $Yaml $SelectedProxy $ExpectedProtocol
Assert-MihomoPrismProxyCredentials `
    $PrismObject $ExpectedProtocol $Yaml $SelectedProxy
$MihomoServerName = Get-MihomoOptionalProxyScalar $Yaml $SelectedProxy 'servername'
if ($null -ne $MihomoServerName) {
    Assert-MihomoPrismProxyServerName `
        $PrismObject $ExpectedProtocol $Yaml $SelectedProxy $MihomoServerName
}
$MihomoSni = Get-MihomoOptionalProxyScalar $Yaml $SelectedProxy 'sni'
if ($null -ne $MihomoSni) {
    Assert-MihomoPrismProxyServerName `
        $PrismObject $ExpectedProtocol $Yaml $SelectedProxy $MihomoSni
}
if ($null -ne $MihomoServerName -and $null -ne $MihomoSni -and
    -not [string]::Equals($MihomoServerName, $MihomoSni,
        [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'Mihomo UDP outbound has conflicting servername and sni fields'
}
if ($ExpectedProtocol -in @('hysteria2', 'tuic')) {
    $QuicProtocol = @($PrismObject.Protocols | Where-Object {
            [string]::Equals([string]$_.Name, $ExpectedProtocol,
                [System.StringComparison]::OrdinalIgnoreCase) -and
            $null -ne $_.PSObject.Properties['Quic']
        })
    if ($QuicProtocol.Count -ne 1) {
        throw 'UDP Mihomo case cannot resolve its Prism QUIC protocol settings'
    }
    Assert-MihomoPrismQuicCredential `
        $PrismObject $ExpectedProtocol $Yaml $SelectedProxy
    Assert-MihomoQuicProxyAlpn `
        $Yaml $SelectedProxy ([string]$QuicProtocol[0].Quic.Alpn)
}
$Yaml = Set-MihomoProxyEndpoint $Yaml $SelectedProxy $ServerAddress $ReplacementPrismPort
Assert-MihomoCaseNetworkIsolation $Yaml $true $ControllerPort $ControllerSecret
Assert-MihomoIsolatedRouteClosure `
    $Yaml $ExpectedRoute $SelectedProxy $ServerAddress $ReplacementPrismPort

$ChildEnvironment = New-MihomoIsolatedChildEnvironment

    Write-Utf8NoBom $PrismConfig ($PrismObject | ConvertTo-Json -Depth 100)
    $PrismReadback = Read-MihomoPrismConfigurationReadback $PrismConfig
    Assert-MihomoPrismLocalPaths $PrismReadback.Configuration
    Assert-MihomoPrismCaseLogging $PrismReadback.Configuration $CaseDirectory
    Assert-MihomoPrismDialCarrierBackend $PrismReadback.Configuration 0
    Assert-MihomoPrismConfigurationCase `
        -Configuration $PrismReadback.Configuration -Mode 'udp' `
        -TcpPort $PrismPort -OperationsPort $PrismOperationsPort `
        -ListenerAddress $ServerAddress -UdpPort $PrismUdpPort
    $PrismConfigSha256 = $PrismReadback.Sha256
    $EchoProcess = Start-Process -FilePath $PowerShellExecutable `
        -ArgumentList @('-NoProfile', '-File', $UdpEchoScript,
            '-Port', [string]$TargetPort) `
        -WorkingDirectory $RepositoryRoot -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput (Get-MihomoCaseArtifactPath $CaseDirectory `
            (Join-Path $CaseDirectory 'udp-echo.stdout.log')) `
        -RedirectStandardError (Get-MihomoCaseArtifactPath $CaseDirectory `
            (Join-Path $CaseDirectory 'udp-echo.stderr.log')) `
        -Environment $ChildEnvironment
    $EchoProcessOwner = Register-MihomoOwnedProcess $Started $EchoProcess $PowerShellExecutable

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
            (Get-Content -LiteralPath $ReadyLog -Raw) -match "Prism READY tcp_port=$PrismPort udp_port=$PrismUdpPort") {
            if ((Test-MihomoOwnedTcpPort $PrismProcessOwner $PrismPort $ServerAddress) -and
                (Test-MihomoOwnedTcpPort $PrismProcessOwner $PrismOperationsPort '127.0.0.1')) {
                $PrismReady = $true
                break
            }
        }
    }
    if (-not $PrismReady) {
        throw 'Prism UDP readiness timeout'
    }
    $UdpSocketsReady = $false
    for ($Index = 0; $Index -lt 40; $Index++) {
        if ($PrismProcess.HasExited) {
            throw "Prism exited with code $($PrismProcess.ExitCode) before UDP socket readiness"
        }
        if ($EchoProcess.HasExited) {
            throw "UDP echo exited with code $($EchoProcess.ExitCode) before UDP socket readiness"
        }
        if ((Test-MihomoOwnedUdpPort $PrismProcessOwner $PrismUdpPort $ServerAddress) -and
            (Test-MihomoOwnedUdpPort $EchoProcessOwner $TargetPort '127.0.0.1')) {
            $UdpSocketsReady = $true
            break
        }
        Start-Sleep -Milliseconds 250
    }
    if (-not $UdpSocketsReady) {
        throw "UDP socket readiness timeout prism=$PrismUdpPort echo=$TargetPort"
    }
    Start-Sleep -Seconds 2

    for ($Attempt = 1; $Attempt -le $RepeatCount; $Attempt++) {
        $AttemptResult = $null
        $ClientProcess = $null
        $ClientOwner = $null
        $MihomoProcess = $null
        $AttemptProxyPort = if ($Attempt -eq 1) {
            $ProxyPort
        } else {
            Get-FreeLoopbackPort @($ControllerPort, $PrismOperationsPort, $PrismPort,
                $PrismUdpPort, $TargetPort)
        }
        $AttemptHome = Join-Path $CaseDirectory ("mihomo-home-{0}" -f $Attempt)
        $AttemptHome = New-MihomoCaseSubdirectory $CaseDirectory (Split-Path -Leaf $AttemptHome)
        [void]$TemporaryDirectories.Add($AttemptHome)
        $AttemptConfig = Join-Path $AttemptHome 'config.yaml'
        $AttemptYaml = Set-MihomoTopLevelScalar $Yaml $ProxyPortKey ([string]$AttemptProxyPort)
        Assert-MihomoNoDnsListener $AttemptYaml
        Assert-MihomoNoShortcutInbounds $AttemptYaml
        Assert-MihomoNoProbeGroups $AttemptYaml
        Assert-MihomoIsolatedInboundPort $AttemptYaml $ProxyPortKey $AttemptProxyPort
        Assert-MihomoCaseNetworkIsolation $AttemptYaml $true $ControllerPort $ControllerSecret
        Assert-MihomoIsolatedRouteClosure `
            $AttemptYaml $ExpectedRoute $SelectedProxy $ServerAddress $ReplacementPrismPort
        Write-Utf8NoBom $AttemptConfig $AttemptYaml
        $AttemptConfigReadback = Get-Content -LiteralPath $AttemptConfig -Raw
        Assert-MihomoNoDnsListener $AttemptConfigReadback
        Assert-MihomoNoShortcutInbounds $AttemptConfigReadback
        Assert-MihomoNoProbeGroups $AttemptConfigReadback
        Assert-MihomoIsolatedInboundPort `
            $AttemptConfigReadback $ProxyPortKey $AttemptProxyPort
        Assert-MihomoCaseNetworkIsolation $AttemptConfigReadback $true $ControllerPort $ControllerSecret
        Assert-MihomoIsolatedRouteClosure `
            $AttemptConfigReadback $ExpectedRoute $SelectedProxy $ServerAddress $ReplacementPrismPort
        $AttemptConfigSha256 = Get-Sha256 $AttemptConfig
        $MihomoOut = Get-MihomoCaseArtifactPath $CaseDirectory `
            (Join-Path $CaseDirectory ("mihomo-{0}.stdout.log" -f $Attempt))
        $MihomoErr = Get-MihomoCaseArtifactPath $CaseDirectory `
            (Join-Path $CaseDirectory ("mihomo-{0}.stderr.log" -f $Attempt))
        $MihomoArguments = "-d `"$AttemptHome`" -f `"$AttemptConfig`""
        $MihomoOwner = $null
        $MihomoProcess = Start-Process -FilePath $MihomoExecutable `
            -ArgumentList $MihomoArguments `
            -WorkingDirectory $AttemptHome -WindowStyle Hidden -PassThru `
            -RedirectStandardOutput (Get-MihomoCaseArtifactPath $CaseDirectory $MihomoOut) `
            -RedirectStandardError (Get-MihomoCaseArtifactPath $CaseDirectory $MihomoErr) `
            -Environment $ChildEnvironment
        $MihomoOwner = Register-MihomoOwnedProcess $Started $MihomoProcess $MihomoExecutable
        try {
            $MihomoIdentity = Get-CimInstance Win32_Process `
                -Filter "ProcessId=$($MihomoProcess.Id)" -ErrorAction SilentlyContinue
            $CommandLine = if ($null -eq $MihomoIdentity) { '' } else { [string]$MihomoIdentity.CommandLine }
            if ($MihomoOwner.Stopped -or $null -eq $MihomoIdentity -or
                -not (Test-MihomoOwnedProcessIdentity $MihomoOwner) -or
                -not [string]::Equals([string]$MihomoIdentity.ExecutablePath,
                    $MihomoOwner.Path, [System.StringComparison]::OrdinalIgnoreCase) -or
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
                $AttemptProxyListenerPorts = @($AttemptProxyPort)
                $AllProxyListenersReady = $true
                foreach ($ProxyListenerPort in $AttemptProxyListenerPorts) {
                    if (-not (Test-MihomoOwnedTcpPort $MihomoOwner $ProxyListenerPort '127.0.0.1') -or
                        -not (Test-MihomoOwnedUdpPort $MihomoOwner $ProxyListenerPort '127.0.0.1')) {
                        $AllProxyListenersReady = $false
                        break
                    }
                }
                if ($AllProxyListenersReady) {
                    $ProxyReady = $true
                    break
                }
            }
            if (-not $ProxyReady) {
                throw 'Mihomo proxy endpoint ownership or loopback readiness timeout'
            }
    $ProxySelection = Get-MihomoSelectedProxyChainSnapshot `
        $ControllerPort $ControllerSecret $MihomoOwner $ExpectedRouteChain
    $ProxySelectionSha256 = [Convert]::ToHexString(
        [System.Security.Cryptography.SHA256]::HashData(
            [System.Text.UTF8Encoding]::new($false).GetBytes(
                ($ProxySelection | ConvertTo-Json -Depth 12 -Compress)))).ToUpperInvariant()
            if ($WarmupSeconds -gt 0) {
                Start-Sleep -Seconds $WarmupSeconds
            }
            $Payload = "prism-udp-$Attempt"
            $StartedAt = Get-Date
            $ClientStdout = Join-Path $CaseDirectory ("udp-client-{0}.stdout.log" -f $Attempt)
            $ClientStderr = Join-Path $CaseDirectory ("udp-client-{0}.stderr.log" -f $Attempt)
            $ClientStdout = Get-MihomoCaseArtifactPath $CaseDirectory $ClientStdout
            $ClientStderr = Get-MihomoCaseArtifactPath $CaseDirectory $ClientStderr
            $ClientScript = Assert-MihomoLocalFixedFilePath (
                Join-Path $PSScriptRoot 'RunSocks5UdpClient.ps1')
            if (-not (Test-MihomoOwnedUdpPort $PrismProcessOwner $PrismUdpPort $ServerAddress) -or
                -not (Test-MihomoOwnedUdpPort $EchoProcessOwner $TargetPort '127.0.0.1') -or
                -not (Test-MihomoOwnedTcpPort $PrismProcessOwner $PrismPort $ServerAddress) -or
                -not (Test-MihomoOwnedTcpPort $PrismProcessOwner $PrismOperationsPort '127.0.0.1')) {
                throw 'UDP request endpoints are not exclusively owned loopback sockets'
            }
            foreach ($ProxyListenerPort in $AttemptProxyListenerPorts) {
                if (-not (Test-MihomoOwnedTcpPort $MihomoOwner $ProxyListenerPort '127.0.0.1') -or
                    -not (Test-MihomoOwnedUdpPort $MihomoOwner $ProxyListenerPort '127.0.0.1')) {
                    throw 'UDP proxy endpoints are not exclusively owned loopback sockets'
                }
            }
            $ClientProcess = Start-Process -FilePath $PowerShellExecutable `
                -ArgumentList @('-NoProfile', '-File', $ClientScript,
                    '-ProxyPort', [string]$AttemptProxyPort,
                    '-TargetPort', [string]$TargetPort,
                    '-PayloadText', $Payload,
                    '-RepeatCount', '40',
                    '-DelayMilliseconds', '50') `
                -WorkingDirectory $RepositoryRoot -WindowStyle Hidden -PassThru `
                -RedirectStandardOutput (Get-MihomoCaseArtifactPath $CaseDirectory $ClientStdout) `
                -RedirectStandardError (Get-MihomoCaseArtifactPath $CaseDirectory $ClientStderr) `
                -Environment $ChildEnvironment
            $ClientOwner = Register-MihomoOwnedProcess $Started $ClientProcess $PowerShellExecutable
            $RouteEvidence = Wait-MihomoRouteEvidence @($ClientProcess) $MihomoOwner $ControllerPort `
                $ControllerSecret '127.0.0.1' $TargetPort $AttemptProxyPort 'udp' $ExpectedRoute `
                $ExpectedRouteChain 35
            if (-not $ClientProcess.WaitForExit(35000)) {
                throw "SOCKS5 UDP client did not exit: PID $($ClientProcess.Id)"
            }
            $ExitCode = $ClientProcess.ExitCode
            $Output = [System.Collections.Generic.List[string]]::new()
            if (Test-Path -LiteralPath $ClientStdout) {
                $Output.AddRange([string[]](Get-Content -LiteralPath $ClientStdout))
            }
            if (Test-Path -LiteralPath $ClientStderr) {
                $Output.AddRange([string[]](Get-Content -LiteralPath $ClientStderr))
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
            Write-Utf8NoBom (Join-Path $CaseDirectory ("udp-client-{0}.log" -f $Attempt)) `
                ($Output -join "`n")
            $AttemptResult = [ordered]@{
                    attempt = $Attempt
                    proxyPort = $AttemptProxyPort
                    mihomoPid = if ($null -eq $MihomoProcess) { 0 } else { $MihomoProcess.Id }
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
                    dnsSourceHandling = 'source template is read-only; dns section is removed from the case copy'
                    targetAddress = Protect-MihomoText $ServerAddress @($SensitiveValues)
                    controllerPort = $ControllerPort
                    prismOperationsPort = $PrismOperationsPort
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
                }
        }
        finally {
            $ClientExited = Invoke-MihomoCleanupAction $CleanupFailures 'UDP client process stop' {
                Stop-MihomoOwnedProcess $ClientOwner
            }
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
                    mihomoPid = $MihomoProcess.Id
                    configPath = $AttemptConfig
                    configSha256 = $AttemptConfigSha256
                    prismExecutable = $PrismExecutable
                    prismSha256 = $PrismSha256
                    prismConfig = $PrismConfig
                    prismConfigSha256 = $PrismConfigSha256
                    mihomoExecutable = $MihomoExecutable
                    mihomoSha256 = $MihomoSha256
                    targetAddress = Protect-MihomoText $ServerAddress @($SensitiveValues)
                    controllerPort = $ControllerPort
                    prismOperationsPort = $PrismOperationsPort
                    exitCode = 1
                    elapsedSeconds = 0
                    output = ''
                }
            }
            $AttemptResult['cleanup'] = [ordered]@{
                clientExited = [bool]$ClientExited
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
    throw 'Mihomo UDP runner did not complete every requested attempt'
}
for ($Index = 0; $Index -lt $Results.Count; $Index++) {
    $SelectedChain = @($Results[$Index].controllerSelectedChain | ForEach-Object { [string]$_ })
    if (-not [bool]$Results[$Index].controllerProxiesApiResponded -or
        $SelectedChain.Count -lt 1 -or $SelectedChain[0] -ne $SelectedProxy) {
        throw 'Mihomo UDP attempt does not report its verified controller proxy chain'
    }
}
Protect-MihomoObjectInPlace $Results @($SensitiveValues)
$ResultJson = $Results | ConvertTo-Json -Depth 8
Write-Utf8NoBom (Join-Path $CaseDirectory 'results.json') $ResultJson
$ResultJson
if (@($Results | Where-Object {
        $_.exitCode -ne 0 -or $_.output -notmatch 'UDP_ECHO_OK=' -or
        -not $_.controllerProxiesApiResponded -or
        @($_.controllerSelectedChain).Count -ne @($ExpectedRouteChain).Count -or
        -not $_.routeEvidenceObserved -or -not $_.cleanup.cleanupSucceeded
    }).Count -gt 0) {
    exit 1
}
