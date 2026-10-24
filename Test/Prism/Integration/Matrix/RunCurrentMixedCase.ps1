#requires -Version 7.4
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$PrismTemplate,
    [Parameter(Mandatory = $true)][string]$MihomoTemplate,
    [Parameter(Mandatory = $true)][string]$CaseDirectory,
    [ValidatePattern('^127\.0\.0\.1$|^::1$')][string]$ServerAddress = '127.0.0.1',
    [string]$MihomoExecutable = 'mihomo.exe'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'MihomoTestSupport.ps1')

if ($PSVersionTable.PSVersion -lt [Version]'7.4') {
    throw 'Mihomo interop runners require PowerShell 7.4 or newer'
}

function Write-Utf8NoBom {
    param([string]$Path, [string]$Content)
    [System.IO.File]::WriteAllText($Path, $Content, [System.Text.UTF8Encoding]::new($false))
}

function Get-FreePort {
    for ($Attempt = 0; $Attempt -lt 64; $Attempt++) {
        $Listener = [System.Net.Sockets.TcpListener]::new(
            [System.Net.IPAddress]::Loopback, 0)
        $Udp = $null
        try {
            $Listener.Start()
            $Port = ([System.Net.IPEndPoint]$Listener.LocalEndpoint).Port
            $Udp = [System.Net.Sockets.UdpClient]::new(
                [System.Net.IPAddress]::Loopback, $Port)
            return $Port
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

function Get-UniqueFreePort {
    param([int[]]$AvoidPorts = @())

    do {
        $Port = Get-FreePort
    } while ($Port -in $AvoidPorts)
    return $Port
}

function Get-Sha256 {
    param([string]$Path)
    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToUpperInvariant()
}

$CaseDirectory = New-UniqueMihomoCaseDirectory (Split-Path -Leaf $CaseDirectory)
$PrismTemplatePath = Assert-MihomoLocalFixedFilePath $PrismTemplate
$MihomoTemplatePath = Assert-MihomoLocalFixedFilePath $MihomoTemplate
$PrismTemplateDirectory = Split-Path -Parent $PrismTemplatePath
$MihomoExecutablePath = Resolve-MihomoExecutable $MihomoExecutable
$CurlExecutablePath = Resolve-MihomoExecutablePath 'curl.exe'
$PrismExecutablePath = Assert-MihomoLocalFixedFilePath (
    Join-Path (Get-Location) 'build/src/Prism.exe')
$FileServerPath = Assert-MihomoLocalFixedFilePath (
    Join-Path (Get-Location) 'build/Test/Prism/Integration/PrismMatrixFileServer.exe')
$PrismLogRoot = Join-Path $CaseDirectory 'prism-logs'
$TargetRoot = Join-Path $CaseDirectory 'target-root'
New-Item -ItemType Directory -Force -Path $PrismLogRoot, $TargetRoot | Out-Null
$TargetResponse = [byte[]]::new(64 * 1024)
for ($Index = 0; $Index -lt $TargetResponse.Length; $Index++) {
    $TargetResponse[$Index] = [byte]($Index % 251)
}
[System.IO.File]::WriteAllBytes(
    (Join-Path $TargetRoot 'hello.txt'), $TargetResponse)

$PrismPort = Get-UniqueFreePort
$PrismUdpPort = Get-UniqueFreePort @($PrismPort)
$PrismQuicPort = Get-UniqueFreePort @($PrismPort, $PrismUdpPort)
$TargetPort = Get-UniqueFreePort @($PrismPort, $PrismUdpPort, $PrismQuicPort)
$OperationsPort = Get-UniqueFreePort @($PrismPort, $PrismUdpPort, $PrismQuicPort, $TargetPort)
$PrismObject = Read-MihomoCasePrismConfiguration $PrismTemplatePath
$PrismObject.Listeners.Tcp[0].Address = $ServerAddress
$PrismObject.Listeners.Tcp[0].Port = $PrismPort
$PrismObject.Listeners.Udp[0].Address = $ServerAddress
$PrismObject.Listeners.Udp[0].Port = $PrismUdpPort
$PrismObject.Listeners.Quic[0].Address = $ServerAddress
$PrismObject.Listeners.Quic[0].Port = $PrismQuicPort
$PrismObject.NativeTls.CertificateFile = [System.IO.Path]::GetFullPath(
    (Join-Path $PrismTemplateDirectory $PrismObject.NativeTls.CertificateFile))
$PrismObject.NativeTls.PrivateKeyFile = [System.IO.Path]::GetFullPath(
    (Join-Path $PrismTemplateDirectory $PrismObject.NativeTls.PrivateKeyFile))
foreach ($Carrier in @($PrismObject.Carriers)) {
    foreach ($PropertyName in @('CertificateFile', 'PrivateKeyFile')) {
        if ($Carrier.Options.PSObject.Properties.Name -contains $PropertyName) {
            $Carrier.Options.$PropertyName = [System.IO.Path]::GetFullPath(
                (Join-Path $PrismTemplateDirectory $Carrier.Options.$PropertyName))
        }
    }
}
$PrismObject.Logging.Directory = $PrismLogRoot.Replace('\', '/')
$PrismObject.Logging.FileName = 'prism-mixed.log'
$PrismObject.Logging.Level = 'Trace'
$PrismObject.Operations.Endpoint = "127.0.0.1:$OperationsPort"
$Hysteria2Protocols = @($PrismObject.Protocols | Where-Object Id -eq 'protocol-hysteria2')
if ($Hysteria2Protocols.Count -ne 1 -or $null -eq $Hysteria2Protocols[0].Quic) {
    throw 'Mixed matrix Prism configuration requires exactly one Hysteria2 QUIC protocol'
}
$Hysteria2SecretReference = [string]$Hysteria2Protocols[0].Quic.CredentialSecretRef
$Hysteria2Alpn = [string]$Hysteria2Protocols[0].Quic.Alpn
$Hysteria2SecretProperty = $PrismObject.Secrets.PSObject.Properties[$Hysteria2SecretReference]
if ([string]::IsNullOrWhiteSpace($Hysteria2SecretReference) -or
    $null -eq $Hysteria2SecretProperty -or
    [string]::IsNullOrEmpty([string]$Hysteria2SecretProperty.Value)) {
    throw 'Mixed matrix Prism configuration lacks the Hysteria2 secret scope'
}
$PrismConfig = Join-Path $CaseDirectory 'prism.json'
Write-Utf8NoBom $PrismConfig ($PrismObject | ConvertTo-Json -Depth 100)
$PrismReadback = Read-MihomoPrismConfigurationReadback $PrismConfig
Assert-MihomoPrismMixedConfigurationCase `
    -Configuration $PrismReadback.Configuration `
    -TcpPort $PrismPort -UdpPort $PrismUdpPort -QuicPort $PrismQuicPort `
    -OperationsPort $OperationsPort -ListenerAddress $ServerAddress

$ChildEnvironment = New-MihomoIsolatedChildEnvironment

$Cases = @(
    @{Name = 'Http'; Protocol = 'http'; Slug = 'http'},
    @{Name = 'SOCKS5 TCP Cert'; Protocol = 'socks5'; Slug = 'socks5'},
    @{Name = 'VLESS TCP'; Protocol = 'vless'; Slug = 'vless'},
    @{Name = 'Trojan Native TLS TCP'; Protocol = 'trojan'; Slug = 'trojan-native'},
    @{Name = 'VMess TCP'; Protocol = 'vmess'; Slug = 'vmess'},
    @{Name = 'SS2022 TCP'; Protocol = 'shadowsocks'; Slug = 'ss2022'},
    @{Name = 'VLESS Smux TCP'; Protocol = 'vless'; Slug = 'vless-smux'},
    @{Name = 'VLESS Yamux TCP'; Protocol = 'vless'; Slug = 'vless-yamux'},
    @{Name = 'VLESS H2Mux TCP'; Protocol = 'vless'; Slug = 'vless-h2mux'},
    @{Name = 'Trojan Smux TCP'; Protocol = 'trojan'; Slug = 'trojan-smux'},
    @{Name = 'VMess Yamux TCP'; Protocol = 'vmess'; Slug = 'vmess-yamux'},
    @{Name = 'AnyTLS TCP'; Protocol = 'anytls'; Slug = 'anytls'},
    @{Name = 'Hysteria2 QUIC'; Protocol = 'hysteria2'; Slug = 'hysteria2'}
)
$Started = [System.Collections.Generic.List[object]]::new()
$CurlProcesses = [System.Collections.Generic.List[object]]::new()
$Results = [System.Collections.Generic.List[object]]::new()
$CleanupFailures = [System.Collections.Generic.List[string]]::new()
$PrismProcess = $null
$TargetProcess = $null
$Summary = $null
$AllSensitiveValues = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase)
foreach ($SensitiveValue in @(Get-MihomoConfigurationSensitiveValues $PrismObject)) {
    [void]$AllSensitiveValues.Add($SensitiveValue)
}
$ProxyCredentials = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::Ordinal)
$CredentialSets = @($PrismObject.Accounts) | ForEach-Object {
    if ($null -ne $_.Credentials) { $_.Credentials }
}
foreach ($CredentialSet in $CredentialSets) {
    foreach ($Credential in @($CredentialSet.PSObject.Properties)) {
        if ($Credential.Value -is [string] -and
            -not [string]::IsNullOrEmpty([string]$Credential.Value)) {
            [void]$ProxyCredentials.Add([string]$Credential.Value)
            [void]$AllSensitiveValues.Add([string]$Credential.Value)
        }
    }
}

try {
    $TargetProcess = Start-Process -FilePath $FileServerPath -ArgumentList @($TargetRoot, $TargetPort, '1') -WorkingDirectory (Get-Location) -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $CaseDirectory 'target.stdout.log') -RedirectStandardError (Join-Path $CaseDirectory 'target.stderr.log') -Environment $ChildEnvironment
    $TargetOwner = Register-MihomoOwnedProcess $Started $TargetProcess $FileServerPath
    $PrismProcess = Start-Process -FilePath $PrismExecutablePath -ArgumentList @((Resolve-Path $PrismConfig).Path) -WorkingDirectory (Get-Location) -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $CaseDirectory 'prism.stdout.log') -RedirectStandardError (Join-Path $CaseDirectory 'prism.stderr.log') -Environment $ChildEnvironment
    $PrismOwner = Register-MihomoOwnedProcess $Started $PrismProcess $PrismExecutablePath
    $Ready = $false
    for ($Index = 0; $Index -lt 60; $Index++) {
        Start-Sleep -Milliseconds 250
        if ($PrismProcess.HasExited) { throw "Prism exited with code $($PrismProcess.ExitCode)" }
        $ReadyLog = Join-Path $CaseDirectory 'prism.stdout.log'
        if ((Test-Path -LiteralPath $ReadyLog) -and (Get-Content -LiteralPath $ReadyLog -Raw) -match 'Prism READY') {
            $Ready = $true
            break
        }
    }
    if (-not $Ready) { throw 'Prism readiness timeout' }
    if (-not (Test-MihomoOwnedTcpPort $PrismOwner $PrismPort $ServerAddress) -or
        -not (Test-MihomoOwnedUdpPort $PrismOwner $PrismUdpPort $ServerAddress) -or
        -not (Test-MihomoOwnedUdpPort $PrismOwner $PrismQuicPort $ServerAddress) -or
        -not (Test-MihomoOwnedTcpPort $PrismOwner $OperationsPort '127.0.0.1') -or
        -not (Test-MihomoOwnedTcpPort $TargetOwner $TargetPort '127.0.0.1')) {
        throw 'Mixed matrix Prism or target endpoints are not exclusively owned on loopback'
    }

    $YamlTemplateText = Get-Content -LiteralPath $MihomoTemplatePath -Raw
    Assert-MihomoTemplateProxyEndpointsAreLoopback $YamlTemplateText
    $YamlTemplate = Remove-MihomoTopLevelSections $YamlTemplateText @('dns', 'hosts')
    $ReservedPrismPorts = @($PrismPort, $PrismUdpPort, $PrismQuicPort, $TargetPort, $OperationsPort)
    $UsedCasePorts = [System.Collections.Generic.List[int]]::new()
    foreach ($ReservedPort in $ReservedPrismPorts) {
        $UsedCasePorts.Add([int]$ReservedPort)
    }
    foreach ($Case in $Cases) {
        $CaseDir = Join-Path $CaseDirectory $Case.Slug
        New-Item -ItemType Directory -Force -Path $CaseDir | Out-Null
        $ProxyPort = Get-UniqueFreePort @($UsedCasePorts)
        $UsedCasePorts.Add($ProxyPort)
        $SocksPort = Get-UniqueFreePort @($UsedCasePorts)
        $UsedCasePorts.Add($SocksPort)
        $ControllerPort = Get-UniqueFreePort @($UsedCasePorts)
        $UsedCasePorts.Add($ControllerPort)
        $ControllerSecret = New-MihomoControllerSecret
        [void]$AllSensitiveValues.Add($ControllerSecret)
        $Yaml = $YamlTemplate
        $Yaml = Set-MihomoTopLevelScalar $Yaml 'mixed-port' ([string]$ProxyPort)
        $Yaml = Set-MihomoTopLevelScalar $Yaml 'socks-port' ([string]$SocksPort)
        $Yaml = Remove-MihomoControllerSettings $Yaml
        $Yaml = Set-MihomoTopLevelScalar $Yaml 'external-controller' "127.0.0.1:$ControllerPort"
        $Yaml = Set-MihomoTopLevelScalar $Yaml 'secret' $ControllerSecret
        $Yaml = Set-MihomoTopLevelScalar $Yaml 'bind-address' '127.0.0.1'
        $Yaml = Set-MihomoTopLevelScalar $Yaml 'allow-lan' 'false'
        $Yaml = [regex]::Replace($Yaml, '(?m)^\s*-\s*IP-CIDR,127\.0\.0\.0/8,DIRECT\s*\r?\n', '')
        $Yaml = [regex]::Replace($Yaml, '^(?<indent>\s*)socks5\.preview\s*:\s*.*$',
            '${indent}socks5.preview: 127.0.0.1',
            [System.Text.RegularExpressions.RegexOptions]::Multiline)
        $Yaml = [regex]::Replace($Yaml,
            '(?m)^\s*-\s*MATCH,(?:Prism(?:Preview)?-Active)\s*$',
            "  - MATCH,$($Case.Name)")
        $Yaml = Set-MihomoTopLevelScalar $Yaml 'mode' 'rule'
        $Yaml = [regex]::Replace($Yaml, '(?m)^\s+server:\s+.*$', "    server: $ServerAddress")
        $Yaml = [regex]::Replace($Yaml,
            '(?m)^(\s+port:)\s+18080\s*$',
            ('$1 ' + $PrismPort))
        $SelectedPort = if ($Case.Protocol -eq 'hysteria2') { $PrismQuicPort } else { $PrismPort }
        $Yaml = Set-MihomoTopLevelScalar $Yaml 'geo-auto-update' 'false'
        $MihomoHome = Join-Path $CaseDir 'mihomo-home'
        New-Item -ItemType Directory -Force -Path $MihomoHome | Out-Null
        $Config = Join-Path $MihomoHome 'config.yaml'
        $ConfigDraft = Join-Path $MihomoHome 'config.draft.yaml'
        Write-Utf8NoBom $ConfigDraft $Yaml
        $ConfigDraftReadback = Get-Content -LiteralPath $ConfigDraft -Raw
        $ExpectedRoute = (@(Get-MihomoMatchTargets $ConfigDraftReadback)[0])
        if ($ExpectedRoute -ne $Case.Name) {
            throw "Mihomo route target does not match case: $($Case.Name)"
        }
        $ConfigDraftReadback = Set-MihomoIsolatedRouteClosure $ConfigDraftReadback $ExpectedRoute
        $PrismRouteChain = @(Get-MihomoExpectedRouteChain $ConfigDraftReadback $ExpectedRoute)
        if ($PrismRouteChain.Count -lt 1) {
            throw "Mihomo route closure produced no selected chain: $($Case.Name)"
        }
        $SelectedProxy = $PrismRouteChain[0]
        Assert-MihomoProxyMatchesScenario $ConfigDraftReadback $SelectedProxy $Case.Protocol
        Assert-MihomoPrismProxyCredentials `
            $PrismObject $Case.Protocol $ConfigDraftReadback $SelectedProxy
        $MihomoServerName = Get-MihomoOptionalProxyScalar `
            $ConfigDraftReadback $SelectedProxy 'servername'
        if ($null -ne $MihomoServerName) {
            Assert-MihomoPrismProxyServerName `
                $PrismObject $Case.Protocol $ConfigDraftReadback $SelectedProxy `
                $MihomoServerName
        }
        $MihomoSni = Get-MihomoOptionalProxyScalar `
            $ConfigDraftReadback $SelectedProxy 'sni'
        if ($null -ne $MihomoSni) {
            Assert-MihomoPrismProxyServerName `
                $PrismObject $Case.Protocol $ConfigDraftReadback $SelectedProxy `
                $MihomoSni
        }
        if ($null -ne $MihomoServerName -and $null -ne $MihomoSni -and
            -not [string]::Equals($MihomoServerName, $MihomoSni,
                [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Mihomo outbound has conflicting servername and sni fields: $($Case.Name)"
        }
        if ($Case.Protocol -eq 'hysteria2') {
            if ($null -eq $MihomoSni) {
                throw "Hysteria2 outbound must declare a SNI synchronized with Prism: $($Case.Name)"
            }
            Assert-MihomoPrismQuicCredential `
                $PrismObject $Case.Protocol $ConfigDraftReadback $SelectedProxy
            Assert-MihomoQuicProxyAlpn `
                $ConfigDraftReadback $SelectedProxy $Hysteria2Alpn
        }
        $ConfigDraftReadback = Set-MihomoProxyEndpoint `
            $ConfigDraftReadback $SelectedProxy $ServerAddress $SelectedPort
        Assert-MihomoCaseNetworkIsolation `
            $ConfigDraftReadback $true $ControllerPort $ControllerSecret
        Assert-MihomoIsolatedRouteClosure `
            $ConfigDraftReadback $ExpectedRoute $SelectedProxy $ServerAddress $SelectedPort
        Write-Utf8NoBom $Config $ConfigDraftReadback
        $ConfigReadback = Get-Content -LiteralPath $Config -Raw
        if (@(Get-MihomoProxyEntries $ConfigReadback).Count -ne 1) {
            throw "Mixed case retained unexpected outbounds: $($Case.Name)"
        }
        Assert-MihomoCaseNetworkIsolation $ConfigReadback $true $ControllerPort $ControllerSecret
        Assert-MihomoIsolatedRouteClosure `
            $ConfigReadback $ExpectedRoute $SelectedProxy $ServerAddress $SelectedPort
        [void](Remove-MihomoCaseFile $CaseDirectory $ConfigDraft)
        $MihomoArguments = @('-d', $MihomoHome, '-f', $Config)
        $QuotedMihomoArguments = @($MihomoArguments | ForEach-Object { '"' + $_ + '"' })
        $Mihomo = Start-Process -FilePath $MihomoExecutablePath `
            -ArgumentList $QuotedMihomoArguments `
            -WorkingDirectory $MihomoHome `
            -WindowStyle Hidden -PassThru `
            -RedirectStandardOutput (Join-Path $CaseDir 'mihomo.stdout.log') `
            -RedirectStandardError (Join-Path $CaseDir 'mihomo.stderr.log') `
            -Environment $ChildEnvironment
        $MihomoOwner = Register-MihomoOwnedProcess $Started $Mihomo $MihomoExecutablePath
        $Case.MihomoOwner = $MihomoOwner
        $Case.MihomoPid = $Mihomo.Id
        $Case.ControllerPort = $ControllerPort
        $Case.ControllerSecret = $ControllerSecret
        $Case.ProxyPort = $ProxyPort
        $Case.RouteChain = $PrismRouteChain
        $Case.ConfigReadback = $ConfigReadback
        $Case.ConfigSha = Get-Sha256 $Config
        $Case.MihomoSha = Get-Sha256 $MihomoExecutablePath
        $MihomoReady = $false
        for ($Index = 0; $Index -lt 60; $Index++) {
            Start-Sleep -Milliseconds 250
            if ($Mihomo.HasExited) { throw "$($Case.Name) Mihomo exited with code $($Mihomo.ExitCode)" }
            Assert-MihomoNoUnexpectedDefaultProxyListener $MihomoOwner
            if ((Test-MihomoOwnedTcpPort $MihomoOwner $ProxyPort '127.0.0.1') -and
                (Test-MihomoOwnedUdpPort $MihomoOwner $ProxyPort '127.0.0.1') -and
                (Test-MihomoOwnedTcpPort $MihomoOwner $ControllerPort '127.0.0.1')) {
                $MihomoReady = $true
                break
            }
        }
        if (-not $MihomoReady) { throw "$($Case.Name) Mihomo readiness timeout" }
        $ProxySelection = Get-MihomoSelectedProxyChainSnapshot `
            $ControllerPort $ControllerSecret $MihomoOwner $PrismRouteChain
        $ProxySelectionSha256 = [Convert]::ToHexString(
            [System.Security.Cryptography.SHA256]::HashData(
                [System.Text.UTF8Encoding]::new($false).GetBytes(
                    ($ProxySelection | ConvertTo-Json -Depth 12 -Compress)))).ToUpperInvariant()
        $Case.ProxySelectionSha256 = $ProxySelectionSha256
    }

    foreach ($Case in $Cases) {
        $CaseDir = Join-Path $CaseDirectory $Case.Slug
        $Body = Join-Path $CaseDir 'body.txt'
        $CurlOut = Join-Path $CaseDir 'curl.stdout.log'
        $CurlErr = Join-Path $CaseDir 'curl.stderr.log'
        $CurlArguments = @(
            '-q', '--noproxy=', '--proxy', "http://127.0.0.1:$($Case.ProxyPort)",
            '--max-time', '30', '--limit-rate', '32k', '--silent', '--show-error',
            '--output', $Body,
            '--write-out', 'HTTP_CODE=%{http_code};TIME=%{time_total}',
            "http://127.0.0.1:$TargetPort/hello.txt")
        Assert-MihomoCurlArgumentsDisableDefaults $CurlArguments
        $Curl = Start-Process -FilePath $CurlExecutablePath -ArgumentList $CurlArguments `
            -WorkingDirectory (Get-Location) -WindowStyle Hidden -PassThru `
            -RedirectStandardOutput $CurlOut -RedirectStandardError $CurlErr `
            -Environment $ChildEnvironment
        $CurlOwner = Register-MihomoOwnedProcess $Started $Curl $CurlExecutablePath
        [void]$CurlProcesses.Add([pscustomobject]@{Case = $Case; Process = $Curl; Owner = $CurlOwner; Out = $CurlOut; Err = $CurlErr; Body = $Body})
    }
    $RouteRequests = @($CurlProcesses | ForEach-Object {
        $Case = $_.Case
        [pscustomobject]@{
            Key = [string]$Case.Slug
            Process = $_.Process
            MihomoOwner = $Case.MihomoOwner
            ControllerPort = $Case.ControllerPort
            ControllerSecret = $Case.ControllerSecret
            TargetAddress = '127.0.0.1'
            TargetPort = $TargetPort
            ExpectedInboundPort = $Case.ProxyPort
            ExpectedNetwork = 'tcp'
            ExpectedRoute = $Case.Name
            ExpectedChain = @($Case.RouteChain)
        }
    })
    $RouteEvidenceResults = Wait-MihomoRouteEvidenceBatch $RouteRequests
    foreach ($Case in $Cases) {
        $MatchedEvidence = @($RouteEvidenceResults | Where-Object Key -eq $Case.Slug)
        if ($MatchedEvidence.Count -ne 1) {
            throw "Mixed matrix lacks one controller evidence record for $($Case.Name)"
        }
        $Case.RouteEvidence = $MatchedEvidence[0]
    }
    foreach ($Entry in $CurlProcesses) {
        if (Get-Process -Id $Entry.Process.Id -ErrorAction SilentlyContinue) {
            try {
                Wait-Process -Id $Entry.Process.Id -Timeout 40 -ErrorAction Stop
            }
            catch {
                if (Get-Process -Id $Entry.Process.Id -ErrorAction SilentlyContinue) {
                    throw
                }
            }
        }
    }

    Start-Sleep -Seconds 1
    $PrismLogText = ((Get-ChildItem -LiteralPath $PrismLogRoot -File -ErrorAction SilentlyContinue | ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw }) -join ([Environment]::NewLine))
    foreach ($Entry in $CurlProcesses) {
        $Case = $Entry.Case
        $Output = if (Test-Path -LiteralPath $Entry.Out) { Get-Content -LiteralPath $Entry.Out -Raw } else { '' }
        $CaseDataPlanePattern = if ($Case.Protocol -eq 'anytls') {
            '[Protocol=anytls].*stage=mux outcome=started'
        }
        else {
            ('\[Protocol=' + [regex]::Escape($Case.Protocol) + '\].*stage=relay outcome=success')
        }
        $Observed = [regex]::IsMatch(
            $PrismLogText, $CaseDataPlanePattern,
            [System.Text.RegularExpressions.RegexOptions]::Singleline)
        $BodyBytes = if (Test-Path -LiteralPath $Entry.Body) {
            [System.IO.File]::ReadAllBytes($Entry.Body)
        }
        else {
            [byte[]]@()
        }
        $BodyOk = $BodyBytes.Length -eq $TargetResponse.Length
        for ($Index = 0; $BodyOk -and $Index -lt $TargetResponse.Length; $Index++) {
            $BodyOk = $BodyBytes[$Index] -eq $TargetResponse[$Index]
        }
        $SensitiveValuesForResult = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::OrdinalIgnoreCase)
        foreach ($SensitiveValue in @(Get-MihomoConfigurationSensitiveValues $PrismObject)) {
            [void]$SensitiveValuesForResult.Add($SensitiveValue)
        }
        foreach ($SensitiveValue in @(Get-MihomoYamlSensitiveValues $Case.ConfigReadback)) {
            [void]$SensitiveValuesForResult.Add($SensitiveValue)
        }
        foreach ($ProxyCredential in $ProxyCredentials) {
            [void]$SensitiveValuesForResult.Add($ProxyCredential)
        }
        [void]$SensitiveValuesForResult.Add($Case.ControllerSecret)
        $CaseOutput = Protect-MihomoText $Output @($SensitiveValuesForResult)
        $CaseError = if (Test-Path -LiteralPath $Entry.Err) {
            Protect-MihomoText (Get-Content -LiteralPath $Entry.Err -Raw) @($SensitiveValuesForResult)
        }
        else {
            ''
        }
        [void]$Results.Add([ordered]@{Name = $Case.Name; Protocol = $Case.Protocol; MihomoPid = $Case.MihomoPid; ProxyPort = $Case.ProxyPort; ConfigSha = $Case.ConfigSha; MihomoSha = $Case.MihomoSha; ControllerProxiesApiResponded = $true; ControllerSelectedChain = @($Case.RouteChain); ControllerProxiesSha256 = $Case.ProxySelectionSha256; ControllerConnectionsApiResponded = [bool]$Case.RouteEvidence.ApiResponded; RouteEvidenceObserved = [bool]$Case.RouteEvidence.Observed; CurlExitCode = $Entry.Process.ExitCode; Http200 = $Output -match 'HTTP_CODE=200'; BodyBytes = $BodyBytes.Length; BodySha256 = [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($BodyBytes)).ToUpperInvariant(); BodyOk = $BodyOk; ServerLogObserved = [bool]$Observed; ServerLogPattern = $CaseDataPlanePattern; Output = $CaseOutput; Error = $CaseError; CleanupSucceeded = $false; CleanupFailures = @()})
    }
    $Summary = [ordered]@{PrismPid = $PrismProcess.Id; TargetPid = $TargetProcess.Id; PrismSha = Get-Sha256 "build/src/Prism.exe"; PrismConfigSha = Get-Sha256 $PrismConfig; PrismAliveAfterRequests = -not $PrismProcess.HasExited; Results = @($Results)}
    if (@($Results | Where-Object {
                $_.CurlExitCode -ne 0 -or -not $_.Http200 -or -not $_.BodyOk -or
                [int]$_.BodyBytes -ne $TargetResponse.Length -or
                [string]$_.BodySha256 -notmatch '^[0-9A-F]{64}$' -or
                -not $_.ServerLogObserved -or -not $_.ControllerProxiesApiResponded -or
                -not $_.ControllerConnectionsApiResponded -or -not $_.RouteEvidenceObserved -or
                @($_.ControllerSelectedChain).Count -lt 1
            }).Count -gt 0) {
        throw 'mixed matrix had failed rows'
    }
}
finally {
    foreach ($OwnedProcess in $Started) {
        if (-not (Stop-MihomoOwnedProcess $OwnedProcess)) {
            $CleanupFailures.Add("Owned process did not exit: PID $($OwnedProcess.Id)")
        }
    }
    Start-Sleep -Milliseconds 500
    foreach ($Case in $Cases) {
        $MihomoHome = Join-Path (Join-Path $CaseDirectory $Case.Slug) 'mihomo-home'
        if (Test-Path -LiteralPath $MihomoHome) {
            try {
                if (-not (Remove-MihomoCaseDirectory $CaseDirectory $MihomoHome)) {
                    $CleanupFailures.Add("Mihomo home remained: $MihomoHome")
                }
            }
            catch {
                $CleanupFailures.Add("Mihomo home cleanup failed: $MihomoHome")
            }
        }
    }
    try {
        if (-not (Protect-MihomoCaseLogs $CaseDirectory @($AllSensitiveValues))) {
            $CleanupFailures.Add('Case log redaction was not fully verified')
        }
    }
    catch {
        $CleanupFailures.Add('Case log redaction failed')
    }
    if (Test-Path -LiteralPath $PrismConfig) {
        try {
            if (-not (Remove-MihomoCaseFile $CaseDirectory $PrismConfig)) {
                $CleanupFailures.Add("Prism configuration remained: $PrismConfig")
            }
        }
        catch {
            $CleanupFailures.Add("Prism configuration cleanup failed: $PrismConfig")
        }
    }
    if (Test-Path -LiteralPath $TargetRoot) {
        try {
            if (-not (Remove-MihomoCaseDirectory $CaseDirectory $TargetRoot)) {
                $CleanupFailures.Add("Target root remained: $TargetRoot")
            }
        }
        catch {
            $CleanupFailures.Add("Target root cleanup failed: $TargetRoot")
        }
    }
    $CleanupSucceeded = $CleanupFailures.Count -eq 0
    foreach ($Result in $Results) {
        $Result['CleanupSucceeded'] = $CleanupSucceeded
        $Result['CleanupFailures'] = @($CleanupFailures)
    }
    if (-not $CleanupSucceeded) {
        throw ('Mixed matrix cleanup failed: ' + ($CleanupFailures -join '; '))
    }
}
Write-Utf8NoBom (Join-Path $CaseDirectory 'mixed-results.json') ($Summary | ConvertTo-Json -Depth 12)
$Summary | ConvertTo-Json -Depth 12
