#requires -Version 7.4
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'MihomoTestSupport.ps1')

function Get-QuicTemplateFixture {
    param([Parameter(Mandatory = $true)][ValidateSet('hysteria2', 'tuic')][string]$Protocol)

    $TemplateName = if ($Protocol -eq 'hysteria2') {
        'QuicHysteria2Mihomo.yaml'
    } else {
        'QuicTuicMihomo.yaml'
    }
    $PinnedHash = if ($Protocol -eq 'hysteria2') {
        'F28C742A2CD0BFCF9A64294FADE23D0D1DE80BCB5DE6F4CFD5560DB24948558E'
    } else {
        '91314C01451CD162553F7A9239856075BFB72AA4086CD54ECD2635735DFCDB5D'
    }
    $TemplatePath = Join-Path $PSScriptRoot $TemplateName
    $TemplateBytes = [System.IO.File]::ReadAllBytes($TemplatePath)
    $TemplateHash = [Convert]::ToHexString(
        [System.Security.Cryptography.SHA256]::HashData($TemplateBytes)).ToUpperInvariant()
    if ($TemplateHash -cne $PinnedHash) {
        throw "QUIC template fixture does not match its pinned SHA-256: $TemplateName"
    }
    $TemplateText = [System.Text.UTF8Encoding]::new($false, $true).GetString($TemplateBytes)
    return [pscustomobject]@{
        Path = $TemplatePath
        Sha256 = $TemplateHash
        Text = $TemplateText
    }
}

function New-QuicRunnerContractFixture {
    param([Parameter(Mandatory = $true)][string]$CaseDirectory)

    $Body = [byte[]]::new(1MB)
    for ($Index = 0; $Index -lt $Body.Length; $Index++) {
        $Body[$Index] = [byte]($Index % 251)
    }
    $BodyHash = [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($Body))
    $ServerLog = Join-Path $CaseDirectory 'prism-logs/prism.log'
    $TemplateFixture = Get-QuicTemplateFixture 'hysteria2'
    $TemplatePath = $TemplateFixture.Path
    $TemplateHash = $TemplateFixture.Sha256
    $QuicPort = 18082
    $TargetPort = 18080
    $ProxyPort = 18081
    $ExpectedRoute = 'Hysteria2 QUIC'
    $ExpectedLeaf = 'prism-hysteria2'
    return [pscustomobject]@{
        attempt = 1
        expectedProtocol = 'hysteria2'
        tcpPort = 18085
        proxyPort = $ProxyPort
        prismOperationsPort = 18084
        quicPort = $QuicPort
        targetPort = $TargetPort
        controllerPort = 18083
        controllerListenerOwnerPid = 102
        controllerListenerOwned = $true
        endpointOwnershipVerified = $true
        exitCode = 0
        httpCode = 200
        responseBodyMatched = $true
        responseBodyBytes = $Body.Length
        targetBodyBytes = $Body.Length
        bodySha256 = $BodyHash
        targetBodySha256 = $BodyHash
        controllerRouteApiResponded = $true
        controllerRouteSnapshotCount = 1
        controllerProxiesApiResponded = $true
        controllerSelectedChain = @($ExpectedLeaf, $ExpectedRoute)
        controllerProxiesSha256 = ('A' * 64)
        routeEvidenceObserved = $true
        routeEvidence = [pscustomobject]@{
            connectionId = 'synthetic-connection'
            sourceAddress = '127.0.0.1'
            sourcePort = 49152
            destinationAddress = '127.0.0.1'
            destinationPort = $TargetPort
            inboundPort = $ProxyPort
            network = 'tcp'
            rule = 'Match'
            rulePayload = ''
            expectedRoute = $ExpectedRoute
            expectedChain = @($ExpectedLeaf, $ExpectedRoute)
            chains = @($ExpectedLeaf, $ExpectedRoute)
        }
        curlSourceAddress = '127.0.0.1'
        curlSourcePort = 49152
        curlRemoteAddress = '127.0.0.1'
        curlRemotePort = $ProxyPort
        routeBodyCorrelationUnderSingleCurl = [pscustomobject]@{
            curlInvocationCount = 1
            curlPid = 104
            curlSourceAddress = '127.0.0.1'
            curlSourcePort = 49152
            curlRemoteAddress = '127.0.0.1'
            curlRemotePort = $ProxyPort
            mihomoConnectionId = 'synthetic-connection'
            matchedRouteRows = 1
            destinationAddress = '127.0.0.1'
            destinationPort = $TargetPort
            inboundPort = $ProxyPort
            network = 'tcp'
            route = $ExpectedRoute
            chains = @($ExpectedLeaf, $ExpectedRoute)
            httpCode = 200
            responseBodyBytes = $Body.Length
            responseBodySha256 = $BodyHash
            targetBodyBytes = $Body.Length
            targetBodySha256 = $BodyHash
        }
        prismRelayLogCorrelation = 'not_available'
        prismRelaySessionIdWireObserved = $false
        serverLogDiagnosticAvailable = $false
        serverLogPath = $ServerLog
        serverLogExcerpt = ''
        mihomoTemplatePath = $TemplatePath
        mihomoTemplateSha256 = $TemplateHash
        generatedPrismProfile = $true
        certificateValidation = [pscustomobject]@{
            mihomoSkipCertVerify = $true
            mihomoPeerValidation = 'disabled'
            runnerTrustValidation = 'not-independently-validated'
        }
        serverName = [pscustomobject]@{
            configuredValuesMatched = $true
            wireObserved = $false
        }
        alpn = [pscustomobject]@{
            configuredValuesMatched = $true
            values = @('h3')
            wireObserved = $false
        }
        prismPid = 101
        mihomoPid = 102
        targetPid = 103
        curlPid = 104
        prismExecutable = 'C:\Prism\Prism.exe'
        prismSha256 = ('A' * 64)
        prismConfig = Join-Path $CaseDirectory 'prism.json'
        prismConfigSha256 = ('B' * 64)
        mihomoExecutable = 'C:\Mihomo\mihomo.exe'
        mihomoSha256 = ('C' * 64)
        targetExecutable = 'C:\Prism\PrismMatrixFileServer.exe'
        curlExecutable = 'C:\Tools\curl.exe'
        configPath = Join-Path $CaseDirectory 'mihomo-home-1/config.yaml'
        configSha256 = ('D' * 64)
        targetRoot = Join-Path $CaseDirectory 'target-root'
        ownedProcessIdentities = @(
            [pscustomobject]@{ role = 'prism'; pid = 101; path = 'C:\Prism\Prism.exe'; startTimeUtc = '2026-10-19T10:00:00.0000000Z' },
            [pscustomobject]@{ role = 'mihomo'; pid = 102; path = 'C:\Mihomo\mihomo.exe'; startTimeUtc = '2026-10-19T10:00:01.0000000Z' },
            [pscustomobject]@{ role = 'target'; pid = 103; path = 'C:\Prism\PrismMatrixFileServer.exe'; startTimeUtc = '2026-10-19T10:00:02.0000000Z' },
            [pscustomobject]@{ role = 'curl'; pid = 104; path = 'C:\Tools\curl.exe'; startTimeUtc = '2026-10-19T10:00:03.0000000Z' }
        )
        cleanup = [pscustomobject]@{
            mihomoExited = $true
            curlExited = $true
            homeRemoved = $true
            configRemoved = $true
            processesExited = $true
            cleanupFailures = @()
            cleanupSucceeded = $true
            prismConfigRemoved = $true
            prismExited = $true
            targetExited = $true
            targetRootRemoved = $true
            generatedCertificateRemoved = $true
            generatedPrivateKeyRemoved = $true
            ownedProcessIdentityVerified = $true
        }
    }
}

function Set-QuicRunnerFixtureProtocol {
    param(
        [Parameter(Mandatory = $true)][psobject]$Fixture,
        [Parameter(Mandatory = $true)][ValidateSet('hysteria2', 'tuic')][string]$Protocol
    )

    $RouteName = if ($Protocol -eq 'hysteria2') { 'Hysteria2 QUIC' } else { 'TUIC v5 QUIC' }
    $LeafName = if ($Protocol -eq 'hysteria2') { 'prism-hysteria2' } else { 'prism-tuic' }
    $TemplateFixture = Get-QuicTemplateFixture $Protocol
    $Fixture.expectedProtocol = $Protocol
    $Fixture.controllerSelectedChain = @($LeafName, $RouteName)
    $Fixture.routeEvidence.expectedRoute = $RouteName
    $Fixture.routeEvidence.expectedChain = @($LeafName, $RouteName)
    $Fixture.routeEvidence.chains = @($LeafName, $RouteName)
    $Fixture.routeBodyCorrelationUnderSingleCurl.route = $RouteName
    $Fixture.routeBodyCorrelationUnderSingleCurl.chains = @($LeafName, $RouteName)
    $Fixture.mihomoTemplatePath = $TemplateFixture.Path
    $Fixture.mihomoTemplateSha256 = $TemplateFixture.Sha256
}

function Assert-QuicRunnerContractRejects {
    param(
        [Parameter(Mandatory = $true)][object]$Fixture,
        [Parameter(Mandatory = $true)][string]$CaseDirectory,
        [Parameter(Mandatory = $true)][string]$ExpectedError
    )

    $ActualError = ''
    try {
        Assert-MihomoQuicRunnerContract $CaseDirectory @($Fixture)
    }
    catch {
        $ActualError = $_.Exception.Message
    }
    if ($ActualError -cne $ExpectedError) {
        throw "Expected QUIC contract error '$ExpectedError'; received '$ActualError'."
    }
    $script:NegativeCaseCount++
    $script:RunnerContractNegativeCount++
}

function Assert-QuicRunnerContractRejectsRepeatedProxyPort {
    param(
        [Parameter(Mandatory = $true)][psobject]$Fixture,
        [Parameter(Mandatory = $true)][string]$CaseDirectory,
        [Parameter(Mandatory = $true)][string]$ExpectedError
    )

    $SecondAttempt = $Fixture | Select-Object *
    $SecondAttempt.attempt = 2
    $ActualError = ''
    try {
        Assert-MihomoQuicRunnerContract $CaseDirectory @($Fixture, $SecondAttempt)
    }
    catch {
        $ActualError = $_.Exception.Message
    }
    if ($ActualError -cne $ExpectedError) {
        throw "Expected QUIC contract error '$ExpectedError'; received '$ActualError'."
    }
    $script:NegativeCaseCount++
    $script:RunnerContractNegativeCount++
}

function Invoke-QuicGenericRunnerContract {
    param(
        [Parameter(Mandatory = $true)][psobject]$Fixture,
        [Parameter(Mandatory = $true)][string]$CaseDirectory
    )

    $ResultsPath = Join-Path $CaseDirectory 'results.json'
    $ResultsJson = ConvertTo-Json -InputObject ([object[]]@($Fixture)) -Depth 12
    [System.IO.File]::WriteAllText(
        $ResultsPath, $ResultsJson, [System.Text.UTF8Encoding]::new($false))
    $PowerShellPath = [System.Environment]::ProcessPath
    $StartInfo = [System.Diagnostics.ProcessStartInfo]::new($PowerShellPath)
    $StartInfo.WorkingDirectory = $PSScriptRoot
    $StartInfo.UseShellExecute = $false
    $StartInfo.RedirectStandardOutput = $true
    $StartInfo.RedirectStandardError = $true
    foreach ($Argument in @(
            '-NoLogo', '-NoProfile', '-File', (Join-Path $PSScriptRoot 'RunnerContractTest.ps1'),
            '-CaseDirectory', $CaseDirectory, '-RunnerKind', 'quic')) {
        [void]$StartInfo.ArgumentList.Add($Argument)
    }
    $Process = [System.Diagnostics.Process]::Start($StartInfo)
    try {
        $StandardOutput = $Process.StandardOutput.ReadToEndAsync()
        $StandardError = $Process.StandardError.ReadToEndAsync()
        if (-not $Process.WaitForExit(30000)) {
            if (-not $Process.HasExited) {
                $Process.Kill()
                $Process.WaitForExit()
            }
            throw 'Generic QUIC runner contract harness timed out.'
        }
        $Output = $StandardOutput.GetAwaiter().GetResult()
        $ErrorOutput = $StandardError.GetAwaiter().GetResult()
        if ($Process.ExitCode -ne 0 -or
            $Output -notmatch 'MATRIX RUNNER CONTRACT PASSED \(quic; 1 attempt\(s\)\)') {
            throw "Generic QUIC runner contract failed. $Output $ErrorOutput"
        }
        Write-Host $Output.Trim()
    }
    finally {
        if (-not $Process.HasExited) {
            $Process.Kill()
            $Process.WaitForExit()
        }
        $Process.Dispose()
    }
}

function Assert-MihomoYamlHexSecretString {
    param([Parameter(Mandatory = $true)][string]$Secret)

    $QuotedSecret = ConvertTo-MihomoYamlStringScalar $Secret
    $TestYaml = 'secret: ' + $QuotedSecret
    $TestEntry = Get-MihomoYamlMappingEntry $TestYaml
    $TestValue = ConvertFrom-MihomoYamlScalar $TestEntry.Value
    if (-not $QuotedSecret.StartsWith('"') -or
        $TestValue -isnot [string] -or $TestValue -cne $Secret) {
        throw 'YAML scalar serialization did not preserve a quoted string.'
    }
    if ($Secret -notmatch '^[0-9a-f]{64}$') {
        $RejectedHex = $false
        try {
            ConvertTo-MihomoYamlHexSecretScalar $Secret | Out-Null
        }
        catch {
            $RejectedHex = $true
        }
        if (-not $RejectedHex) {
            throw 'QUIC hex secret formatter accepted a non-hex value.'
        }
        return
    }
    $ControllerYaml = Set-MihomoTopLevelScalar 'mode: rule' 'secret' $Secret
    $ControllerLine = @($ControllerYaml -split "`r?`n" |
        Where-Object { $_ -match '^secret:' })[0]
    $ControllerEntry = Get-MihomoYamlMappingEntry $ControllerLine
    $ControllerValue = ConvertFrom-MihomoYamlScalar $ControllerEntry.Value
    if (-not $ControllerEntry.Value.TrimStart().StartsWith('"') -or
        $ControllerValue -isnot [string] -or $ControllerValue -cne $Secret) {
        throw 'Controller secret YAML reparse did not preserve its string value.'
    }
    $ProxyYaml = @'
proxies:
  - name: Hysteria2 QUIC
    server: 127.0.0.1
    port: 443
    password: previous
'@
    $UpdatedProxyYaml = Set-MihomoProxyScalar $ProxyYaml 'Hysteria2 QUIC' 'password' $Secret
    $PasswordLine = @($UpdatedProxyYaml -split "`r?`n" |
        Where-Object { $_ -match '^    password:' })[0]
    $PasswordEntry = Get-MihomoYamlMappingEntry $PasswordLine
    $PasswordValue = ConvertFrom-MihomoYamlScalar $PasswordEntry.Value
    if (-not $PasswordEntry.Value.TrimStart().StartsWith('"') -or
        $PasswordValue -isnot [string] -or $PasswordValue -cne $Secret) {
        throw 'QUIC outbound password YAML reparse did not preserve its string value.'
    }
}

function Assert-QuicAlpnRejected {
    param(
        [Parameter(Mandatory = $true)][string]$Yaml,
        [Parameter(Mandatory = $true)][string]$ExpectedError
    )

    $ActualError = ''
    try {
        Assert-MihomoQuicProxyAlpn $Yaml 'prism-hysteria2' 'h3'
    }
    catch {
        $ActualError = $_.Exception.Message
    }
    if ($ActualError -cne $ExpectedError) {
        throw "Expected QUIC ALPN error '$ExpectedError'; received '$ActualError'."
    }
    $script:NegativeCaseCount++
    $script:AlpnNegativeCount++
}

$TemporaryRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
$CaseDirectory = Join-Path $TemporaryRoot ('PrismQuicRunnerContract-' + [guid]::NewGuid().ToString('N'))
$ClaimPath = Join-Path $CaseDirectory '.synthetic-claim'
$Claim = [guid]::NewGuid().ToString('N')
$ClaimStream = $null
$ClaimStreamCloseFailed = $false
$DirectoryCreateAttempted = $false
$DirectoryCreateReturned = $false
$ClaimFileCreated = $false
$ClaimWriteCompleted = $false
$ClaimEstablished = $false
$script:NegativeCaseCount = 0
$script:RunnerContractNegativeCount = 0
$script:AlpnNegativeCount = 0
try {
    if (Test-Path -LiteralPath $CaseDirectory) {
        throw 'Synthetic QUIC contract fixture path already exists.'
    }
    $DirectoryCreateAttempted = $true
    [void][System.IO.Directory]::CreateDirectory($CaseDirectory)
    $DirectoryCreateReturned = $true
    $ClaimStream = [System.IO.FileStream]::new(
        $ClaimPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::None)
    $ClaimFileCreated = $true
    $ClaimBytes = [System.Text.Encoding]::ASCII.GetBytes($Claim)
    try {
        $ClaimStream.Write($ClaimBytes, 0, $ClaimBytes.Length)
        $ClaimStream.Flush($true)
        $ClaimWriteCompleted = $true
    }
    finally {
        if ($null -ne $ClaimStream) {
            $ClaimStream.Dispose()
            $ClaimStream = $null
        }
    }
    if (-not (Test-Path -LiteralPath $ClaimPath -PathType Leaf) -or
        [System.IO.File]::ReadAllText($ClaimPath, [System.Text.Encoding]::ASCII) -cne $Claim) {
        throw 'Synthetic QUIC contract fixture claim could not be verified.'
    }
    $ClaimEstablished = $true

    Assert-MihomoYamlHexSecretString ('0' * 64)
    Assert-MihomoYamlHexSecretString ('0x' + ('a' * 62))
    $HysteriaTemplate = Get-QuicTemplateFixture 'hysteria2'
    $TuicTemplate = Get-QuicTemplateFixture 'tuic'
    $IsolatedTemplate = Set-MihomoTopLevelScalar $HysteriaTemplate.Text 'geo-auto-update' 'false'
    $IsolatedTemplate = Set-MihomoTopLevelScalar $IsolatedTemplate 'bind-address' '127.0.0.1'
    $IsolatedTemplate = Set-MihomoTopLevelScalar $IsolatedTemplate 'allow-lan' 'false'
    $IsolatedTemplate = Set-MihomoTopLevelScalar $IsolatedTemplate 'external-controller' '127.0.0.1:18083'
    $IsolatedTemplate = Set-MihomoTopLevelScalar $IsolatedTemplate 'secret' ('0' * 64)
    Assert-MihomoCaseNetworkIsolation $IsolatedTemplate $true 18083 ('0' * 64)
    $AliasTemplate = Set-MihomoProxyEndpoint $IsolatedTemplate 'prism-hysteria2' '127.0.0.1' 18082
    $AliasTemplate = [regex]::Replace($AliasTemplate,
        '(?m)^(\s+server:\s+)127\.0\.0\.1\s*$', '${1}example.invalid')
    $AliasRejected = $false
    try {
        Assert-MihomoCaseNetworkIsolation $AliasTemplate $true 18083 ('0' * 64)
    }
    catch {
        $AliasRejected = $_.Exception.Message -eq
            'Isolated Mihomo outbounds must use an explicit loopback server and scalar port'
    }
    if (-not $AliasRejected) {
        throw 'Isolation validation accepted a DNS-name outbound server'
    }
    $PortExpressionTemplate = Set-MihomoProxyEndpoint `
        $IsolatedTemplate 'prism-hysteria2' '127.0.0.1' 18082
    $PortExpressionTemplate = [regex]::Replace($PortExpressionTemplate,
        '(?m)^(\s+port:\s+)18082\s*$', '${1}18082/18083')
    $PortExpressionRejected = $false
    try {
        Assert-MihomoCaseNetworkIsolation $PortExpressionTemplate $true 18083 ('0' * 64)
    }
    catch {
        $PortExpressionRejected = $_.Exception.Message -eq
            'Isolated Mihomo outbounds must use an explicit loopback server and scalar port'
    }
    if (-not $PortExpressionRejected) {
        throw 'Isolation validation accepted a non-scalar outbound port expression'
    }
    $script:NegativeCaseCount += 2
    $script:RunnerContractNegativeCount += 2
    Assert-MihomoQuicProxyAlpn $HysteriaTemplate.Text 'prism-hysteria2' 'h3'
    Assert-MihomoQuicProxyAlpn $TuicTemplate.Text 'prism-tuic' 'h3'
    $MissingAlpnYaml = @'
proxies:
  - name: prism-hysteria2
    type: hysteria2
'@
    Assert-QuicAlpnRejected $MissingAlpnYaml `
        'Mihomo QUIC outbound ALPN must exactly match Prism Quic.Alpn=h3'
    $WrongAlpnYaml = @'
proxies:
  - name: prism-hysteria2
    type: hysteria2
    alpn:
      - h2
'@
    Assert-QuicAlpnRejected $WrongAlpnYaml `
        'Mihomo QUIC outbound ALPN must exactly match Prism Quic.Alpn=h3'
    $Fixture = New-QuicRunnerContractFixture $CaseDirectory
    $ExpectedRoute = [string]$Fixture.routeEvidence.expectedRoute
    $ExpectedLeaf = [string]$Fixture.routeEvidence.expectedChain[0]
    Assert-MihomoQuicRunnerContract $CaseDirectory @($Fixture)
    Invoke-QuicGenericRunnerContract $Fixture $CaseDirectory
    [void][System.IO.Directory]::CreateDirectory((Split-Path -Parent $Fixture.serverLogPath))
    [System.IO.File]::WriteAllText($Fixture.serverLogPath, 'QuicNativeStage Stage=Initialized Code=0')
    $Fixture.serverLogDiagnosticAvailable = $true
    $Fixture.serverLogExcerpt = 'QuicNativeStage Stage=Initialized Code=0'
    Assert-MihomoQuicRunnerContract $CaseDirectory @($Fixture)

    Set-QuicRunnerFixtureProtocol $Fixture 'tuic'
    Assert-MihomoQuicRunnerContract $CaseDirectory @($Fixture)

    Set-QuicRunnerFixtureProtocol $Fixture 'hysteria2'
    $Fixture.controllerSelectedChain = @('prism-tuic', $ExpectedRoute)
    Assert-QuicRunnerContractRejects $Fixture $CaseDirectory `
        'QUIC runner result lacks verified /proxies selection evidence'
    Set-QuicRunnerFixtureProtocol $Fixture 'hysteria2'

    $Fixture.controllerProxiesApiResponded = $false
    Assert-QuicRunnerContractRejects $Fixture $CaseDirectory `
        'QUIC runner result lacks verified /proxies selection evidence'
    $Fixture.controllerProxiesApiResponded = $true

    $MissingProxiesField = $Fixture | Select-Object *
    $MissingProxiesField.PSObject.Properties.Remove('controllerProxiesSha256')
    Assert-QuicRunnerContractRejects $MissingProxiesField $CaseDirectory `
        "QUIC attempt 0 is missing result field 'controllerProxiesSha256'"

    $MissingControllerField = $Fixture | Select-Object *
    $MissingControllerField.PSObject.Properties.Remove('controllerRouteApiResponded')
    Assert-QuicRunnerContractRejects $MissingControllerField $CaseDirectory `
        "QUIC attempt 0 is missing result field 'controllerRouteApiResponded'"

    Assert-QuicRunnerContractRejectsRepeatedProxyPort $Fixture $CaseDirectory `
        'QUIC attempts must use a fresh isolated proxy port'

    $Fixture.routeEvidence.inboundPort++
    Assert-QuicRunnerContractRejects $Fixture $CaseDirectory `
        'routeEvidence.inboundPort does not match the isolated Mihomo proxy'
    $Fixture.routeEvidence.inboundPort = $Fixture.proxyPort

    $Fixture.routeEvidence.destinationPort++
    Assert-QuicRunnerContractRejects $Fixture $CaseDirectory `
        'routeEvidence.destinationPort does not match the local target'
    $Fixture.routeEvidence.destinationPort = $Fixture.targetPort

    $Fixture.routeEvidence.expectedRoute = 'unrelated-group'
    Assert-QuicRunnerContractRejects $Fixture $CaseDirectory `
        'routeEvidence.expectedRoute does not match the protocol-specific group'
    $Fixture.routeEvidence.expectedRoute = $ExpectedRoute

    $Fixture.routeEvidence.expectedChain = @('DIRECT', $ExpectedRoute)
    Assert-QuicRunnerContractRejects $Fixture $CaseDirectory `
        'QUIC route evidence does not match the case-specific selected chain'
    Set-QuicRunnerFixtureProtocol $Fixture 'hysteria2'

    $Fixture.routeBodyCorrelationUnderSingleCurl.chains = @('DIRECT', $ExpectedRoute)
    Assert-QuicRunnerContractRejects $Fixture $CaseDirectory `
        'routeBodyCorrelationUnderSingleCurl.chains does not match the Mihomo API row'
    Set-QuicRunnerFixtureProtocol $Fixture 'hysteria2'

    $Fixture.routeEvidence.chains = @('unrelated-proxy', $ExpectedRoute)
    Assert-QuicRunnerContractRejects $Fixture $CaseDirectory `
        'QUIC route evidence does not match the case-specific selected chain'
    Set-QuicRunnerFixtureProtocol $Fixture 'hysteria2'

    $Fixture.routeBodyCorrelationUnderSingleCurl.chains = @('unrelated-proxy', $ExpectedRoute)
    Assert-QuicRunnerContractRejects $Fixture $CaseDirectory `
        'routeBodyCorrelationUnderSingleCurl.chains does not match the Mihomo API row'
    Set-QuicRunnerFixtureProtocol $Fixture 'hysteria2'

    $Fixture.routeEvidence.chains = @($ExpectedLeaf)
    Assert-QuicRunnerContractRejects $Fixture $CaseDirectory `
        'QUIC result has no exact curl-source route tuple through its isolated proxy'
    Set-QuicRunnerFixtureProtocol $Fixture 'hysteria2'

    $Fixture.routeBodyCorrelationUnderSingleCurl.chains = @($ExpectedLeaf)
    Assert-QuicRunnerContractRejects $Fixture $CaseDirectory `
        'routeBodyCorrelationUnderSingleCurl.chains length does not match the route row'
    Set-QuicRunnerFixtureProtocol $Fixture 'hysteria2'

    $Fixture.routeBodyCorrelationUnderSingleCurl.route = 'unrelated-group'
    Assert-QuicRunnerContractRejects $Fixture $CaseDirectory `
        'routeBodyCorrelationUnderSingleCurl.route does not match the selected group'
    Set-QuicRunnerFixtureProtocol $Fixture 'hysteria2'

    $Fixture.routeEvidence.connectionId = 'other-mihomo-connection'
    Assert-QuicRunnerContractRejects $Fixture $CaseDirectory `
        'routeBodyCorrelationUnderSingleCurl.mihomoConnectionId does not match the route row'
    $Fixture.routeEvidence.connectionId = 'synthetic-connection'

    $Fixture.routeBodyCorrelationUnderSingleCurl.destinationPort++
    Assert-QuicRunnerContractRejects $Fixture $CaseDirectory `
        'routeBodyCorrelationUnderSingleCurl.destinationPort does not match the route row'
    $Fixture.routeBodyCorrelationUnderSingleCurl.destinationPort = $Fixture.targetPort

    $Fixture.routeBodyCorrelationUnderSingleCurl.matchedRouteRows = 2
    Assert-QuicRunnerContractRejects $Fixture $CaseDirectory `
        'routeBodyCorrelationUnderSingleCurl.matchedRouteRows must equal one'
    $Fixture.routeBodyCorrelationUnderSingleCurl.matchedRouteRows = 1

    $Fixture.routeBodyCorrelationUnderSingleCurl.curlPid++
    Assert-QuicRunnerContractRejects $Fixture $CaseDirectory `
        'routeBodyCorrelationUnderSingleCurl.curlPid does not match the owned curl process'
    $Fixture.routeBodyCorrelationUnderSingleCurl.curlPid = $Fixture.curlPid

    $Fixture.routeBodyCorrelationUnderSingleCurl.curlSourcePort = 0
    Assert-QuicRunnerContractRejects $Fixture $CaseDirectory `
        'routeBodyCorrelationUnderSingleCurl.curlSourceTuple is invalid'
    $Fixture.routeBodyCorrelationUnderSingleCurl.curlSourcePort = $Fixture.curlSourcePort

    $Fixture.routeBodyCorrelationUnderSingleCurl.curlInvocationCount = 2
    Assert-QuicRunnerContractRejects $Fixture $CaseDirectory `
        'routeBodyCorrelationUnderSingleCurl.curlInvocationCount must equal one'
    $Fixture.routeBodyCorrelationUnderSingleCurl.curlInvocationCount = 1

    $Fixture.bodySha256 = ('E' * 64)
    Assert-QuicRunnerContractRejects $Fixture $CaseDirectory `
        'QUIC attempt lacks exact HTTP status and literal body hash evidence'
    $Fixture.bodySha256 = $Fixture.targetBodySha256

    $Fixture.routeBodyCorrelationUnderSingleCurl.responseBodySha256 = ('F' * 64)
    Assert-QuicRunnerContractRejects $Fixture $CaseDirectory `
        'routeBodyCorrelationUnderSingleCurl.responseBodySha256 does not match the target body'
    $Fixture.routeBodyCorrelationUnderSingleCurl.responseBodySha256 = $Fixture.bodySha256

    $Fixture.cleanup.cleanupSucceeded = $false
    Assert-QuicRunnerContractRejects $Fixture $CaseDirectory `
        "QUIC attempt cleanup field 'cleanupSucceeded' is not true"
    $Fixture.cleanup.cleanupSucceeded = $true

    $Fixture.prismRelayLogCorrelation = 'matched'
    Assert-QuicRunnerContractRejects $Fixture $CaseDirectory `
        'QUIC result has inconsistent configuration or diagnostic evidence'
    $Fixture.prismRelayLogCorrelation = 'not_available'
    $Fixture.prismRelaySessionIdWireObserved = $true
    Assert-QuicRunnerContractRejects $Fixture $CaseDirectory `
        'QUIC result has inconsistent configuration or diagnostic evidence'
    $Fixture.prismRelaySessionIdWireObserved = $false

    $Fixture.alpn.values = @('h2')
    Assert-QuicRunnerContractRejects $Fixture $CaseDirectory `
        'QUIC result has inconsistent configuration or diagnostic evidence'
    $Fixture.alpn.values = @('h3')
    $MissingAlpnFixture = $Fixture | Select-Object *
    $MissingAlpnFixture.PSObject.Properties.Remove('alpn')
    Assert-QuicRunnerContractRejects $MissingAlpnFixture $CaseDirectory `
        "QUIC attempt 0 is missing result field 'alpn'"

    $Fixture.mihomoTemplatePath = $Fixture.configPath
    Assert-QuicRunnerContractRejects $Fixture $CaseDirectory `
        'QUIC runner result does not identify the protocol-specific checked-in source fixture it used'
    $Fixture.mihomoTemplatePath = (Get-QuicTemplateFixture 'tuic').Path
    Assert-QuicRunnerContractRejects $Fixture $CaseDirectory `
        'QUIC runner result does not identify the protocol-specific checked-in source fixture it used'
    Set-QuicRunnerFixtureProtocol $Fixture 'hysteria2'

    $Fixture.mihomoTemplateSha256 = (Get-QuicTemplateFixture 'tuic').Sha256
    Assert-QuicRunnerContractRejects $Fixture $CaseDirectory `
        'QUIC runner result does not match the pinned protocol-specific template bytes'
    $Fixture.mihomoTemplateSha256 = (Get-QuicTemplateFixture 'hysteria2').Sha256

    $Fixture.mihomoTemplateSha256 = ('0' * 64)
    Assert-QuicRunnerContractRejects $Fixture $CaseDirectory `
        'QUIC runner result does not match the pinned protocol-specific template bytes'
    $Fixture.mihomoTemplateSha256 = (Get-QuicTemplateFixture 'hysteria2').Sha256

    Write-Host ("QUIC RUNNER CONTRACT FIXTURES PASSED (3 positive, {0} negative: {1} runner-contract, {2} ALPN; 2 template ALPN checks, 2 YAML string boundaries)" -f `
        $script:NegativeCaseCount, $script:RunnerContractNegativeCount, $script:AlpnNegativeCount)
}
finally {
    if ($null -ne $ClaimStream) {
        try {
            $ClaimStream.Dispose()
            $ClaimStream = $null
        }
        catch {
            $ClaimStreamCloseFailed = $true
        }
    }
    if ($null -eq $ClaimStream -and $ClaimFileCreated -and $ClaimEstablished) {
        $ResolvedTemporaryRoot = [System.IO.Path]::GetFullPath($TemporaryRoot).TrimEnd(
            [System.IO.Path]::DirectorySeparatorChar)
        $ResolvedCaseDirectory = [System.IO.Path]::GetFullPath($CaseDirectory)
        $ResolvedCaseParent = [System.IO.Path]::GetFullPath(
            [System.IO.Path]::GetDirectoryName($ResolvedCaseDirectory))
        $CaseDirectoryItem = Get-Item -LiteralPath $ResolvedCaseDirectory -Force
        if (-not [string]::Equals($ResolvedCaseParent, $ResolvedTemporaryRoot,
                [System.StringComparison]::OrdinalIgnoreCase) -or
            ($CaseDirectoryItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
            -not (Test-Path -LiteralPath $ClaimPath -PathType Leaf) -or
            [System.IO.File]::ReadAllText($ClaimPath, [System.Text.Encoding]::ASCII) -cne $Claim) {
            throw 'Synthetic QUIC contract fixture cleanup ownership could not be verified.'
        }
        $LogDirectory = Join-Path $CaseDirectory 'prism-logs'
        $LogPath = Join-Path $LogDirectory 'prism.log'
        $ResultsPath = Join-Path $CaseDirectory 'results.json'
        $ExpectedPaths = @($ClaimPath, $LogDirectory, $LogPath, $ResultsPath) | ForEach-Object {
            [System.IO.Path]::GetFullPath($_)
        }
        $Children = @(Get-ChildItem -LiteralPath $CaseDirectory -Force -Recurse -ErrorAction Stop)
        if (@($Children | Where-Object {
                    ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
                    $_.FullName -notin $ExpectedPaths
                }).Count -gt 0) {
            throw 'Synthetic QUIC contract fixture contains an unowned path.'
        }
        if (Test-Path -LiteralPath $LogPath) {
            [System.IO.File]::Delete($LogPath)
        }
        if (Test-Path -LiteralPath $LogDirectory) {
            [System.IO.Directory]::Delete($LogDirectory, $false)
        }
        if (Test-Path -LiteralPath $ResultsPath) {
            [System.IO.File]::Delete($ResultsPath)
        }
        [System.IO.File]::Delete($ClaimPath)
        [System.IO.Directory]::Delete($CaseDirectory, $false)
    }
    elseif ($null -eq $ClaimStream -and $DirectoryCreateReturned -and $ClaimFileCreated -and
        (Test-Path -LiteralPath $CaseDirectory -PathType Container)) {
        $CanRemoveDirectory = $false
        try {
            $ResolvedTemporaryRoot = [System.IO.Path]::GetFullPath($TemporaryRoot).TrimEnd(
                [System.IO.Path]::DirectorySeparatorChar)
            $ResolvedCaseDirectory = [System.IO.Path]::GetFullPath($CaseDirectory)
            $ResolvedCaseParent = [System.IO.Path]::GetFullPath(
                [System.IO.Path]::GetDirectoryName($ResolvedCaseDirectory))
            $CaseDirectoryItem = Get-Item -LiteralPath $ResolvedCaseDirectory -Force
            $Children = @(Get-ChildItem -LiteralPath $ResolvedCaseDirectory -Force -Recurse -ErrorAction Stop)
            $HasReparsePoint = ($CaseDirectoryItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
                @($Children | Where-Object {
                    ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
                }).Count -gt 0
            $IsDirectTemporaryChild = [string]::Equals($ResolvedCaseParent, $ResolvedTemporaryRoot,
                [System.StringComparison]::OrdinalIgnoreCase)
            $ExpectedClaimPath = [System.IO.Path]::GetFullPath($ClaimPath)
            $OnlyOwnedClaim = $Children.Count -eq 1 -and
                [string]::Equals($Children[0].FullName, $ExpectedClaimPath,
                    [System.StringComparison]::OrdinalIgnoreCase) -and
                -not $Children[0].PSIsContainer -and
                (-not $ClaimWriteCompleted -or
                    [System.IO.File]::ReadAllText($ExpectedClaimPath,
                        [System.Text.Encoding]::ASCII) -ceq $Claim)
            $CanRemoveDirectory = $IsDirectTemporaryChild -and -not $HasReparsePoint -and
                $OnlyOwnedClaim
        }
        catch {
            $CanRemoveDirectory = $false
        }
        if ($CanRemoveDirectory) {
            [System.IO.File]::Delete($ClaimPath)
            [System.IO.Directory]::Delete($CaseDirectory, $false)
        }
        else {
            Write-Warning "Synthetic QUIC setup left an unowned or non-empty residual directory: $CaseDirectory"
        }
    }
    elseif ($null -eq $ClaimStream -and $DirectoryCreateReturned -and -not $ClaimFileCreated -and
        (Test-Path -LiteralPath $CaseDirectory -PathType Container)) {
        Write-Warning "Synthetic QUIC setup did not establish an exclusive claim; leaving residual directory: $CaseDirectory"
    }
    elseif ($ClaimStreamCloseFailed) {
        Write-Warning "Synthetic QUIC claim stream could not be closed; leaving fixture path untouched: $CaseDirectory"
    }
    elseif ($DirectoryCreateAttempted -and -not $DirectoryCreateReturned -and
        (Test-Path -LiteralPath $CaseDirectory -PathType Container)) {
        Write-Warning "Synthetic QUIC setup could not establish directory ownership; leaving residual directory: $CaseDirectory"
    }
}
