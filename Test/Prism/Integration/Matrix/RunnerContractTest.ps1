[CmdletBinding()]
param(
    [string]$CaseDirectory = '',
    [ValidateSet('tcp', 'udp', 'quic')][string]$RunnerKind = 'tcp',
    [switch]$StaticOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'MihomoTestSupport.ps1')

function Assert-QuicMihomoTemplateInputContract {
    $QuicRunnerPath = Join-Path $PSScriptRoot 'MihomoQuic.ps1'
    $QuicRunnerSource = Get-Content -LiteralPath $QuicRunnerPath -Raw
    $ValidationCall = '$MihomoTemplatePath = Resolve-QuicMihomoTemplatePath $MihomoTemplate $PSScriptRoot'
    $TemplateBytesRead = '$MihomoTemplateBytes = [System.IO.File]::ReadAllBytes($MihomoTemplatePath)'
    $TemplateHash = '$MihomoTemplateSha256 = Get-Sha256Bytes $MihomoTemplateBytes'
    $TemplateDecode = '$Yaml = [System.Text.UTF8Encoding]::new($false, $true).GetString($MihomoTemplateBytes)'
    $TemplateReadCount = [regex]::Matches($QuicRunnerSource,
        '(?i)\[System\.IO\.File\]::ReadAllBytes\(\s*\$MihomoTemplatePath\s*\)').Count
    $ValidationIndex = $QuicRunnerSource.IndexOf(
        $ValidationCall, [System.StringComparison]::Ordinal)
    $BytesIndex = $QuicRunnerSource.IndexOf($TemplateBytesRead, [System.StringComparison]::Ordinal)
    $HashIndex = $QuicRunnerSource.IndexOf($TemplateHash, [System.StringComparison]::Ordinal)
    $DecodeIndex = $QuicRunnerSource.IndexOf($TemplateDecode, [System.StringComparison]::Ordinal)
    if ($ValidationIndex -lt 0 -or $BytesIndex -le $ValidationIndex -or
        $HashIndex -le $BytesIndex -or $DecodeIndex -le $BytesIndex -or
        $TemplateReadCount -ne 1 -or
        $QuicRunnerSource -match '(?im)Get-Content\b[^\r\n]*\$MihomoTemplatePath\b' -or
        $QuicRunnerSource -match '(?im)Get-FileHash\b[^\r\n]*\$MihomoTemplatePath\b' -or
        -not $QuicRunnerSource.Contains(
            'F28C742A2CD0BFCF9A64294FADE23D0D1DE80BCB5DE6F4CFD5560DB24948558E') -or
        -not $QuicRunnerSource.Contains(
            '91314C01451CD162553F7A9239856075BFB72AA4086CD54ECD2635735DFCDB5D')) {
        throw 'Current QUIC runner must read the selected template exactly once, then hash and decode that byte buffer.'
    }
    $Tokens = $null
    $ParseErrors = $null
    $QuicRunnerAst = [System.Management.Automation.Language.Parser]::ParseFile(
        $QuicRunnerPath, [ref]$Tokens, [ref]$ParseErrors)
    if ($ParseErrors.Count -ne 0) {
        throw 'Current QUIC runner has PowerShell syntax errors.'
    }
    $TemplatePathFunction = $QuicRunnerAst.Find({
        param($Node)
        $Node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $Node.Name -eq 'Resolve-QuicMihomoTemplatePath'
    }, $true)
    if ($null -eq $TemplatePathFunction) {
        throw 'Current QUIC runner has no fixture-only template path validator.'
    }
    . ([System.Management.Automation.ScriptBlock]::Create($TemplatePathFunction.Extent.Text))

    $FixtureHashes = @{
        'QuicHysteria2Mihomo.yaml' = 'F28C742A2CD0BFCF9A64294FADE23D0D1DE80BCB5DE6F4CFD5560DB24948558E'
        'QuicTuicMihomo.yaml' = '91314C01451CD162553F7A9239856075BFB72AA4086CD54ECD2635735DFCDB5D'
    }
    foreach ($FixtureName in $FixtureHashes.Keys) {
        $FixturePath = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot $FixtureName))
        $ResolvedPath = Resolve-QuicMihomoTemplatePath $FixturePath $PSScriptRoot
        if (-not [string]::Equals($FixturePath, $ResolvedPath,
                [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "QUIC template validator changed the accepted fixture path: $FixtureName"
        }
        $CaseVariantPath = $FixturePath.ToUpperInvariant()
        $CaseVariantResolved = Resolve-QuicMihomoTemplatePath $CaseVariantPath $PSScriptRoot
        if (-not [string]::Equals($FixturePath, $CaseVariantResolved,
                [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "QUIC template validator rejected a Windows case variant: $FixtureName"
        }
        $FixtureBytes = [System.IO.File]::ReadAllBytes($FixturePath)
        $FixtureSha256 = [Convert]::ToHexString(
            [System.Security.Cryptography.SHA256]::HashData($FixtureBytes)).ToUpperInvariant()
        if ($FixtureSha256 -cne [string]$FixtureHashes[$FixtureName]) {
            throw "QUIC template fixture does not match its pinned SHA-256: $FixtureName"
        }
    }

    $ExternalTemplate = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot `
        '..\..\..\..\Include\Prism\Application\Configuration\PrismConfiguration.json'))
    $RejectedExternalTemplate = $false
    try {
        Resolve-QuicMihomoTemplatePath $ExternalTemplate $PSScriptRoot | Out-Null
    }
    catch {
        $RejectedExternalTemplate = $true
    }
    if (-not $RejectedExternalTemplate) {
        throw 'QUIC runner accepted a non-fixture local Mihomo template.'
    }
}

function Assert-CurrentMihomoRunnerStaticContract {
    $SupportPath = Join-Path $PSScriptRoot 'MihomoTestSupport.ps1'
    $SupportSource = Get-Content -LiteralPath $SupportPath -Raw
    foreach ($RequiredSupportText in @(
            'function Assert-MihomoTemplateProxyEndpointsAreLoopback',
            'function Assert-MihomoPrismQuicCredential',
            '[System.Net.Http.HttpClientHandler]::new()',
            '$Handler.UseProxy = $false',
            "'/proxies'",
            "'/connections'")) {
        Test-CurrentRunnerContains $SupportSource $RequiredSupportText 'MihomoTestSupport.ps1'
    }
    $RunnerSources = @{}
    foreach ($Name in @(
            'RunCurrentMihomoCase.ps1', 'MihomoUdp.ps1',
            'MihomoQuic.ps1', 'RunCurrentMixedCase.ps1')) {
        $RunnerSources[$Name] = Get-Content -LiteralPath (Join-Path $PSScriptRoot $Name) -Raw
    }
    foreach ($Entry in $RunnerSources.GetEnumerator()) {
        $Source = $Entry.Value
        if ($Source -match '192\.168\.0\.106' -or
            $Source -match 'verge-mihomo|clash-verge') {
            throw "Current Mihomo runner contains a stale LAN or user process literal: $($Entry.Key)"
        }
        Test-CurrentRunnerContains $Source 'New-MihomoIsolatedChildEnvironment' $Entry.Key
        Test-CurrentRunnerContains $Source "127.0.0.1:" $Entry.Key
        if ($Entry.Key -ne 'MihomoUdp.ps1') {
            Test-CurrentRunnerContains $Source '--noproxy=' $Entry.Key
        }
        Test-CurrentRunnerContains $Source 'Get-MihomoSelectedProxyChainSnapshot' $Entry.Key
        if ($Entry.Key -ne 'MihomoQuic.ps1') {
            if ($Source -notmatch '(?i)controllerProxiesApiResponded') {
                throw "Current Mihomo runner is missing required controller result evidence: $($Entry.Key)"
            }
        }
        if ($Entry.Key -eq 'RunCurrentMixedCase.ps1' -and
            -not $Source.Contains('Wait-MihomoRouteEvidenceBatch')) {
            throw 'Mixed Mihomo runner must capture /connections while curl requests are active'
        }
        if ($Entry.Key -eq 'RunCurrentMixedCase.ps1' -and
            (-not $Source.Contains('Assert-MihomoQuicProxyAlpn') -or
             -not $Source.Contains('Assert-MihomoPrismProxyServerName'))) {
            throw 'Mixed Mihomo runner must synchronize SNI and QUIC ALPN with Prism'
        }
        if ($Source -match '(?m)^\s*Remove-Item\b' -and
            $Source -notmatch 'Get-MihomoCaseArtifactPath|Resolve-MihomoCaseChildPath') {
            throw "Current Mihomo runner has an unchecked cleanup removal: $($Entry.Key)"
        }
    }
    $UdpSource = [string]$RunnerSources['MihomoUdp.ps1']
    if (-not $UdpSource.Contains('if ($PrismPort -eq 0 -and $PrismUdpPort -eq 0)')) {
        throw 'UDP Mihomo runner must skip automatic port probing when both ports are explicit'
    }
    foreach ($Entry in $RunnerSources.GetEnumerator()) {
        if ($Entry.Key -eq 'RunCurrentMixedCase.ps1') {
            continue
        }
        if ($Entry.Value -notmatch '(?m)^\s*\[ValidateRange\(0, 65535\)\]\[int\]\$(?:PrismPort|TargetPort|ProxyPort|TcpPort|QuicPort) = 0\b') {
            throw "Current Mihomo runner does not default every case port to zero: $($Entry.Key)"
        }
    }
    $QuicSource = [string]$RunnerSources['MihomoQuic.ps1']
    if (-not $QuicSource.Contains('Get-NextLoopbackPort $ProxyAvoidPorts') -or
        -not $QuicSource.Contains('Get-NextLoopbackPort $ControllerAvoidPorts')) {
        throw 'QUIC Mihomo runner must reserve distinct ports for every repeated attempt'
    }
    foreach ($Entry in $RunnerSources.GetEnumerator()) {
        Test-CurrentRunnerContains $Entry.Value 'Assert-MihomoTemplateProxyEndpointsAreLoopback' $Entry.Key
    }
}

function Assert-CurrentMixedRunnerFixtureContract {
    $Source = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'RunCurrentMixedCase.ps1') -Raw
    if ($Source -notmatch '(?m)^\s*\$TargetResponse\s*=\s*\[byte\[\]\]::new\(64 \* 1024\)\s*$' -or
        -not $Source.Contains("'--limit-rate', '32k'") -or
        $Source -notmatch 'Assert-MihomoPrismMixedConfigurationCase' -or
        $Source -notmatch 'Wait-MihomoRouteEvidenceBatch' -or
        $Source -notmatch 'CleanupSucceeded' -or
        $Source -notmatch 'mixed-results\.json' -or
        $Source -notmatch '(?m)^\s*if \(@\(Get-MihomoProxyEntries \$ConfigReadback\)\.Count -ne 1\)') {
        throw 'Mixed runner must slow an exact 64 KiB target response while sampling controller routes.'
    }
    $FixtureYaml = @'
proxies:
  - name: "prism-test"
    type: http
    server: 127.0.0.1
    port: 18080
proxy-groups:
  - name: "PrismPreview-Active"
    type: select
    proxies:
      - prism-test
rules:
  - MATCH,PrismPreview-Active
'@
    $ObservedNames = @(Get-MihomoMatchTargets $FixtureYaml)
    if ($ObservedNames.Count -ne 1 -or $ObservedNames[0] -ne 'PrismPreview-Active') {
        throw 'Mixed runner route fixture is not parseable.'
    }
}

function Assert-PrismClientMatrixFixtureContract {
    $FixturePath = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot `
        '..\..\..\..\PrismClient.yaml'))
    $Fixture = Get-Content -LiteralPath $FixturePath -Raw
    if ($Fixture -match '192\.168\.0\.106' -or
        $Fixture -match '(?m)^mixed-port:\s*7890\s*$' -or
        $Fixture -match '(?m)^socks-port:\s*7891\s*$' -or
        $Fixture -match '(?m)^bind-address:\s*[''"]?\*') {
        throw 'PrismClient.yaml retains a user listener or LAN endpoint'
    }
    Assert-MihomoYamlSupportedSyntax $Fixture
    Assert-MihomoTemplateProxyEndpointsAreLoopback $Fixture
}

function Test-CurrentRunnerContains {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Text,
        [Parameter(Mandatory = $true)][string]$Runner
    )
    if (-not $Source.Contains($Text)) {
        throw "Current Mihomo runner is missing required contract text: $Runner :: $Text"
    }
}

if ($RunnerKind -eq 'quic') {
    Assert-QuicMihomoTemplateInputContract
}
Assert-CurrentMihomoRunnerStaticContract
Assert-CurrentMixedRunnerFixtureContract
Assert-PrismClientMatrixFixtureContract
if ($StaticOnly) {
    Write-Host 'MATRIX RUNNER STATIC CONTRACT PASSED'
    exit 0
}
if ([string]::IsNullOrWhiteSpace($CaseDirectory)) {
    throw 'Matrix runner contract execution requires CaseDirectory unless StaticOnly is selected.'
}

function Get-Sha256 {
    param([Parameter(Mandatory = $true)][string]$Path)

    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToUpperInvariant()
}

$ResolvedCase = (Resolve-Path -LiteralPath $CaseDirectory).Path
$ResultsPath = Join-Path $ResolvedCase 'results.json'
if (-not (Test-Path -LiteralPath $ResultsPath)) {
    throw "Matrix runner did not produce results.json: $ResultsPath"
}

$Results = @(Get-Content -LiteralPath $ResultsPath -Raw | ConvertFrom-Json)
if ($Results.Count -eq 0) {
    throw 'Matrix runner produced no attempts.'
}

if ($RunnerKind -eq 'quic') {
    Assert-MihomoQuicRunnerContract $ResolvedCase $Results
    Write-Host "MATRIX RUNNER CONTRACT PASSED (quic; $($Results.Count) attempt(s))"
    exit 0
}

if ($RunnerKind -eq 'udp') {
    foreach ($Result in $Results) {
        foreach ($Field in @(
                'prismSha256', 'prismConfigSha256', 'prismConfigAudit',
                'prismConfigAuditSha256', 'mihomoSha256', 'prismNaturalExit',
                'prismExitCode', 'prismDrainUri', 'prismDrainRequested',
                'prismDrainStatus', 'ownedProcessIdentities', 'cleanup',
                'controllerProxiesApiResponded', 'controllerSelectedChain',
                'controllerProxiesSha256')) {
            if (-not ($Result.PSObject.Properties.Name -contains $Field)) {
                throw "Attempt $($Result.attempt) is missing result field '$Field'."
            }
        }
        foreach ($Hash in @($Result.prismSha256, $Result.prismConfigSha256,
                $Result.prismConfigAuditSha256, $Result.mihomoSha256)) {
            if ($Hash -notmatch '^[0-9A-F]{64}$') {
                throw "Attempt $($Result.attempt) has an invalid executable/config SHA-256."
            }
        }
        if (-not [bool]$Result.prismNaturalExit -or
            [int]$Result.prismExitCode -ne 0 -or
            -not [bool]$Result.prismDrainRequested -or
            $Result.prismDrainUri -notmatch '/Operations/Drain\?worker=0&stop_accepting=true&force=false' -or
            ($Result.prismDrainStatus -ne 'accepted' -and
             $Result.prismDrainStatus -ne 'completed')) {
            throw "Attempt $($Result.attempt) did not drain and exit naturally."
        }
        if (-not (Test-Path -LiteralPath $Result.prismConfigAudit -PathType Leaf) -or
            (Get-Sha256 $Result.prismConfigAudit) -ne $Result.prismConfigAuditSha256) {
            throw "Attempt $($Result.attempt) Prism config audit is missing or mismatched."
        }
        if (@($Result.ownedProcessIdentities).Count -lt 3 -or
            -not [bool]$Result.cleanup.ownedProcessIdentityVerified) {
            throw "Attempt $($Result.attempt) lacks owned process identity cleanup evidence."
        }
        if (-not [bool]$Result.controllerProxiesApiResponded -or
            @($Result.controllerSelectedChain).Count -lt 1 -or
            [string]$Result.controllerProxiesSha256 -notmatch '^[0-9A-F]{64}$') {
            throw "Attempt $($Result.attempt) lacks verified /proxies selection evidence."
        }
        if ($RunnerKind -eq 'udp') {
            foreach ($Field in @('payloadBytes', 'payloadHex', 'payloadSha256',
                    'providerUdpPort', 'providerControlPort', 'providerMatchingRecordCount',
                    'providerRecordPath', 'providerRecordSha256')) {
                if (-not ($Result.PSObject.Properties.Name -contains $Field)) {
                    throw "UDP attempt $($Result.attempt) is missing result field '$Field'."
                }
            }
            if ([int]$Result.payloadBytes -le 0 -or
                $Result.payloadHex -notmatch '^[0-9a-f]+$' -or
                $Result.payloadSha256 -notmatch '^[0-9A-F]{64}$' -or
                [int]$Result.providerMatchingRecordCount -lt 1 -or
                $Result.providerRecordSha256 -notmatch '^[0-9A-F]{64}$' -or
                -not (Test-Path -LiteralPath $Result.providerRecordPath -PathType Leaf) -or
                (Get-Sha256 $Result.providerRecordPath) -ne $Result.providerRecordSha256) {
                throw "UDP attempt $($Result.attempt) lacks matching provider byte evidence."
            }
        }
    }
    Write-Host "MATRIX RUNNER CONTRACT PASSED ($RunnerKind; $($Results.Count) attempt(s))"
    exit 0
}

$RequiredFields = @(
    'prismExecutable',
    'prismSha256',
    'prismConfigSha256',
    'prismConfigAudit',
    'prismConfigAuditSha256',
    'mihomoExecutable',
    'mihomoSha256',
    'expectedProtocol',
    'concurrentRequests',
    'literalBodyExpected',
    'literalBodyMatchCount',
    'responseEvidence',
    'prismNaturalExit',
    'prismExitCode',
    'prismDrainUri',
    'prismDrainRequested',
    'prismDrainStatus',
    'targetBodyPath',
    'targetBodySha256',
    'ownedProcessIdentities',
    'serverLogObserved',
    'serverLogPath',
    'serverLogExcerpt',
    'serverLogSuccessCount',
    'serverLogMinimumCount',
    'serverLogStructured',
    'serverLogExpectedProtocolName',
    'serverLogExpectedTarget',
    'serverLogMatchedSessionCount',
    'serverLogMatchedSessions',
    'serverLogTargetRequired',
    'serverLogTargetObserved',
    'controllerProxiesApiResponded',
    'controllerSelectedChain',
    'controllerProxiesSha256',
    'cleanup'
)
foreach ($Result in $Results) {
    foreach ($Field in $RequiredFields) {
        if (-not ($Result.PSObject.Properties.Name -contains $Field)) {
            throw "Attempt $($Result.attempt) is missing result field '$Field'."
        }
    }
    if ($Result.prismSha256 -notmatch '^[0-9A-F]{64}$' -or
        $Result.prismConfigSha256 -notmatch '^[0-9A-F]{64}$' -or
        $Result.mihomoSha256 -notmatch '^[0-9A-F]{64}$' -or
        $Result.targetBodySha256 -notmatch '^[0-9A-F]{64}$') {
        throw "Attempt $($Result.attempt) has an invalid SHA-256 record."
    }
    if (-not (Test-Path -LiteralPath $Result.targetBodyPath -PathType Leaf) -or
        (Get-Sha256 $Result.targetBodyPath) -ne $Result.targetBodySha256) {
        throw "Attempt $($Result.attempt) target literal input hash is missing or mismatched."
    }
    $OwnedIdentities = @($Result.ownedProcessIdentities)
    if ($OwnedIdentities.Count -lt 3) {
        throw "Attempt $($Result.attempt) has incomplete owned-process identity evidence."
    }
    foreach ($Identity in $OwnedIdentities) {
        if ([string]::IsNullOrWhiteSpace($Identity.role) -or
            [int]$Identity.pid -le 0 -or
            [string]::IsNullOrWhiteSpace($Identity.path) -or
            [string]::IsNullOrWhiteSpace($Identity.startTime)) {
            throw "Attempt $($Result.attempt) has malformed owned-process identity evidence."
        }
    }
    $RequiredLogSessionCount = if ($Result.serverLogTargetRequired) {
        [int]$Result.concurrentRequests
    }
    else {
        1
    }
    if ([string]::IsNullOrWhiteSpace($Result.expectedProtocol) -or
        -not [bool]$Result.serverLogStructured -or
        -not [bool]$Result.serverLogObserved -or
        [int]$Result.serverLogSuccessCount -ne $RequiredLogSessionCount -or
        [int]$Result.serverLogMinimumCount -ne $RequiredLogSessionCount -or
        [int]$Result.serverLogMatchedSessionCount -lt $RequiredLogSessionCount -or
        [string]::IsNullOrWhiteSpace($Result.serverLogExpectedProtocolName) -or
        [string]::IsNullOrWhiteSpace($Result.serverLogExpectedTarget) -or
        -not (Test-Path -LiteralPath $Result.serverLogPath)) {
        throw "Attempt $($Result.attempt) has no correlated structured success for $($Result.expectedProtocol)."
    }
    $MatchedSessions = @($Result.serverLogMatchedSessions)
    if ($Result.serverLogTargetRequired -and
        $MatchedSessions.Count -ne [int]$Result.concurrentRequests) {
        throw "Attempt $($Result.attempt) structured session evidence count mismatch."
    }
    $SessionIds = @($MatchedSessions | ForEach-Object { [string]$_.Session })
    if (@($SessionIds | Sort-Object -Unique).Count -ne $SessionIds.Count) {
        throw "Attempt $($Result.attempt) reused a session for multiple terminal evidence records."
    }
    foreach ($SessionEvidence in $MatchedSessions) {
        if ([int]$SessionEvidence.TerminalCount -ne 1 -or
            [string]$SessionEvidence.Protocol -cne [string]$Result.serverLogExpectedProtocolName -or
            ([bool]$Result.serverLogTargetRequired -and
             (-not [bool]$SessionEvidence.TargetObserved -or
              [string]$SessionEvidence.Target -cne [string]$Result.serverLogExpectedTarget)) -or
            [string]$SessionEvidence.Stage -cne 'Close' -or
            [string]$SessionEvidence.Status -cne 'Success' -or
            [string]$SessionEvidence.FaultCode -cne 'Success' -or
            [string]$SessionEvidence.PhaseSequence -notmatch 'Relay>Close$') {
            throw "Attempt $($Result.attempt) has invalid structured terminal session evidence."
        }
    }
    if (-not [bool]$Result.prismNaturalExit -or
        $null -eq $Result.prismExitCode -or
        [int]$Result.prismExitCode -ne 0 -or
        -not [bool]$Result.prismDrainRequested -or
        $Result.prismDrainUri -notmatch '/Operations/Drain\?worker=0&stop_accepting=true&force=false' -or
        ($Result.prismDrainStatus -ne 'accepted' -and
         $Result.prismDrainStatus -ne 'completed')) {
        throw "Attempt $($Result.attempt) Prism did not drain and exit naturally with code 0."
    }
    if (-not (Test-Path -LiteralPath $Result.prismConfigAudit -PathType Leaf) -or
        $Result.prismConfigAuditSha256 -notmatch '^[0-9A-F]{64}$' -or
        (Get-Sha256 $Result.prismConfigAudit) -ne $Result.prismConfigAuditSha256) {
        throw "Attempt $($Result.attempt) Prism config audit copy is missing or hash-mismatched."
    }
    if ([int]$Result.literalBodyMatchCount -ne [int]$Result.concurrentRequests) {
        throw "Attempt $($Result.attempt) did not validate every literal response body."
    }
    if (-not [bool]$Result.controllerProxiesApiResponded -or
        @($Result.controllerSelectedChain).Count -lt 1 -or
        [string]$Result.controllerProxiesSha256 -notmatch '^[0-9A-F]{64}$') {
        throw "Attempt $($Result.attempt) lacks verified /proxies selection evidence."
    }
    $ResponseEvidence = @($Result.responseEvidence)
    if ($ResponseEvidence.Count -ne [int]$Result.concurrentRequests) {
        throw "Attempt $($Result.attempt) response evidence count does not match concurrency."
    }
    foreach ($Response in $ResponseEvidence) {
        if ([int]$Response.HttpCode -ne 200 -or
            -not [bool]$Response.BodyMatchesExpected -or
            $Response.Body -cne [string]$Result.literalBodyExpected -or
            -not (Test-Path -LiteralPath $Response.BodyPath -PathType Leaf) -or
            $Response.BodySha256 -notmatch '^[0-9A-F]{64}$' -or
            (Get-Sha256 $Response.BodyPath) -ne $Response.BodySha256) {
            throw "Attempt $($Result.attempt) has invalid HTTP/literal response evidence."
        }
    }
    foreach ($CleanupField in @(
            'mihomoExited', 'mihomoIdentityVerified', 'homeRemoved', 'configRemoved',
            'prismConfigRemoved', 'prismIdentityVerified', 'targetIdentityVerified',
            'tlsIdentityVerified', 'ownedProcessIdentityVerified')) {
        if (-not ($Result.cleanup.PSObject.Properties.Name -contains $CleanupField) -or
            -not [bool]$Result.cleanup.$CleanupField) {
            throw "Attempt $($Result.attempt) cleanup field '$CleanupField' is not true."
        }
    }
    if (Test-Path -LiteralPath $Result.prismConfig) {
        throw "Attempt $($Result.attempt) left temporary Prism config: $($Result.prismConfig)"
    }
}

$ResidualHomes = @(Get-ChildItem -LiteralPath $ResolvedCase -Directory -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -like 'mihomo-home*' })
if ($ResidualHomes.Count -ne 0) {
    throw "Matrix runner left temporary Mihomo homes: $($ResidualHomes.Name -join ', ')"
}

Write-Host "MATRIX RUNNER CONTRACT PASSED ($($Results.Count) attempt(s))"
