[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$CaseDirectory,
    [ValidateSet('tcp', 'udp', 'quic')][string]$RunnerKind = 'tcp'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

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

if ($RunnerKind -ne 'tcp') {
    foreach ($Result in $Results) {
        foreach ($Field in @(
                'prismSha256', 'prismConfigSha256', 'prismConfigAudit',
                'prismConfigAuditSha256', 'mihomoSha256', 'prismNaturalExit',
                'prismExitCode', 'prismDrainUri', 'prismDrainRequested',
                'prismDrainStatus', 'ownedProcessIdentities', 'cleanup')) {
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
        else {
            foreach ($Field in @('httpCode', 'literalBodyExpected', 'literalBodyMatch',
                    'bodyPath', 'bodyBytes', 'bodySha256', 'serverLogObserved')) {
                if (-not ($Result.PSObject.Properties.Name -contains $Field)) {
                    throw "QUIC attempt $($Result.attempt) is missing result field '$Field'."
                }
            }
            if ([int]$Result.httpCode -ne 200 -or
                -not [bool]$Result.literalBodyMatch -or
                [int]$Result.bodyBytes -le 0 -or
                $Result.bodySha256 -notmatch '^[0-9A-F]{64}$' -or
                -not [bool]$Result.serverLogObserved -or
                -not (Test-Path -LiteralPath $Result.bodyPath -PathType Leaf) -or
                (Get-Sha256 $Result.bodyPath) -ne $Result.bodySha256) {
                throw "QUIC attempt $($Result.attempt) lacks literal body/hash/log evidence."
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
