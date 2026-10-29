param(
    [switch]$StaticOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'InvokeInterop.ps1') -LibraryOnly
. (Join-Path $PSScriptRoot 'RunPrism.ps1') -LibraryOnly

function Assert-Equal([object]$Expected, [object]$Actual, [string]$Message) {
    if ($Expected -ne $Actual) {
        throw "$Message. Expected '$Expected', got '$Actual'."
    }
}

function Assert-ClearInteropArtifactsContract {
    $SourcePath = Join-Path $PSScriptRoot 'InvokeInterop.ps1'
    $Source = Get-Content -LiteralPath $SourcePath -Raw -ErrorAction Stop
    $FunctionSource = [regex]::Match(
        $Source,
        '(?ms)^function Clear-InteropArtifacts \{.*?(?=^function Stop-InteropProcessTree \{)'
    ).Value
    Assert-Equal $true ($FunctionSource.Length -gt 0) 'cleanup function source'
    Assert-Equal $true ($FunctionSource -match '(?ms)\bforeach\s*\(\s*\$Artifact\s+in\s+\$Artifacts') `
        'cleanup handles artifacts individually'
    Assert-Equal $true ($FunctionSource -match '(?ms)\btry\s*\{.*?\bcatch\s*\{') `
        'cleanup skips an individual removal failure'
    Assert-Equal $true ($FunctionSource -match 'Remove-Item\s+-LiteralPath\s+\$Artifact\.FullName\s+-Force\s+-ErrorAction\s+Stop') `
        'cleanup removes the selected artifact'
    Assert-Equal $true ($FunctionSource -match '\bWrite-Warning\b') `
        'cleanup records a skipped artifact'
    Assert-Equal $false ($FunctionSource -match '\|\s*Remove-Item\b') `
        'cleanup does not use a terminating deletion pipeline'
}

Assert-ClearInteropArtifactsContract

function Assert-TrusttunnelReadinessContract {
    $SourcePath = Join-Path $PSScriptRoot 'RunMatrix.ps1'
    $Source = Get-Content -LiteralPath $SourcePath -Raw -ErrorAction Stop
    $WaitFunctionSource = [regex]::Match(
        $Source,
        '(?ms)^function Wait-TcpReady \{.*?(?=^function Wait-OutputReady \{)'
    ).Value
    Assert-Equal $true ($WaitFunctionSource.Length -gt 0) 'TCP readiness function source'
    Assert-Equal $true ($WaitFunctionSource -match '\$Owned\s+-ne\s+\$true') `
        'TCP readiness fails closed when ownership is not confirmed'

    $TrusttunnelFunctionSource = [regex]::Match(
        $Source,
        '(?ms)^function Invoke-TrusttunnelInterop \{.*?(?=^function Invoke-TuicInterop \{)'
    ).Value
    Assert-Equal $true ($TrusttunnelFunctionSource.Length -gt 0) 'TrustTunnel function source'
    Assert-Equal $true ($TrusttunnelFunctionSource -match
        'Wait-TcpReady\s+''127\.0\.0\.1''\s+\$TrusttunnelPort\s+-ProcessId\s+\$GoServerProcess\.Id') `
        'Go TrustTunnel readiness is bound to the launched process'
    Assert-Equal $true ($TrusttunnelFunctionSource -match
        'Wait-OutputReady\s+\$CppServerProcess\s+\$CppOut') `
        'Prism TrustTunnel readiness uses its server READY record'
    Assert-Equal $false ($TrusttunnelFunctionSource -match
        'Wait-TcpReady\s+''127\.0\.0\.1''\s+\$TrusttunnelPort\s+-ProcessId\s+\$CppServerProcess\.Id') `
        'Prism TrustTunnel readiness does not consume its single accepted connection'
}

Assert-TrusttunnelReadinessContract

function Assert-ServerReadinessResultContract {
    $SourcePath = Join-Path $PSScriptRoot 'RunMatrix.ps1'
    $Source = Get-Content -LiteralPath $SourcePath -Raw -ErrorAction Stop
    $ReadinessFunctionSource = [regex]::Match(
        $Source,
        '(?ms)^function Add-ServerReadinessResult \{.*?(?=^function Invoke-TrojanInterop \{)'
    ).Value
    Assert-Equal $true ($ReadinessFunctionSource.Length -gt 0) 'server readiness result function source'
    Assert-Equal $true ($ReadinessFunctionSource -match
        '\$ResultStatus\s*=\s*if\s*\(\$Exited\)\s*\{\s*''server-start-failure''\s*\}\s*else\s*\{\s*''environment-unavailable''\s*\}') `
        'early server exit and unconfirmed readiness have distinct statuses'
    Assert-Equal $true ($ReadinessFunctionSource -match
        '(?s)\$ExitCode\s*=\s*if\s*\(\$Exited\).*?\$ServerExitCode\s*-ne\s*0.*?\$ServerExitCode.*?127') `
        'early server exit preserves nonzero code while readiness timeout is blocked'
    Assert-Equal $true ($ReadinessFunctionSource -match "client_status\s*=\s*'not-run'") `
        'readiness failure records client as not run'
    Assert-Equal $true ($ReadinessFunctionSource -match 'server_exit_code\s*=\s*\$ServerExitCode') `
        'readiness result preserves server exit code'
    Assert-Equal $false ($ReadinessFunctionSource -match '''protocol-failure''') `
        'pre-client server readiness failures are not protocol failures'

    $SummarySource = [regex]::Match(
        $Source,
        '(?ms)^\$Summary = \[ordered\]@\{.*?^\}'
    ).Value
    Assert-Equal $true ($SummarySource -match
        'server_start_failed\s*=\s*@\(\$Results\s*\|\s*Where-Object\s*\{\s*\$_.status\s*-eq\s*''server-start-failure''') `
        'summary separately counts server start failures'
    Assert-Equal $true ($SummarySource -match
        'failed\s*=\s*@\(\$Results\s*\|\s*Where-Object\s*\{\s*\$_.status\s*-in\s*@\(''protocol-failure'',\s*''implementation-mismatch'',\s*''server-start-failure''\)') `
        'server start failures remain included in Gate D failed count'
    Assert-Equal $true ($SummarySource -match
        'blocked\s*=\s*@\(\$Results\s*\|\s*Where-Object\s*\{\s*\$_.status\s*-in\s*@\(''environment-unavailable''') `
        'unconfirmed readiness remains included in blocked count'

    Assert-Equal $true ($Source -match
        '(?s)\$Summary\.gate_d_classification\s*=\s*if\s*\(\$Summary\.failed\s*-gt\s*0\)\s*\{\s*''failed''') `
        'Gate D gives server start failures the hard-failure classification'
    Assert-Equal $true ($Source -match
        '(?s)\$Summary\.gate_d_classification.*?\$Summary\.blocked\s*-gt\s*0\)\s*\{\s*''prism-only-blocked''') `
        'Gate D preserves environment-unavailable as blocked'
}

Assert-ServerReadinessResultContract

function Assert-TuicReferenceServerImplementationContract {
    $SourcePath = Join-Path $PSScriptRoot 'RunMatrix.ps1'
    $Source = Get-Content -LiteralPath $SourcePath -Raw -ErrorAction Stop
    $TuicFunctionSource = [regex]::Match(
        $Source,
        '(?ms)^function Invoke-TuicInterop \{.*?(?=^function Invoke-Hysteria2Interop \{)'
    ).Value
    Assert-Equal $true ($TuicFunctionSource.Length -gt 0) 'TUIC interop function source'

    $ReverseReferencePattern = '(?ms)\$GoServerProcess\s*=\s*Start-Process\s+-FilePath\s+\$TuicGoServer.*?Invoke-InteropCase\s+-Executable\s+\$TuicCpp.*?-Direction\s+''prism-client-to-reference-server''.*?-Implementation\s+''go-quic-tuic-reference-server'''
    Assert-Equal $true ($TuicFunctionSource -match $ReverseReferencePattern) `
        'TUIC reverse case label identifies its Go reference server and Prism client'
    Assert-Equal $false ($TuicFunctionSource -match "mihomo-tuic-v5-reference-tcp-udp") `
        'TUIC reverse case does not claim a Mihomo implementation'
}

Assert-TuicReferenceServerImplementationContract
if ($StaticOnly) {
    Write-Output 'PASS: InteropRunner static contracts'
    return
}

Assert-Equal 'pass' (Get-InteropStatus -ExitCode 0 -Output 'PASS: echo') 'zero exit is pass'
Assert-Equal 'protocol-failure' (Get-InteropStatus -ExitCode 1 -Output 'FAIL: protocol handshake rejected') 'protocol failure marker'
Assert-Equal 'implementation-mismatch' (Get-InteropStatus -ExitCode 1 -Output 'FAIL: echo mismatch') 'mismatch marker'
Assert-Equal 'environment-unavailable' (Get-InteropStatus -ExitCode 127 -Output 'command not found') 'missing command exit'
Assert-Equal 'interface-gap' (Get-InteropStatus -ExitCode 2 -Output 'BLOCKED: interface-gap: missing stream API') 'interface gap marker'
Assert-Equal 'blocked-production-prerequisite' (Get-InteropStatus -ExitCode 0 -Output '' -BlockedProductionPrerequisite) 'blocked prerequisite wins'
Assert-Equal 'prism-only' (Get-InteropMatrixScope -PrismExe '') 'prism-only matrix scope'
Assert-Equal 'full' (Get-InteropMatrixScope -PrismExe 'build/src/Prism.exe') 'full matrix scope'
Assert-Equal 'production-blocked' (Get-GateDClassification -Scope full -Status blocked-production-prerequisite) 'full gate blocks production prerequisite'
Assert-Equal 'prism-only-blocked' (Get-GateDClassification -Scope prism-only -Status blocked-production-prerequisite) 'prism-only gate classifies production prerequisite'
Assert-Equal 'prism-only-blocked' (Get-GateDClassification -Scope prism-only -Status environment-unavailable) 'prism-only gate classifies missing environment'
Assert-Equal 'failed' (Get-GateDClassification -Scope full -Status failed) 'gate preserves hard failures'

$Listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
$Listener.Start()
try {
    $ListenerPort = ([System.Net.IPEndPoint]$Listener.LocalEndpoint).Port
    Assert-Equal $true (Test-InteropOwnedTcpPort -ProcessId $PID -Port $ListenerPort) `
        'listener readiness recognizes the owning process'
    Assert-Equal $false (Test-InteropOwnedTcpPort -ProcessId ($PID + 1) -Port $ListenerPort) `
        'listener readiness rejects a stale process owner'
}
finally {
    $Listener.Stop()
}

$ReferenceVersions = Get-InteropReferenceVersions -RepoRoot (Get-Location).Path
Assert-Equal 'v1.19.30' $ReferenceVersions['github.com/metacubex/mihomo'] 'mihomo reference version'
Assert-Equal 'v0.1.8' $ReferenceVersions['github.com/metacubex/tls'] 'TLS reference version'

$result = New-InteropResult -Protocol 'ss2022' -Direction 'go-server-cpp-client' `
    -Scenario 'echo' -Implementation 'sing-shadowsocks-v0.2.12' -Commit 'deadbeef' `
    -Platform 'windows-amd64' -Status 'pass' -ExitCode 0 -Command 'test command' `
    -Artifacts @('stdout.log', 'stderr.log')
Assert-Equal 'ss2022' $result.protocol 'result protocol'
Assert-Equal 'go-server-cpp-client' $result.direction 'result direction'
Assert-Equal 2 $result.artifacts.Count 'result artifacts'
Assert-Equal 'not-exercised' $result.recognition_mode 'default recognition coverage'
Assert-Equal '' $result.candidate_profile 'default candidate profile'
Assert-Equal '' $result.route 'default route'
Assert-Equal 0 $result.wall_time_ms 'default wall time'
Assert-Equal 0 $result.peak_working_set_bytes 'default peak working set'
Assert-Equal $false $result.metrics_available 'default metrics availability'

$metricResult = New-InteropResult -Protocol 'http' -Direction 'metrics' -Scenario 'echo' `
    -Implementation 'reference' -Commit 'deadbeef' -Platform 'windows-amd64' -Status 'pass' `
    -ExitCode 0 -Command 'test command' -WallTimeMs 12.5 -PeakWorkingSetBytes 4096
Assert-Equal 12.5 $metricResult.wall_time_ms 'measured wall time'
Assert-Equal 4096 $metricResult.peak_working_set_bytes 'measured peak working set'
Assert-Equal $true $metricResult.metrics_available 'measured metrics availability'

$profileResult = New-InteropResult -Protocol 'http' -Direction 'prism-single-port' `
    -Scenario 'authenticated-echo' -Implementation 'prism-listener' -Commit 'deadbeef' `
    -Platform 'windows-amd64' -Status 'pass' -ExitCode 0 -Command 'test command' `
    -RecognitionMode 'Deterministic' -CandidateProfile 'http+socks5' -Route 'edge.example -> http'
Assert-Equal 'Deterministic' $profileResult.recognition_mode 'explicit recognition mode'
Assert-Equal 'http+socks5' $profileResult.candidate_profile 'explicit candidate profile'
Assert-Equal 'edge.example -> http' $profileResult.route 'explicit route'

$coverage = [ordered]@{
    Deterministic = 1
    MixedTrial = 1
    'direct-handler' = 0
    'not-exercised' = 0
}
Assert-Equal $true ($coverage['Deterministic'] -gt 0 -and $coverage['MixedTrial'] -gt 0) 'recognition coverage complete'

$ReadyOutput = 'Prism READY tcp_port=18081 udp_port=18082 udp_ready=true quic_ready=false generation=7'
$ReadyEvidence = Get-PrismReadinessEvidence -Output $ReadyOutput -ExpectedPort 18081
Assert-Equal $true $ReadyEvidence.ready_log 'readiness log evidence'
Assert-Equal $true $ReadyEvidence.ready_port 'readiness tcp port evidence'
Assert-Equal 18082 $ReadyEvidence.udp_port 'readiness udp port evidence'
Assert-Equal $true $ReadyEvidence.udp_ready 'readiness udp state evidence'
Assert-Equal $false $ReadyEvidence.quic_ready 'readiness quic state evidence'
Assert-Equal 7 $ReadyEvidence.ready_generation 'readiness generation evidence'

$MissingReadiness = Get-PrismReadinessEvidence -Output 'startup failed' -ExpectedPort 18081
Assert-Equal $false $MissingReadiness.ready_log 'missing readiness log evidence'
Assert-Equal $false $MissingReadiness.ready_port 'missing readiness port evidence'

$HashRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('prism-interop-hash-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $HashRoot -Force | Out-Null
try {
    $HashExe = Join-Path $HashRoot 'prism.exe'
    $HashConfig = Join-Path $HashRoot 'configuration.json'
    'executable' | Set-Content -LiteralPath $HashExe -Encoding UTF8
    'configuration' | Set-Content -LiteralPath $HashConfig -Encoding UTF8
    $HashEvidence = Get-PrismHashEvidence -ExecutablePath $HashExe -ConfigPath $HashConfig
    Assert-Equal 'SHA256' $HashEvidence.algorithm 'hash algorithm evidence'
    Assert-Equal $true ($HashEvidence.executable_sha256.Length -eq 64) 'executable hash evidence'
    Assert-Equal $true ($HashEvidence.configuration_sha256.Length -eq 64) 'configuration hash evidence'
    Assert-Equal $true ($HashEvidence.executable_size_bytes -gt 0) 'executable size evidence'
    Assert-Equal $true ($HashEvidence.configuration_size_bytes -gt 0) 'configuration size evidence'
}
finally {
    Remove-Item -LiteralPath $HashRoot -Recurse -Force -ErrorAction SilentlyContinue
}

$TemporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('prism-interop-temp-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path (Join-Path $TemporaryRoot 'evidence') -Force | Out-Null
$CleanupResult = Remove-PrismTemporaryDirectory -Path $TemporaryRoot
Assert-Equal 'completed' $CleanupResult.status 'temporary directory cleanup status'
Assert-Equal $false (Test-Path -LiteralPath $TemporaryRoot) 'temporary directory cleanup'

$CleanupRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('prism-interop-clean-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $CleanupRoot -Force | Out-Null
try {
    'old result' | Set-Content -LiteralPath (Join-Path $CleanupRoot 'old.json') -Encoding UTF8
    'old log' | Set-Content -LiteralPath (Join-Path $CleanupRoot 'old.log') -Encoding UTF8
    'keep' | Set-Content -LiteralPath (Join-Path $CleanupRoot 'keep.txt') -Encoding UTF8
    Clear-InteropArtifacts -OutputDirectory $CleanupRoot
    Assert-Equal $false (Test-Path -LiteralPath (Join-Path $CleanupRoot 'old.json')) 'stale json cleanup'
    Assert-Equal $false (Test-Path -LiteralPath (Join-Path $CleanupRoot 'old.log')) 'stale log cleanup'
    Assert-Equal $true (Test-Path -LiteralPath (Join-Path $CleanupRoot 'keep.txt')) 'non-artifact preservation'
}
finally {
    Remove-Item -LiteralPath $CleanupRoot -Recurse -Force -ErrorAction SilentlyContinue
}

$TimeoutRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('prism-interop-timeout-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $TimeoutRoot -Force | Out-Null
try {
    $PowerShell = (Get-Command pwsh -ErrorAction SilentlyContinue).Source
    if (-not $PowerShell) {
        $PowerShell = (Get-Command powershell -ErrorAction Stop).Source
    }
    $TimeoutResult = Invoke-InteropCase -Executable $PowerShell -Arguments @(
        '-NoProfile', '-Command', 'Start-Sleep -Seconds 2') `
        -Protocol 'synthetic' -Direction 'timeout' -Scenario 'bounded-wait' `
        -Implementation 'runner-regression' -Commit 'deadbeef' -Platform 'windows-amd64' `
        -OutputDirectory $TimeoutRoot -TimeoutSeconds 1
    Assert-Equal 124 $TimeoutResult.exit_code 'timed-out case exit code'
    Assert-Equal 'protocol-failure' $TimeoutResult.status 'timed-out case status'
}
finally {
    Remove-Item -LiteralPath $TimeoutRoot -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Output 'PASS: InteropRunner classifier tests'
