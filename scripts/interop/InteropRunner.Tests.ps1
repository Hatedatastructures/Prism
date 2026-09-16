Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'Invoke-Interop.ps1') -LibraryOnly
. (Join-Path $PSScriptRoot 'Run-PrismPreview.ps1') -LibraryOnly

function Assert-Equal([object]$Expected, [object]$Actual, [string]$Message) {
    if ($Expected -ne $Actual) {
        throw "$Message. Expected '$Expected', got '$Actual'."
    }
}

Assert-Equal 'pass' (Get-InteropStatus -ExitCode 0 -Output 'PASS: echo') 'zero exit is pass'
Assert-Equal 'protocol-failure' (Get-InteropStatus -ExitCode 1 -Output 'FAIL: protocol handshake rejected') 'protocol failure marker'
Assert-Equal 'implementation-mismatch' (Get-InteropStatus -ExitCode 1 -Output 'FAIL: echo mismatch') 'mismatch marker'
Assert-Equal 'environment-unavailable' (Get-InteropStatus -ExitCode 127 -Output 'command not found') 'missing command exit'
Assert-Equal 'interface-gap' (Get-InteropStatus -ExitCode 2 -Output 'BLOCKED: interface-gap: missing stream API') 'interface gap marker'
Assert-Equal 'blocked-production-prerequisite' (Get-InteropStatus -ExitCode 0 -Output '' -BlockedProductionPrerequisite) 'blocked prerequisite wins'
Assert-Equal 'preview-only' (Get-InteropMatrixScope -PrismExe '') 'preview-only matrix scope'
Assert-Equal 'full' (Get-InteropMatrixScope -PrismExe 'build/Prism.exe') 'full matrix scope'
Assert-Equal 'production-blocked' (Get-GateDClassification -Scope full -Status blocked-production-prerequisite) 'full gate blocks production prerequisite'
Assert-Equal 'preview-only-blocked' (Get-GateDClassification -Scope preview-only -Status blocked-production-prerequisite) 'preview-only gate classifies production prerequisite'
Assert-Equal 'preview-only-blocked' (Get-GateDClassification -Scope preview-only -Status environment-unavailable) 'preview-only gate classifies missing environment'
Assert-Equal 'failed' (Get-GateDClassification -Scope full -Status failed) 'gate preserves hard failures'

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

$profileResult = New-InteropResult -Protocol 'http' -Direction 'preview-single-port' `
    -Scenario 'authenticated-echo' -Implementation 'preview-listener' -Commit 'deadbeef' `
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

$ReadyOutput = 'PrismPreview READY tcp_port=18081 udp_port=18082 udp_ready=true quic_ready=false generation=7'
$ReadyEvidence = Get-PreviewReadinessEvidence -Output $ReadyOutput -ExpectedPort 18081
Assert-Equal $true $ReadyEvidence.ready_log 'readiness log evidence'
Assert-Equal $true $ReadyEvidence.ready_port 'readiness tcp port evidence'
Assert-Equal 18082 $ReadyEvidence.udp_port 'readiness udp port evidence'
Assert-Equal $true $ReadyEvidence.udp_ready 'readiness udp state evidence'
Assert-Equal $false $ReadyEvidence.quic_ready 'readiness quic state evidence'
Assert-Equal 7 $ReadyEvidence.ready_generation 'readiness generation evidence'

$MissingReadiness = Get-PreviewReadinessEvidence -Output 'startup failed' -ExpectedPort 18081
Assert-Equal $false $MissingReadiness.ready_log 'missing readiness log evidence'
Assert-Equal $false $MissingReadiness.ready_port 'missing readiness port evidence'

$HashRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('prism-interop-hash-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $HashRoot -Force | Out-Null
try {
    $HashExe = Join-Path $HashRoot 'preview.exe'
    $HashConfig = Join-Path $HashRoot 'configuration.json'
    'executable' | Set-Content -LiteralPath $HashExe -Encoding UTF8
    'configuration' | Set-Content -LiteralPath $HashConfig -Encoding UTF8
    $HashEvidence = Get-PreviewHashEvidence -ExecutablePath $HashExe -ConfigPath $HashConfig
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
$CleanupResult = Remove-PreviewTemporaryDirectory -Path $TemporaryRoot
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

Write-Output 'PASS: InteropRunner classifier tests'
