param(
    [Parameter(Mandatory = $true)][string]$RepoRoot,
    [Parameter(Mandatory = $true)][string]$OutputDirectory,
    [string]$Platform = $env:RUNNER_OS,
    [string]$Commit = '',
    [string]$PrismExe = '',
    [switch]$AllowBlocked
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Invoke-Interop.ps1') -LibraryOnly

if (-not $Commit) {
    $Commit = (& git -C $RepoRoot rev-parse HEAD).Trim()
}
if (-not $Platform) {
    $Platform = [System.Environment]::OSVersion.Platform.ToString()
}
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

$Results = [System.Collections.Generic.List[object]]::new()
$Protocols = @(
    'http', 'socks5', 'trojan', 'vless', 'vmess', 'ss2022',
    'anytls', 'trusttunnel', 'websocket', 'xhttp', 'grpc',
    'hysteria2', 'tuic', 'reality', 'shadowtls', 'restls', 'native-tls'
)

function Add-BlockedResult {
    param([string]$Protocol, [string]$Direction, [string]$Status, [string]$Reason)
    $ExitCode = if ($Status -eq 'environment-unavailable') { 127 } else { 0 }
    $Result = New-InteropResult -Protocol $Protocol -Direction $Direction -Scenario 'authenticated-echo' `
        -Implementation 'not-run' -Commit $Commit -Platform $Platform -Status $Status -ExitCode $ExitCode `
        -Command $Reason -Artifacts @()
    $Name = ($Protocol + '_' + $Direction) -replace '[^A-Za-z0-9_.-]', '_'
    $Path = Join-Path $OutputDirectory ($Name + '.json')
    Write-InteropResult -Result $Result -Path $Path
    [void]$Results.Add($Result)
}

$CodecVectorTools = @{
    anytls = 'anytlscmp'
    grpc = 'guncmp'
    reality = 'realitycmp'
    restls = 'restlscmp'
    shadowtls = 'shadowtlscmp'
    trusttunnel = 'trusttunnelcmp'
    websocket = 'wscmp'
}

$CppClient = Join-Path $RepoRoot 'build/tests/preview/integration/InteropSs2022Client.exe'
$CppServer = Join-Path $RepoRoot 'build/tests/preview/integration/InteropSs2022Server.exe'
$LegacyCppClient = Join-Path $RepoRoot 'build/tests/InteropSs2022Client.exe'
$LegacyCppServer = Join-Path $RepoRoot 'build/tests/InteropSs2022Server.exe'
if (-not (Test-Path -LiteralPath $CppClient -PathType Leaf) -and
    (Test-Path -LiteralPath $LegacyCppClient -PathType Leaf)) {
    $CppClient = $LegacyCppClient
}
if (-not (Test-Path -LiteralPath $CppServer -PathType Leaf) -and
    (Test-Path -LiteralPath $LegacyCppServer -PathType Leaf)) {
    $CppServer = $LegacyCppServer
}
$GoServer = Join-Path $RepoRoot 'build/tests/go/ss2022_server.exe'
$GoClient = Join-Path $RepoRoot 'build/tests/go/ss2022_client.exe'
$InteropScript = Join-Path $RepoRoot 'tests/go/interop/run_interop.ps1'
$Pwsh = (Get-Command pwsh -ErrorAction SilentlyContinue).Source
if (-not $Pwsh) {
    $Pwsh = (Get-Command powershell -ErrorAction SilentlyContinue).Source
}

if ((Test-Path -LiteralPath $CppClient -PathType Leaf) -and
    (Test-Path -LiteralPath $CppServer -PathType Leaf) -and
    (Test-Path -LiteralPath $GoServer -PathType Leaf) -and
    (Test-Path -LiteralPath $GoClient -PathType Leaf) -and $Pwsh) {
    $Result = Invoke-InteropCase -Executable $Pwsh -Arguments @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $InteropScript,
        '-CppClient', $CppClient, '-CppServer', $CppServer,
        '-GoServer', $GoServer, '-GoClient', $GoClient) `
        -Protocol 'ss2022' -Direction 'preview-reference-bidirectional' -Scenario 'authenticated-echo' `
        -Implementation 'sing-shadowsocks-v0.2.12' -Commit $Commit -Platform $Platform `
        -OutputDirectory $OutputDirectory
    [void]$Results.Add($Result)
} else {
    Add-BlockedResult 'ss2022' 'preview-reference-bidirectional' 'environment-unavailable' `
        'SS2022 C++/Go interop executables or PowerShell runner are unavailable'
}

foreach ($Protocol in $Protocols) {
    if ($Protocol -eq 'ss2022') {
        continue
    }

    if ($CodecVectorTools.ContainsKey($Protocol)) {
        $VectorExecutable = Join-Path $RepoRoot ('build/tests/go/' + $CodecVectorTools[$Protocol] + '.exe')
        $VectorResult = Invoke-InteropCase -Executable $VectorExecutable `
            -Protocol $Protocol -Direction 'reference-codec-vector' -Scenario 'codec-vector' `
            -Implementation 'go-reference-vector' -Commit $Commit -Platform $Platform `
            -OutputDirectory $OutputDirectory
        [void]$Results.Add($VectorResult)
    } else {
        Add-BlockedResult $Protocol 'reference-codec-vector' 'environment-unavailable' `
            "No deterministic codec-vector executable is registered for $Protocol"
    }

    foreach ($Direction in @('preview-client-to-reference-server', 'reference-client-to-preview-server')) {
        Add-BlockedResult $Protocol $Direction 'environment-unavailable' `
            "No pinned full external harness is registered for $Protocol"
    }

    if ($Protocol -in @('vless', 'trojan', 'vmess') -and $PrismExe) {
        Add-BlockedResult $Protocol 'preview-production-single-port' 'blocked-production-prerequisite' `
            'Production analyzer change is not authorized in this Preview-only run'
    }
}

$SummaryPath = Join-Path $OutputDirectory 'summary.json'
$Summary = [ordered]@{
    schema = 'prism.interop-summary.v1'
    commit = $Commit
    platform = $Platform
    generated_utc = [DateTime]::UtcNow.ToString('o')
    total = $Results.Count
    pass = @($Results | Where-Object { $_.status -eq 'pass' }).Count
    blocked = @($Results | Where-Object { $_.status -in @('environment-unavailable', 'blocked-production-prerequisite') }).Count
    failed = @($Results | Where-Object { $_.status -in @('protocol-failure', 'implementation-mismatch') }).Count
    results = @($Results)
}
Write-InteropResult -Result $Summary -Path $SummaryPath

Write-Output ("Interop matrix: total={0} pass={1} blocked={2} failed={3}" -f $Summary.total, $Summary.pass, $Summary.blocked, $Summary.failed)
if ($Summary.failed -gt 0) {
    exit 1
}
if (-not $AllowBlocked -and $Summary.blocked -gt 0) {
    exit 2
}
exit 0
