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
$WorkspaceDirty = @(& git -C $RepoRoot status --porcelain=v1).Count -gt 0
$SourceState = if ($WorkspaceDirty) { 'dirty' } else { 'clean' }
$MatrixScope = Get-InteropMatrixScope -PrismExe $PrismExe
$ReferenceVersions = Get-InteropReferenceVersions -RepoRoot $RepoRoot
if (-not $Platform) {
    $Platform = [System.Environment]::OSVersion.Platform.ToString()
}
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
Clear-InteropArtifacts -OutputDirectory $OutputDirectory

$Results = [System.Collections.Generic.List[object]]::new()
$Protocols = @(
    'http', 'socks5', 'trojan', 'vless', 'vmess', 'ss2022',
    'anytls', 'trusttunnel', 'websocket', 'xhttp', 'grpc',
    'hysteria2', 'tuic', 'reality', 'shadowtls', 'restls', 'native-tls'
)

function Add-BlockedResult {
    param(
        [string]$Protocol,
        [string]$Direction,
        [string]$Status,
        [string]$Reason,
        [ValidateSet('Deterministic', 'MixedTrial', 'direct-handler', 'not-exercised')][string]$RecognitionMode = 'not-exercised',
        [string]$CandidateProfile = '',
        [string]$Route = ''
    )
    $ExitCode = switch ($Status) {
        'environment-unavailable' { 127; break }
        'interface-gap' { 2; break }
        default { 0 }
    }
    $Result = New-InteropResult -Protocol $Protocol -Direction $Direction -Scenario 'authenticated-echo' `
        -Implementation 'not-run' -Commit $Commit -Platform $Platform -Status $Status -ExitCode $ExitCode `
        -Command $Reason -Artifacts @() -RecognitionMode $RecognitionMode `
        -CandidateProfile $CandidateProfile -Route $Route
    $Name = ($Protocol + '_' + $Direction) -replace '[^A-Za-z0-9_.-]', '_'
    $Path = Join-Path $OutputDirectory ($Name + '.json')
    Write-InteropResult -Result $Result -Path $Path
    [void]$Results.Add($Result)
}

$CodecVectorTools = @{
    http = 'httpcmp'
    socks5 = 'socks5cmp'
    trojan = 'trojancmp'
    vless = 'vlesscmp'
    anytls = 'anytlscmp'
    grpc = 'guncmp'
    hysteria2 = 'hysteria2cmp'
    tuic = 'tuiccmp'
    xhttp = 'xhttpcmp'
    vmess = 'vmesscmp'
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

$TrojanCpp = Join-Path $RepoRoot 'build/tests/preview/integration/InteropTrojan.exe'
$TrojanGo = Join-Path $RepoRoot 'build/tests/go/trojan.exe'
$TrojanPort = 19082
$VmessCpp = Join-Path $RepoRoot 'build/tests/preview/integration/InteropVmess.exe'
$VmessGo = Join-Path $RepoRoot 'build/tests/go/singvmess.exe'
$VmessGoServer = Join-Path $RepoRoot 'build/tests/go/vmess_server.exe'
$VmessPort = 19083
$VlessCpp = Join-Path $RepoRoot 'build/tests/preview/integration/InteropVless.exe'
$VlessGo = Join-Path $RepoRoot 'build/tests/go/vless.exe'
$VlessPort = 19084
$Socks5Cpp = Join-Path $RepoRoot 'build/tests/preview/integration/InteropSocks5.exe'
$Socks5Go = Join-Path $RepoRoot 'build/tests/go/socks5.exe'
$Socks5Port = 19085
$HttpCpp = Join-Path $RepoRoot 'build/tests/preview/integration/InteropHttp.exe'
$HttpGo = Join-Path $RepoRoot 'build/tests/go/http.exe'
$HttpPort = 19086
$RecognitionCpp = Join-Path $RepoRoot 'build/tests/preview/integration/InteropRecognition.exe'
$RecognitionDeterministicPort = 19110
$RecognitionDeterministicSocks5Port = 19112
$RecognitionMixedTrialPort = 19111
$RecognitionMixedTrojanPort = 19113
$RecognitionMixedVmessPort = 19114
$RecognitionMixedSs2022Port = 19115
$NativeTlsCpp = Join-Path $RepoRoot 'build/tests/preview/integration/InteropNativeTls.exe'
$NativeTlsGo = Join-Path $RepoRoot 'build/tests/go/native_tls.exe'
$NativeTlsPort = 19092
$WsCpp = Join-Path $RepoRoot 'build/tests/preview/integration/InteropWs.exe'
$WsGo = Join-Path $RepoRoot 'build/tests/go/websocket.exe'
$WsPort = 19093
$AnytlsCpp = Join-Path $RepoRoot 'build/tests/preview/integration/InteropAnytls.exe'
$AnytlsGo = Join-Path $RepoRoot 'build/tests/go/anytls.exe'
$AnytlsPort = 19094
$GunCpp = Join-Path $RepoRoot 'build/tests/preview/integration/InteropGun.exe'
$GunGo = Join-Path $RepoRoot 'build/tests/go/gun.exe'
$GunPort = 19095
$XhttpCpp = Join-Path $RepoRoot 'build/tests/preview/integration/InteropXhttp.exe'
$XhttpGo = Join-Path $RepoRoot 'build/tests/go/xhttp.exe'
$XhttpPort = 19096
$TrusttunnelCpp = Join-Path $RepoRoot 'build/tests/preview/integration/InteropTrusttunnel.exe'
$TrusttunnelGo = Join-Path $RepoRoot 'build/tests/go/trusttunnel.exe'
$TrusttunnelPort = 19097
$ShadowtlsCpp = Join-Path $RepoRoot 'build/tests/preview/integration/InteropShadowtls.exe'
$ShadowtlsGo = Join-Path $RepoRoot 'build/tests/go/shadowtls.exe'
$ShadowtlsPort = 19100
$ShadowtlsTargetPort = 19101
$TuicCpp = Join-Path $RepoRoot 'build/tests/preview/integration/InteropTuic.exe'
$TuicGo = Join-Path $RepoRoot 'build/tests/go/tuic.exe'
$TuicGoServer = Join-Path $RepoRoot 'build/tests/go/tuic_server.exe'
$TuicPort = 19087
$TuicReferencePort = 19091
$Hysteria2Cpp = Join-Path $RepoRoot 'build/tests/preview/integration/InteropHysteria2.exe'
$Hysteria2CppClient = Join-Path $RepoRoot 'build/tests/preview/integration/InteropHysteria2Client.exe'
$Hysteria2Go = Join-Path $RepoRoot 'build/tests/go/hysteria2.exe'
$Hysteria2GoServer = Join-Path $RepoRoot 'build/tests/go/hysteria2_server.exe'
$Hysteria2Port = 19088
$Hysteria2ReferencePort = 19089
$Hysteria2ReferenceUdpPort = 19090

function Stop-InteropProcess {
    param([System.Diagnostics.Process]$Process)
    if ($Process -and -not $Process.HasExited) {
        Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
    }
}

function Wait-TcpReady {
    param([string]$HostName, [int]$Port, [int]$TimeoutSeconds = 10)
    $Deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ([DateTime]::UtcNow -lt $Deadline) {
        $Client = $null
        try {
            $Client = [System.Net.Sockets.TcpClient]::new()
            $Connect = $Client.ConnectAsync($HostName, $Port)
            if ($Connect.Wait(200) -and $Client.Connected) {
                return $true
            }
        } catch {
        } finally {
            if ($Client) {
                $Client.Dispose()
            }
        }
        Start-Sleep -Milliseconds 100
    }
    return $false
}

function Wait-OutputReady {
    param([System.Diagnostics.Process]$Process, [string]$Path, [int]$TimeoutSeconds = 10)
    $Deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ([DateTime]::UtcNow -lt $Deadline) {
        if ($Process -and $Process.HasExited) {
            return $false
        }
        if (Test-Path -LiteralPath $Path) {
            $Output = Get-Content -LiteralPath $Path -Raw -ErrorAction SilentlyContinue
            if ($Output -match '(?m)^READY:') {
                return $true
            }
        }
        Start-Sleep -Milliseconds 100
    }
    return $false
}

function Add-DependencyArtifacts {
    param([object]$Result, [string[]]$Artifacts)
    $Result.artifacts = @($Result.artifacts) + @($Artifacts)
    $CaseName = ($Result.protocol + '_' + $Result.direction + '_' + $Result.scenario) -replace '[^A-Za-z0-9_.-]', '_'
    $ResultPath = Join-Path $OutputDirectory ($CaseName + '.json')
    Write-InteropResult -Result $Result -Path $ResultPath
    return $Result
}

function Invoke-TrojanInterop {
    if (-not (Test-Path -LiteralPath $TrojanCpp -PathType Leaf) -or
        -not (Test-Path -LiteralPath $TrojanGo -PathType Leaf)) {
        Add-BlockedResult 'trojan' 'preview-client-to-reference-server' 'environment-unavailable' `
            'Preview Trojan or Go Trojan harness executable is unavailable'
        Add-BlockedResult 'trojan' 'reference-client-to-preview-server' 'environment-unavailable' `
            'Preview Trojan or Go Trojan harness executable is unavailable'
        return
    }

    $Prefix = 'trojan_' + [Guid]::NewGuid().ToString('N')
    $GoOut = Join-Path $OutputDirectory ($Prefix + '_go_server.stdout.log')
    $GoErr = Join-Path $OutputDirectory ($Prefix + '_go_server.stderr.log')
    $CppOut = Join-Path $OutputDirectory ($Prefix + '_cpp_server.stdout.log')
    $CppErr = Join-Path $OutputDirectory ($Prefix + '_cpp_server.stderr.log')
    $ServerAddress = '127.0.0.1:' + $TrojanPort
    $GoServerProcess = $null
    $CppServerProcess = $null
    try {
        $GoServerProcess = Start-Process -FilePath $TrojanGo -ArgumentList @(
            '-mode', 'server', '-listen', $ServerAddress, '-pass', 'prism') -PassThru -WindowStyle Hidden `
            -RedirectStandardOutput $GoOut -RedirectStandardError $GoErr
        if (-not (Wait-TcpReady '127.0.0.1' $TrojanPort)) {
            Add-BlockedResult 'trojan' 'preview-client-to-reference-server' 'environment-unavailable' `
                'Go Trojan reference server did not become ready'
        }
        else {
            $Result = Invoke-InteropCase -Executable $TrojanCpp -Arguments @(
                '-mode', 'client', '-addr', $ServerAddress, '-pass', 'prism', '-target', 'example.com:443') `
                -Protocol 'trojan' -Direction 'preview-client-to-reference-server' -Scenario 'authenticated-echo' `
                -Implementation 'go-trojan-reference' -Commit $Commit -Platform $Platform `
                -OutputDirectory $OutputDirectory
            $Results.Add((Add-DependencyArtifacts $Result @($GoOut, $GoErr)))
        }
    }
    finally {
        Stop-InteropProcess $GoServerProcess
        $GoServerProcess = $null
    }

    try {
        $CppServerProcess = Start-Process -FilePath $TrojanCpp -ArgumentList @(
            '-mode', 'server', '-addr', $ServerAddress, '-pass', 'prism') -PassThru -WindowStyle Hidden `
            -RedirectStandardOutput $CppOut -RedirectStandardError $CppErr
        if (-not (Wait-TcpReady '127.0.0.1' $TrojanPort)) {
            Add-BlockedResult 'trojan' 'reference-client-to-preview-server' 'environment-unavailable' `
                'Preview Trojan server did not become ready'
        }
        else {
            $Result = Invoke-InteropCase -Executable $TrojanGo -Arguments @(
                '-mode', 'selftest', '-server', $ServerAddress, '-pass', 'prism',
                '-target', 'example.com:443', '-total', '65536', '-block', '4096') `
                -Protocol 'trojan' -Direction 'reference-client-to-preview-server' -Scenario 'authenticated-echo' `
                -Implementation 'preview-trojan-server' -Commit $Commit -Platform $Platform `
                -OutputDirectory $OutputDirectory
            $Results.Add((Add-DependencyArtifacts $Result @($CppOut, $CppErr)))
        }
    }
    finally {
        Stop-InteropProcess $CppServerProcess
        $CppServerProcess = $null
    }

}

function Invoke-VmessInterop {
    if (-not (Test-Path -LiteralPath $VmessCpp -PathType Leaf) -or
        -not (Test-Path -LiteralPath $VmessGo -PathType Leaf) -or
        -not (Test-Path -LiteralPath $VmessGoServer -PathType Leaf)) {
        Add-BlockedResult 'vmess' 'reference-client-to-preview-server' 'environment-unavailable' `
            'Preview VMess or sing-vmess reference executable/server is unavailable'
        Add-BlockedResult 'vmess' 'preview-client-to-reference-server' 'environment-unavailable' `
            'Preview VMess or sing-vmess reference executable/server is unavailable'
        return
    }

    $Prefix = 'vmess_' + [Guid]::NewGuid().ToString('N')
    $CppOut = Join-Path $OutputDirectory ($Prefix + '_cpp_server.stdout.log')
    $CppErr = Join-Path $OutputDirectory ($Prefix + '_cpp_server.stderr.log')
    $ServerAddress = '127.0.0.1:' + $VmessPort
    $CppServerProcess = $null
    try {
        $CppServerProcess = Start-Process -FilePath $VmessCpp -ArgumentList @(
            '-addr', $ServerAddress) -PassThru -WindowStyle Hidden `
            -RedirectStandardOutput $CppOut -RedirectStandardError $CppErr
        if (-not (Wait-TcpReady '127.0.0.1' $VmessPort)) {
            Add-BlockedResult 'vmess' 'reference-client-to-preview-server' 'environment-unavailable' `
                'Preview VMess server did not become ready'
        }
        else {
            $Result = Invoke-InteropCase -Executable $VmessGo -Arguments @($ServerAddress) `
                -Protocol 'vmess' -Direction 'reference-client-to-preview-server' -Scenario 'authenticated-echo' `
                -Implementation 'sing-vmess-reference' -Commit $Commit -Platform $Platform `
                -OutputDirectory $OutputDirectory
            if ($CppServerProcess -and -not $CppServerProcess.HasExited) {
                [void]$CppServerProcess.WaitForExit(2000)
            }
            $Results.Add((Add-DependencyArtifacts $Result @($CppOut, $CppErr)))
        }
    }
    finally {
        Stop-InteropProcess $CppServerProcess
        $CppServerProcess = $null
    }

    $ReversePrefix = 'vmess_reverse_' + [Guid]::NewGuid().ToString('N')
    $GoOut = Join-Path $OutputDirectory ($ReversePrefix + '_go_server.stdout.log')
    $GoErr = Join-Path $OutputDirectory ($ReversePrefix + '_go_server.stderr.log')
    $GoServerProcess = $null
    try {
        $GoServerProcess = Start-Process -FilePath $VmessGoServer -ArgumentList @(
            '-listen', $ServerAddress) -PassThru -WindowStyle Hidden `
            -RedirectStandardOutput $GoOut -RedirectStandardError $GoErr
        if (-not (Wait-OutputReady $GoServerProcess $GoOut)) {
            Add-BlockedResult 'vmess' 'preview-client-to-reference-server' 'environment-unavailable' `
                'Go sing-vmess reference server did not become ready'
        }
        else {
            $Result = Invoke-InteropCase -Executable $VmessCpp -Arguments @(
                '-mode', 'client', '-addr', $ServerAddress) `
                -Protocol 'vmess' -Direction 'preview-client-to-reference-server' -Scenario 'authenticated-echo' `
                -Implementation 'preview-vmess-client-sing-vmess-reference' -Commit $Commit -Platform $Platform `
                -OutputDirectory $OutputDirectory
            if ($GoServerProcess -and -not $GoServerProcess.HasExited) {
                [void]$GoServerProcess.WaitForExit(2000)
            }
            $Results.Add((Add-DependencyArtifacts $Result @($GoOut, $GoErr)))
        }
    }
    finally {
        Stop-InteropProcess $GoServerProcess
        $GoServerProcess = $null
    }

}

function Invoke-VlessInterop {
    if (-not (Test-Path -LiteralPath $VlessCpp -PathType Leaf) -or
        -not (Test-Path -LiteralPath $VlessGo -PathType Leaf)) {
        Add-BlockedResult 'vless' 'preview-client-to-reference-server' 'environment-unavailable' `
            'Preview VLESS or Go VLESS harness executable is unavailable'
        Add-BlockedResult 'vless' 'reference-client-to-preview-server' 'environment-unavailable' `
            'Preview VLESS or Go VLESS harness executable is unavailable'
        return
    }

    $Prefix = 'vless_' + [Guid]::NewGuid().ToString('N')
    $GoOut = Join-Path $OutputDirectory ($Prefix + '_go_server.stdout.log')
    $GoErr = Join-Path $OutputDirectory ($Prefix + '_go_server.stderr.log')
    $CppOut = Join-Path $OutputDirectory ($Prefix + '_cpp_server.stdout.log')
    $CppErr = Join-Path $OutputDirectory ($Prefix + '_cpp_server.stderr.log')
    $ServerAddress = '127.0.0.1:' + $VlessPort
    $GoServerProcess = $null
    $CppServerProcess = $null
    try {
        $GoServerProcess = Start-Process -FilePath $VlessGo -ArgumentList @(
            '-mode', 'server', '-listen', $ServerAddress) -PassThru -WindowStyle Hidden `
            -RedirectStandardOutput $GoOut -RedirectStandardError $GoErr
        if (-not (Wait-TcpReady '127.0.0.1' $VlessPort)) {
            Add-BlockedResult 'vless' 'preview-client-to-reference-server' 'environment-unavailable' `
                'Go VLESS reference server did not become ready'
        }
        else {
            $Result = Invoke-InteropCase -Executable $VlessCpp -Arguments @(
                '-mode', 'client', '-addr', $ServerAddress, '-target', 'example.com:443') `
                -Protocol 'vless' -Direction 'preview-client-to-reference-server' -Scenario 'authenticated-echo' `
                -Implementation 'go-vless-reference' -Commit $Commit -Platform $Platform `
                -OutputDirectory $OutputDirectory
            $Results.Add((Add-DependencyArtifacts $Result @($GoOut, $GoErr)))
        }
    }
    finally {
        Stop-InteropProcess $GoServerProcess
        $GoServerProcess = $null
    }

    try {
        $CppServerProcess = Start-Process -FilePath $VlessCpp -ArgumentList @(
            '-mode', 'server', '-addr', $ServerAddress) -PassThru -WindowStyle Hidden `
            -RedirectStandardOutput $CppOut -RedirectStandardError $CppErr
        if (-not (Wait-TcpReady '127.0.0.1' $VlessPort)) {
            Add-BlockedResult 'vless' 'reference-client-to-preview-server' 'environment-unavailable' `
                'Preview VLESS server did not become ready'
        }
        else {
            $Result = Invoke-InteropCase -Executable $VlessGo -Arguments @(
                '-mode', 'client', '-server', $ServerAddress, '-target', 'example.com:443') `
                -Protocol 'vless' -Direction 'reference-client-to-preview-server' -Scenario 'authenticated-echo' `
                -Implementation 'preview-vless-server' -Commit $Commit -Platform $Platform `
                -OutputDirectory $OutputDirectory
            $Results.Add((Add-DependencyArtifacts $Result @($CppOut, $CppErr)))
        }
    }
    finally {
        Stop-InteropProcess $CppServerProcess
        $CppServerProcess = $null
    }

    $UdpPrefix = 'vless_udp_' + [Guid]::NewGuid().ToString('N')
    $UdpGoOut = Join-Path $OutputDirectory ($UdpPrefix + '_go_server.stdout.log')
    $UdpGoErr = Join-Path $OutputDirectory ($UdpPrefix + '_go_server.stderr.log')
    $UdpCppOut = Join-Path $OutputDirectory ($UdpPrefix + '_cpp_server.stdout.log')
    $UdpCppErr = Join-Path $OutputDirectory ($UdpPrefix + '_cpp_server.stderr.log')
    $UdpGoServerProcess = $null
    $UdpCppServerProcess = $null
    try {
        $UdpGoServerProcess = Start-Process -FilePath $VlessGo -ArgumentList @(
            '-mode', 'server', '-listen', $ServerAddress) -PassThru -WindowStyle Hidden `
            -RedirectStandardOutput $UdpGoOut -RedirectStandardError $UdpGoErr
        if (-not (Wait-TcpReady '127.0.0.1' $VlessPort)) {
            Add-BlockedResult 'vless' 'preview-client-to-reference-server' 'environment-unavailable' `
                'Go VLESS UDP reference server did not become ready'
        }
        else {
            $UdpResult = Invoke-InteropCase -Executable $VlessCpp -Arguments @(
                '-mode', 'client', '-addr', $ServerAddress, '-target', 'example.com:53', '-udp', '1') `
                -Protocol 'vless' -Direction 'preview-client-to-reference-server' -Scenario 'authenticated-udp-echo' `
                -Implementation 'go-vless-reference-udp' -Commit $Commit -Platform $Platform `
                -OutputDirectory $OutputDirectory
            $Results.Add((Add-DependencyArtifacts $UdpResult @($UdpGoOut, $UdpGoErr)))
        }
    }
    finally {
        Stop-InteropProcess $UdpGoServerProcess
        $UdpGoServerProcess = $null
    }

    try {
        $UdpCppServerProcess = Start-Process -FilePath $VlessCpp -ArgumentList @(
            '-mode', 'server', '-addr', $ServerAddress, '-udp', '1') -PassThru -WindowStyle Hidden `
            -RedirectStandardOutput $UdpCppOut -RedirectStandardError $UdpCppErr
        if (-not (Wait-TcpReady '127.0.0.1' $VlessPort)) {
            Add-BlockedResult 'vless' 'reference-client-to-preview-server' 'environment-unavailable' `
                'Preview VLESS UDP server did not become ready'
        }
        else {
            $UdpResult = Invoke-InteropCase -Executable $VlessGo -Arguments @(
                '-mode', 'client', '-server', $ServerAddress, '-target', 'example.com:53', '-udp') `
                -Protocol 'vless' -Direction 'reference-client-to-preview-server' -Scenario 'authenticated-udp-echo' `
                -Implementation 'preview-vless-server-udp' -Commit $Commit -Platform $Platform `
                -OutputDirectory $OutputDirectory
            $Results.Add((Add-DependencyArtifacts $UdpResult @($UdpCppOut, $UdpCppErr)))
        }
    }
    finally {
        Stop-InteropProcess $UdpCppServerProcess
        $UdpCppServerProcess = $null
    }
}

function Invoke-Socks5Interop {
    if (-not (Test-Path -LiteralPath $Socks5Cpp -PathType Leaf) -or
        -not (Test-Path -LiteralPath $Socks5Go -PathType Leaf)) {
        Add-BlockedResult 'socks5' 'preview-client-to-reference-server' 'environment-unavailable' `
            'Preview SOCKS5 or Go SOCKS5 harness executable is unavailable'
        Add-BlockedResult 'socks5' 'reference-client-to-preview-server' 'environment-unavailable' `
            'Preview SOCKS5 or Go SOCKS5 harness executable is unavailable'
        return
    }

    $Prefix = 'socks5_' + [Guid]::NewGuid().ToString('N')
    $GoOut = Join-Path $OutputDirectory ($Prefix + '_go_server.stdout.log')
    $GoErr = Join-Path $OutputDirectory ($Prefix + '_go_server.stderr.log')
    $CppOut = Join-Path $OutputDirectory ($Prefix + '_cpp_server.stdout.log')
    $CppErr = Join-Path $OutputDirectory ($Prefix + '_cpp_server.stderr.log')
    $ServerAddress = '127.0.0.1:' + $Socks5Port
    $GoServerProcess = $null
    $CppServerProcess = $null
    try {
        $GoServerProcess = Start-Process -FilePath $Socks5Go -ArgumentList @(
            '-mode', 'server', '-listen', $ServerAddress) -PassThru -WindowStyle Hidden `
            -RedirectStandardOutput $GoOut -RedirectStandardError $GoErr
        if (-not (Wait-TcpReady '127.0.0.1' $Socks5Port)) {
            Add-BlockedResult 'socks5' 'preview-client-to-reference-server' 'environment-unavailable' `
                'Go SOCKS5 reference server did not become ready'
        }
        else {
            $Result = Invoke-InteropCase -Executable $Socks5Cpp -Arguments @(
                '-mode', 'client', '-addr', $ServerAddress, '-target', 'example.com:443') `
                -Protocol 'socks5' -Direction 'preview-client-to-reference-server' -Scenario 'authenticated-echo' `
                -Implementation 'go-socks5-reference' -Commit $Commit -Platform $Platform `
                -OutputDirectory $OutputDirectory
            $Results.Add((Add-DependencyArtifacts $Result @($GoOut, $GoErr)))
        }
    }
    finally {
        Stop-InteropProcess $GoServerProcess
        $GoServerProcess = $null
    }

    try {
        $CppServerProcess = Start-Process -FilePath $Socks5Cpp -ArgumentList @(
            '-mode', 'server', '-addr', $ServerAddress) -PassThru -WindowStyle Hidden `
            -RedirectStandardOutput $CppOut -RedirectStandardError $CppErr
        if (-not (Wait-TcpReady '127.0.0.1' $Socks5Port)) {
            Add-BlockedResult 'socks5' 'reference-client-to-preview-server' 'environment-unavailable' `
                'Preview SOCKS5 server did not become ready'
        }
        else {
            $Result = Invoke-InteropCase -Executable $Socks5Go -Arguments @(
                '-mode', 'client', '-server', $ServerAddress, '-target', 'example.com:443') `
                -Protocol 'socks5' -Direction 'reference-client-to-preview-server' -Scenario 'authenticated-echo' `
                -Implementation 'preview-socks5-server' -Commit $Commit -Platform $Platform `
                -OutputDirectory $OutputDirectory
            $Results.Add((Add-DependencyArtifacts $Result @($CppOut, $CppErr)))
        }
    }
    finally {
        Stop-InteropProcess $CppServerProcess
        $CppServerProcess = $null
    }
}

function Invoke-HttpInterop {
    if (-not (Test-Path -LiteralPath $HttpCpp -PathType Leaf) -or
        -not (Test-Path -LiteralPath $HttpGo -PathType Leaf)) {
        Add-BlockedResult 'http' 'preview-client-to-reference-server' 'environment-unavailable' `
            'Preview HTTP or Go HTTP harness executable is unavailable'
        Add-BlockedResult 'http' 'reference-client-to-preview-server' 'environment-unavailable' `
            'Preview HTTP or Go HTTP harness executable is unavailable'
        return
    }

    $Prefix = 'http_' + [Guid]::NewGuid().ToString('N')
    $GoOut = Join-Path $OutputDirectory ($Prefix + '_go_server.stdout.log')
    $GoErr = Join-Path $OutputDirectory ($Prefix + '_go_server.stderr.log')
    $CppOut = Join-Path $OutputDirectory ($Prefix + '_cpp_server.stdout.log')
    $CppErr = Join-Path $OutputDirectory ($Prefix + '_cpp_server.stderr.log')
    $ServerAddress = '127.0.0.1:' + $HttpPort
    $GoServerProcess = $null
    $CppServerProcess = $null
    try {
        $GoServerProcess = Start-Process -FilePath $HttpGo -ArgumentList @(
            '-mode', 'server', '-listen', $ServerAddress) -PassThru -WindowStyle Hidden `
            -RedirectStandardOutput $GoOut -RedirectStandardError $GoErr
        if (-not (Wait-TcpReady '127.0.0.1' $HttpPort)) {
            Add-BlockedResult 'http' 'preview-client-to-reference-server' 'environment-unavailable' `
                'Go HTTP CONNECT reference server did not become ready'
        }
        else {
            $Result = Invoke-InteropCase -Executable $HttpCpp -Arguments @(
                '-mode', 'client', '-addr', $ServerAddress) `
                -Protocol 'http' -Direction 'preview-client-to-reference-server' -Scenario 'authenticated-echo' `
                -Implementation 'go-http-connect-reference' -Commit $Commit -Platform $Platform `
                -OutputDirectory $OutputDirectory
            $Results.Add((Add-DependencyArtifacts $Result @($GoOut, $GoErr)))
        }
    }
    finally {
        Stop-InteropProcess $GoServerProcess
        $GoServerProcess = $null
    }

    try {
        $CppServerProcess = Start-Process -FilePath $HttpCpp -ArgumentList @(
            '-mode', 'server', '-addr', $ServerAddress) -PassThru -WindowStyle Hidden `
            -RedirectStandardOutput $CppOut -RedirectStandardError $CppErr
        if (-not (Wait-TcpReady '127.0.0.1' $HttpPort)) {
            Add-BlockedResult 'http' 'reference-client-to-preview-server' 'environment-unavailable' `
                'Preview HTTP CONNECT server did not become ready'
        }
        else {
            $Result = Invoke-InteropCase -Executable $HttpGo -Arguments @(
                '-mode', 'client', '-server', $ServerAddress, '-target', 'example.com:443') `
                -Protocol 'http' -Direction 'reference-client-to-preview-server' -Scenario 'authenticated-echo' `
                -Implementation 'preview-http-connect-server' -Commit $Commit -Platform $Platform `
                -OutputDirectory $OutputDirectory
            $Results.Add((Add-DependencyArtifacts $Result @($CppOut, $CppErr)))
        }
    }
    finally {
        Stop-InteropProcess $CppServerProcess
        $CppServerProcess = $null
    }
}

function Invoke-RecognitionModeInterop {
    if (-not (Test-Path -LiteralPath $RecognitionCpp -PathType Leaf) -or
        -not (Test-Path -LiteralPath $HttpGo -PathType Leaf) -or
        -not (Test-Path -LiteralPath $Socks5Go -PathType Leaf) -or
        -not (Test-Path -LiteralPath $VlessGo -PathType Leaf) -or
        -not (Test-Path -LiteralPath $TrojanGo -PathType Leaf) -or
        -not (Test-Path -LiteralPath $VmessGo -PathType Leaf) -or
        -not (Test-Path -LiteralPath $GoClient -PathType Leaf)) {
        Add-BlockedResult 'http' 'external-client-to-preview-single-port' 'environment-unavailable' `
            'Preview recognition listener or Go HTTP/SOCKS5/VLESS reference client is unavailable' `
            -RecognitionMode 'Deterministic' -CandidateProfile 'http|socks5' `
            -Route 'first-byte 0x43 -> http; 0x05 -> socks5'
        Add-BlockedResult 'socks5' 'external-client-to-preview-single-port' 'environment-unavailable' `
            'Preview recognition listener or Go HTTP/SOCKS5/VLESS reference client is unavailable' `
            -RecognitionMode 'Deterministic' -CandidateProfile 'http|socks5' `
            -Route 'first-byte 0x43 -> http; 0x05 -> socks5'
        Add-BlockedResult 'vless' 'external-client-to-preview-single-port' 'environment-unavailable' `
            'Preview recognition listener or Go HTTP/SOCKS5/VLESS reference client is unavailable' `
            -RecognitionMode 'MixedTrial' -CandidateProfile 'vless|vmess' `
            -Route 'first-byte 0x00 -> vless; opaque fallback -> vmess'
        Add-BlockedResult 'trojan' 'external-client-to-preview-single-port' 'environment-unavailable' `
            'Preview recognition listener or Go HTTP/SOCKS5/Trojan/VLESS reference client is unavailable' `
            -RecognitionMode 'MixedTrial' -CandidateProfile 'trojan|vmess' `
            -Route 'credential prefix -> trojan; opaque fallback -> vmess'
        Add-BlockedResult 'vmess' 'external-client-to-preview-single-port' 'environment-unavailable' `
            'Preview recognition listener or Go VMess reference client is unavailable' `
            -RecognitionMode 'MixedTrial' -CandidateProfile 'vmess|trojan' `
            -Route 'opaque authentication -> vmess; opaque fallback -> trojan'
        Add-BlockedResult 'ss2022' 'external-client-to-preview-single-port' 'environment-unavailable' `
            'Preview recognition listener or Go SS2022 reference client is unavailable' `
            -RecognitionMode 'MixedTrial' -CandidateProfile 'ss2022|vmess' `
            -Route 'raw PSK authentication -> ss2022; opaque fallback -> vmess'
        return
    }

    $Cases = @(
        [ordered]@{
            Protocol = 'http'
            Mode = 'Deterministic'
            Port = $RecognitionDeterministicPort
            Client = $HttpGo
            Arguments = @('-mode', 'client', '-server', ('127.0.0.1:' + $RecognitionDeterministicPort), '-target', 'example.com:443')
            Scenario = 'deterministic-profile-single-port'
            Implementation = 'go-http-reference-preview-profile-listener'
            CandidateProfile = 'http|socks5'
            Route = 'first-byte 0x43 -> http; 0x05 -> socks5'
        }
        [ordered]@{
            Protocol = 'socks5'
            Mode = 'Deterministic'
            Port = $RecognitionDeterministicSocks5Port
            Client = $Socks5Go
            Arguments = @('-mode', 'client', '-server', ('127.0.0.1:' + $RecognitionDeterministicSocks5Port), '-target', 'example.com:443')
            Scenario = 'deterministic-profile-single-port'
            Implementation = 'go-socks5-reference-preview-profile-listener'
            CandidateProfile = 'http|socks5'
            Route = 'first-byte 0x43 -> http; 0x05 -> socks5'
        }
        [ordered]@{
            Protocol = 'vless'
            Mode = 'MixedTrial'
            Port = $RecognitionMixedTrialPort
            Client = $VlessGo
            Arguments = @('-mode', 'client', '-server', ('127.0.0.1:' + $RecognitionMixedTrialPort), '-uuid', '123e4567-e89b-12d3-a456-426614174000', '-target', 'example.com:443')
            Scenario = 'mixed-trial-profile-single-port'
            Implementation = 'go-vless-reference-preview-profile-listener'
            CandidateProfile = 'vless|vmess'
            Route = 'first-byte 0x00 -> vless; opaque fallback -> vmess'
        }
        [ordered]@{
            Protocol = 'trojan'
            Mode = 'MixedTrial'
            Port = $RecognitionMixedTrojanPort
            Client = $TrojanGo
            Arguments = @('-mode', 'client', '-server', ('127.0.0.1:' + $RecognitionMixedTrojanPort), '-pass', 'prism', '-target', 'example.com:443')
            Scenario = 'mixed-trial-opaque-authentication'
            Implementation = 'go-trojan-reference-preview-profile-listener'
            CandidateProfile = 'trojan|vmess'
            Route = 'credential prefix -> trojan; opaque fallback -> vmess'
        }
        [ordered]@{
            Protocol = 'vmess'
            Mode = 'MixedTrial'
            Port = $RecognitionMixedVmessPort
            Client = $VmessGo
            Arguments = @('127.0.0.1:' + $RecognitionMixedVmessPort, '-tcp-only')
            Scenario = 'mixed-trial-opaque-authentication'
            Implementation = 'sing-vmess-reference-preview-profile-listener'
            CandidateProfile = 'vmess|trojan'
            Route = 'opaque authentication -> vmess; opaque fallback -> trojan'
        }
        [ordered]@{
            Protocol = 'ss2022'
            Mode = 'MixedTrial'
            Port = $RecognitionMixedSs2022Port
            Client = $GoClient
            Arguments = @('127.0.0.1:' + $RecognitionMixedSs2022Port)
            Scenario = 'mixed-trial-opaque-authentication'
            Implementation = 'sing-shadowsocks-reference-preview-profile-listener'
            CandidateProfile = 'ss2022|vmess'
            Route = 'raw PSK authentication -> ss2022; opaque fallback -> vmess'
        }
    )

    foreach ($Case in $Cases) {
        $Prefix = 'recognition_' + $Case.Mode.ToLowerInvariant() + '_' + $Case.Protocol
        $ServerOut = Join-Path $OutputDirectory ($Prefix + '_server.stdout.log')
        $ServerErr = Join-Path $OutputDirectory ($Prefix + '_server.stderr.log')
        $ServerAddress = '127.0.0.1:' + $Case.Port
        $ServerProcess = $null
        try {
            $ServerProcess = Start-Process -FilePath $RecognitionCpp -ArgumentList @(
                '-mode', $Case.Mode, '-protocol', $Case.Protocol, '-addr', $ServerAddress) `
                -PassThru -WindowStyle Hidden -RedirectStandardOutput $ServerOut -RedirectStandardError $ServerErr
            if (-not (Wait-OutputReady $ServerProcess $ServerOut)) {
                Add-BlockedResult $Case.Protocol 'external-client-to-preview-single-port' 'environment-unavailable' `
                    ('Preview ' + $Case.Mode + ' recognition listener did not become ready') `
                    -RecognitionMode $Case.Mode -CandidateProfile $Case.CandidateProfile -Route $Case.Route
            }
            else {
                $Result = Invoke-InteropCase -Executable $Case.Client -Arguments $Case.Arguments `
                    -Protocol $Case.Protocol -Direction 'external-client-to-preview-single-port' `
                    -Scenario $Case.Scenario -Implementation $Case.Implementation `
                    -Commit $Commit -Platform $Platform -OutputDirectory $OutputDirectory `
                    -RecognitionMode $Case.Mode -CandidateProfile $Case.CandidateProfile -Route $Case.Route
                $Results.Add((Add-DependencyArtifacts $Result @($ServerOut, $ServerErr)))
            }
        }
        finally {
            Stop-InteropProcess $ServerProcess
            $ServerProcess = $null
        }
    }
}

function Invoke-NativeTlsInterop {
    if (-not (Test-Path -LiteralPath $NativeTlsCpp -PathType Leaf) -or
        -not (Test-Path -LiteralPath $NativeTlsGo -PathType Leaf)) {
        Add-BlockedResult 'native-tls' 'preview-client-to-reference-server' 'environment-unavailable' `
            'Preview native TLS endpoint or Go reference harness executable is unavailable'
        Add-BlockedResult 'native-tls' 'reference-client-to-preview-server' 'environment-unavailable' `
            'Preview native TLS endpoint or Go reference harness executable is unavailable'
        return
    }

    $Prefix = 'native_tls_' + [Guid]::NewGuid().ToString('N')
    $GoOut = Join-Path $OutputDirectory ($Prefix + '_go_server.stdout.log')
    $GoErr = Join-Path $OutputDirectory ($Prefix + '_go_server.stderr.log')
    $ServerAddress = '127.0.0.1:' + $NativeTlsPort
    $GoServerProcess = $null
    try {
        $GoServerProcess = Start-Process -FilePath $NativeTlsGo -ArgumentList @(
            '-mode', 'server', '-addr', $ServerAddress) -PassThru -WindowStyle Hidden `
            -RedirectStandardOutput $GoOut -RedirectStandardError $GoErr
        if (-not (Wait-OutputReady $GoServerProcess $GoOut)) {
            Add-BlockedResult 'native-tls' 'preview-client-to-reference-server' 'environment-unavailable' `
                'Go native TLS reference server did not become ready'
        }
        else {
            $Result = Invoke-InteropCase -Executable $NativeTlsCpp -Arguments @(
                '-mode', 'client', '-addr', $ServerAddress) `
                -Protocol 'native-tls' -Direction 'preview-client-to-reference-server' -Scenario 'authenticated-echo' `
                -Implementation 'go-crypto-tls-reference' -Commit $Commit -Platform $Platform `
                -OutputDirectory $OutputDirectory
            $Results.Add((Add-DependencyArtifacts $Result @($GoOut, $GoErr)))
        }
    }
    finally {
        Stop-InteropProcess $GoServerProcess
        $GoServerProcess = $null
    }

    $CppOut = Join-Path $OutputDirectory ($Prefix + '_cpp_server.stdout.log')
    $CppErr = Join-Path $OutputDirectory ($Prefix + '_cpp_server.stderr.log')
    $CppServerProcess = $null
    try {
        $CppServerProcess = Start-Process -FilePath $NativeTlsCpp -ArgumentList @(
            '-mode', 'server', '-addr', $ServerAddress) -PassThru -WindowStyle Hidden `
            -RedirectStandardOutput $CppOut -RedirectStandardError $CppErr
        if (-not (Wait-OutputReady $CppServerProcess $CppOut)) {
            Add-BlockedResult 'native-tls' 'reference-client-to-preview-server' 'environment-unavailable' `
                'Preview native TLS server did not become ready'
        }
        else {
            $Result = Invoke-InteropCase -Executable $NativeTlsGo -Arguments @(
                '-mode', 'client', '-addr', $ServerAddress) `
                -Protocol 'native-tls' -Direction 'reference-client-to-preview-server' -Scenario 'authenticated-echo' `
                -Implementation 'preview-native-tls-server' -Commit $Commit -Platform $Platform `
                -OutputDirectory $OutputDirectory
            $Results.Add((Add-DependencyArtifacts $Result @($CppOut, $CppErr)))
        }
    }
    finally {
        Stop-InteropProcess $CppServerProcess
        $CppServerProcess = $null
    }
}

function Invoke-ShadowtlsInterop {
    if (-not (Test-Path -LiteralPath $ShadowtlsCpp -PathType Leaf) -or
        -not (Test-Path -LiteralPath $ShadowtlsGo -PathType Leaf)) {
        Add-BlockedResult 'shadowtls' 'reference-client-to-preview-server' 'environment-unavailable' `
            'Preview ShadowTLS endpoint or Go/mihomo harness executable is unavailable'
        Add-BlockedResult 'shadowtls' 'preview-client-to-reference-server' 'interface-gap' `
            'Preview ShadowTLS client lacks a real TLS ClientHello/outer TLS state machine'
        return
    }

    $Prefix = 'shadowtls_' + [Guid]::NewGuid().ToString('N')
    $TargetOut = Join-Path $OutputDirectory ($Prefix + '_target.stdout.log')
    $TargetErr = Join-Path $OutputDirectory ($Prefix + '_target.stderr.log')
    $RelayOut = Join-Path $OutputDirectory ($Prefix + '_cpp_server.stdout.log')
    $RelayErr = Join-Path $OutputDirectory ($Prefix + '_cpp_server.stderr.log')
    $TargetAddress = '127.0.0.1:' + $ShadowtlsTargetPort
    $RelayAddress = '127.0.0.1:' + $ShadowtlsPort
    $TargetProcess = $null
    $RelayProcess = $null
    try {
        $TargetProcess = Start-Process -FilePath $ShadowtlsGo -ArgumentList @(
            '-mode', 'target-server', '-addr', $TargetAddress) -PassThru -WindowStyle Hidden `
            -RedirectStandardOutput $TargetOut -RedirectStandardError $TargetErr
        if (-not (Wait-OutputReady $TargetProcess $TargetOut)) {
            Add-BlockedResult 'shadowtls' 'reference-client-to-preview-server' 'environment-unavailable' `
                'Go TLS target for ShadowTLS did not become ready'
        }
        else {
            $RelayProcess = Start-Process -FilePath $ShadowtlsCpp -ArgumentList @(
                '-addr', $RelayAddress, '-target', $TargetAddress, '-password', 'relay-password') `
                -PassThru -WindowStyle Hidden -RedirectStandardOutput $RelayOut -RedirectStandardError $RelayErr
            if (-not (Wait-OutputReady $RelayProcess $RelayOut)) {
                Add-BlockedResult 'shadowtls' 'reference-client-to-preview-server' 'environment-unavailable' `
                    'Preview ShadowTLS relay did not become ready'
            }
            else {
                $Result = Invoke-InteropCase -Executable $ShadowtlsGo -Arguments @(
                    '-mode', 'client', '-addr', $RelayAddress, '-target', 'target', '-password', 'relay-password') `
                    -Protocol 'shadowtls' -Direction 'reference-client-to-preview-server' -Scenario 'authenticated-echo' `
                    -Implementation 'mihomo-shadowtls-v3-client-preview-server' -Commit $Commit -Platform $Platform `
                    -OutputDirectory $OutputDirectory
                $Results.Add((Add-DependencyArtifacts $Result @($TargetOut, $TargetErr, $RelayOut, $RelayErr)))
            }
        }
    }
    finally {
        Stop-InteropProcess $RelayProcess
        Stop-InteropProcess $TargetProcess
    }

    Add-BlockedResult 'shadowtls' 'preview-client-to-reference-server' 'interface-gap' `
        'Preview ShadowTLS client lacks a real TLS ClientHello/outer TLS state machine'
}

function Invoke-WebsocketInterop {
    if (-not (Test-Path -LiteralPath $WsCpp -PathType Leaf) -or
        -not (Test-Path -LiteralPath $WsGo -PathType Leaf)) {
        Add-BlockedResult 'websocket' 'preview-client-to-reference-server' 'environment-unavailable' `
            'Preview WebSocket endpoint or Go reference harness executable is unavailable'
        Add-BlockedResult 'websocket' 'reference-client-to-preview-server' 'environment-unavailable' `
            'Preview WebSocket endpoint or Go reference harness executable is unavailable'
        return
    }

    $Prefix = 'websocket_' + [Guid]::NewGuid().ToString('N')
    $GoOut = Join-Path $OutputDirectory ($Prefix + '_go_server.stdout.log')
    $GoErr = Join-Path $OutputDirectory ($Prefix + '_go_server.stderr.log')
    $ServerAddress = '127.0.0.1:' + $WsPort
    $GoServerProcess = $null
    try {
        $GoServerProcess = Start-Process -FilePath $WsGo -ArgumentList @(
            '-mode', 'server', '-addr', $ServerAddress) -PassThru -WindowStyle Hidden `
            -RedirectStandardOutput $GoOut -RedirectStandardError $GoErr
        if (-not (Wait-OutputReady $GoServerProcess $GoOut)) {
            Add-BlockedResult 'websocket' 'preview-client-to-reference-server' 'environment-unavailable' `
                'Go WebSocket reference server did not become ready'
        }
        else {
            $Result = Invoke-InteropCase -Executable $WsCpp -Arguments @(
                '-mode', 'client', '-addr', $ServerAddress) `
                -Protocol 'websocket' -Direction 'preview-client-to-reference-server' -Scenario 'authenticated-echo' `
                -Implementation 'go-gobwas-ws-reference' -Commit $Commit -Platform $Platform `
                -OutputDirectory $OutputDirectory
            $Results.Add((Add-DependencyArtifacts $Result @($GoOut, $GoErr)))
        }
    }
    finally {
        Stop-InteropProcess $GoServerProcess
        $GoServerProcess = $null
    }

    $CppOut = Join-Path $OutputDirectory ($Prefix + '_cpp_server.stdout.log')
    $CppErr = Join-Path $OutputDirectory ($Prefix + '_cpp_server.stderr.log')
    $CppServerProcess = $null
    try {
        $CppServerProcess = Start-Process -FilePath $WsCpp -ArgumentList @(
            '-mode', 'server', '-addr', $ServerAddress) -PassThru -WindowStyle Hidden `
            -RedirectStandardOutput $CppOut -RedirectStandardError $CppErr
        if (-not (Wait-OutputReady $CppServerProcess $CppOut)) {
            Add-BlockedResult 'websocket' 'reference-client-to-preview-server' 'environment-unavailable' `
                'Preview WebSocket reference server did not become ready'
        }
        else {
            $Result = Invoke-InteropCase -Executable $WsGo -Arguments @(
                '-mode', 'client', '-addr', $ServerAddress) `
                -Protocol 'websocket' -Direction 'reference-client-to-preview-server' -Scenario 'authenticated-echo' `
                -Implementation 'preview-websocket-server-gobwas-ws-reference' -Commit $Commit -Platform $Platform `
                -OutputDirectory $OutputDirectory
            $Results.Add((Add-DependencyArtifacts $Result @($CppOut, $CppErr)))
        }
    }
    finally {
        Stop-InteropProcess $CppServerProcess
        $CppServerProcess = $null
    }
}

function Invoke-AnytlsInterop {
    if (-not (Test-Path -LiteralPath $AnytlsCpp -PathType Leaf) -or
        -not (Test-Path -LiteralPath $AnytlsGo -PathType Leaf)) {
        Add-BlockedResult 'anytls' 'preview-client-to-reference-server' 'environment-unavailable' `
            'Preview AnyTLS endpoint or Go reference harness executable is unavailable'
        Add-BlockedResult 'anytls' 'reference-client-to-preview-server' 'environment-unavailable' `
            'Preview AnyTLS endpoint or Go reference harness executable is unavailable'
        return
    }

    $Prefix = 'anytls_' + [Guid]::NewGuid().ToString('N')
    $GoOut = Join-Path $OutputDirectory ($Prefix + '_go_server.stdout.log')
    $GoErr = Join-Path $OutputDirectory ($Prefix + '_go_server.stderr.log')
    $ServerAddress = '127.0.0.1:' + $AnytlsPort
    $GoServerProcess = $null
    try {
        $GoServerProcess = Start-Process -FilePath $AnytlsGo -ArgumentList @(
            '-mode', 'server', '-addr', $ServerAddress) -PassThru -WindowStyle Hidden `
            -RedirectStandardOutput $GoOut -RedirectStandardError $GoErr
        if (-not (Wait-OutputReady $GoServerProcess $GoOut)) {
            Add-BlockedResult 'anytls' 'preview-client-to-reference-server' 'environment-unavailable' `
                'Go AnyTLS reference server did not become ready'
        }
        else {
            $Result = Invoke-InteropCase -Executable $AnytlsCpp -Arguments @(
                '-mode', 'client', '-addr', $ServerAddress) `
                -Protocol 'anytls' -Direction 'preview-client-to-reference-server' -Scenario 'authenticated-echo' `
                -Implementation 'go-anytls-reference' -Commit $Commit -Platform $Platform `
                -OutputDirectory $OutputDirectory
            $Results.Add((Add-DependencyArtifacts $Result @($GoOut, $GoErr)))
        }
    }
    finally {
        Stop-InteropProcess $GoServerProcess
        $GoServerProcess = $null
    }

    $CppOut = Join-Path $OutputDirectory ($Prefix + '_cpp_server.stdout.log')
    $CppErr = Join-Path $OutputDirectory ($Prefix + '_cpp_server.stderr.log')
    $CppServerProcess = $null
    try {
        $CppServerProcess = Start-Process -FilePath $AnytlsCpp -ArgumentList @(
            '-mode', 'server', '-addr', $ServerAddress) -PassThru -WindowStyle Hidden `
            -RedirectStandardOutput $CppOut -RedirectStandardError $CppErr
        if (-not (Wait-OutputReady $CppServerProcess $CppOut)) {
            Add-BlockedResult 'anytls' 'reference-client-to-preview-server' 'environment-unavailable' `
                'Preview AnyTLS server did not become ready'
        }
        else {
            $Result = Invoke-InteropCase -Executable $AnytlsGo -Arguments @(
                '-mode', 'client', '-addr', $ServerAddress) `
                -Protocol 'anytls' -Direction 'reference-client-to-preview-server' -Scenario 'authenticated-echo' `
                -Implementation 'preview-anytls-server-go-reference' -Commit $Commit -Platform $Platform `
                -OutputDirectory $OutputDirectory
            $Results.Add((Add-DependencyArtifacts $Result @($CppOut, $CppErr)))
        }
    }
    finally {
        Stop-InteropProcess $CppServerProcess
        $CppServerProcess = $null
    }
}

function Invoke-GunInterop {
    if (-not (Test-Path -LiteralPath $GunCpp -PathType Leaf) -or
        -not (Test-Path -LiteralPath $GunGo -PathType Leaf)) {
        Add-BlockedResult 'grpc' 'preview-client-to-reference-server' 'environment-unavailable' `
            'Preview gun-lite endpoint or Go reference harness executable is unavailable'
        Add-BlockedResult 'grpc' 'reference-client-to-preview-server' 'environment-unavailable' `
            'Preview gun-lite endpoint or Go reference harness executable is unavailable'
        return
    }

    $Prefix = 'grpc_' + [Guid]::NewGuid().ToString('N')
    $GoOut = Join-Path $OutputDirectory ($Prefix + '_go_server.stdout.log')
    $GoErr = Join-Path $OutputDirectory ($Prefix + '_go_server.stderr.log')
    $ServerAddress = '127.0.0.1:' + $GunPort
    $GoServerProcess = $null
    try {
        $GoServerProcess = Start-Process -FilePath $GunGo -ArgumentList @(
            '-mode', 'server', '-addr', $ServerAddress) -PassThru -WindowStyle Hidden `
            -RedirectStandardOutput $GoOut -RedirectStandardError $GoErr
        if (-not (Wait-OutputReady $GoServerProcess $GoOut)) {
            Add-BlockedResult 'grpc' 'preview-client-to-reference-server' 'environment-unavailable' `
                'Go gun-lite reference server did not become ready'
        }
        else {
            $Result = Invoke-InteropCase -Executable $GunCpp -Arguments @(
                '-mode', 'client', '-addr', $ServerAddress) `
                -Protocol 'grpc' -Direction 'preview-client-to-reference-server' -Scenario 'gun-lite-authenticated-echo' `
                -Implementation 'go-gun-lite-reference' -Commit $Commit -Platform $Platform `
                -OutputDirectory $OutputDirectory
            $Results.Add((Add-DependencyArtifacts $Result @($GoOut, $GoErr)))
        }
    }
    finally {
        Stop-InteropProcess $GoServerProcess
        $GoServerProcess = $null
    }

    $CppOut = Join-Path $OutputDirectory ($Prefix + '_cpp_server.stdout.log')
    $CppErr = Join-Path $OutputDirectory ($Prefix + '_cpp_server.stderr.log')
    $CppServerProcess = $null
    try {
        $CppServerProcess = Start-Process -FilePath $GunCpp -ArgumentList @(
            '-mode', 'server', '-addr', $ServerAddress) -PassThru -WindowStyle Hidden `
            -RedirectStandardOutput $CppOut -RedirectStandardError $CppErr
        if (-not (Wait-OutputReady $CppServerProcess $CppOut)) {
            Add-BlockedResult 'grpc' 'reference-client-to-preview-server' 'environment-unavailable' `
                'Preview gun-lite server did not become ready'
        }
        else {
            $Result = Invoke-InteropCase -Executable $GunGo -Arguments @(
                '-mode', 'client', '-addr', $ServerAddress) `
                -Protocol 'grpc' -Direction 'reference-client-to-preview-server' -Scenario 'gun-lite-authenticated-echo' `
                -Implementation 'preview-gun-lite-server-go-reference' -Commit $Commit -Platform $Platform `
                -OutputDirectory $OutputDirectory
            $Results.Add((Add-DependencyArtifacts $Result @($CppOut, $CppErr)))
        }
    }
    finally {
        Stop-InteropProcess $CppServerProcess
        $CppServerProcess = $null
    }
}

function Invoke-XhttpInterop {
    if (-not (Test-Path -LiteralPath $XhttpCpp -PathType Leaf) -or
        -not (Test-Path -LiteralPath $XhttpGo -PathType Leaf)) {
        Add-BlockedResult 'xhttp' 'preview-client-to-reference-server' 'environment-unavailable' `
            'Preview XHTTP client or Go HTTP/2 reference harness executable is unavailable'
        Add-BlockedResult 'xhttp' 'reference-client-to-preview-server' 'environment-unavailable' `
            'Preview XHTTP endpoint or Go HTTP/2 reference harness executable is unavailable'
        return
    }

    $Prefix = 'xhttp_' + [Guid]::NewGuid().ToString('N')
    $ServerAddress = '127.0.0.1:' + $XhttpPort
    $GoOut = Join-Path $OutputDirectory ($Prefix + '_go_server.stdout.log')
    $GoErr = Join-Path $OutputDirectory ($Prefix + '_go_server.stderr.log')
    $CppOut = Join-Path $OutputDirectory ($Prefix + '_cpp_server.stdout.log')
    $CppErr = Join-Path $OutputDirectory ($Prefix + '_cpp_server.stderr.log')
    $GoServerProcess = $null
    $CppServerProcess = $null
    try {
        $GoServerProcess = Start-Process -FilePath $XhttpGo -ArgumentList @(
            '-mode', 'server', '-addr', $ServerAddress) -PassThru -WindowStyle Hidden `
            -RedirectStandardOutput $GoOut -RedirectStandardError $GoErr
        if (-not (Wait-OutputReady $GoServerProcess $GoOut)) {
            Add-BlockedResult 'xhttp' 'preview-client-to-reference-server' 'environment-unavailable' `
                'Go XHTTP reference server did not become ready'
        }
        else {
            $Result = Invoke-InteropCase -Executable $XhttpCpp -Arguments @(
                '-mode', 'client', '-addr', $ServerAddress) `
                -Protocol 'xhttp' -Direction 'preview-client-to-reference-server' -Scenario 'http2-stream-one-echo' `
                -Implementation 'preview-xhttp-client-go-x-net-http2-server' -Commit $Commit -Platform $Platform `
                -OutputDirectory $OutputDirectory
            $Results.Add((Add-DependencyArtifacts $Result @($GoOut, $GoErr)))
        }
    }
    finally {
        Stop-InteropProcess $GoServerProcess
        $GoServerProcess = $null
    }

    try {
        $CppServerProcess = Start-Process -FilePath $XhttpCpp -ArgumentList @(
            '-addr', $ServerAddress) -PassThru -WindowStyle Hidden `
            -RedirectStandardOutput $CppOut -RedirectStandardError $CppErr
        if (-not (Wait-OutputReady $CppServerProcess $CppOut)) {
            Add-BlockedResult 'xhttp' 'reference-client-to-preview-server' 'environment-unavailable' `
                'Preview XHTTP server did not become ready'
        }
        else {
            $Result = Invoke-InteropCase -Executable $XhttpGo -Arguments @(
                '-addr', $ServerAddress) `
                -Protocol 'xhttp' -Direction 'reference-client-to-preview-server' -Scenario 'http2-stream-one-echo' `
                -Implementation 'go-x-net-http2-reference' -Commit $Commit -Platform $Platform `
                -OutputDirectory $OutputDirectory
            $Results.Add((Add-DependencyArtifacts $Result @($CppOut, $CppErr)))
        }
    }
    finally {
        Stop-InteropProcess $CppServerProcess
        $CppServerProcess = $null
    }
}

function Invoke-TrusttunnelInterop {
    if (-not (Test-Path -LiteralPath $TrusttunnelCpp -PathType Leaf) -or
        -not (Test-Path -LiteralPath $TrusttunnelGo -PathType Leaf)) {
        Add-BlockedResult 'trusttunnel' 'preview-client-to-reference-server' 'environment-unavailable' `
            'Preview TrustTunnel standard HTTP/2 endpoint or Go reference harness executable is unavailable'
        Add-BlockedResult 'trusttunnel' 'reference-client-to-preview-server' 'environment-unavailable' `
            'Preview TrustTunnel standard HTTP/2 endpoint or Go reference harness executable is unavailable'
        return
    }

    $Prefix = 'trusttunnel_' + [Guid]::NewGuid().ToString('N')
    $ServerAddress = '127.0.0.1:' + $TrusttunnelPort
    $GoOut = Join-Path $OutputDirectory ($Prefix + '_go_server.stdout.log')
    $GoErr = Join-Path $OutputDirectory ($Prefix + '_go_server.stderr.log')
    $CppOut = Join-Path $OutputDirectory ($Prefix + '_cpp_server.stdout.log')
    $CppErr = Join-Path $OutputDirectory ($Prefix + '_cpp_server.stderr.log')
    $GoServerProcess = $null
    $CppServerProcess = $null
    try {
        $GoServerProcess = Start-Process -FilePath $TrusttunnelGo -ArgumentList @(
            '-mode', 'server', '-addr', $ServerAddress) -PassThru -WindowStyle Hidden `
            -RedirectStandardOutput $GoOut -RedirectStandardError $GoErr
        if (-not (Wait-OutputReady $GoServerProcess $GoOut)) {
            Add-BlockedResult 'trusttunnel' 'preview-client-to-reference-server' 'environment-unavailable' `
                'Go TrustTunnel reference server did not become ready'
        }
        else {
            $Result = Invoke-InteropCase -Executable $TrusttunnelCpp -Arguments @(
                '-mode', 'client', '-addr', $ServerAddress) `
                -Protocol 'trusttunnel' -Direction 'preview-client-to-reference-server' -Scenario 'http2-connect-echo' `
                -Implementation 'preview-trusttunnel-go-x-net-http2-server' -Commit $Commit -Platform $Platform `
                -OutputDirectory $OutputDirectory
            $Results.Add((Add-DependencyArtifacts $Result @($GoOut, $GoErr)))
        }
    }
    finally {
        Stop-InteropProcess $GoServerProcess
        $GoServerProcess = $null
    }

    try {
        $CppServerProcess = Start-Process -FilePath $TrusttunnelCpp -ArgumentList @(
            '-mode', 'server', '-addr', $ServerAddress) -PassThru -WindowStyle Hidden `
            -RedirectStandardOutput $CppOut -RedirectStandardError $CppErr
        if (-not (Wait-OutputReady $CppServerProcess $CppOut)) {
            Add-BlockedResult 'trusttunnel' 'reference-client-to-preview-server' 'environment-unavailable' `
                'Preview TrustTunnel standard HTTP/2 server did not become ready'
        }
        else {
            $Result = Invoke-InteropCase -Executable $TrusttunnelGo -Arguments @(
                '-mode', 'client', '-addr', $ServerAddress) `
                -Protocol 'trusttunnel' -Direction 'reference-client-to-preview-server' -Scenario 'http2-connect-echo' `
                -Implementation 'go-x-net-http2-reference-preview-trusttunnel-server' -Commit $Commit -Platform $Platform `
                -OutputDirectory $OutputDirectory
            $Results.Add((Add-DependencyArtifacts $Result @($CppOut, $CppErr)))
        }
    }
    finally {
        Stop-InteropProcess $CppServerProcess
        $CppServerProcess = $null
    }
}

function Invoke-TuicInterop {
    if (-not (Test-Path -LiteralPath $TuicCpp -PathType Leaf) -or
        -not (Test-Path -LiteralPath $TuicGo -PathType Leaf) -or
        -not (Test-Path -LiteralPath $TuicGoServer -PathType Leaf)) {
        Add-BlockedResult 'tuic' 'reference-client-to-preview-server' 'environment-unavailable' `
            'Preview TUIC endpoint or Go quic-go harness executable is unavailable'
        Add-BlockedResult 'tuic' 'preview-client-to-reference-server' 'environment-unavailable' `
            'Preview TUIC or Go reference server executable is unavailable'
        return
    }

    $Prefix = 'tuic_' + [Guid]::NewGuid().ToString('N')
    $CppOut = Join-Path $OutputDirectory ($Prefix + '_cpp_server.stdout.log')
    $CppErr = Join-Path $OutputDirectory ($Prefix + '_cpp_server.stderr.log')
    $ServerAddress = '127.0.0.1:' + $TuicPort
    $CppServerProcess = $null
    try {
        $CppServerProcess = Start-Process -FilePath $TuicCpp -ArgumentList @(
            '-addr', $ServerAddress, '-password', 'tuic_password',
            '-uuid', '123e4567-e89b-12d3-a456-426614174000') -PassThru -WindowStyle Hidden `
            -RedirectStandardOutput $CppOut -RedirectStandardError $CppErr
        if (-not (Wait-OutputReady $CppServerProcess $CppOut)) {
            Add-BlockedResult 'tuic' 'reference-client-to-preview-server' 'environment-unavailable' `
                'Preview TUIC server did not become ready'
        }
        else {
            $Result = Invoke-InteropCase -Executable $TuicGo -Arguments @(
                '-server', $ServerAddress, '-password', 'tuic_password',
                '-uuid', '123e4567-e89b-12d3-a456-426614174000') `
                -Protocol 'tuic' -Direction 'reference-client-to-preview-server' -Scenario 'authenticated-echo' `
                -Implementation 'go-quic-tuic-reference' -Commit $Commit -Platform $Platform `
                -OutputDirectory $OutputDirectory
            $Results.Add((Add-DependencyArtifacts $Result @($CppOut, $CppErr)))
        }
    }
    finally {
        Stop-InteropProcess $CppServerProcess
        $CppServerProcess = $null
    }

    $UdpPrefix = 'tuic_udp_' + [Guid]::NewGuid().ToString('N')
    $UdpOut = Join-Path $OutputDirectory ($UdpPrefix + '_cpp_server.stdout.log')
    $UdpErr = Join-Path $OutputDirectory ($UdpPrefix + '_cpp_server.stderr.log')
    $UdpServerProcess = $null
    try {
        $UdpServerProcess = Start-Process -FilePath $TuicCpp -ArgumentList @(
            '-addr', $ServerAddress, '-password', 'tuic_password',
            '-uuid', '123e4567-e89b-12d3-a456-426614174000', '-udp', '1') -PassThru -WindowStyle Hidden `
            -RedirectStandardOutput $UdpOut -RedirectStandardError $UdpErr
        if (-not (Wait-OutputReady $UdpServerProcess $UdpOut)) {
            Add-BlockedResult 'tuic' 'reference-client-to-preview-server' 'environment-unavailable' `
                'Preview TUIC UDP server did not become ready'
        }
        else {
            $UdpResult = Invoke-InteropCase -Executable $TuicGo -Arguments @(
                '-server', $ServerAddress, '-password', 'tuic_password',
                '-uuid', '123e4567-e89b-12d3-a456-426614174000', '-udp') `
                -Protocol 'tuic' -Direction 'reference-client-to-preview-server' -Scenario 'authenticated-udp-echo' `
                -Implementation 'go-quic-tuic-reference-udp' -Commit $Commit -Platform $Platform `
                -OutputDirectory $OutputDirectory
            $Results.Add((Add-DependencyArtifacts $UdpResult @($UdpOut, $UdpErr)))
        }
    }
    finally {
        Stop-InteropProcess $UdpServerProcess
        $UdpServerProcess = $null
    }

    $ReversePrefix = 'tuic_reverse_' + [Guid]::NewGuid().ToString('N')
    $GoOut = Join-Path $OutputDirectory ($ReversePrefix + '_go_server.stdout.log')
    $GoErr = Join-Path $OutputDirectory ($ReversePrefix + '_go_server.stderr.log')
    $ReferenceAddress = '127.0.0.1:' + $TuicReferencePort
    $GoServerProcess = $null
    try {
        $GoServerProcess = Start-Process -FilePath $TuicGoServer -ArgumentList @(
            '-listen', $ReferenceAddress, '-password', 'tuic_password',
            '-uuid', '123e4567-e89b-12d3-a456-426614174000') -PassThru -WindowStyle Hidden `
            -RedirectStandardOutput $GoOut -RedirectStandardError $GoErr
        if (-not (Wait-OutputReady $GoServerProcess $GoOut)) {
            Add-BlockedResult 'tuic' 'preview-client-to-reference-server' 'environment-unavailable' `
                'Go TUIC reference server did not become ready'
        }
        else {
            $Result = Invoke-InteropCase -Executable $TuicCpp -Arguments @(
                '-mode', 'client', '-addr', $ReferenceAddress, '-password', 'tuic_password',
                '-uuid', '123e4567-e89b-12d3-a456-426614174000') `
                -Protocol 'tuic' -Direction 'preview-client-to-reference-server' -Scenario 'authenticated-echo' `
                -Implementation 'mihomo-tuic-v5-reference-tcp-udp' -Commit $Commit -Platform $Platform `
                -OutputDirectory $OutputDirectory
            $Results.Add((Add-DependencyArtifacts $Result @($GoOut, $GoErr)))
        }
    }
    finally {
        Stop-InteropProcess $GoServerProcess
        $GoServerProcess = $null
    }
}

function Invoke-Hysteria2Interop {
    if (-not (Test-Path -LiteralPath $Hysteria2Cpp -PathType Leaf) -or
        -not (Test-Path -LiteralPath $Hysteria2CppClient -PathType Leaf) -or
        -not (Test-Path -LiteralPath $Hysteria2Go -PathType Leaf) -or
        -not (Test-Path -LiteralPath $Hysteria2GoServer -PathType Leaf)) {
        Add-BlockedResult 'hysteria2' 'reference-client-to-preview-server' 'environment-unavailable' `
            'Preview Hysteria2 endpoint or Go sing-quic harness executable is unavailable'
        Add-BlockedResult 'hysteria2' 'preview-client-to-reference-server' 'environment-unavailable' `
            'No pinned full external Hysteria2 reference server executable is available'
        return
    }

    $Prefix = 'hysteria2_' + [Guid]::NewGuid().ToString('N')
    $CppOut = Join-Path $OutputDirectory ($Prefix + '_cpp_server.stdout.log')
    $CppErr = Join-Path $OutputDirectory ($Prefix + '_cpp_server.stderr.log')
    $ServerAddress = '127.0.0.1:' + $Hysteria2Port
    $CppServerProcess = $null
    try {
        $CppServerProcess = Start-Process -FilePath $Hysteria2Cpp -ArgumentList @(
            '-addr', $ServerAddress, '-password', 'hysteria2_password') -PassThru -WindowStyle Hidden `
            -RedirectStandardOutput $CppOut -RedirectStandardError $CppErr
        if (-not (Wait-OutputReady $CppServerProcess $CppOut)) {
            Add-BlockedResult 'hysteria2' 'reference-client-to-preview-server' 'environment-unavailable' `
                'Preview Hysteria2 server did not become ready'
        }
        else {
            $Result = Invoke-InteropCase -Executable $Hysteria2Go -Arguments @(
                '-server', $ServerAddress, '-password', 'hysteria2_password') `
                -Protocol 'hysteria2' -Direction 'reference-client-to-preview-server' -Scenario 'authenticated-echo' `
                -Implementation 'sing-quic-hysteria2-reference' -Commit $Commit -Platform $Platform `
                -OutputDirectory $OutputDirectory
            $Results.Add((Add-DependencyArtifacts $Result @($CppOut, $CppErr)))
        }
    }
    finally {
        Stop-InteropProcess $CppServerProcess
        $CppServerProcess = $null
    }

    $UdpPrefix = 'hysteria2_udp_' + [Guid]::NewGuid().ToString('N')
    $UdpOut = Join-Path $OutputDirectory ($UdpPrefix + '_cpp_server.stdout.log')
    $UdpErr = Join-Path $OutputDirectory ($UdpPrefix + '_cpp_server.stderr.log')
    $UdpServerProcess = $null
    try {
        $UdpServerProcess = Start-Process -FilePath $Hysteria2Cpp -ArgumentList @(
            '-addr', $ServerAddress, '-password', 'hysteria2_password', '-udp', '1') -PassThru -WindowStyle Hidden `
            -RedirectStandardOutput $UdpOut -RedirectStandardError $UdpErr
        if (-not (Wait-OutputReady $UdpServerProcess $UdpOut)) {
            Add-BlockedResult 'hysteria2' 'reference-client-to-preview-server' 'environment-unavailable' `
                'Preview Hysteria2 UDP server did not become ready'
        }
        else {
            $UdpResult = Invoke-InteropCase -Executable $Hysteria2Go -Arguments @(
                '-server', $ServerAddress, '-password', 'hysteria2_password', '-udp') `
                -Protocol 'hysteria2' -Direction 'reference-client-to-preview-server' -Scenario 'authenticated-udp-echo' `
                -Implementation 'sing-quic-hysteria2-reference-udp' -Commit $Commit -Platform $Platform `
                -OutputDirectory $OutputDirectory
            $Results.Add((Add-DependencyArtifacts $UdpResult @($UdpOut, $UdpErr)))
        }
    }
    finally {
        Stop-InteropProcess $UdpServerProcess
        $UdpServerProcess = $null
    }

    $ReversePrefix = 'hysteria2_' + [Guid]::NewGuid().ToString('N')
    $GoOut = Join-Path $OutputDirectory ($ReversePrefix + '_go_server.stdout.log')
    $GoErr = Join-Path $OutputDirectory ($ReversePrefix + '_go_server.stderr.log')
    $ReferenceAddress = '127.0.0.1:' + $Hysteria2ReferencePort
    $GoServerProcess = $null
    try {
        $GoServerProcess = Start-Process -FilePath $Hysteria2GoServer -ArgumentList @(
            '-listen', $ReferenceAddress, '-password', 'hysteria2_password') -PassThru -WindowStyle Hidden `
            -RedirectStandardOutput $GoOut -RedirectStandardError $GoErr
        if (-not (Wait-OutputReady $GoServerProcess $GoOut)) {
            Add-BlockedResult 'hysteria2' 'preview-client-to-reference-server' 'environment-unavailable' `
                'Go Hysteria2 reference server did not become ready'
        }
        else {
            $Result = Invoke-InteropCase -Executable $Hysteria2CppClient -Arguments @(
                '-addr', $ReferenceAddress, '-password', 'hysteria2_password') `
                -Protocol 'hysteria2' -Direction 'preview-client-to-reference-server' -Scenario 'authenticated-echo' `
                -Implementation 'preview-http3-native-ngtcp2-reference' -Commit $Commit -Platform $Platform `
                -OutputDirectory $OutputDirectory
            $Results.Add((Add-DependencyArtifacts $Result @($GoOut, $GoErr)))
        }
    }
    finally {
        Stop-InteropProcess $GoServerProcess
        $GoServerProcess = $null
    }
    # Hysteria2 reverse UDP uses a separate reference server port so TCP and
    # datagram sessions do not share connection teardown state.
    $ReverseUdpPrefix = 'hysteria2_reverse_udp_' + [Guid]::NewGuid().ToString('N')
    $GoUdpOut = Join-Path $OutputDirectory ($ReverseUdpPrefix + '_go_server.stdout.log')
    $GoUdpErr = Join-Path $OutputDirectory ($ReverseUdpPrefix + '_go_server.stderr.log')
    $ReferenceUdpAddress = '127.0.0.1:' + $Hysteria2ReferenceUdpPort
    $GoUdpServerProcess = $null
    try {
        $GoUdpServerProcess = Start-Process -FilePath $Hysteria2GoServer -ArgumentList @(
            '-listen', $ReferenceUdpAddress, '-password', 'hysteria2_password') -PassThru -WindowStyle Hidden `
            -RedirectStandardOutput $GoUdpOut -RedirectStandardError $GoUdpErr
        if (-not (Wait-OutputReady $GoUdpServerProcess $GoUdpOut)) {
            Add-BlockedResult 'hysteria2' 'preview-client-to-reference-server' 'environment-unavailable' `
                'Go Hysteria2 UDP reference server did not become ready'
        }
        else {
            $UdpResult = Invoke-InteropCase -Executable $Hysteria2CppClient -Arguments @(
                '-addr', $ReferenceUdpAddress, '-password', 'hysteria2_password', '-udp', '1') `
                -Protocol 'hysteria2' -Direction 'preview-client-to-reference-server' -Scenario 'authenticated-udp-echo' `
                -Implementation 'preview-http3-native-ngtcp2-reference-udp' -Commit $Commit -Platform $Platform `
                -OutputDirectory $OutputDirectory
            $Results.Add((Add-DependencyArtifacts $UdpResult @($GoUdpOut, $GoUdpErr)))
        }
    }
    finally {
        Stop-InteropProcess $GoUdpServerProcess
        $GoUdpServerProcess = $null
    }
}

Invoke-RecognitionModeInterop

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

    if ($Protocol -eq 'trojan') {
        Invoke-TrojanInterop
        if ($PrismExe) {
            Add-BlockedResult 'trojan' 'preview-production-single-port' 'blocked-production-prerequisite' `
                'Production analyzer change is not authorized in this Preview-only run'
        }
        continue
    }

    if ($Protocol -eq 'vmess') {
        Invoke-VmessInterop
        if ($PrismExe) {
            Add-BlockedResult 'vmess' 'preview-production-single-port' 'blocked-production-prerequisite' `
                'Production analyzer change is not authorized in this Preview-only run'
        }
        continue
    }

    if ($Protocol -eq 'vless') {
        Invoke-VlessInterop
        if ($PrismExe) {
            Add-BlockedResult 'vless' 'preview-production-single-port' 'blocked-production-prerequisite' `
                'Production analyzer change is not authorized in this Preview-only run'
        }
        continue
    }

    if ($Protocol -eq 'socks5') {
        Invoke-Socks5Interop
        continue
    }

    if ($Protocol -eq 'http') {
        Invoke-HttpInterop
        continue
    }

    if ($Protocol -eq 'native-tls') {
        Invoke-NativeTlsInterop
        continue
    }

    if ($Protocol -eq 'websocket') {
        Invoke-WebsocketInterop
        continue
    }

    if ($Protocol -eq 'anytls') {
        Invoke-AnytlsInterop
        continue
    }

    if ($Protocol -eq 'grpc') {
        Invoke-GunInterop
        continue
    }

    if ($Protocol -eq 'xhttp') {
        Invoke-XhttpInterop
        continue
    }

    if ($Protocol -eq 'trusttunnel') {
        Invoke-TrusttunnelInterop
        continue
    }

    if ($Protocol -in @('reality', 'shadowtls', 'restls')) {
        if ($Protocol -eq 'shadowtls') {
            Invoke-ShadowtlsInterop
            continue
        }
        Add-BlockedResult $Protocol 'preview-client-to-reference-server' 'interface-gap' `
            "Preview $Protocol has codec/loopback coverage but no standard external carrier endpoint"
        Add-BlockedResult $Protocol 'reference-client-to-preview-server' 'interface-gap' `
            "Preview $Protocol has codec/loopback coverage but no standard external carrier endpoint"
        continue
    }

    if ($Protocol -eq 'hysteria2') {
        Invoke-Hysteria2Interop
        continue
    }

    if ($Protocol -eq 'tuic') {
        Invoke-TuicInterop
        continue
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
$RecognitionCoverage = [ordered]@{}
foreach ($Mode in @('Deterministic', 'MixedTrial', 'direct-handler', 'not-exercised')) {
    $RecognitionCoverage[$Mode] = @($Results | Where-Object {
            $_.recognition_mode -eq $Mode
        }).Count
}
$RecognitionCoverageComplete =
    $RecognitionCoverage['Deterministic'] -gt 0 -and
    $RecognitionCoverage['MixedTrial'] -gt 0
$Summary = [ordered]@{
    schema = 'prism.interop-summary.v2'
    scope = $MatrixScope
    production_prerequisite_included = ($MatrixScope -eq 'full')
    commit = $Commit
    source_state = $SourceState
    platform = $Platform
    generated_utc = [DateTime]::UtcNow.ToString('o')
    total = $Results.Count
    pass = @($Results | Where-Object { $_.status -eq 'pass' }).Count
    blocked = @($Results | Where-Object { $_.status -in @('environment-unavailable', 'interface-gap', 'blocked-production-prerequisite') }).Count
    failed = @($Results | Where-Object { $_.status -in @('protocol-failure', 'implementation-mismatch') }).Count
    recognition_coverage = $RecognitionCoverage
    recognition_coverage_complete = $RecognitionCoverageComplete
    reference_versions = $ReferenceVersions
    results = @($Results)
}
Write-InteropResult -Result $Summary -Path $SummaryPath

Write-Output ("Interop matrix ({0}): total={1} pass={2} blocked={3} failed={4}" -f `
        $Summary.scope, $Summary.total, $Summary.pass, $Summary.blocked, $Summary.failed)
if ($Summary.failed -gt 0) {
    exit 1
}
if (-not $AllowBlocked -and $Summary.blocked -gt 0) {
    exit 2
}
exit 0
