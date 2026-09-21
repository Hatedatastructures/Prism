[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$PreviewTemplate,
    [Parameter(Mandatory = $true)][string]$MihomoTemplate,
    [Parameter(Mandatory = $true)][string]$CaseDirectory,
    [Parameter(Mandatory = $true)][int]$PreviewPort,
    [Parameter(Mandatory = $true)][int]$TargetPort,
    [Parameter(Mandatory = $true)][int]$ProxyPort,
    [int]$HandshakeBackendPort = 0,
    [string]$TlsCertificate = 'cert.pem',
    [string]$TlsPrivateKey = 'key.pem',
    [switch]$Tls12HandshakeBackend,
    [string]$ActiveProxy = '',
    [string]$ExpectedProtocol = '',
    [string]$MihomoExecutable = 'logs/preview-validation-local/20260917-221136/mihomo.exe',
    [string]$MihomoLogLevel = '',
    [string]$ServerAddress = '127.0.0.1',
    [int]$ControllerPort = 0,
    [int]$RepeatCount = 3,
    [ValidateRange(1, 32)][int]$ConcurrentRequests = 1
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Utf8NoBom {
    param([string]$Path, [string]$Content)

    $Encoding = New-Object System.Text.UTF8Encoding -ArgumentList $false
    [System.IO.File]::WriteAllText($Path, $Content, $Encoding)
}

function Get-FreeLoopbackPort {
    for ($Attempt = 0; $Attempt -lt 64; $Attempt++) {
        $Listener = [System.Net.Sockets.TcpListener]::new(
            [System.Net.IPAddress]::Loopback, 0)
        $Udp = $null
        try {
            $Listener.Start()
            $Port = ([System.Net.IPEndPoint]$Listener.LocalEndpoint).Port
            # Mihomo's mixed-port binds both TCP and UDP. Probe both protocols
            # before returning so a TCP-only free-port check cannot race it.
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

function Resolve-TemplateRelativePath {
    param(
        [AllowEmptyString()][string]$Value,
        [Parameter(Mandatory = $true)][string]$BaseDirectory
    )

    if ([string]::IsNullOrWhiteSpace($Value) -or [System.IO.Path]::IsPathRooted($Value)) {
        return $Value
    }
    return [System.IO.Path]::GetFullPath((Join-Path $BaseDirectory $Value))
}

function Stop-OwnedProcess {
    param([System.Diagnostics.Process]$ProcessValue)

    if ($null -ne $ProcessValue -and
        (Get-Process -Id $ProcessValue.Id -ErrorAction SilentlyContinue)) {
        Stop-Process -Id $ProcessValue.Id -Force -ErrorAction SilentlyContinue
        try { $ProcessValue.WaitForExit(5000) } catch { }
    }
    if ($null -eq $ProcessValue) {
        return $true
    }
    return $ProcessValue.HasExited -or
        $null -eq (Get-Process -Id $ProcessValue.Id -ErrorAction SilentlyContinue)
}

function Get-Sha256 {
    param([Parameter(Mandatory = $true)][string]$Path)

    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToUpperInvariant()
}

function Read-NewPreviewLogEvidence {
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

function Remove-TemporaryDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)

    for ($Attempt = 0; $Attempt -lt 30; $Attempt++) {
        if (-not (Test-Path -LiteralPath $Path)) {
            return $true
        }
        try {
            Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
            return -not (Test-Path -LiteralPath $Path)
        }
        catch {
            if ($Attempt -eq 29) {
                throw
            }
            Start-Sleep -Milliseconds 250
        }
    }
    return $false
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

New-Item -ItemType Directory -Path $CaseDirectory -Force | Out-Null
$CaseDirectory = (Resolve-Path -LiteralPath $CaseDirectory).Path
$PreviewExecutable = (Resolve-Path -LiteralPath 'build/src/PrismPreview.exe').Path
$MihomoExecutable = (Resolve-Path -LiteralPath $MihomoExecutable).Path
$FileServerExecutable = (Resolve-Path -LiteralPath 'build/tests/perf/FileServer.exe').Path
$PreviewSha256 = Get-Sha256 $PreviewExecutable
$MihomoSha256 = Get-Sha256 $MihomoExecutable
$TargetRoot = Join-Path $CaseDirectory 'target-root'
$PreviewLogRoot = Join-Path $CaseDirectory 'preview-logs'
New-Item -ItemType Directory -Path $TargetRoot,$PreviewLogRoot -Force | Out-Null
Write-Utf8NoBom (Join-Path $TargetRoot 'hello.txt') 'prism-current-mihomo-response'

$PreviewTemplatePath = (Resolve-Path -LiteralPath $PreviewTemplate).Path
$PreviewTemplateDirectory = Split-Path -Parent $PreviewTemplatePath
$PreviewObject = Get-Content -LiteralPath $PreviewTemplatePath -Raw | ConvertFrom-Json
$OldPreviewPort = [int]$PreviewObject.Listeners.Tcp[0].Port
$PreviewObject.Listeners.Tcp[0].Port = $PreviewPort
$PreviewObject.NativeTls.CertificateFile = Resolve-TemplateRelativePath `
    $PreviewObject.NativeTls.CertificateFile $PreviewTemplateDirectory
$PreviewObject.NativeTls.PrivateKeyFile = Resolve-TemplateRelativePath `
    $PreviewObject.NativeTls.PrivateKeyFile $PreviewTemplateDirectory
foreach ($Carrier in @($PreviewObject.Carriers)) {
    $Options = $Carrier.Options
    if ($null -eq $Options) {
        continue
    }
    foreach ($PropertyName in @('CertificateFile', 'PrivateKeyFile')) {
        if ($Options.PSObject.Properties.Name -contains $PropertyName) {
            $Options.$PropertyName = Resolve-TemplateRelativePath `
                $Options.$PropertyName $PreviewTemplateDirectory
        }
    }
}
$TlsBackendCertificate = $null
$TlsBackendPrivateKey = $null
if ($HandshakeBackendPort -gt 0) {
    $TlsBackendCertificate = (Resolve-Path -LiteralPath $TlsCertificate).Path
    $TlsBackendPrivateKey = (Resolve-Path -LiteralPath $TlsPrivateKey).Path
    foreach ($Carrier in @($PreviewObject.Carriers)) {
        $Options = $Carrier.Options
        if ($null -eq $Options) {
            continue
        }
        foreach ($PropertyName in @('HandshakeDest', 'HandshakeTarget', 'Host')) {
            if ($Options.PSObject.Properties.Name -contains $PropertyName) {
                $Options.$PropertyName = "127.0.0.1:$HandshakeBackendPort"
            }
        }
    }
}
$PreviewObject.Logging.Directory = $PreviewLogRoot.Replace('\', '/')
$PreviewOperationsPort = 0
if ($PreviewObject.Operations.Enabled) {
    $PreviewOperationsPort = Get-FreeLoopbackPort
    $PreviewObject.Operations.Endpoint = "127.0.0.1:$PreviewOperationsPort"
}
$ControllerPort = if ($ControllerPort -gt 0) { $ControllerPort } else { Get-FreeLoopbackPort }
$PreviewConfig = Join-Path $CaseDirectory 'preview.json'
Write-Utf8NoBom $PreviewConfig ($PreviewObject | ConvertTo-Json -Depth 100)
$PreviewConfigSha256 = Get-Sha256 $PreviewConfig

$Yaml = Get-Content -LiteralPath $MihomoTemplate -Raw
$Yaml = if ([string]::IsNullOrWhiteSpace($MihomoLogLevel)) {
    $Yaml
} else {
    [regex]::Replace($Yaml, '(?m)^log-level:\s+.*$', "log-level: $MihomoLogLevel")
}
$Yaml = [regex]::Replace($Yaml, '(?m)^mixed-port:\s+\d+\s*$', "mixed-port: $ProxyPort")
$Yaml = [regex]::Replace(
    $Yaml,
    '(?m)^\s*server:\s+(?!socks5\.preview\s*$).*$',
    "    server: $ServerAddress")
$Yaml = [regex]::Replace($Yaml, '(?m)^external-controller:\s+.*$', "external-controller: 127.0.0.1:$ControllerPort")
$Yaml = [regex]::Replace($Yaml, '(?m)^bind-address:\s+.*$', 'bind-address: 127.0.0.1')
$Yaml = [regex]::Replace($Yaml, '(?m)^allow-lan:\s+.*$', 'allow-lan: false')
# 强制本地回环目标经过隔离 Mihomo；主配置的回环直连规则不能进入这个测试模板。
$Yaml = [regex]::Replace(
    $Yaml,
    '(?m)^\s*-\s*IP-CIDR,127\.0\.0\.0/8,DIRECT\s*\r?\n',
    '')
# 隔离矩阵时移除自动健康探测组，避免启动探测混入服务端协议证据。
$Yaml = [regex]::Replace(
    $Yaml,
    '(?ms)^[ \t]*-[ \t]+name:\s+"PrismPreview-Xiaomi-Health"[^\r\n]*\r?\n.*?(?=^[ \t]*-[ \t]+name:|^# ---------- 规则 ----------)',
    '')
if ($Yaml -match 'name:\s+"PrismPreview-Xiaomi-Health"') {
    throw 'Isolated Mihomo template still contains PrismPreview-Xiaomi-Health'
}
if (-not [string]::IsNullOrWhiteSpace($ActiveProxy)) {
    $Yaml = [regex]::Replace(
        $Yaml,
        '(?m)^(\s*-\s*MATCH,)PrismPreview-Active\s*$',
        ('$1' + $ActiveProxy))
    if ($Yaml -notmatch [regex]::Escape($ActiveProxy)) {
        throw "ActiveProxy was not found in Mihomo template: $ActiveProxy"
    }
}
$ProxyPortLines = @([regex]::Matches($Yaml, '(?m)^\s+port:\s+(\d+)\s*$') |
    ForEach-Object { [int]$_.Groups[1].Value })
if ($ProxyPortLines.Count -eq 0) {
    throw 'Mihomo template has no proxy port field'
}
$MihomoPreviewPorts = @($ProxyPortLines | Where-Object { $_ -eq $OldPreviewPort } | Select-Object -Unique)
if ($MihomoPreviewPorts.Count -eq 0 -and @($ProxyPortLines | Select-Object -Unique).Count -eq 1) {
    $MihomoPreviewPorts = @($ProxyPortLines | Select-Object -Unique)
}
if ($MihomoPreviewPorts.Count -ne 1) {
    throw "Mihomo template preview port is ambiguous: $($ProxyPortLines -join ',')"
}
$Yaml = [regex]::Replace(
    $Yaml,
    "(?m)^(\s+port:)\s+$($MihomoPreviewPorts[0])\s*$",
    ('$1 ' + $PreviewPort))
$ChildEnvironment = @{}
Get-ChildItem Env: | ForEach-Object { $ChildEnvironment[$_.Name] = $_.Value }
$ChildEnvironment['NO_PROXY'] = 'localhost;127.0.0.1;::1'
$ChildEnvironment['no_proxy'] = $ChildEnvironment['NO_PROXY']
$ChildEnvironment['HTTP_PROXY'] = ''
$ChildEnvironment['HTTPS_PROXY'] = ''
$ChildEnvironment['ALL_PROXY'] = ''
$ChildEnvironment['http_proxy'] = ''
$ChildEnvironment['https_proxy'] = ''
$ChildEnvironment['all_proxy'] = ''

$Started = [System.Collections.Generic.List[int]]::new()
$PreviewProcess = $null
$TargetProcess = $null
$TlsProcess = $null
$Results = [System.Collections.Generic.List[object]]::new()
try {
    $TargetProcess = Start-Process -FilePath $FileServerExecutable `
        -ArgumentList @($TargetRoot, $TargetPort, '1') `
        -WorkingDirectory (Get-Location) -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput (Join-Path $CaseDirectory 'target.stdout.log') `
        -RedirectStandardError (Join-Path $CaseDirectory 'target.stderr.log') `
        -Environment $ChildEnvironment
    [void]$Started.Add($TargetProcess.Id)

    if ($HandshakeBackendPort -gt 0) {
        $OpenSslExecutable = (Get-Command openssl.exe -ErrorAction Stop).Source
        $TlsArguments = [System.Collections.Generic.List[string]]::new()
        foreach ($TlsArgument in @(
                's_server', '-accept', [string]$HandshakeBackendPort,
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
            -WorkingDirectory (Get-Location) -WindowStyle Hidden -PassThru `
            -RedirectStandardOutput (Join-Path $CaseDirectory 'tls.stdout.log') `
            -RedirectStandardError (Join-Path $CaseDirectory 'tls.stderr.log') `
            -Environment $ChildEnvironment
        [void]$Started.Add($TlsProcess.Id)
        $TlsReady = $false
        for ($Index = 0; $Index -lt 40; $Index++) {
            Start-Sleep -Milliseconds 250
            if ($TlsProcess.HasExited) {
                throw "TLS backend exited with code $($TlsProcess.ExitCode)"
            }
            $TlsListeners = @(Get-NetTCPConnection -State Listen -LocalPort $HandshakeBackendPort `
                    -ErrorAction SilentlyContinue)
            if (@($TlsListeners | Where-Object {
                        $_.OwningProcess -eq $TlsProcess.Id
                    }).Count -gt 0) {
                $TlsReady = $true
                break
            }
        }
        if (-not $TlsReady) {
            throw 'TLS backend readiness timeout'
        }
    }

    $PreviewProcess = Start-Process -FilePath $PreviewExecutable `
        -ArgumentList @($PreviewConfig) `
        -WorkingDirectory (Get-Location) -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput (Join-Path $CaseDirectory 'preview.stdout.log') `
        -RedirectStandardError (Join-Path $CaseDirectory 'preview.stderr.log') `
        -Environment $ChildEnvironment
    [void]$Started.Add($PreviewProcess.Id)

    $PreviewReady = $false
    for ($Index = 0; $Index -lt 40; $Index++) {
        Start-Sleep -Milliseconds 250
        if ($PreviewProcess.HasExited) {
            throw "Preview exited with code $($PreviewProcess.ExitCode)"
        }
        $ReadyLog = Join-Path $CaseDirectory 'preview.stdout.log'
        if ((Test-Path -LiteralPath $ReadyLog) -and
            (Get-Content -LiteralPath $ReadyLog -Raw) -match 'PrismPreview READY') {
            $PreviewReady = $true
            break
        }
    }
    if (-not $PreviewReady) {
        throw 'Preview readiness timeout'
    }

    for ($Attempt = 1; $Attempt -le $RepeatCount; $Attempt++) {
        $AttemptResult = $null
        $MihomoProcess = $null
        $ServerEvidence = [pscustomobject]@{
            Observed = $false
            Path = ''
            Excerpt = ''
        }
        $AttemptProxyPort = if ($Attempt -eq 1) { $ProxyPort } else { Get-FreeLoopbackPort }
        $AttemptHome = Join-Path $CaseDirectory ("mihomo-home-{0}" -f $Attempt)
        New-Item -ItemType Directory -Path $AttemptHome -Force | Out-Null
        $AttemptConfig = Join-Path $AttemptHome 'config.yaml'
        $MihomoOut = Join-Path $CaseDirectory ("mihomo-{0}.stdout.log" -f $Attempt)
        $MihomoErr = Join-Path $CaseDirectory ("mihomo-{0}.stderr.log" -f $Attempt)
        $AttemptYaml = [regex]::Replace(
            $Yaml,
            '(?m)^mixed-port:\s+\d+\s*$',
            "mixed-port: $AttemptProxyPort")
        Write-Utf8NoBom $AttemptConfig $AttemptYaml
        $PortLine = [regex]::Match($AttemptYaml, '(?m)^mixed-port:\s+(\d+)\s*$')
        if (-not $PortLine.Success -or [int]$PortLine.Groups[1].Value -ne $AttemptProxyPort) {
            throw "Mihomo config port mismatch: expected $AttemptProxyPort"
        }
        if (-not (Test-Path -LiteralPath $AttemptConfig)) {
            throw "Mihomo config was not written: $AttemptConfig"
        }
        $AttemptConfigSha256 = Get-Sha256 $AttemptConfig
        $MihomoArguments = "-d `"$AttemptHome`" -f `"$AttemptConfig`""
        $MihomoProcess = Start-Process -FilePath $MihomoExecutable `
            -ArgumentList $MihomoArguments `
            -WorkingDirectory $AttemptHome -WindowStyle Hidden -PassThru `
            -RedirectStandardOutput $MihomoOut -RedirectStandardError $MihomoErr `
            -Environment $ChildEnvironment
        [void]$Started.Add($MihomoProcess.Id)
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
            if ($null -eq $MihomoIdentity -or
                $MihomoIdentity.ExecutablePath -ne $MihomoExecutable -or
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
                $ProxyListeners = @(Get-NetTCPConnection -State Listen -LocalPort $AttemptProxyPort `
                        -ErrorAction SilentlyContinue)
                $UnexpectedDefaultListener = @(Get-NetTCPConnection -State Listen -LocalPort 7890 `
                        -OwningProcess $MihomoProcess.Id -ErrorAction SilentlyContinue)
                if ($UnexpectedDefaultListener.Count -gt 0) {
                    throw "Isolated Mihomo PID $($MihomoProcess.Id) unexpectedly listened on 7890"
                }
                if (@($ProxyListeners | Where-Object {
                            $_.OwningProcess -eq $MihomoProcess.Id
                        }).Count -gt 0) {
                    $ProxyReady = $true
                    break
                }
            }
            if (-not $ProxyReady) {
                throw 'Mihomo readiness timeout'
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
            $PreviewSuccessCount = 0
            foreach ($PreviewLogFile in @(Get-ChildItem -LiteralPath $PreviewLogRoot -File -ErrorAction SilentlyContinue)) {
                $PreviewSuccessCount += @(Get-Content -LiteralPath $PreviewLogFile.FullName -ErrorAction SilentlyContinue |
                    Where-Object {
                        $_ -match $DataPlanePattern -and
                        ([string]::IsNullOrEmpty($ProtocolPattern) -or $_ -match $ProtocolPattern)
                    }).Count
            }
            $StartedAt = Get-Date
            $Output = [System.Collections.Generic.List[string]]::new()
            $ExitCode = 0
            if ($ConcurrentRequests -eq 1) {
                $SingleOutput = @(& curl.exe --noproxy '' `
                    --proxy ("http://127.0.0.1:{0}" -f $AttemptProxyPort) `
                    --max-time 30 --silent --show-error `
                    --write-out "`nHTTP_CODE=%{http_code}`nTIME=%{time_total}`n" `
                    ("http://127.0.0.1:{0}/hello.txt" -f $TargetPort) 2>&1)
                $ExitCode = $LASTEXITCODE
                $Output.AddRange([string[]]$SingleOutput)
            }
            else {
                $CurlProcesses = [System.Collections.Generic.List[System.Diagnostics.Process]]::new()
                $CurlStdout = [System.Collections.Generic.List[string]]::new()
                $CurlStderr = [System.Collections.Generic.List[string]]::new()
                for ($RequestIndex = 1; $RequestIndex -le $ConcurrentRequests; $RequestIndex++) {
                    $StdoutPath = Join-Path $CaseDirectory ("curl-{0}-{1}.stdout.log" -f $Attempt, $RequestIndex)
                    $StderrPath = Join-Path $CaseDirectory ("curl-{0}-{1}.stderr.log" -f $Attempt, $RequestIndex)
                    $CurlStdout.Add($StdoutPath)
                    $CurlStderr.Add($StderrPath)
                    $CurlProcesses.Add((Start-Process -FilePath 'curl.exe' -ArgumentList @(
                                '--noproxy=',
                                ("--proxy=http://127.0.0.1:{0}" -f $AttemptProxyPort),
                                '--max-time', '30', '--silent', '--show-error',
                                '--write-out', "`nHTTP_CODE=%{http_code}`nTIME=%{time_total}`n",
                                ("http://127.0.0.1:{0}/hello.txt" -f $TargetPort)) `
                            -WindowStyle Hidden -PassThru -RedirectStandardOutput $StdoutPath `
                            -RedirectStandardError $StderrPath))
                }
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
            $HttpCode200Count = @($Output | Where-Object { $_ -match 'HTTP_CODE=200' }).Count
            # Mihomo keeps AnyTLS application-mux connections pooled after the
            # request. Close this task-owned client before waiting for the
            # server-side close/mux evidence, otherwise the evidence wait is
            # measuring the client's idle pool lifetime.
            [void](Stop-OwnedProcess $MihomoProcess)
            # AnyTLS 将并发请求复用到一个应用层 mux 会话；其服务端成功日志
            # 按物理会话计数，payload 数量仍由 HTTP 结果逐请求校验。
            $MinimumSuccessCount = if ($ExpectedProtocol -eq 'anytls') {
                $PreviewSuccessCount
            }
            else {
                $PreviewSuccessCount + $ConcurrentRequests - 1
            }
            for ($LogAttempt = 0; $LogAttempt -lt 450; $LogAttempt++) {
                $ServerEvidence = Read-NewPreviewLogEvidence `
                    -LogRoot $PreviewLogRoot `
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
                    commandLine = $CommandLine
                    exitCode = $ExitCode
                    elapsedSeconds = ((Get-Date) - $StartedAt).TotalSeconds
                    output = ($Output -join "`n")
                    previewExecutable = $PreviewExecutable
                    previewSha256 = $PreviewSha256
                    previewConfig = $PreviewConfig
                    previewConfigSha256 = $PreviewConfigSha256
                    mihomoExecutable = $MihomoExecutable
                    mihomoSha256 = $MihomoSha256
                    expectedProtocol = $ExpectedProtocol
                    concurrentRequests = $ConcurrentRequests
                    httpCode200Count = $HttpCode200Count
                    serverLogObserved = [bool]$ServerEvidence.Observed
                    serverLogPath = $ServerEvidence.Path
                    serverLogExcerpt = $ServerEvidence.Excerpt
                    targetAddress = $ServerAddress
                    controllerPort = $ControllerPort
                    previewOperationsPort = $PreviewOperationsPort
                }
        }
        finally {
            $MihomoExited = Stop-OwnedProcess $MihomoProcess
            $HomeRemoved = Remove-TemporaryDirectory $AttemptHome
            $ConfigRemoved = -not (Test-Path -LiteralPath $AttemptConfig)
            if ($null -eq $AttemptResult) {
                $AttemptResult = [ordered]@{
                    attempt = $Attempt
                    proxyPort = $AttemptProxyPort
                    mihomoPid = $MihomoProcess.Id
                    configPath = $AttemptConfig
                    configSha256 = $AttemptConfigSha256
                    previewExecutable = $PreviewExecutable
                    previewSha256 = $PreviewSha256
                    previewConfig = $PreviewConfig
                    previewConfigSha256 = $PreviewConfigSha256
                    mihomoExecutable = $MihomoExecutable
                    mihomoSha256 = $MihomoSha256
                    expectedProtocol = $ExpectedProtocol
                    serverLogObserved = [bool]$ServerEvidence.Observed
                    serverLogPath = $ServerEvidence.Path
                    serverLogExcerpt = $ServerEvidence.Excerpt
                    targetAddress = $ServerAddress
                    controllerPort = $ControllerPort
                    previewOperationsPort = $PreviewOperationsPort
                    exitCode = 1
                    elapsedSeconds = 0
                    output = ''
                }
            }
            $AttemptResult['cleanup'] = [ordered]@{
                mihomoExited = [bool]$MihomoExited
                homeRemoved = [bool]$HomeRemoved
                configRemoved = [bool]$ConfigRemoved
            }
            [void]$Results.Add($AttemptResult)
        }
    }
}
finally {
    [void](Stop-OwnedProcess $PreviewProcess)
    [void](Stop-OwnedProcess $TargetProcess)
    [void](Stop-OwnedProcess $TlsProcess)
    foreach ($ProcessId in ($Started | Select-Object -Unique)) {
        if (Get-Process -Id $ProcessId -ErrorAction SilentlyContinue) {
            Stop-Process -Id $ProcessId -Force -ErrorAction SilentlyContinue
        }
    }
    if (Test-Path -LiteralPath $PreviewConfig) {
        Remove-Item -LiteralPath $PreviewConfig -Force -ErrorAction Stop
    }
    $PreviewConfigRemoved = -not (Test-Path -LiteralPath $PreviewConfig)
    foreach ($Result in $Results) {
        $Result['cleanup']['previewConfigRemoved'] = [bool]$PreviewConfigRemoved
    }
}

$ResultJson = $Results | ConvertTo-Json -Depth 8
Write-Utf8NoBom (Join-Path $CaseDirectory 'results.json') $ResultJson
$ResultJson
if (@($Results | Where-Object {
        $_.exitCode -ne 0 -or $_.httpCode200Count -lt $_.concurrentRequests -or
        -not $_.serverLogObserved
    }).Count -gt 0) {
    exit 1
}
