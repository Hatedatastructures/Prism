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
. (Join-Path $PSScriptRoot '..\OperationsCommandAuth.ps1')

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

function Get-ProcessImagePath {
    param([Parameter(Mandatory = $true)][int]$ProcessId)

    try {
        $Identity = Get-CimInstance Win32_Process -Filter "ProcessId=$ProcessId" `
            -ErrorAction Stop
        return [string]$Identity.ExecutablePath
    }
    catch {
        return ''
    }
}

function New-OwnedProcessIdentity {
    param(
        [Parameter(Mandatory = $true)][System.Diagnostics.Process]$ProcessValue,
        [Parameter(Mandatory = $true)][string]$ExpectedPath,
        [Parameter(Mandatory = $true)][string]$Role
    )

    return [pscustomobject]@{
        Process = $ProcessValue
        Pid = [int]$ProcessValue.Id
        Path = (Resolve-Path -LiteralPath $ExpectedPath).Path
        StartTime = $ProcessValue.StartTime.ToUniversalTime()
        Role = $Role
    }
}

function Test-OwnedProcessIdentity {
    param([Parameter(Mandatory = $true)][pscustomobject]$Identity)

    $Current = Get-Process -Id $Identity.Pid -ErrorAction SilentlyContinue
    if ($null -eq $Current) {
        return $true
    }
    try {
        $CurrentPath = Get-ProcessImagePath $Identity.Pid
        $CurrentStartTime = $Current.StartTime.ToUniversalTime()
        return [string]::Equals(
                $CurrentPath,
                $Identity.Path,
                [System.StringComparison]::OrdinalIgnoreCase) -and
            $CurrentStartTime.Ticks -eq $Identity.StartTime.Ticks
    }
    catch {
        return $false
    }
}

function Stop-OwnedProcess {
    param(
        [System.Diagnostics.Process]$ProcessValue,
        [pscustomobject]$Identity
    )

    if ($null -eq $ProcessValue) {
        return $true
    }
    if ($null -eq $Identity) {
        Write-Warning "Refusing cleanup for PID $($ProcessValue.Id): no recorded identity"
        return $false
    }
    $Current = Get-Process -Id $Identity.Pid -ErrorAction SilentlyContinue
    if ($null -eq $Current) {
        return $true
    }
    try {
        if ($Current.HasExited) {
            return $true
        }
    }
    catch {
        return $false
    }
    if (-not (Test-OwnedProcessIdentity $Identity)) {
        Write-Warning "Refusing cleanup for $($Identity.Role) PID $($Identity.Pid): identity mismatch"
        return $false
    }
    try {
        $Current.Kill()
        if (-not $Current.WaitForExit(5000)) {
            return $false
        }
    }
    catch {
        return $false
    }
    return $true
}

function Get-Sha256 {
    param([Parameter(Mandatory = $true)][string]$Path)

    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToUpperInvariant()
}

function Read-CurlResponseEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$BodyPath,
        [Parameter(Mandatory = $true)][string]$MetadataText,
        [Parameter(Mandatory = $true)][string]$ExpectedBody
    )

    $CodeMatch = [regex]::Match($MetadataText, '(?m)HTTP_CODE=(?<Code>\d+)')
    $TimeMatch = [regex]::Match($MetadataText, '(?m)TIME=(?<Time>[^\r\n]+)')
    $BodyBytes = if (Test-Path -LiteralPath $BodyPath -PathType Leaf) {
        [System.IO.File]::ReadAllBytes($BodyPath)
    }
    else {
        [byte[]]::new(0)
    }
    $BodyText = [System.Text.Encoding]::UTF8.GetString($BodyBytes)
    return [pscustomobject]@{
        BodyPath = $BodyPath
        BodySha256 = if (Test-Path -LiteralPath $BodyPath -PathType Leaf) {
            Get-Sha256 $BodyPath
        } else { '' }
        BodyBytes = $BodyBytes.Length
        Body = $BodyText
        BodyMatchesExpected = $BodyText -ceq $ExpectedBody
        HttpCode = if ($CodeMatch.Success) { [int]$CodeMatch.Groups['Code'].Value } else { 0 }
        Time = if ($TimeMatch.Success) { $TimeMatch.Groups['Time'].Value } else { '' }
        Metadata = $MetadataText
    }
}

function Get-ExpectedProtocolLogName {
    param([AllowEmptyString()][string]$Protocol)

    switch ($Protocol.ToLowerInvariant()) {
        'http' { return 'Http' }
        'socks5' { return 'Socks5' }
        'trojan' { return 'Trojan' }
        'vless' { return 'Vless' }
        'shadowsocks' { return 'Shadowsocks' }
        'ss2022' { return 'Shadowsocks' }
        'vmess' { return 'Vmess' }
        'hysteria2' { return 'Hysteria2' }
        'tuic' { return 'Tuic' }
        'tls' { return 'Tls' }
        'anytls' { return 'Anytls' }
        'trusttunnel' { return 'Trusttunnel' }
        default { throw "Unsupported expected protocol for structured log evidence: $Protocol" }
    }
}

function Read-PreviewStructuredRecords {
    param([Parameter(Mandatory = $true)][string]$LogRoot)

    $Records = [System.Collections.Generic.List[object]]::new()
    foreach ($LogFile in @(Get-ChildItem -LiteralPath $LogRoot -File -ErrorAction SilentlyContinue)) {
        $LineNumber = 0
        foreach ($Line in @(Get-Content -LiteralPath $LogFile.FullName -ErrorAction Stop)) {
            $LineNumber++
            if ([string]::IsNullOrWhiteSpace($Line)) {
                continue
            }
            try {
                $Value = $Line | ConvertFrom-Json -Depth 30 -ErrorAction Stop
            }
            catch {
                throw "Structured log parse failed at $($LogFile.FullName):$LineNumber : $($_.Exception.Message)"
            }
            [void]$Records.Add([pscustomobject]@{
                    Path = $LogFile.FullName
                    Line = $LineNumber
                    Value = $Value
                })
        }
    }
    return @($Records)
}

function Get-StructuredSessionIds {
    param([Parameter(Mandatory = $true)][string]$LogRoot)

    return @(
        Read-PreviewStructuredRecords -LogRoot $LogRoot |
            Where-Object { $null -ne $_.Value.Session } |
            ForEach-Object { ([string]$_.Value.Worker) + '/' + ([string]$_.Value.Session) } |
            Sort-Object -Unique
    )
}

function Get-StructuredField {
    param(
        [Parameter(Mandatory = $true)][object]$Record,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if ($null -eq $Record.Fields) {
        return $null
    }
    $Property = $Record.Fields.PSObject.Properties[$Name]
    if ($null -eq $Property) {
        return $null
    }
    return $Property.Value
}

function Read-NewPreviewLogEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$LogRoot,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$BaselineSessionIds,
        [Parameter(Mandatory = $true)][int]$RequiredSessionCount,
        [Parameter(Mandatory = $true)][string]$Protocol,
        [Parameter(Mandatory = $true)][string]$Target,
        [switch]$AllowRootWithoutTarget
    )

    $ExpectedProtocolName = Get-ExpectedProtocolLogName $Protocol
    $Baseline = @($BaselineSessionIds | ForEach-Object { [string]$_ })
    $Groups = @{}
    foreach ($Entry in @(Read-PreviewStructuredRecords -LogRoot $LogRoot)) {
        if ($null -eq $Entry.Value.Session) {
            continue
        }
        $Session = [string]$Entry.Value.Session
        $Identity = ([string]$Entry.Value.Worker) + '/' + $Session
        if ($Baseline -contains $Identity) {
            continue
        }
        if (-not $Groups.ContainsKey($Identity)) {
            $Groups[$Identity] = [System.Collections.Generic.List[object]]::new()
        }
        [void]$Groups[$Identity].Add($Entry)
    }

    $Matched = [System.Collections.Generic.List[object]]::new()
    foreach ($Identity in $Groups.Keys) {
        $Group = @($Groups[$Identity])
        $Session = [string]$Group[0].Value.Session
        $Messages = @($Group | ForEach-Object { [string]$_.Value.Message })
        $Recognition = @($Messages | Where-Object {
                $_.StartsWith("RecognitionDetails Protocol=$ExpectedProtocolName")
            })
        $Request = @($Messages | Where-Object {
                $_ -match ('(^|\s)Target=' + [regex]::Escape($Target) + '(\s|$)')
            })
        $Closed = @($Group | Where-Object {
                ([string]$_.Value.Message).StartsWith('SessionClosed ')
            })
        $TargetObserved = $Request.Count -gt 0
        if ($Recognition.Count -eq 0 -or
            (-not $AllowRootWithoutTarget -and -not $TargetObserved) -or
            $Closed.Count -ne 1) {
            continue
        }

        $Terminal = $Closed[0]
        $Stage = [string](Get-StructuredField -Record $Terminal.Value -Name 'Stage')
        $Status = [string](Get-StructuredField -Record $Terminal.Value -Name 'Status')
        $FaultCode = [string](Get-StructuredField -Record $Terminal.Value -Name 'FaultCode')
        $Message = [string]$Terminal.Value.Message
        $PhaseMatch = [regex]::Match($Message, '(?:^|\s)PhaseSequence=(?<Value>[^\r\n]+)$')
        if ($Stage -ne 'Close' -or $Status -ne 'Success' -or $FaultCode -ne 'Success' -or
            -not $PhaseMatch.Success -or $PhaseMatch.Groups['Value'].Value -notmatch 'Relay>Close$') {
            continue
        }

        [void]$Matched.Add([pscustomobject]@{
                Session = $Session
                Worker = if ($null -eq $Terminal.Value.Worker) { '' } else { [string]$Terminal.Value.Worker }
                Protocol = $ExpectedProtocolName
                Target = $Target
                TargetObserved = $TargetObserved
                TerminalCount = $Closed.Count
                Stage = $Stage
                Status = $Status
                FaultCode = $FaultCode
                PhaseSequence = $PhaseMatch.Groups['Value'].Value
                Path = $Terminal.Path
                Line = $Terminal.Line
            })
    }

    $SuccessCount = $Matched.Count
    $Observed = $SuccessCount -ge $RequiredSessionCount
    return [pscustomobject]@{
        Observed = $Observed
        Path = if ($Matched.Count -gt 0) { $Matched[0].Path } else { '' }
        Excerpt = (@($Matched | ForEach-Object {
                "$($_.Path):$($_.Line) Session=$($_.Session) Protocol=$($_.Protocol) Target=$($_.Target) Phase=$($_.PhaseSequence)"
            }) -join "`n")
        SuccessCount = $SuccessCount
        MinimumSuccessCount = $RequiredSessionCount
        ExpectedProtocolName = $ExpectedProtocolName
        ExpectedTarget = $Target
        MatchedSessions = @($Matched)
        TargetRequired = -not $AllowRootWithoutTarget
        TargetObserved = @($Matched | Where-Object { $_.TargetObserved }).Count -gt 0
        Structured = $true
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
$RequireTargetForSession = -not (
    $ExpectedProtocol -eq 'anytls' -or
    $ActiveProxy -match '(?i)(Smux|Yamux|H2Mux)')

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
$ExpectedLiteralBody = 'prism-current-mihomo-response'
$TargetBodyPath = Join-Path $TargetRoot 'hello.txt'
Write-Utf8NoBom $TargetBodyPath $ExpectedLiteralBody
$TargetBodySha256 = Get-Sha256 $TargetBodyPath

$PreviewTemplatePath = (Resolve-Path -LiteralPath $PreviewTemplate).Path
$PreviewTemplateDirectory = Split-Path -Parent $PreviewTemplatePath
$PreviewObject = Get-Content -LiteralPath $PreviewTemplatePath -Raw | ConvertFrom-Json
$OldPreviewPort = [int]$PreviewObject.Listeners.Tcp[0].Port
$PreviewObject.Listeners.Tcp[0].Address = $ServerAddress
$PreviewObject.Listeners.Tcp[0].Port = $PreviewPort
$PreviewObject.Listeners.Udp = @()
$PreviewObject.Listeners.Quic = @()
$PreviewObject.Protocols = @($PreviewObject.Protocols |
    Where-Object { $_.Builtin -ne 'hysteria2' -and $_.Builtin -ne 'tuic' })
$PreviewObject.ProtocolBindings = @($PreviewObject.ProtocolBindings |
    Where-Object { $_.ProtocolId -ne 'protocol-hysteria2' -and $_.ProtocolId -ne 'protocol-tuic' })
foreach ($Binding in @($PreviewObject.ProtocolBindings)) {
    $Binding.UdpEnabled = $false
}
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
$PreviewObject.Logging.Level = 'Trace'
$PreviewObject.Logging | Add-Member -NotePropertyName RenderMode -NotePropertyValue 'Structured' -Force
$PreviewObject.Trace.IncludeWorker = $true
$PreviewObject.Trace.IncludeSession = $true
$PreviewObject.Trace.IncludeCorrelation = $true
$PreviewOperationsPort = 0
if ($PreviewObject.Operations.Enabled) {
    $PreviewOperationsPort = Get-FreeLoopbackPort
    $PreviewObject.Operations.Endpoint = "127.0.0.1:$PreviewOperationsPort"
}
$ControllerPort = if ($ControllerPort -gt 0) { $ControllerPort } else { Get-FreeLoopbackPort }
$PreviewConfig = Join-Path $CaseDirectory 'preview.json'
Write-Utf8NoBom $PreviewConfig ($PreviewObject | ConvertTo-Json -Depth 100)
$PreviewConfigSha256 = Get-Sha256 $PreviewConfig
$PreviewConfigAudit = Join-Path $CaseDirectory 'preview-config.audit.json'
Copy-Item -LiteralPath $PreviewConfig -Destination $PreviewConfigAudit -Force
$PreviewConfigAuditSha256 = Get-Sha256 $PreviewConfigAudit

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

$Started = [System.Collections.Generic.List[object]]::new()
$PreviewProcess = $null
$PreviewIdentity = $null
$TargetProcess = $null
$TargetIdentity = $null
$TlsProcess = $null
$TlsIdentity = $null
$PreviewDrainUri = if ($PreviewOperationsPort -gt 0) {
    "http://127.0.0.1:$PreviewOperationsPort/Operations/Drain?worker=0&stop_accepting=true&force=false"
} else { '' }
$PreviewDrainStatus = ''
$PreviewDrainMessage = ''
$PreviewDrainRequested = $false
$PreviewNaturalExit = $false
$PreviewExitCode = $null
$Results = [System.Collections.Generic.List[object]]::new()
try {
    $TargetProcess = Start-Process -FilePath $FileServerExecutable `
        -ArgumentList @($TargetRoot, $TargetPort, '1') `
        -WorkingDirectory (Get-Location) -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput (Join-Path $CaseDirectory 'target.stdout.log') `
        -RedirectStandardError (Join-Path $CaseDirectory 'target.stderr.log') `
        -Environment $ChildEnvironment
    $TargetIdentity = New-OwnedProcessIdentity -ProcessValue $TargetProcess `
        -ExpectedPath $FileServerExecutable -Role 'target'
    [void]$Started.Add($TargetIdentity)

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
        $TlsIdentity = New-OwnedProcessIdentity -ProcessValue $TlsProcess `
            -ExpectedPath $OpenSslExecutable -Role 'tls-backend'
        [void]$Started.Add($TlsIdentity)
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
    $PreviewIdentity = New-OwnedProcessIdentity -ProcessValue $PreviewProcess `
        -ExpectedPath $PreviewExecutable -Role 'preview'
    [void]$Started.Add($PreviewIdentity)

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
    if ($PreviewOperationsPort -le 0) {
        throw 'Preview Operations must be enabled for natural drain acceptance'
    }
    $OperationsReady = $false
    for ($Index = 0; $Index -lt 40; $Index++) {
        Start-Sleep -Milliseconds 250
        if ($PreviewProcess.HasExited) {
            throw "Preview exited before Operations readiness: $($PreviewProcess.ExitCode)"
        }
        try {
            $Health = Invoke-RestMethod -Method Get `
                -Uri "http://127.0.0.1:$PreviewOperationsPort/Operations/Health" `
                -TimeoutSec 2
            if ($Health.value.ready) {
                $OperationsReady = $true
                break
            }
        }
        catch { }
    }
    if (-not $OperationsReady) {
        throw 'Preview Operations readiness timeout'
    }

    for ($Attempt = 1; $Attempt -le $RepeatCount; $Attempt++) {
        $AttemptResult = $null
        $MihomoProcess = $null
        $MihomoProcessIdentity = $null
        $AttemptConfigAudit = ''
        $AttemptConfigAuditSha256 = ''
        $HttpCode200Count = 0
        $LiteralBodyMatchCount = 0
        $ResponseEvidence = @()
        $MihomoClosed = $false
        $ServerEvidence = [pscustomobject]@{
            Observed = $false
            Path = ''
            Excerpt = ''
            SuccessCount = 0
            MinimumSuccessCount = 0
            ExpectedProtocolName = Get-ExpectedProtocolLogName $ExpectedProtocol
            ExpectedTarget = "$ServerAddress`:$TargetPort"
            MatchedSessions = @()
            TargetRequired = $RequireTargetForSession
            TargetObserved = $false
            Structured = $true
        }
        $AttemptProxyPort = if ($Attempt -eq 1) { $ProxyPort } else { Get-FreeLoopbackPort }
        $AttemptHome = Join-Path $CaseDirectory ("mihomo-home-{0}" -f $Attempt)
        New-Item -ItemType Directory -Path $AttemptHome -Force | Out-Null
        $AttemptConfig = Join-Path $AttemptHome 'config.yaml'
        $AttemptConfigAudit = Join-Path $CaseDirectory ("mihomo-{0}.config.yaml" -f $Attempt)
        $MihomoOut = Join-Path $CaseDirectory ("mihomo-{0}.stdout.log" -f $Attempt)
        $MihomoErr = Join-Path $CaseDirectory ("mihomo-{0}.stderr.log" -f $Attempt)
        $AttemptYaml = [regex]::Replace(
            $Yaml,
            '(?m)^mixed-port:\s+\d+\s*$',
            "mixed-port: $AttemptProxyPort")
        Write-Utf8NoBom $AttemptConfig $AttemptYaml
        Copy-Item -LiteralPath $AttemptConfig -Destination $AttemptConfigAudit -Force
        $PortLine = [regex]::Match($AttemptYaml, '(?m)^mixed-port:\s+(\d+)\s*$')
        if (-not $PortLine.Success -or [int]$PortLine.Groups[1].Value -ne $AttemptProxyPort) {
            throw "Mihomo config port mismatch: expected $AttemptProxyPort"
        }
        if (-not (Test-Path -LiteralPath $AttemptConfig)) {
            throw "Mihomo config was not written: $AttemptConfig"
        }
        $AttemptConfigSha256 = Get-Sha256 $AttemptConfig
        $AttemptConfigAuditSha256 = Get-Sha256 $AttemptConfigAudit
        $MihomoArguments = "-d `"$AttemptHome`" -f `"$AttemptConfig`""
        $MihomoProcess = Start-Process -FilePath $MihomoExecutable `
            -ArgumentList $MihomoArguments `
            -WorkingDirectory $AttemptHome -WindowStyle Hidden -PassThru `
            -RedirectStandardOutput $MihomoOut -RedirectStandardError $MihomoErr `
            -Environment $ChildEnvironment
        $MihomoProcessIdentity = New-OwnedProcessIdentity -ProcessValue $MihomoProcess `
            -ExpectedPath $MihomoExecutable -Role "mihomo-$Attempt"
        [void]$Started.Add($MihomoProcessIdentity)
        try {
            $MihomoCommandIdentity = Get-CimInstance Win32_Process `
                    -Filter "ProcessId=$($MihomoProcess.Id)" `
                    -ErrorAction SilentlyContinue
            $CommandLine = if ($null -eq $MihomoCommandIdentity) {
                ''
            }
            else {
                [string]$MihomoCommandIdentity.CommandLine
            }
            if ($null -eq $MihomoCommandIdentity -or
                -not (Test-OwnedProcessIdentity $MihomoProcessIdentity) -or
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

            $BaselineSessionIds = @(Get-StructuredSessionIds -LogRoot $PreviewLogRoot)
            $RequiredLogSessionCount = if ($RequireTargetForSession) {
                $ConcurrentRequests
            }
            else {
                1
            }
            $StartedAt = Get-Date
            $Output = [System.Collections.Generic.List[string]]::new()
            $BodyPaths = [System.Collections.Generic.List[string]]::new()
            $ResponseMetadata = [System.Collections.Generic.List[string]]::new()
            $ExitCode = 0
            if ($ConcurrentRequests -eq 1) {
                $BodyPath = Join-Path $CaseDirectory ("curl-{0}-1.body" -f $Attempt)
                [void]$BodyPaths.Add($BodyPath)
                $SingleOutput = @(& curl.exe --noproxy '' `
                    --proxy ("http://127.0.0.1:{0}" -f $AttemptProxyPort) `
                    --max-time 30 --silent --show-error `
                    --output $BodyPath `
                    --write-out "`nHTTP_CODE=%{http_code}`nTIME=%{time_total}`n" `
                    ("http://127.0.0.1:{0}/hello.txt" -f $TargetPort) 2>&1)
                $ExitCode = $LASTEXITCODE
                [void]$ResponseMetadata.Add(($SingleOutput -join "`n"))
                $Output.AddRange([string[]]$SingleOutput)
            }
            else {
                $CurlProcesses = [System.Collections.Generic.List[System.Diagnostics.Process]]::new()
                $CurlStdout = [System.Collections.Generic.List[string]]::new()
                $CurlStderr = [System.Collections.Generic.List[string]]::new()
                for ($RequestIndex = 1; $RequestIndex -le $ConcurrentRequests; $RequestIndex++) {
                    $BodyPath = Join-Path $CaseDirectory ("curl-{0}-{1}.body" -f $Attempt, $RequestIndex)
                    $StdoutPath = Join-Path $CaseDirectory ("curl-{0}-{1}.stdout.log" -f $Attempt, $RequestIndex)
                    $StderrPath = Join-Path $CaseDirectory ("curl-{0}-{1}.stderr.log" -f $Attempt, $RequestIndex)
                    $BodyPaths.Add($BodyPath)
                    $CurlStdout.Add($StdoutPath)
                    $CurlStderr.Add($StderrPath)
                    $CurlProcesses.Add((Start-Process -FilePath 'curl.exe' -ArgumentList @(
                                '--noproxy=',
                                ("--proxy=http://127.0.0.1:{0}" -f $AttemptProxyPort),
                                '--max-time', '30', '--silent', '--show-error',
                                '--output', $BodyPath,
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
                        [void]$ResponseMetadata.Add(($StdoutLines -join "`n"))
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
            $ResponseEvidence = [System.Collections.Generic.List[object]]::new()
            for ($ResponseIndex = 0; $ResponseIndex -lt $BodyPaths.Count; $ResponseIndex++) {
                [void]$ResponseEvidence.Add((Read-CurlResponseEvidence `
                        -BodyPath $BodyPaths[$ResponseIndex] `
                        -MetadataText $ResponseMetadata[$ResponseIndex] `
                        -ExpectedBody $ExpectedLiteralBody))
            }
            $HttpCode200Count = @($ResponseEvidence | Where-Object { $_.HttpCode -eq 200 }).Count
            $LiteralBodyMatchCount = @($ResponseEvidence |
                Where-Object { $_.BodyMatchesExpected }).Count
            if ($ExitCode -ne 0 -or $ResponseEvidence.Count -ne $ConcurrentRequests -or
                $HttpCode200Count -ne $ConcurrentRequests -or
                $LiteralBodyMatchCount -ne $ConcurrentRequests) {
                throw "Mihomo request evidence failed: exit=$ExitCode responses=$($ResponseEvidence.Count) http200=$HttpCode200Count literal=$LiteralBodyMatchCount expected=$ConcurrentRequests"
            }
            # Mihomo keeps AnyTLS application-mux connections pooled after the
            # request. Close this task-owned client before waiting for the
            # server-side close/mux evidence, otherwise the evidence wait is
            # measuring the client's idle pool lifetime.
            $MihomoClosed = Stop-OwnedProcess -ProcessValue $MihomoProcess `
                -Identity $MihomoProcessIdentity
            if (-not $MihomoClosed) {
                throw "Mihomo PID $($MihomoProcess.Id) cleanup identity verification failed"
            }
            # AnyTLS 将并发请求复用到一个应用层 mux 会话；其服务端成功日志
            # 按物理会话计数，payload 数量仍由 HTTP 结果逐请求校验。
            for ($LogAttempt = 0; $LogAttempt -lt 450; $LogAttempt++) {
                $ServerEvidence = Read-NewPreviewLogEvidence `
                    -LogRoot $PreviewLogRoot `
                    -BaselineSessionIds $BaselineSessionIds `
                    -RequiredSessionCount $RequiredLogSessionCount `
                    -Protocol $ExpectedProtocol `
                    -Target "$ServerAddress`:$TargetPort" `
                    -AllowRootWithoutTarget:(-not $RequireTargetForSession)
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
                     configAuditPath = $AttemptConfigAudit
                     configAuditSha256 = $AttemptConfigAuditSha256
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
                     literalBodyExpected = $ExpectedLiteralBody
                     literalBodyMatchCount = $LiteralBodyMatchCount
                     responseEvidence = @($ResponseEvidence)
                    serverLogObserved = [bool]$ServerEvidence.Observed
                     serverLogSuccessCount = $ServerEvidence.SuccessCount
                     serverLogMinimumCount = $ServerEvidence.MinimumSuccessCount
                    serverLogPath = $ServerEvidence.Path
                    serverLogExcerpt = $ServerEvidence.Excerpt
                    serverLogStructured = [bool]$ServerEvidence.Structured
                    serverLogExpectedProtocolName = $ServerEvidence.ExpectedProtocolName
                    serverLogExpectedTarget = $ServerEvidence.ExpectedTarget
                    serverLogMatchedSessionCount = @($ServerEvidence.MatchedSessions).Count
                    serverLogMatchedSessions = @($ServerEvidence.MatchedSessions)
                    serverLogTargetRequired = [bool]$ServerEvidence.TargetRequired
                    serverLogTargetObserved = [bool]$ServerEvidence.TargetObserved
                    targetAddress = $ServerAddress
                     targetBodyPath = $TargetBodyPath
                     targetBodySha256 = $TargetBodySha256
                    controllerPort = $ControllerPort
                    previewOperationsPort = $PreviewOperationsPort
                }
        }
        finally {
            $MihomoExited = Stop-OwnedProcess -ProcessValue $MihomoProcess `
                -Identity $MihomoProcessIdentity
            $MihomoClosed = $MihomoExited
            $HomeRemoved = Remove-TemporaryDirectory $AttemptHome
            $ConfigRemoved = -not (Test-Path -LiteralPath $AttemptConfig)
            if ($null -eq $AttemptResult) {
                $AttemptResult = [ordered]@{
                    attempt = $Attempt
                    proxyPort = $AttemptProxyPort
                    mihomoPid = if ($null -ne $MihomoProcess) { $MihomoProcess.Id } else { $null }
                    configPath = $AttemptConfig
                    configSha256 = $AttemptConfigSha256
                    configAuditPath = $AttemptConfigAudit
                    configAuditSha256 = $AttemptConfigAuditSha256
                    previewExecutable = $PreviewExecutable
                    previewSha256 = $PreviewSha256
                    previewConfig = $PreviewConfig
                    previewConfigSha256 = $PreviewConfigSha256
                    mihomoExecutable = $MihomoExecutable
                    mihomoSha256 = $MihomoSha256
                    expectedProtocol = $ExpectedProtocol
                    concurrentRequests = $ConcurrentRequests
                    httpCode200Count = $HttpCode200Count
                    literalBodyExpected = $ExpectedLiteralBody
                    literalBodyMatchCount = $LiteralBodyMatchCount
                    responseEvidence = @($ResponseEvidence)
                    serverLogObserved = [bool]$ServerEvidence.Observed
                    serverLogPath = $ServerEvidence.Path
                    serverLogExcerpt = $ServerEvidence.Excerpt
                    serverLogSuccessCount = $ServerEvidence.SuccessCount
                    serverLogMinimumCount = $ServerEvidence.MinimumSuccessCount
                    serverLogStructured = [bool]$ServerEvidence.Structured
                    serverLogExpectedProtocolName = $ServerEvidence.ExpectedProtocolName
                    serverLogExpectedTarget = $ServerEvidence.ExpectedTarget
                    serverLogMatchedSessionCount = @($ServerEvidence.MatchedSessions).Count
                    serverLogMatchedSessions = @($ServerEvidence.MatchedSessions)
                    serverLogTargetRequired = [bool]$ServerEvidence.TargetRequired
                    serverLogTargetObserved = [bool]$ServerEvidence.TargetObserved
                    targetAddress = $ServerAddress
                    targetBodyPath = $TargetBodyPath
                    targetBodySha256 = $TargetBodySha256
                    controllerPort = $ControllerPort
                    previewOperationsPort = $PreviewOperationsPort
                    exitCode = 1
                    elapsedSeconds = 0
                    output = ''
                }
            }
            $AttemptResult['cleanup'] = [ordered]@{
                mihomoExited = [bool]$MihomoExited
                mihomoIdentityVerified = [bool]$MihomoClosed
                homeRemoved = [bool]$HomeRemoved
                configRemoved = [bool]$ConfigRemoved
            }
            [void]$Results.Add($AttemptResult)
        }
    }
    if ($null -eq $PreviewProcess -or $null -eq $PreviewIdentity) {
        throw 'Preview process identity is unavailable for natural drain acceptance'
    }
    if ($PreviewProcess.HasExited) {
        throw "Preview exited before Operations drain: $($PreviewProcess.ExitCode)"
    }
    $Headers = Get-OperationsCommandHeaders -Port $PreviewOperationsPort
    $DrainResponse = Invoke-RestMethod -Method Post -Uri $PreviewDrainUri -Headers $Headers -TimeoutSec 5
    $PreviewDrainRequested = $true
    $PreviewDrainStatus = [string]$DrainResponse.status
    $PreviewDrainMessage = [string]$DrainResponse.message
    if ($PreviewDrainStatus -ne 'completed' -and $PreviewDrainStatus -ne 'accepted') {
        throw "Operations drain returned status $PreviewDrainStatus"
    }
    if (-not $PreviewProcess.WaitForExit(45000)) {
        throw 'PrismPreview did not exit naturally after Operations drain'
    }
    $PreviewProcess.Refresh()
    $PreviewExitCode = [int]$PreviewProcess.ExitCode
    $PreviewNaturalExit = $PreviewExitCode -eq 0
    if (-not $PreviewNaturalExit) {
        throw "PrismPreview exited after Operations drain with code $PreviewExitCode"
    }
    foreach ($Result in $Results) {
        $Result['previewDrainUri'] = $PreviewDrainUri
        $Result['previewDrainRequested'] = [bool]$PreviewDrainRequested
        $Result['previewDrainStatus'] = $PreviewDrainStatus
        $Result['previewDrainMessage'] = $PreviewDrainMessage
        $Result['previewExitCode'] = $PreviewExitCode
        $Result['previewNaturalExit'] = [bool]$PreviewNaturalExit
        $Result['previewConfigAudit'] = $PreviewConfigAudit
        $Result['previewConfigAuditSha256'] = $PreviewConfigAuditSha256
        $Result['ownedProcessIdentities'] = @($Started | ForEach-Object {
                [ordered]@{
                    role = $_.Role
                    pid = $_.Pid
                    path = $_.Path
                    startTime = $_.StartTime.ToString('o')
                }
            })
    }
}
finally {
    $PreviewCleanup = Stop-OwnedProcess -ProcessValue $PreviewProcess -Identity $PreviewIdentity
    $TargetCleanup = Stop-OwnedProcess -ProcessValue $TargetProcess -Identity $TargetIdentity
    $TlsCleanup = Stop-OwnedProcess -ProcessValue $TlsProcess -Identity $TlsIdentity
    $OwnedCleanup = $PreviewCleanup -and $TargetCleanup -and $TlsCleanup
    foreach ($OwnedProcess in $Started) {
        $OwnedCleanup = (Stop-OwnedProcess -ProcessValue $OwnedProcess.Process `
            -Identity $OwnedProcess) -and $OwnedCleanup
    }
    if (Test-Path -LiteralPath $PreviewConfig) {
        Remove-Item -LiteralPath $PreviewConfig -Force -ErrorAction Stop
    }
    $PreviewConfigRemoved = -not (Test-Path -LiteralPath $PreviewConfig)
    foreach ($Result in $Results) {
        $Result['cleanup']['previewConfigRemoved'] = [bool]$PreviewConfigRemoved
        $Result['cleanup']['previewIdentityVerified'] = [bool]$PreviewCleanup
        $Result['cleanup']['targetIdentityVerified'] = [bool]$TargetCleanup
        $Result['cleanup']['tlsIdentityVerified'] = [bool]$TlsCleanup
        $Result['cleanup']['ownedProcessIdentityVerified'] = [bool]$OwnedCleanup
        $Result['previewDrainUri'] = $PreviewDrainUri
        $Result['previewDrainRequested'] = [bool]$PreviewDrainRequested
        $Result['previewDrainStatus'] = $PreviewDrainStatus
        $Result['previewDrainMessage'] = $PreviewDrainMessage
        $Result['previewExitCode'] = $PreviewExitCode
        $Result['previewNaturalExit'] = [bool]$PreviewNaturalExit
        $Result['previewConfigAudit'] = $PreviewConfigAudit
        $Result['previewConfigAuditSha256'] = $PreviewConfigAuditSha256
        $Result['ownedProcessIdentities'] = @($Started | ForEach-Object {
                [ordered]@{
                    role = $_.Role
                    pid = $_.Pid
                    path = $_.Path
                    startTime = $_.StartTime.ToString('o')
                }
            })
    }
}

$ResultJson = $Results | ConvertTo-Json -Depth 8
Write-Utf8NoBom (Join-Path $CaseDirectory 'results.json') $ResultJson
$ResultJson
if (@($Results | Where-Object {
        $_.exitCode -ne 0 -or $_.httpCode200Count -lt $_.concurrentRequests -or
        $_.literalBodyMatchCount -ne $_.concurrentRequests -or
        -not $_.serverLogObserved -or -not $_.previewNaturalExit -or
        $_.previewExitCode -ne 0 -or -not $_.cleanup.ownedProcessIdentityVerified
    }).Count -gt 0) {
    exit 1
}
