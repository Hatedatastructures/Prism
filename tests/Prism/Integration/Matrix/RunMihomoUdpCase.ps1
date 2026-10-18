[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$PrismTemplate,
    [Parameter(Mandatory = $true)][string]$MihomoTemplate,
    [Parameter(Mandatory = $true)][string]$ProviderEchoScript,
    [Parameter(Mandatory = $true)][string]$CaseDirectory,
    [Parameter(Mandatory = $true)][int]$PrismPort,
    [Parameter(Mandatory = $true)][int]$PrismUdpPort,
    [Parameter(Mandatory = $true)][int]$ProxyPort,
    [switch]$UseUdpServerPort,
    [string]$ActiveProxy = '',
    [string]$MihomoExecutable = 'mihomo.exe',
    [string]$ServerAddress = '127.0.0.1',
    [int]$ControllerPort = 0,
    [string]$UdpClientScript = '',
    [int]$RepeatCount = 3
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'MihomoTestSupport.ps1')
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
    catch { return '' }
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
    if ($null -eq $Current) { return $true }
    try {
        return [string]::Equals(
                (Get-ProcessImagePath $Identity.Pid), $Identity.Path,
                [System.StringComparison]::OrdinalIgnoreCase) -and
            $Current.StartTime.ToUniversalTime().Ticks -eq $Identity.StartTime.Ticks
    }
    catch { return $false }
}

function Stop-OwnedProcess {
    param([AllowNull()][pscustomobject]$Identity)

    if ($null -eq $Identity) { return $true }
    $Current = Get-Process -Id $Identity.Pid -ErrorAction SilentlyContinue
    if ($null -eq $Current) { return $true }
    try { if ($Current.HasExited) { return $true } } catch { return $false }
    if (-not (Test-OwnedProcessIdentity $Identity)) {
        Write-Warning "Refusing cleanup for $($Identity.Role) PID $($Identity.Pid): identity mismatch"
        return $false
    }
    try {
        $Current.Kill()
        return $Current.WaitForExit(5000)
    }
    catch { return $false }
}

function Get-Sha256 {
    param([Parameter(Mandatory = $true)][string]$Path)

    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToUpperInvariant()
}

function Get-BytesSha256 {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)

    $Hash = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([System.BitConverter]::ToString($Hash.ComputeHash($Bytes)) -replace '-', '').ToUpperInvariant()
    }
    finally { $Hash.Dispose() }
}

function ConvertTo-LowerHex {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)

    return (($Bytes | ForEach-Object { $_.ToString('x2') }) -join '')
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

function Get-ProviderRecords {
    param([Parameter(Mandatory = $true)][int]$ControlPort)

    try {
        return @(Invoke-RestMethod -Method Get `
            -Uri "http://127.0.0.1:$ControlPort/" -TimeoutSec 2)
    }
    catch {
        return @()
    }
}

New-Item -ItemType Directory -Path $CaseDirectory -Force | Out-Null
$CaseDirectory = (Resolve-Path -LiteralPath $CaseDirectory).Path
$PrismExecutable = (Resolve-Path -LiteralPath 'build/src/Prism.exe').Path
$MihomoExecutable = Resolve-MihomoExecutable $MihomoExecutable
if ([string]::IsNullOrWhiteSpace($UdpClientScript)) {
    $UdpClientScript = Join-Path $PSScriptRoot 'RunSocks5UdpClient.ps1'
}
if ([string]::IsNullOrWhiteSpace($UdpClientScript)) {
    $UdpClientScript = Join-Path $PSScriptRoot 'RunSocks5UdpClient.ps1'
}
$PrismSha256 = Get-Sha256 $PrismExecutable
$MihomoSha256 = Get-Sha256 $MihomoExecutable
$PrismTemplatePath = (Resolve-Path -LiteralPath $PrismTemplate).Path
$PrismTemplateDirectory = Split-Path -Parent $PrismTemplatePath
$PrismObject = Get-Content -LiteralPath $PrismTemplatePath -Raw | ConvertFrom-Json
$OldPrismPort = [int]$PrismObject.Listeners.Tcp[0].Port
$PrismObject.Listeners.Tcp[0].Address = $ServerAddress
$PrismObject.Listeners.Tcp[0].Port = $PrismPort
$PrismObject.Listeners.Udp[0].Address = $ServerAddress
$PrismObject.Listeners.Udp[0].Port = $PrismUdpPort
# raw UDP 用例不需要 QUIC listener；从派生配置移除未使用绑定，避免占用无关端口。
$PrismObject.Listeners.Quic = @()
$PrismObject.Protocols = @($PrismObject.Protocols |
    Where-Object { $_.Builtin -ne 'hysteria2' -and $_.Builtin -ne 'tuic' })
$PrismObject.ProtocolBindings = @($PrismObject.ProtocolBindings |
    Where-Object { $_.ProtocolId -ne 'protocol-hysteria2' -and $_.ProtocolId -ne 'protocol-tuic' })
$PrismObject.NativeTls.CertificateFile = Resolve-TemplateRelativePath `
    $PrismObject.NativeTls.CertificateFile $PrismTemplateDirectory
$PrismObject.NativeTls.PrivateKeyFile = Resolve-TemplateRelativePath `
    $PrismObject.NativeTls.PrivateKeyFile $PrismTemplateDirectory
foreach ($Carrier in @($PrismObject.Carriers)) {
    $Options = $Carrier.Options
    if ($null -eq $Options) {
        continue
    }
    foreach ($PropertyName in @('CertificateFile', 'PrivateKeyFile')) {
        if ($Options.PSObject.Properties.Name -contains $PropertyName) {
            $Options.$PropertyName = Resolve-TemplateRelativePath `
                $Options.$PropertyName $PrismTemplateDirectory
        }
    }
}
$PrismLogRoot = Join-Path $CaseDirectory 'prism-logs'
New-Item -ItemType Directory -Path $PrismLogRoot -Force | Out-Null
$PrismObject.Logging.Directory = $PrismLogRoot.Replace('\', '/')
$PrismOperationsPort = Get-FreeLoopbackPort
$PrismObject.Operations.Enabled = $true
$PrismObject.Operations.Endpoint = "127.0.0.1:$PrismOperationsPort"
$PrismDrainUri = "http://127.0.0.1:$PrismOperationsPort/Operations/Drain?worker=0&stop_accepting=true&force=false"
$ControllerPort = if ($ControllerPort -gt 0) { $ControllerPort } else { Get-FreeLoopbackPort }
$PrismConfig = Join-Path $CaseDirectory 'prism.json'
$PrismConfigAudit = Join-Path $CaseDirectory 'prism-config.audit.json'
Write-Utf8NoBom $PrismConfig ($PrismObject | ConvertTo-Json -Depth 100)
Copy-Item -LiteralPath $PrismConfig -Destination $PrismConfigAudit -Force
$PrismConfigSha256 = Get-Sha256 $PrismConfig
$PrismConfigAuditSha256 = Get-Sha256 $PrismConfigAudit
$ReplacementPrismPort = if ($UseUdpServerPort) { $PrismUdpPort } else { $PrismPort }

$Yaml = Get-Content -LiteralPath $MihomoTemplate -Raw
$Yaml = [regex]::Replace($Yaml, '(?m)^\s*server:\s+.*$', "    server: $ServerAddress")
$Yaml = [regex]::Replace($Yaml, '(?m)^external-controller:\s+.*$', "external-controller: 127.0.0.1:$ControllerPort")
$Yaml = [regex]::Replace($Yaml, '(?m)^bind-address:\s+.*$', 'bind-address: 127.0.0.1')
$Yaml = [regex]::Replace($Yaml, '(?m)^allow-lan:\s+.*$', 'allow-lan: false')
$Yaml = [regex]::Replace($Yaml, '(?m)^(mixed-port|socks-port):\s+\d+\s*$', {
        param($Match)
        "{0}: {1}" -f $Match.Groups[1].Value, $ProxyPort
    })
$ProxyPorts = @([regex]::Matches($Yaml, '(?m)^\s+port:\s+(\d+)\s*$') |
    ForEach-Object { [int]$_.Groups[1].Value })
if ($ProxyPorts.Count -eq 0) {
    throw 'Mihomo template has no proxy port field'
}
$MihomoPrismPorts = @($ProxyPorts | Where-Object { $_ -eq $OldPrismPort } | Select-Object -Unique)
if ($MihomoPrismPorts.Count -eq 0 -and @($ProxyPorts | Select-Object -Unique).Count -eq 1) {
    $MihomoPrismPorts = @($ProxyPorts | Select-Object -Unique)
}
if ($MihomoPrismPorts.Count -ne 1) {
    throw "Mihomo template preview port is ambiguous: $($ProxyPorts -join ',')"
}
$Yaml = [regex]::Replace(
    $Yaml,
    "(?m)^(\s+port:)\s+$($MihomoPrismPorts[0])\s*$",
    ('$1 ' + $ReplacementPrismPort))
$Yaml = [regex]::Replace(
    $Yaml,
    '(?m)^\s*-\s*IP-CIDR,127\.0\.0\.0/8,DIRECT\s*\r?\n',
    '')
$Yaml = [regex]::Replace(
    $Yaml,
    '(?ms)(- name:\s+"PrismPreview-Xiaomi-Health"\s*\r?\n\s+type:\s+)url-test',
    '${1}select')
if (-not [string]::IsNullOrWhiteSpace($ActiveProxy)) {
    $Yaml = [regex]::Replace(
        $Yaml,
        '(?m)^(\s*-\s*MATCH,)PrismPreview-Active\s*$',
        ('$1' + $ActiveProxy))
    if ($Yaml -notmatch [regex]::Escape($ActiveProxy)) {
        throw "ActiveProxy was not found in Mihomo template: $ActiveProxy"
    }
}

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

$HasSocksPort = $Yaml -match '(?m)^socks-port:\s+\d+\s*$'
$Started = [System.Collections.Generic.List[object]]::new()
$ProviderProcess = $null
$ProviderIdentity = $null
$PrismProcess = $null
$PrismIdentity = $null
$Results = [System.Collections.Generic.List[object]]::new()
$PrismDrainRequested = $false
$PrismDrainStatus = ''
$PrismDrainMessage = ''
$PrismNaturalExit = $false
$PrismExitCode = $null
$ProviderControlPort = 0
$ActualTargetPort = 0
try {
    $Node = (Get-Command node.exe -ErrorAction Stop).Source
    $ProviderProcess = Start-Process -FilePath $Node `
        -ArgumentList @((Resolve-Path -LiteralPath $ProviderEchoScript).Path) `
        -WorkingDirectory (Get-Location) -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput (Join-Path $CaseDirectory 'provider-echo.stdout.log') `
        -RedirectStandardError (Join-Path $CaseDirectory 'provider-echo.stderr.log') `
        -Environment $ChildEnvironment
    $ProviderIdentity = New-OwnedProcessIdentity $ProviderProcess $Node 'provider-echo'
    [void]$Started.Add($ProviderIdentity)
    $ProviderReady = $null
    for ($Index = 0; $Index -lt 40; $Index++) {
        Start-Sleep -Milliseconds 250
        if ($ProviderProcess.HasExited) {
            throw "ProviderEcho exited with code $($ProviderProcess.ExitCode)"
        }
        if (Test-Path -LiteralPath (Join-Path $CaseDirectory 'provider-echo.stdout.log')) {
            foreach ($Line in @(Get-Content -LiteralPath (Join-Path $CaseDirectory 'provider-echo.stdout.log'))) {
                try {
                    $Candidate = $Line | ConvertFrom-Json
                    if ($Candidate.udp -and $Candidate.control) {
                        $ProviderReady = $Candidate
                        break
                    }
                }
                catch { }
            }
        }
        if ($null -ne $ProviderReady) { break }
    }
    if ($null -eq $ProviderReady) { throw 'ProviderEcho readiness timeout' }
    $ActualTargetPort = [int]$ProviderReady.udp
    $ProviderControlPort = [int]$ProviderReady.control

    $PrismProcess = Start-Process -FilePath $PrismExecutable `
        -ArgumentList @($PrismConfig) `
        -WorkingDirectory (Get-Location) -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput (Join-Path $CaseDirectory 'prism.stdout.log') `
        -RedirectStandardError (Join-Path $CaseDirectory 'prism.stderr.log') `
        -Environment $ChildEnvironment
    $PrismIdentity = New-OwnedProcessIdentity $PrismProcess $PrismExecutable 'prism'
    [void]$Started.Add($PrismIdentity)

    $PrismReady = $false
    for ($Index = 0; $Index -lt 40; $Index++) {
        Start-Sleep -Milliseconds 250
        if ($PrismProcess.HasExited) {
            throw "Prism exited with code $($PrismProcess.ExitCode)"
        }
        $ReadyLog = Join-Path $CaseDirectory 'prism.stdout.log'
        if ((Test-Path -LiteralPath $ReadyLog) -and
            (Get-Content -LiteralPath $ReadyLog -Raw) -match "Prism READY tcp_port=$PrismPort udp_port=$PrismUdpPort") {
            $PrismReady = $true
            break
        }
    }
    if (-not $PrismReady) {
        throw 'Prism UDP readiness timeout'
    }
    $UdpSocketsReady = $false
    for ($Index = 0; $Index -lt 40; $Index++) {
        if ($PrismProcess.HasExited) {
            throw "Prism exited with code $($PrismProcess.ExitCode) before UDP socket readiness"
        }
        if ($ProviderProcess.HasExited) {
            throw "ProviderEcho exited with code $($ProviderProcess.ExitCode) before UDP socket readiness"
        }
        $PrismUdpSocket = @(Get-NetUDPEndpoint -LocalPort $PrismUdpPort `
                -ErrorAction SilentlyContinue |
                Where-Object { $_.OwningProcess -eq $PrismProcess.Id })
        $EchoUdpSocket = @(Get-NetUDPEndpoint -LocalPort $ActualTargetPort `
                -ErrorAction SilentlyContinue |
                Where-Object { $_.OwningProcess -eq $ProviderProcess.Id })
        if ($PrismUdpSocket.Count -gt 0 -and $EchoUdpSocket.Count -gt 0) {
            $UdpSocketsReady = $true
            break
        }
        Start-Sleep -Milliseconds 250
    }
    if (-not $UdpSocketsReady) {
        throw "UDP socket readiness timeout prism=$PrismUdpPort echo=$ActualTargetPort"
    }
    $OperationsReady = $false
    for ($Index = 0; $Index -lt 40; $Index++) {
        Start-Sleep -Milliseconds 250
        if ($PrismProcess.HasExited) {
            throw "Prism exited before Operations readiness: $($PrismProcess.ExitCode)"
        }
        try {
            $Health = Invoke-RestMethod -Method Get `
                -Uri "http://127.0.0.1:$PrismOperationsPort/Operations/Health" -TimeoutSec 2
            if ($Health.value.ready) { $OperationsReady = $true; break }
        }
        catch { }
    }
    if (-not $OperationsReady) { throw 'Prism Operations readiness timeout' }

    for ($Attempt = 1; $Attempt -le $RepeatCount; $Attempt++) {
        $AttemptResult = $null
        $MihomoProcess = $null
        $MihomoIdentity = $null
        $AttemptProxyPort = if ($Attempt -eq 1) { $ProxyPort } else { Get-FreeLoopbackPort }
        $AttemptHome = Join-Path $CaseDirectory ("mihomo-home-{0}" -f $Attempt)
        New-Item -ItemType Directory -Path $AttemptHome -Force | Out-Null
        $AttemptConfig = Join-Path $AttemptHome 'config.yaml'
        $AttemptConfigAudit = Join-Path $CaseDirectory ("mihomo-{0}.config.yaml" -f $Attempt)
        $ProviderRecordPath = Join-Path $CaseDirectory ("provider-records-{0}.json" -f $Attempt)
        $AttemptMixedPort = if ($HasSocksPort) { Get-FreeLoopbackPort } else { $AttemptProxyPort }
        $AttemptYaml = [regex]::Replace(
            $Yaml,
            '(?m)^(mixed-port|socks-port):\s+\d+\s*$',
            {
                param($Match)
                $Port = if ($Match.Groups[1].Value -eq 'mixed-port') {
                    $AttemptMixedPort
                }
                else {
                    $AttemptProxyPort
                }
                "{0}: {1}" -f $Match.Groups[1].Value, $Port
        })
        Write-Utf8NoBom $AttemptConfig $AttemptYaml
        Copy-Item -LiteralPath $AttemptConfig -Destination $AttemptConfigAudit -Force
        $AttemptConfigSha256 = Get-Sha256 $AttemptConfig
        $AttemptConfigAuditSha256 = Get-Sha256 $AttemptConfigAudit
        $MihomoOut = Join-Path $CaseDirectory ("mihomo-{0}.stdout.log" -f $Attempt)
        $MihomoErr = Join-Path $CaseDirectory ("mihomo-{0}.stderr.log" -f $Attempt)
        $MihomoArguments = "-d `"$AttemptHome`" -f `"$AttemptConfig`""
        $MihomoProcess = Start-Process -FilePath $MihomoExecutable `
            -ArgumentList $MihomoArguments `
            -WorkingDirectory $AttemptHome -WindowStyle Hidden -PassThru `
            -RedirectStandardOutput $MihomoOut -RedirectStandardError $MihomoErr `
            -Environment $ChildEnvironment
        $MihomoIdentity = New-OwnedProcessIdentity $MihomoProcess $MihomoExecutable "mihomo-$Attempt"
        [void]$Started.Add($MihomoIdentity)
        try {
            $MihomoCommandIdentity = Get-CimInstance Win32_Process `
                -Filter "ProcessId=$($MihomoProcess.Id)" -ErrorAction SilentlyContinue
            $CommandLine = if ($null -eq $MihomoCommandIdentity) { '' } else { [string]$MihomoCommandIdentity.CommandLine }
            if ($null -eq $MihomoCommandIdentity -or
                -not (Test-OwnedProcessIdentity $MihomoIdentity) -or
                $CommandLine.IndexOf($AttemptConfig, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
                throw "Mihomo PID $($MihomoProcess.Id) did not receive the isolated config path"
            }
            $ProxyReady = $false
            for ($Index = 0; $Index -lt 40; $Index++) {
                Start-Sleep -Milliseconds 250
                if ($MihomoProcess.HasExited) {
                    throw "Mihomo exited with code $($MihomoProcess.ExitCode)"
                }
                $Listeners = @(Get-NetTCPConnection -State Listen -LocalPort $AttemptProxyPort `
                    -ErrorAction SilentlyContinue)
                if (@($Listeners | Where-Object { $_.OwningProcess -eq $MihomoProcess.Id }).Count -gt 0) {
                    $ProxyReady = $true
                    break
                }
            }
            if (-not $ProxyReady) {
                throw 'Mihomo readiness timeout'
            }
            $Payload = "prism-udp-$Attempt"
            $PayloadBytes = [System.Text.Encoding]::UTF8.GetBytes($Payload)
            $PayloadHex = ConvertTo-LowerHex $PayloadBytes
            $PayloadSha256 = Get-BytesSha256 $PayloadBytes
            $StartedAt = Get-Date
            $Output = @(& pwsh -NoProfile -File (Resolve-Path -LiteralPath $UdpClientScript).Path `
                -ProxyPort $AttemptProxyPort -TargetPort $ActualTargetPort -PayloadText $Payload 2>&1)
            $ExitCode = $LASTEXITCODE
            $Output | Set-Content -LiteralPath (Join-Path $CaseDirectory ("udp-client-{0}.log" -f $Attempt)) -Encoding UTF8
            $MihomoExited = Stop-OwnedProcess $MihomoIdentity
            $ProviderRecords = @(Get-ProviderRecords $ProviderControlPort)
            $ProviderRecordPath = Join-Path $CaseDirectory ("provider-records-{0}.json" -f $Attempt)
            Write-Utf8NoBom $ProviderRecordPath ($ProviderRecords | ConvertTo-Json -Depth 8)
            $ProviderRecordSha256 = Get-Sha256 $ProviderRecordPath
            $MatchingRecords = @($ProviderRecords | Where-Object {
                    $_.type -eq 'udp' -and [int]$_.bytes -eq $PayloadBytes.Length -and
                    [string]$_.hex -ceq $PayloadHex
                })
            if ($ExitCode -ne 0 -or $Output -notmatch 'UDP_ECHO_OK=' -or
                $MatchingRecords.Count -lt 1) {
                throw "UDP evidence failed: exit=$ExitCode records=$($MatchingRecords.Count)"
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
                    payload = $Payload
                    payloadBytes = $PayloadBytes.Length
                    payloadHex = $PayloadHex
                    payloadSha256 = $PayloadSha256
                    providerControlPort = $ProviderControlPort
                    providerUdpPort = $ActualTargetPort
                    providerRecordCount = $ProviderRecords.Count
                    providerMatchingRecordCount = $MatchingRecords.Count
                    providerRecordPath = $ProviderRecordPath
                    providerRecordSha256 = $ProviderRecordSha256
                    prismExecutable = $PrismExecutable
                    prismSha256 = $PrismSha256
                    prismConfig = $PrismConfig
                    prismConfigSha256 = $PrismConfigSha256
                    mihomoExecutable = $MihomoExecutable
                    mihomoSha256 = $MihomoSha256
                    prismConfigAudit = $PrismConfigAudit
                    prismConfigAuditSha256 = $PrismConfigAuditSha256
                    targetAddress = $ServerAddress
                    controllerPort = $ControllerPort
                    prismOperationsPort = $PrismOperationsPort
                }
        }
        finally {
            $MihomoExited = Stop-OwnedProcess $MihomoIdentity
            $HomeRemoved = Remove-TemporaryDirectory $AttemptHome
            $ConfigRemoved = -not (Test-Path -LiteralPath $AttemptConfig)
            if ($null -eq $AttemptResult) {
                $AttemptResult = [ordered]@{
                    attempt = $Attempt
                    proxyPort = $AttemptProxyPort
                    mihomoPid = $MihomoProcess.Id
                    configPath = $AttemptConfig
                    configSha256 = $AttemptConfigSha256
                    configAuditPath = $AttemptConfigAudit
                    configAuditSha256 = $AttemptConfigAuditSha256
                    prismExecutable = $PrismExecutable
                    prismSha256 = $PrismSha256
                    prismConfig = $PrismConfig
                    prismConfigSha256 = $PrismConfigSha256
                    mihomoExecutable = $MihomoExecutable
                    mihomoSha256 = $MihomoSha256
                    targetAddress = $ServerAddress
                    controllerPort = $ControllerPort
                    prismOperationsPort = $PrismOperationsPort
                    exitCode = 1
                    elapsedSeconds = 0
                    output = ''
                    payload = ''
                    payloadBytes = 0
                    payloadHex = ''
                    payloadSha256 = ''
                    providerControlPort = $ProviderControlPort
                    providerUdpPort = $ActualTargetPort
                    providerRecordCount = 0
                    providerMatchingRecordCount = 0
                    providerRecordPath = $ProviderRecordPath
                    providerRecordSha256 = if (Test-Path $ProviderRecordPath) {
                        Get-Sha256 $ProviderRecordPath
                    } else { '' }
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
    $Headers = Get-OperationsCommandHeaders -Port $PrismOperationsPort
    $DrainResponse = Invoke-RestMethod -Method Post -Uri $PrismDrainUri -Headers $Headers -TimeoutSec 5
    $PrismDrainRequested = $true
    $PrismDrainStatus = [string]$DrainResponse.status
    $PrismDrainMessage = [string]$DrainResponse.message
    if ($PrismDrainStatus -ne 'accepted' -and $PrismDrainStatus -ne 'completed') {
        throw "Operations drain returned status $PrismDrainStatus"
    }
    if (-not $PrismProcess.WaitForExit(45000)) {
        throw 'Prism did not exit naturally after Operations drain'
    }
    $PrismProcess.Refresh()
    $PrismExitCode = [int]$PrismProcess.ExitCode
    $PrismNaturalExit = $PrismExitCode -eq 0
    if (-not $PrismNaturalExit) {
        throw "Prism exited after Operations drain with code $PrismExitCode"
    }
}
finally {
    $PrismCleanup = Stop-OwnedProcess $PrismIdentity
    $ProviderStopRequested = $false
    try {
        if ($null -ne $ProviderControlPort) {
            Invoke-RestMethod -Method Get `
                -Uri "http://127.0.0.1:$ProviderControlPort/stop" -TimeoutSec 2 | Out-Null
            $ProviderStopRequested = $true
        }
    }
    catch { }
    $ProviderCleanup = Stop-OwnedProcess $ProviderIdentity
    $OwnedCleanup = $PrismCleanup -and $ProviderCleanup
    foreach ($Identity in $Started) {
        $OwnedCleanup = (Stop-OwnedProcess $Identity) -and $OwnedCleanup
    }
    if (Test-Path -LiteralPath $PrismConfig) {
        Remove-Item -LiteralPath $PrismConfig -Force -ErrorAction Stop
    }
    $PrismConfigRemoved = -not (Test-Path -LiteralPath $PrismConfig)
    foreach ($Result in $Results) {
        $Result['prismDrainUri'] = $PrismDrainUri
        $Result['prismDrainRequested'] = [bool]$PrismDrainRequested
        $Result['prismDrainStatus'] = $PrismDrainStatus
        $Result['prismDrainMessage'] = $PrismDrainMessage
        $Result['prismNaturalExit'] = [bool]$PrismNaturalExit
        $Result['prismExitCode'] = $PrismExitCode
        $Result['providerStopRequested'] = [bool]$ProviderStopRequested
        $Result['prismConfigAudit'] = $PrismConfigAudit
        $Result['prismConfigAuditSha256'] = $PrismConfigAuditSha256
        $Result['ownedProcessIdentities'] = @($Started | ForEach-Object {
                [ordered]@{ role = $_.Role; pid = $_.Pid; path = $_.Path
                    startTime = $_.StartTime.ToString('o') }
            })
        $Result['cleanup']['prismConfigRemoved'] = [bool]$PrismConfigRemoved
        $Result['cleanup']['prismIdentityVerified'] = [bool]$PrismCleanup
        $Result['cleanup']['providerIdentityVerified'] = [bool]$ProviderCleanup
        $Result['cleanup']['ownedProcessIdentityVerified'] = [bool]$OwnedCleanup
    }
}

$ResultJson = $Results | ConvertTo-Json -Depth 12
Write-Utf8NoBom (Join-Path $CaseDirectory 'results.json') $ResultJson
$ResultJson
if ($Results.Count -ne $RepeatCount -or @($Results | Where-Object {
        $_.exitCode -ne 0 -or $_.output -notmatch 'UDP_ECHO_OK=' -or
        [int]$_.providerMatchingRecordCount -lt 1 -or
        -not $_.prismNaturalExit -or $_.prismExitCode -ne 0 -or
        -not $_.cleanup.ownedProcessIdentityVerified
    }).Count -gt 0) {
    exit 1
}
