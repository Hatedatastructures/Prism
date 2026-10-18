[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$PrismTemplate,
    [Parameter(Mandatory = $true)][string]$MihomoTemplate,
    [string]$UdpEchoScript = '',
    [Parameter(Mandatory = $true)][string]$CaseDirectory,
    [Parameter(Mandatory = $true)][int]$PrismPort,
    [Parameter(Mandatory = $true)][int]$PrismUdpPort,
    [Parameter(Mandatory = $true)][int]$TargetPort,
    [Parameter(Mandatory = $true)][int]$ProxyPort,
    [switch]$UseUdpServerPort,
    [string]$ActiveProxy = '',
    [string]$MihomoExecutable = 'mihomo.exe',
    [string]$ServerAddress = '127.0.0.1',
    [int]$ControllerPort = 0,
    [int]$WarmupSeconds = 0,
    [int]$RepeatCount = 3
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'MihomoTestSupport.ps1')
if ([string]::IsNullOrWhiteSpace($UdpEchoScript)) {
    $UdpEchoScript = Join-Path $PSScriptRoot 'RunUdpEchoServer.ps1'
}

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

New-Item -ItemType Directory -Path $CaseDirectory -Force | Out-Null
$CaseDirectory = (Resolve-Path -LiteralPath $CaseDirectory).Path
$PrismExecutable = (Resolve-Path -LiteralPath 'build/src/Prism.exe').Path
$MihomoExecutable = Resolve-MihomoExecutable $MihomoExecutable
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
if (@($PrismObject.Listeners.Quic).Count -gt 0) {
    $PrismObject.Listeners.Quic[0].Address = $ServerAddress
    $PrismObject.Listeners.Quic[0].Port = $PrismUdpPort
}
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
$PrismOperationsPort = 0
if ($PrismObject.Operations.Enabled) {
    $PrismOperationsPort = Get-FreeLoopbackPort
    $PrismObject.Operations.Endpoint = "127.0.0.1:$PrismOperationsPort"
}
$ControllerPort = if ($ControllerPort -gt 0) { $ControllerPort } else { Get-FreeLoopbackPort }
$PrismConfig = Join-Path $CaseDirectory 'prism.json'
Write-Utf8NoBom $PrismConfig ($PrismObject | ConvertTo-Json -Depth 100)
$PrismConfigSha256 = Get-Sha256 $PrismConfig
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
$Started = [System.Collections.Generic.List[int]]::new()
$EchoProcess = $null
$PrismProcess = $null
$Results = [System.Collections.Generic.List[object]]::new()
try {
    $Pwsh = (Get-Command pwsh.exe -ErrorAction Stop).Source
    $EchoProcess = Start-Process -FilePath $Pwsh `
        -ArgumentList @('-NoProfile', '-File', (Resolve-Path -LiteralPath $UdpEchoScript).Path,
            '-Port', [string]$TargetPort) `
        -WorkingDirectory (Get-Location) -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput (Join-Path $CaseDirectory 'udp-echo.stdout.log') `
        -RedirectStandardError (Join-Path $CaseDirectory 'udp-echo.stderr.log') `
        -Environment $ChildEnvironment
    [void]$Started.Add($EchoProcess.Id)

    $PrismProcess = Start-Process -FilePath $PrismExecutable `
        -ArgumentList @($PrismConfig) `
        -WorkingDirectory (Get-Location) -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput (Join-Path $CaseDirectory 'prism.stdout.log') `
        -RedirectStandardError (Join-Path $CaseDirectory 'prism.stderr.log') `
        -Environment $ChildEnvironment
    [void]$Started.Add($PrismProcess.Id)

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
        if ($EchoProcess.HasExited) {
            throw "UDP echo exited with code $($EchoProcess.ExitCode) before UDP socket readiness"
        }
        $PrismUdpSocket = @(Get-NetUDPEndpoint -LocalPort $PrismUdpPort `
                -ErrorAction SilentlyContinue |
                Where-Object { $_.OwningProcess -eq $PrismProcess.Id })
        $EchoUdpSocket = @(Get-NetUDPEndpoint -LocalPort $TargetPort `
                -ErrorAction SilentlyContinue |
                Where-Object { $_.OwningProcess -eq $EchoProcess.Id })
        if ($PrismUdpSocket.Count -gt 0 -and $EchoUdpSocket.Count -gt 0) {
            $UdpSocketsReady = $true
            break
        }
        Start-Sleep -Milliseconds 250
    }
    if (-not $UdpSocketsReady) {
        throw "UDP socket readiness timeout prism=$PrismUdpPort echo=$TargetPort"
    }
    Start-Sleep -Seconds 2

    for ($Attempt = 1; $Attempt -le $RepeatCount; $Attempt++) {
        $AttemptResult = $null
        $MihomoProcess = $null
        $AttemptProxyPort = if ($Attempt -eq 1) { $ProxyPort } else { Get-FreeLoopbackPort }
        $AttemptHome = Join-Path $CaseDirectory ("mihomo-home-{0}" -f $Attempt)
        New-Item -ItemType Directory -Path $AttemptHome -Force | Out-Null
        $AttemptConfig = Join-Path $AttemptHome 'config.yaml'
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
        $AttemptConfigSha256 = Get-Sha256 $AttemptConfig
        $MihomoOut = Join-Path $CaseDirectory ("mihomo-{0}.stdout.log" -f $Attempt)
        $MihomoErr = Join-Path $CaseDirectory ("mihomo-{0}.stderr.log" -f $Attempt)
        $MihomoArguments = "-d `"$AttemptHome`" -f `"$AttemptConfig`""
        $MihomoProcess = Start-Process -FilePath $MihomoExecutable `
            -ArgumentList $MihomoArguments `
            -WorkingDirectory $AttemptHome -WindowStyle Hidden -PassThru `
            -RedirectStandardOutput $MihomoOut -RedirectStandardError $MihomoErr `
            -Environment $ChildEnvironment
        [void]$Started.Add($MihomoProcess.Id)
        try {
            $MihomoIdentity = Get-CimInstance Win32_Process `
                -Filter "ProcessId=$($MihomoProcess.Id)" -ErrorAction SilentlyContinue
            $CommandLine = if ($null -eq $MihomoIdentity) { '' } else { [string]$MihomoIdentity.CommandLine }
            if ($null -eq $MihomoIdentity -or
                $MihomoIdentity.ExecutablePath -ne $MihomoExecutable -or
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
            if ($WarmupSeconds -gt 0) {
                Start-Sleep -Seconds $WarmupSeconds
            }
            $Payload = "prism-udp-$Attempt"
            $StartedAt = Get-Date
            $Output = @(& pwsh -NoProfile -File (Join-Path $PSScriptRoot 'RunSocks5UdpClient.ps1') `
                -ProxyPort $AttemptProxyPort -TargetPort $TargetPort -PayloadText $Payload 2>&1)
            $ExitCode = $LASTEXITCODE
            $Output | Set-Content -LiteralPath (Join-Path $CaseDirectory ("udp-client-{0}.log" -f $Attempt)) -Encoding UTF8
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
                    prismExecutable = $PrismExecutable
                    prismSha256 = $PrismSha256
                    prismConfig = $PrismConfig
                    prismConfigSha256 = $PrismConfigSha256
                    mihomoExecutable = $MihomoExecutable
                    mihomoSha256 = $MihomoSha256
                    targetAddress = $ServerAddress
                    controllerPort = $ControllerPort
                    prismOperationsPort = $PrismOperationsPort
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
    [void](Stop-OwnedProcess $PrismProcess)
    [void](Stop-OwnedProcess $EchoProcess)
    foreach ($ProcessId in ($Started | Select-Object -Unique)) {
        if (Get-Process -Id $ProcessId -ErrorAction SilentlyContinue) {
            Stop-Process -Id $ProcessId -Force -ErrorAction SilentlyContinue
        }
    }
    if (Test-Path -LiteralPath $PrismConfig) {
        Remove-Item -LiteralPath $PrismConfig -Force -ErrorAction Stop
    }
    $PrismConfigRemoved = -not (Test-Path -LiteralPath $PrismConfig)
    foreach ($Result in $Results) {
        $Result['cleanup']['prismConfigRemoved'] = [bool]$PrismConfigRemoved
    }
}

$ResultJson = $Results | ConvertTo-Json -Depth 8
Write-Utf8NoBom (Join-Path $CaseDirectory 'results.json') $ResultJson
$ResultJson
if (@($Results | Where-Object {
        $_.exitCode -ne 0 -or $_.output -notmatch 'UDP_ECHO_OK='
    }).Count -gt 0) {
    exit 1
}
