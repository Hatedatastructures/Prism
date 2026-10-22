[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$PrismTemplate,
    [Parameter(Mandatory = $true)][string]$MihomoTemplate,
    [Parameter(Mandatory = $true)][string]$CaseDirectory,
    [ValidatePattern('^127\.0\.0\.1$|^::1$')][string]$ServerAddress = '127.0.0.1',
    [string]$MihomoExecutable = 'mihomo.exe'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'MihomoTestSupport.ps1')

function Write-Utf8NoBom {
    param([string]$Path, [string]$Content)
    [System.IO.File]::WriteAllText($Path, $Content, (New-Object System.Text.UTF8Encoding($false)))
}

function Get-FreePort {
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

function Get-Sha256 {
    param([string]$Path)
    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToUpperInvariant()
}

function Remove-TemporaryDirectory {
    param([string]$Path)
    for ($Attempt = 0; $Attempt -lt 30; $Attempt++) {
        if (-not (Test-Path -LiteralPath $Path)) { return $true }
        try {
            Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
            return -not (Test-Path -LiteralPath $Path)
        }
        catch { Start-Sleep -Milliseconds 250 }
    }
    return -not (Test-Path -LiteralPath $Path)
}

if (-not (Test-Path -LiteralPath $CaseDirectory)) {
    New-Item -ItemType Directory -Force -Path $CaseDirectory | Out-Null
}
$CaseDirectory = (Resolve-Path -LiteralPath $CaseDirectory).Path
$PrismTemplatePath = (Resolve-Path -LiteralPath $PrismTemplate).Path
$PrismTemplateDirectory = Split-Path -Parent $PrismTemplatePath
$MihomoExecutablePath = Resolve-MihomoExecutable $MihomoExecutable
$PrismExecutablePath = (Resolve-Path -LiteralPath 'build/src/Prism.exe').Path
$FileServerPath = (Resolve-Path -LiteralPath 'build/Test/Prism/Integration/PrismMatrixFileServer.exe').Path
$PrismLogRoot = Join-Path $CaseDirectory 'prism-logs'
$TargetRoot = Join-Path $CaseDirectory 'target-root'
New-Item -ItemType Directory -Force -Path $PrismLogRoot, $TargetRoot | Out-Null
Write-Utf8NoBom (Join-Path $TargetRoot 'hello.txt') 'prism-current-mixed-response'

$PrismPort = Get-FreePort
$TargetPort = Get-FreePort
$OperationsPort = Get-FreePort
if ($OperationsPort -in @($PrismPort, $TargetPort)) {
    throw 'Mixed case ports must be distinct'
}
$PrismObject = Get-Content -LiteralPath $PrismTemplatePath -Raw | ConvertFrom-Json
$PrismObject.Listeners.Tcp[0].Address = $ServerAddress
$PrismObject.Listeners.Tcp[0].Port = $PrismPort
$PrismObject.Listeners.Udp[0].Address = $ServerAddress
$PrismObject.Listeners.Udp[0].Port = $PrismPort
$PrismObject.Listeners.Quic[0].Address = $ServerAddress
$PrismObject.Listeners.Quic[0].Port = $PrismPort
$PrismObject.NativeTls.CertificateFile = [System.IO.Path]::GetFullPath(
    (Join-Path $PrismTemplateDirectory $PrismObject.NativeTls.CertificateFile))
$PrismObject.NativeTls.PrivateKeyFile = [System.IO.Path]::GetFullPath(
    (Join-Path $PrismTemplateDirectory $PrismObject.NativeTls.PrivateKeyFile))
foreach ($Carrier in @($PrismObject.Carriers)) {
    foreach ($PropertyName in @('CertificateFile', 'PrivateKeyFile')) {
        if ($Carrier.Options.PSObject.Properties.Name -contains $PropertyName) {
            $Carrier.Options.$PropertyName = [System.IO.Path]::GetFullPath(
                (Join-Path $PrismTemplateDirectory $Carrier.Options.$PropertyName))
        }
    }
}
$PrismObject.Logging.Directory = $PrismLogRoot.Replace('\', '/')
$PrismObject.Logging.FileName = 'prism-mixed.log'
$PrismObject.Operations.Endpoint = "127.0.0.1:$OperationsPort"
$PrismConfig = Join-Path $CaseDirectory 'prism.json'
Write-Utf8NoBom $PrismConfig ($PrismObject | ConvertTo-Json -Depth 100)

$ChildEnvironment = @{}
Get-ChildItem Env: | ForEach-Object { $ChildEnvironment[$_.Name] = $_.Value }
foreach ($Name in @('NO_PROXY', 'no_proxy', 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY',
                    'http_proxy', 'https_proxy', 'all_proxy')) {
    $ChildEnvironment[$Name] = ''
}

$Cases = @(
    @{Name = 'Http'; Protocol = 'http'; Slug = 'http'},
    @{Name = 'SOCKS5 TCP Cert'; Protocol = 'socks5'; Slug = 'socks5'},
    @{Name = 'VLESS TCP'; Protocol = 'vless'; Slug = 'vless'},
    @{Name = 'Trojan Native TLS TCP'; Protocol = 'trojan'; Slug = 'trojan-native'},
    @{Name = 'VMess TCP'; Protocol = 'vmess'; Slug = 'vmess'},
    @{Name = 'SS2022 TCP'; Protocol = 'shadowsocks'; Slug = 'ss2022'},
    @{Name = 'VLESS Smux TCP'; Protocol = 'vless'; Slug = 'vless-smux'},
    @{Name = 'VLESS Yamux TCP'; Protocol = 'vless'; Slug = 'vless-yamux'},
    @{Name = 'VLESS H2Mux TCP'; Protocol = 'vless'; Slug = 'vless-h2mux'},
    @{Name = 'Trojan Smux TCP'; Protocol = 'trojan'; Slug = 'trojan-smux'},
    @{Name = 'VMess Yamux TCP'; Protocol = 'vmess'; Slug = 'vmess-yamux'},
    @{Name = 'AnyTLS TCP'; Protocol = 'anytls'; Slug = 'anytls'},
    @{Name = 'Hysteria2 QUIC'; Protocol = 'hysteria2'; Slug = 'hysteria2'}
)
$Started = [System.Collections.Generic.List[int]]::new()
$CurlProcesses = [System.Collections.Generic.List[object]]::new()
$Results = [System.Collections.Generic.List[object]]::new()
$PrismProcess = $null
$TargetProcess = $null

try {
    $TargetProcess = Start-Process -FilePath $FileServerPath -ArgumentList @($TargetRoot, $TargetPort, '1') -WorkingDirectory (Get-Location) -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $CaseDirectory 'target.stdout.log') -RedirectStandardError (Join-Path $CaseDirectory 'target.stderr.log') -Environment $ChildEnvironment
    [void]$Started.Add($TargetProcess.Id)
    $PrismProcess = Start-Process -FilePath $PrismExecutablePath -ArgumentList @((Resolve-Path $PrismConfig).Path) -WorkingDirectory (Get-Location) -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $CaseDirectory 'prism.stdout.log') -RedirectStandardError (Join-Path $CaseDirectory 'prism.stderr.log') -Environment $ChildEnvironment
    [void]$Started.Add($PrismProcess.Id)
    $Ready = $false
    for ($Index = 0; $Index -lt 60; $Index++) {
        Start-Sleep -Milliseconds 250
        if ($PrismProcess.HasExited) { throw "Prism exited with code $($PrismProcess.ExitCode)" }
        $ReadyLog = Join-Path $CaseDirectory 'prism.stdout.log'
        if ((Test-Path -LiteralPath $ReadyLog) -and (Get-Content -LiteralPath $ReadyLog -Raw) -match 'Prism READY') {
            $Ready = $true
            break
        }
    }
    if (-not $Ready) { throw 'Prism readiness timeout' }

    $YamlTemplate = Get-Content -LiteralPath (Resolve-Path $MihomoTemplate) -Raw
    foreach ($Case in $Cases) {
        $CaseDir = Join-Path $CaseDirectory $Case.Slug
        New-Item -ItemType Directory -Force -Path $CaseDir | Out-Null
        $ProxyPort = Get-FreePort
        $SocksPort = Get-FreePort
        $ControllerPort = Get-FreePort
        $CasePorts = @($PrismPort, $TargetPort, $OperationsPort, $ProxyPort, $SocksPort, $ControllerPort)
        if (@($CasePorts | Select-Object -Unique).Count -ne $CasePorts.Count) {
            throw 'Mixed case ports must be distinct'
        }
        $Yaml = $YamlTemplate
        $Yaml = [regex]::Replace($Yaml, '(?m)^mixed-port:\s+\d+\s*$', "mixed-port: $ProxyPort")
        $Yaml = [regex]::Replace($Yaml, '(?m)^socks-port:\s+\d+\s*$', "socks-port: $SocksPort")
        $Yaml = [regex]::Replace($Yaml, '(?m)^external-controller:\s+.*$', "external-controller: 127.0.0.1:$ControllerPort")
        $Yaml = [regex]::Replace($Yaml, '(?m)^bind-address:\s+.*$', 'bind-address: 127.0.0.1')
        $Yaml = [regex]::Replace($Yaml, '(?m)^allow-lan:\s+.*$', 'allow-lan: false')
        $Yaml = [regex]::Replace($Yaml, '(?m)^\s*-\s*IP-CIDR,127\.0\.0\.0/8,DIRECT\s*\r?\n', '')
        $Yaml = [regex]::Replace($Yaml, '(?m)^\s*-\s*MATCH,PrismPreview-Active\s*$', "  - MATCH,$($Case.Name)")
        $Yaml = [regex]::Replace($Yaml, '(?m)^\s+server:\s+(?!socks5\.preview\s*$).*$', "    server: $ServerAddress")
        $Yaml = [regex]::Replace($Yaml, '(?m)^(\s+port:)\s+18080\s*$', ('$1 ' + $PrismPort))
        $MihomoHome = Join-Path $CaseDir 'mihomo-home'
        New-Item -ItemType Directory -Force -Path $MihomoHome | Out-Null
        $Config = Join-Path $MihomoHome 'config.yaml'
        Write-Utf8NoBom $Config $Yaml
        $Mihomo = Start-Process -FilePath $MihomoExecutablePath -ArgumentList @('-d', $MihomoHome, '-f', $Config) -WorkingDirectory $MihomoHome -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $CaseDir 'mihomo.stdout.log') -RedirectStandardError (Join-Path $CaseDir 'mihomo.stderr.log') -Environment $ChildEnvironment
        [void]$Started.Add($Mihomo.Id)
        $Case.MihomoPid = $Mihomo.Id
        $Case.ProxyPort = $ProxyPort
        $Case.ConfigSha = Get-Sha256 $Config
        $Case.MihomoSha = Get-Sha256 $MihomoExecutablePath
        $MihomoReady = $false
        for ($Index = 0; $Index -lt 60; $Index++) {
            Start-Sleep -Milliseconds 250
            if ($Mihomo.HasExited) { throw "$($Case.Name) Mihomo exited with code $($Mihomo.ExitCode)" }
            if (@(Get-NetTCPConnection -State Listen -LocalPort $ProxyPort -ErrorAction SilentlyContinue | Where-Object { $_.OwningProcess -eq $Mihomo.Id }).Count -gt 0) {
                $MihomoReady = $true
                break
            }
        }
        if (-not $MihomoReady) { throw "$($Case.Name) Mihomo readiness timeout" }
    }

    foreach ($Case in $Cases) {
        $CaseDir = Join-Path $CaseDirectory $Case.Slug
        $Body = Join-Path $CaseDir 'body.txt'
        $CurlOut = Join-Path $CaseDir 'curl.stdout.log'
        $CurlErr = Join-Path $CaseDir 'curl.stderr.log'
        $Curl = Start-Process -FilePath (Get-Command curl.exe).Source -ArgumentList @('--proxy', "http://127.0.0.1:$($Case.ProxyPort)", '--max-time', '30', '--silent', '--show-error', '--output', $Body, '--write-out', 'HTTP_CODE=%{http_code};TIME=%{time_total}', "http://127.0.0.1:$TargetPort/hello.txt") -WorkingDirectory (Get-Location) -WindowStyle Hidden -PassThru -RedirectStandardOutput $CurlOut -RedirectStandardError $CurlErr -Environment $ChildEnvironment
        [void]$Started.Add($Curl.Id)
        [void]$CurlProcesses.Add([pscustomobject]@{Case = $Case; Process = $Curl; Out = $CurlOut; Err = $CurlErr; Body = $Body})
    }
    foreach ($Entry in $CurlProcesses) {
        if (Get-Process -Id $Entry.Process.Id -ErrorAction SilentlyContinue) {
            try {
                Wait-Process -Id $Entry.Process.Id -Timeout 40 -ErrorAction Stop
            }
            catch {
                if (Get-Process -Id $Entry.Process.Id -ErrorAction SilentlyContinue) {
                    throw
                }
            }
        }
    }

    Start-Sleep -Seconds 1
    $PrismLogText = ((Get-ChildItem -LiteralPath $PrismLogRoot -File -ErrorAction SilentlyContinue | ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw }) -join ([Environment]::NewLine))
    foreach ($Entry in $CurlProcesses) {
        $Case = $Entry.Case
        $Output = if (Test-Path -LiteralPath $Entry.Out) { Get-Content -LiteralPath $Entry.Out -Raw } else { '' }
        $Body = if (Test-Path -LiteralPath $Entry.Body) { Get-Content -LiteralPath $Entry.Body -Raw } else { '' }
        $ProtocolPattern = '\[Protocol=' + [regex]::Escape($Case.Protocol) + '\]'
        $SuccessPattern = if ($Case.Protocol -eq 'anytls') {
            'stage=mux outcome=started'
        } else {
            'stage=relay outcome=success'
        }
        $Observed = $PrismLogText -match $ProtocolPattern -and $PrismLogText -match [regex]::Escape($SuccessPattern)
        [void]$Results.Add([ordered]@{Name = $Case.Name; Protocol = $Case.Protocol; MihomoPid = $Case.MihomoPid; ProxyPort = $Case.ProxyPort; ConfigSha = $Case.ConfigSha; MihomoSha = $Case.MihomoSha; CurlExitCode = $Entry.Process.ExitCode; Http200 = $Output -match 'HTTP_CODE=200'; BodyOk = $Body -eq 'prism-current-mixed-response'; ServerLogObserved = [bool]$Observed; Output = $Output; Error = if (Test-Path -LiteralPath $Entry.Err) { Get-Content -LiteralPath $Entry.Err -Raw } else { '' }})
    }
    $Summary = [ordered]@{PrismPid = $PrismProcess.Id; TargetPid = $TargetProcess.Id; PrismSha = Get-Sha256 "build/src/Prism.exe"; PrismConfigSha = Get-Sha256 $PrismConfig; PrismAliveAfterRequests = -not $PrismProcess.HasExited; Results = @($Results)}
    Write-Utf8NoBom (Join-Path $CaseDirectory 'mixed-results.json') ($Summary | ConvertTo-Json -Depth 12)
    $Summary | ConvertTo-Json -Depth 12
    if (@($Results | Where-Object { $_.CurlExitCode -ne 0 -or -not $_.Http200 -or -not $_.BodyOk -or -not $_.ServerLogObserved }).Count -gt 0) { throw 'mixed matrix had failed rows' }
}
finally {
    foreach ($Id in @($Started | Select-Object -Unique)) {
    if (Get-Process -Id $Id -ErrorAction SilentlyContinue) { Stop-Process -Id $Id -Force -ErrorAction SilentlyContinue }
    }
    Start-Sleep -Milliseconds 500
    foreach ($Case in $Cases) {
        $MihomoHome = Join-Path (Join-Path $CaseDirectory $Case.Slug) 'mihomo-home'
        if (Test-Path -LiteralPath $MihomoHome) { [void](Remove-TemporaryDirectory $MihomoHome) }
    }
    if (Test-Path -LiteralPath $PrismConfig) { Remove-Item -LiteralPath $PrismConfig -Force -ErrorAction SilentlyContinue }
    if (Test-Path -LiteralPath $TargetRoot) { Remove-Item -LiteralPath $TargetRoot -Recurse -Force -ErrorAction SilentlyContinue }
}
