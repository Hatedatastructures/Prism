[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$PrismTemplate,
    [Parameter(Mandatory = $true)][string]$MihomoTemplate,
    [Parameter(Mandatory = $true)][ValidateSet('hysteria2', 'tuic')][string]$Protocol,
    [Parameter(Mandatory = $true)][string]$CaseDirectory,
    [Parameter(Mandatory = $true)][int]$TcpPort,
    [Parameter(Mandatory = $true)][int]$QuicPort,
    [Parameter(Mandatory = $true)][int]$TargetPort,
    [Parameter(Mandatory = $true)][int]$ProxyPort,
    [Parameter(Mandatory = $true)][string]$SecretEnvironmentName,
    [Parameter(Mandatory = $true)][string]$SecretValue,
    [string]$MihomoExecutable = 'mihomo.exe',
    [int]$RepeatCount = 3
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'MihomoTestSupport.ps1')

function Write-Utf8NoBom {
    param([string]$Path, [string]$Content)

    $Encoding = New-Object System.Text.UTF8Encoding -ArgumentList $false
    [System.IO.File]::WriteAllText($Path, $Content, $Encoding)
}

function Get-Sha256 {
    param([Parameter(Mandatory = $true)][string]$Path)

    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToUpperInvariant()
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
            Start-Sleep -Milliseconds 250
        }
    }
    return -not (Test-Path -LiteralPath $Path)
}

function Read-QuicLogEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$LogRoot,
        [Parameter(Mandatory = $true)][string]$Protocol,
        [Parameter(Mandatory = $true)][int]$MinimumSuccessCount
    )

    $Pattern = 'carrier=quic protocol=' + [regex]::Escape($Protocol) +
        '\s+session_id=\S+\s+stage=relay outcome=success'
    $Count = 0
    $EvidenceLines = [System.Collections.Generic.List[string]]::new()
    $LastPath = ''
    foreach ($LogFile in @(Get-ChildItem -LiteralPath $LogRoot -File -ErrorAction SilentlyContinue)) {
        $FileMatches = @(Get-Content -LiteralPath $LogFile.FullName -ErrorAction SilentlyContinue |
            Where-Object { $_ -match $Pattern })
        if ($FileMatches.Count -gt 0) {
            $Count += $FileMatches.Count
            $EvidenceLines.AddRange([string[]]$FileMatches)
            $LastPath = $LogFile.FullName
        }
    }
    [pscustomobject]@{
        Count = $Count
        Observed = $Count -gt $MinimumSuccessCount
        Path = if ($Count -gt $MinimumSuccessCount) { $LastPath } else { '' }
        Excerpt = if ($Count -gt $MinimumSuccessCount) {
            ($EvidenceLines | Select-Object -Last 3) -join "`n"
        } else { '' }
    }
}

New-Item -ItemType Directory -Path $CaseDirectory -Force | Out-Null
$CaseDirectory = (Resolve-Path -LiteralPath $CaseDirectory).Path
$PrismExecutable = (Resolve-Path -LiteralPath 'build/src/Prism.exe').Path
$MihomoExecutable = Resolve-MihomoExecutable $MihomoExecutable
$FileServerExecutable = (Resolve-Path -LiteralPath 'build/tests/PrismMatrixFileServer.exe').Path
$PrismSha256 = Get-Sha256 $PrismExecutable
$MihomoSha256 = Get-Sha256 $MihomoExecutable
$TargetRoot = Join-Path $CaseDirectory 'target-root'
$PrismLogRoot = Join-Path $CaseDirectory 'prism-logs'
New-Item -ItemType Directory -Path $TargetRoot,$PrismLogRoot -Force | Out-Null
Write-Utf8NoBom (Join-Path $TargetRoot 'hello.txt') 'prism-quic-response'

$PrismTemplatePath = (Resolve-Path -LiteralPath $PrismTemplate).Path
$PrismTemplateDirectory = Split-Path -Parent $PrismTemplatePath
$PrismObject = Get-Content -LiteralPath $PrismTemplatePath -Raw | ConvertFrom-Json
$PrismObject.NativeTls.CertificateFile = [System.IO.Path]::GetFullPath(
    (Join-Path $PrismTemplateDirectory $PrismObject.NativeTls.CertificateFile))
$PrismObject.NativeTls.PrivateKeyFile = [System.IO.Path]::GetFullPath(
    (Join-Path $PrismTemplateDirectory $PrismObject.NativeTls.PrivateKeyFile))
$PrismObject.Protocols = @($PrismObject.Protocols |
        Where-Object { $_.Id -eq ('protocol-' + $Protocol) })
$PrismObject.Protocols += [pscustomobject]@{
    Id = 'protocol-http'; Name = 'http'; Builtin = 'http'; Requires = @()
}
$PrismObject.Carriers = @()
$PrismObject.ProtocolBindings = @(
    [pscustomobject]@{
        Id = 'binding-http'; ProtocolId = 'protocol-http'; TcpEnabled = $true
        UdpEnabled = $false; MuxModes = @(); Priority = 0
        Recognition = [pscustomobject]@{}
    },
    [pscustomobject]@{
        Id = 'binding-' + $Protocol; ProtocolId = 'protocol-' + $Protocol
        TcpEnabled = $false; UdpEnabled = $true; MuxModes = @(); Priority = 100
        Recognition = [pscustomobject]@{}
    })
$PrismObject.Listeners.Tcp[0].Address = '127.0.0.1'
$PrismObject.Listeners.Tcp[0].Port = $TcpPort
if (@($PrismObject.Listeners.Udp).Count -eq 0) {
    $PrismObject.Listeners.Udp = @([pscustomobject]@{
            Id = 'udp-main'; Address = '127.0.0.1'; Port = $QuicPort; Timeout = 5000
        })
}
else {
    $PrismObject.Listeners.Udp[0].Address = '127.0.0.1'
    $PrismObject.Listeners.Udp[0].Port = $QuicPort
}
if (@($PrismObject.Listeners.Quic).Count -eq 0) {
    $PrismObject.Listeners.Quic = @([pscustomobject]@{
            Id = 'quic-main'; Address = '127.0.0.1'; Port = $QuicPort; Timeout = 5000
        })
}
else {
    $PrismObject.Listeners.Quic[0].Address = '127.0.0.1'
    $PrismObject.Listeners.Quic[0].Port = $QuicPort
}
$PrismObject.Logging.Directory = $PrismLogRoot.Replace('\', '/')
$PrismObject.Logging.FileName = 'prism.log'
$PrismObject.Operations.Enabled = $false
$PrismConfig = Join-Path $CaseDirectory 'prism.json'
Write-Utf8NoBom $PrismConfig ($PrismObject | ConvertTo-Json -Depth 100)
$PrismConfigSha256 = Get-Sha256 $PrismConfig

$Yaml = Get-Content -LiteralPath (Resolve-Path $MihomoTemplate) -Raw
$Yaml = [regex]::Replace($Yaml, '(?m)^mixed-port:\s+\d+\s*$', "mixed-port: $ProxyPort")
$Yaml = [regex]::Replace($Yaml, '(?m)^\s*server:\s+.*$', '    server: 127.0.0.1')
$Yaml = [regex]::Replace($Yaml, '(?m)^\s*port:\s+\d+\s*$', "    port: $QuicPort")
$Yaml = [regex]::Replace($Yaml, '(?m)^bind-address:\s+.*$', 'bind-address: 127.0.0.1')
$Yaml = [regex]::Replace($Yaml, '(?m)^allow-lan:\s+.*$', 'allow-lan: false')
$Yaml = [regex]::Replace(
    $Yaml,
    '(?m)^\s*-\s*IP-CIDR,127\.0\.0\.0/8,DIRECT\s*\r?\n',
    '')
$ActiveProxy = if ($Protocol -eq 'hysteria2') { 'Hysteria2 QUIC' } else { 'TUIC v5 QUIC' }
$Yaml = [regex]::Replace(
    $Yaml,
    '(?m)^(\s*-\s*MATCH,)PrismPreview-Active\s*$',
    ('$1' + $ActiveProxy))
if ($Yaml -notmatch [regex]::Escape($ActiveProxy)) {
    throw "QUIC active proxy was not found in Mihomo template: $ActiveProxy"
}
$MihomoTemplatePath = Join-Path $CaseDirectory 'mihomo-template.yaml'
Write-Utf8NoBom $MihomoTemplatePath $Yaml

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
# QUIC credentials come from PrismConfigurationMatrix.json Secrets.  Keep the
# legacy parameters for invocation compatibility, but do not inject secrets via
# environment variables.

$Started = [System.Collections.Generic.List[int]]::new()
$TargetProcess = $null
$PrismProcess = $null
$Results = [System.Collections.Generic.List[object]]::new()
try {
    $TargetProcess = Start-Process -FilePath $FileServerExecutable `
        -ArgumentList @($TargetRoot, $TargetPort, '1') `
        -WorkingDirectory (Get-Location) -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput (Join-Path $CaseDirectory 'target.stdout.log') `
        -RedirectStandardError (Join-Path $CaseDirectory 'target.stderr.log') `
        -Environment $ChildEnvironment
    [void]$Started.Add($TargetProcess.Id)

    $PrismProcess = Start-Process -FilePath $PrismExecutable `
        -ArgumentList @($PrismConfig) `
        -WorkingDirectory (Get-Location) -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput (Join-Path $CaseDirectory 'prism.stdout.log') `
        -RedirectStandardError (Join-Path $CaseDirectory 'prism.stderr.log') `
        -Environment $ChildEnvironment
    [void]$Started.Add($PrismProcess.Id)

    $Ready = $false
    for ($Index = 0; $Index -lt 60; $Index++) {
        Start-Sleep -Milliseconds 250
        if ($PrismProcess.HasExited) {
            throw "Prism exited with code $($PrismProcess.ExitCode)"
        }
        $ReadyLog = Join-Path $CaseDirectory 'prism.stdout.log'
        $ReadyText = if (Test-Path $ReadyLog) { Get-Content $ReadyLog -Raw } else { '' }
        if ($ReadyText -match 'quic_socket_ready=true') {
            $Ready = $true
            break
        }
    }
    if (-not $Ready) {
        throw 'QUIC readiness timeout'
    }

    for ($Attempt = 1; $Attempt -le $RepeatCount; $Attempt++) {
        $AttemptProxyPort = if ($Attempt -eq 1) { $ProxyPort } else { Get-FreeLoopbackPort }
        $AttemptHome = Join-Path $CaseDirectory ("mihomo-home-{0}" -f $Attempt)
        New-Item -ItemType Directory -Path $AttemptHome -Force | Out-Null
        $AttemptConfig = Join-Path $AttemptHome 'config.yaml'
        $AttemptYaml = [regex]::Replace(
            $Yaml, '(?m)^mixed-port:\s+\d+\s*$', "mixed-port: $AttemptProxyPort")
        Write-Utf8NoBom $AttemptConfig $AttemptYaml
        $AttemptConfigSha256 = Get-Sha256 $AttemptConfig
        $MihomoOut = Join-Path $CaseDirectory ("mihomo-{0}.stdout.log" -f $Attempt)
        $MihomoErr = Join-Path $CaseDirectory ("mihomo-{0}.stderr.log" -f $Attempt)
        $Mihomo = $null
        try {
            $Mihomo = Start-Process -FilePath $MihomoExecutable `
                -ArgumentList @('-d', $AttemptHome, '-f', $AttemptConfig) `
                -WorkingDirectory $AttemptHome -WindowStyle Hidden -PassThru `
                -RedirectStandardOutput $MihomoOut -RedirectStandardError $MihomoErr `
                -Environment $ChildEnvironment
            [void]$Started.Add($Mihomo.Id)
            $Listening = $false
            for ($Index = 0; $Index -lt 60; $Index++) {
                Start-Sleep -Milliseconds 250
                if ($Mihomo.HasExited) {
                    throw "Mihomo exited with code $($Mihomo.ExitCode)"
                }
                if (@(Get-NetTCPConnection -State Listen -LocalPort $AttemptProxyPort `
                            -ErrorAction SilentlyContinue |
                            Where-Object { $_.OwningProcess -eq $Mihomo.Id }).Count -gt 0) {
                    $Listening = $true
                    break
                }
            }
            if (-not $Listening) {
                throw 'Mihomo QUIC proxy readiness timeout'
            }
            $BeforeEvidence = Read-QuicLogEvidence `
                -LogRoot $PrismLogRoot -Protocol $Protocol -MinimumSuccessCount 0
            $PrismSuccessCount = $BeforeEvidence.Count
            $Output = @(& curl.exe --noproxy '' `
                --proxy ("http://127.0.0.1:{0}" -f $AttemptProxyPort) `
                --max-time 30 --silent --show-error `
                --write-out "`nHTTP_CODE=%{http_code}`n" `
                ("http://127.0.0.1:{0}/hello.txt" -f $TargetPort) 2>&1)
            $ExitCode = $LASTEXITCODE
            $Output | Set-Content -LiteralPath (Join-Path $CaseDirectory ("curl-{0}.log" -f $Attempt)) -Encoding UTF8
            $ServerEvidence = Read-QuicLogEvidence `
                -LogRoot $PrismLogRoot -Protocol $Protocol `
                -MinimumSuccessCount $PrismSuccessCount
            for ($LogAttempt = 0; $LogAttempt -lt 450 -and -not $ServerEvidence.Observed; $LogAttempt++) {
                Start-Sleep -Milliseconds 100
                $ServerEvidence = Read-QuicLogEvidence `
                    -LogRoot $PrismLogRoot -Protocol $Protocol `
                    -MinimumSuccessCount $PrismSuccessCount
            }
            $Results.Add([ordered]@{
                    attempt = $Attempt
                    prismPid = $PrismProcess.Id
                    mihomoPid = $Mihomo.Id
                    targetPid = $TargetProcess.Id
                    proxyPort = $AttemptProxyPort
                    quicPort = $QuicPort
                    targetPort = $TargetPort
                    exitCode = $ExitCode
                    output = ($Output -join "`n")
                    expectedProtocol = $Protocol
                    serverLogObserved = [bool]$ServerEvidence.Observed
                    serverLogPath = $ServerEvidence.Path
                    serverLogExcerpt = $ServerEvidence.Excerpt
                    prismExecutable = $PrismExecutable
                    prismSha256 = $PrismSha256
                    prismConfig = $PrismConfig
                    prismConfigSha256 = $PrismConfigSha256
                    mihomoExecutable = $MihomoExecutable
                    mihomoSha256 = $MihomoSha256
                    configPath = $AttemptConfig
                    configSha256 = $AttemptConfigSha256
                    cleanup = [ordered]@{
                        mihomoExited = $false
                        homeRemoved = $false
                        configRemoved = $false
                        prismConfigRemoved = $false
                        prismExited = $false
                        targetExited = $false
                        targetRootRemoved = $false
                    }
                })
        }
        finally {
            $Exited = Stop-OwnedProcess $Mihomo
            $HomeRemoved = Remove-TemporaryDirectory $AttemptHome
            $Result = $Results | Select-Object -Last 1
            if ($null -ne $Result) {
                $Result.cleanup.mihomoExited = [bool]$Exited
                $Result.cleanup.homeRemoved = [bool]$HomeRemoved
                $Result.cleanup.configRemoved = -not (Test-Path $AttemptConfig)
            }
        }
    }
}
finally {
    $PrismExited = Stop-OwnedProcess $PrismProcess
    $TargetExited = Stop-OwnedProcess $TargetProcess
    $TargetRootRemoved = Remove-TemporaryDirectory $TargetRoot
    if (Test-Path $PrismConfig) { Remove-Item -LiteralPath $PrismConfig -Force }
    if (Test-Path $MihomoTemplatePath) { Remove-Item -LiteralPath $MihomoTemplatePath -Force }
    foreach ($Result in $Results) {
        $Result.cleanup.prismConfigRemoved = -not (Test-Path $PrismConfig)
        $Result.cleanup.prismExited = [bool]$PrismExited
        $Result.cleanup.targetExited = [bool]$TargetExited
        $Result.cleanup.targetRootRemoved = [bool]$TargetRootRemoved
    }
    foreach ($ProcessId in ($Started | Select-Object -Unique)) {
        if (Get-Process -Id $ProcessId -ErrorAction SilentlyContinue) {
            Stop-Process -Id $ProcessId -Force -ErrorAction SilentlyContinue
        }
    }
}

$Json = $Results | ConvertTo-Json -Depth 12
Write-Utf8NoBom (Join-Path $CaseDirectory 'results.json') $Json
$Json
if (@($Results | Where-Object {
            $_.exitCode -ne 0 -or $_.output -notmatch 'HTTP_CODE=200' -or
            -not $_.serverLogObserved
        }).Count -gt 0) {
    exit 1
}
