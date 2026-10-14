[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$PreviewTemplate,
    [Parameter(Mandatory = $true)][string]$MihomoTemplate,
    [Parameter(Mandatory = $true)][ValidateSet('hysteria2', 'tuic')][string]$Protocol,
    [Parameter(Mandatory = $true)][string]$CaseDirectory,
    [Parameter(Mandatory = $true)][int]$TcpPort,
    [Parameter(Mandatory = $true)][int]$QuicPort,
    [Parameter(Mandatory = $true)][int]$TargetPort,
    [Parameter(Mandatory = $true)][int]$ProxyPort,
    [string]$MihomoExecutable = 'logs/preview-validation-local/20260917-221136/mihomo.exe',
    [int]$RepeatCount = 3
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\OperationsCommandAuth.ps1')

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

function Read-CurlBodyEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$BodyPath,
        [Parameter(Mandatory = $true)][string]$MetadataPath,
        [Parameter(Mandatory = $true)][string]$ExpectedBody
    )

    $Metadata = if (Test-Path -LiteralPath $MetadataPath) {
        Get-Content -LiteralPath $MetadataPath -Raw
    } else { '' }
    $Bytes = if (Test-Path -LiteralPath $BodyPath -PathType Leaf) {
        [System.IO.File]::ReadAllBytes($BodyPath)
    } else { [byte[]]::new(0) }
    $Body = [System.Text.Encoding]::UTF8.GetString($Bytes)
    $CodeMatch = [regex]::Match($Metadata, '(?m)HTTP_CODE=(?<Code>\d+)')
    return [pscustomobject]@{
        BodyPath = $BodyPath
        BodyBytes = $Bytes.Length
        BodySha256 = if (Test-Path -LiteralPath $BodyPath -PathType Leaf) {
            Get-Sha256 $BodyPath
        } else { '' }
        Body = $Body
        BodyMatchesExpected = $Body -ceq $ExpectedBody
        HttpCode = if ($CodeMatch.Success) {
            [int]$CodeMatch.Groups['Code'].Value
        } else { 0 }
        Metadata = $Metadata
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
Write-Utf8NoBom (Join-Path $TargetRoot 'hello.txt') 'prism-quic-response'

$PreviewTemplatePath = (Resolve-Path -LiteralPath $PreviewTemplate).Path
$PreviewTemplateDirectory = Split-Path -Parent $PreviewTemplatePath
$PreviewObject = Get-Content -LiteralPath $PreviewTemplatePath -Raw | ConvertFrom-Json
$ProtocolEntry = @($PreviewObject.Protocols |
    Where-Object { $_.Id -eq ('protocol-' + $Protocol) })
if ($ProtocolEntry.Count -ne 1) {
    throw "QUIC template must contain exactly one protocol-$Protocol entry; found $($ProtocolEntry.Count)"
}
if (-not ($ProtocolEntry[0].PSObject.Properties.Name -contains 'Quic') -or
    $null -eq $ProtocolEntry[0].Quic) {
    throw "QUIC template protocol-$Protocol has no Quic configuration"
}
$PreviewObject.NativeTls.CertificateFile = [System.IO.Path]::GetFullPath(
    (Join-Path $PreviewTemplateDirectory $PreviewObject.NativeTls.CertificateFile))
$PreviewObject.NativeTls.PrivateKeyFile = [System.IO.Path]::GetFullPath(
    (Join-Path $PreviewTemplateDirectory $PreviewObject.NativeTls.PrivateKeyFile))
$PreviewObject.Protocols = @($ProtocolEntry)
$PreviewObject.Protocols += [pscustomobject]@{
    Id = 'protocol-http'; Name = 'http'; Builtin = 'http'; Requires = @()
}
$PreviewObject.Carriers = @()
$PreviewObject.ProtocolBindings = @(
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
$PreviewObject.Listeners.Tcp[0].Address = '127.0.0.1'
$PreviewObject.Listeners.Tcp[0].Port = $TcpPort
if (@($PreviewObject.Listeners.Udp).Count -eq 0) {
    $PreviewObject.Listeners.Udp = @([pscustomobject]@{
            Id = 'udp-main'; Address = '127.0.0.1'; Port = $QuicPort; Timeout = 5000
        })
}
else {
    $PreviewObject.Listeners.Udp[0].Address = '127.0.0.1'
    $PreviewObject.Listeners.Udp[0].Port = $QuicPort
}
if (@($PreviewObject.Listeners.Quic).Count -eq 0) {
    $PreviewObject.Listeners.Quic = @([pscustomobject]@{
            Id = 'quic-main'; Address = '127.0.0.1'; Port = $QuicPort; Timeout = 5000
        })
}
else {
    $PreviewObject.Listeners.Quic[0].Address = '127.0.0.1'
    $PreviewObject.Listeners.Quic[0].Port = $QuicPort
}
$PreviewObject.Logging.Directory = $PreviewLogRoot.Replace('\', '/')
$PreviewObject.Logging.FileName = 'preview.log'
$PreviewOperationsPort = Get-FreeLoopbackPort
$PreviewObject.Operations.Enabled = $true
$PreviewObject.Operations.Endpoint = "127.0.0.1:$PreviewOperationsPort"
$PreviewDrainUri = "http://127.0.0.1:$PreviewOperationsPort/Operations/Drain?worker=0&stop_accepting=true&force=false"
$PreviewConfig = Join-Path $CaseDirectory 'preview.json'
$PreviewConfigAudit = Join-Path $CaseDirectory 'preview-config.audit.json'
Write-Utf8NoBom $PreviewConfig ($PreviewObject | ConvertTo-Json -Depth 100)
Copy-Item -LiteralPath $PreviewConfig -Destination $PreviewConfigAudit -Force
$PreviewConfigSha256 = Get-Sha256 $PreviewConfig
$PreviewConfigAuditSha256 = Get-Sha256 $PreviewConfigAudit

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
$MihomoTemplateSha256 = Get-Sha256 $MihomoTemplatePath

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
$TargetProcess = $null
$TargetIdentity = $null
$PreviewProcess = $null
$PreviewIdentity = $null
$Results = [System.Collections.Generic.List[object]]::new()
$ExpectedLiteralBody = 'prism-quic-response'
$TargetBodyPath = Join-Path $TargetRoot 'hello.txt'
$TargetBodySha256 = Get-Sha256 $TargetBodyPath
$PreviewDrainRequested = $false
$PreviewDrainStatus = ''
$PreviewDrainMessage = ''
$PreviewNaturalExit = $false
$PreviewExitCode = $null
try {
    $TargetProcess = Start-Process -FilePath $FileServerExecutable `
        -ArgumentList @($TargetRoot, $TargetPort, '1') `
        -WorkingDirectory (Get-Location) -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput (Join-Path $CaseDirectory 'target.stdout.log') `
        -RedirectStandardError (Join-Path $CaseDirectory 'target.stderr.log') `
        -Environment $ChildEnvironment
    $TargetIdentity = New-OwnedProcessIdentity $TargetProcess $FileServerExecutable 'target'
    [void]$Started.Add($TargetIdentity)

    $PreviewProcess = Start-Process -FilePath $PreviewExecutable `
        -ArgumentList @($PreviewConfig) `
        -WorkingDirectory (Get-Location) -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput (Join-Path $CaseDirectory 'preview.stdout.log') `
        -RedirectStandardError (Join-Path $CaseDirectory 'preview.stderr.log') `
        -Environment $ChildEnvironment
    $PreviewIdentity = New-OwnedProcessIdentity $PreviewProcess $PreviewExecutable 'preview'
    [void]$Started.Add($PreviewIdentity)

    $Ready = $false
    for ($Index = 0; $Index -lt 60; $Index++) {
        Start-Sleep -Milliseconds 250
        if ($PreviewProcess.HasExited) {
            throw "Preview exited with code $($PreviewProcess.ExitCode)"
        }
        $ReadyLog = Join-Path $CaseDirectory 'preview.stdout.log'
        $ReadyText = if (Test-Path $ReadyLog) { Get-Content $ReadyLog -Raw } else { '' }
        if ($ReadyText -match 'quic_socket_ready=true') {
            $Ready = $true
            break
        }
    }
    if (-not $Ready) {
        throw 'QUIC readiness timeout'
    }

    $OperationsReady = $false
    for ($Index = 0; $Index -lt 40; $Index++) {
        Start-Sleep -Milliseconds 250
        if ($PreviewProcess.HasExited) {
            throw "Preview exited before Operations readiness: $($PreviewProcess.ExitCode)"
        }
        try {
            $Health = Invoke-RestMethod -Method Get `
                -Uri "http://127.0.0.1:$PreviewOperationsPort/Operations/Health" -TimeoutSec 2
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
        $AttemptProxyPort = if ($Attempt -eq 1) { $ProxyPort } else { Get-FreeLoopbackPort }
        $AttemptHome = Join-Path $CaseDirectory ("mihomo-home-{0}" -f $Attempt)
        New-Item -ItemType Directory -Path $AttemptHome -Force | Out-Null
        $AttemptConfig = Join-Path $AttemptHome 'config.yaml'
        $AttemptConfigAudit = Join-Path $CaseDirectory ("mihomo-{0}.config.yaml" -f $Attempt)
        $BodyPath = Join-Path $CaseDirectory ("response-{0}.body" -f $Attempt)
        $MetadataPath = Join-Path $CaseDirectory ("curl-{0}.log" -f $Attempt)
        $AttemptYaml = [regex]::Replace(
            $Yaml, '(?m)^mixed-port:\s+\d+\s*$', "mixed-port: $AttemptProxyPort")
        Write-Utf8NoBom $AttemptConfig $AttemptYaml
        Copy-Item -LiteralPath $AttemptConfig -Destination $AttemptConfigAudit -Force
        $AttemptConfigSha256 = Get-Sha256 $AttemptConfig
        $AttemptConfigAuditSha256 = Get-Sha256 $AttemptConfigAudit
        $MihomoOut = Join-Path $CaseDirectory ("mihomo-{0}.stdout.log" -f $Attempt)
        $MihomoErr = Join-Path $CaseDirectory ("mihomo-{0}.stderr.log" -f $Attempt)
        $Mihomo = $null
        $MihomoIdentity = $null
        try {
            $Mihomo = Start-Process -FilePath $MihomoExecutable `
                -ArgumentList @('-d', $AttemptHome, '-f', $AttemptConfig) `
                -WorkingDirectory $AttemptHome -WindowStyle Hidden -PassThru `
                -RedirectStandardOutput $MihomoOut -RedirectStandardError $MihomoErr `
                -Environment $ChildEnvironment
            $MihomoIdentity = New-OwnedProcessIdentity $Mihomo $MihomoExecutable "mihomo-$Attempt"
            [void]$Started.Add($MihomoIdentity)
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
                -LogRoot $PreviewLogRoot -Protocol $Protocol -MinimumSuccessCount 0
            $PreviewSuccessCount = $BeforeEvidence.SuccessCount
            $StartedAt = Get-Date
            $BodyPath = Join-Path $CaseDirectory ("response-{0}.body" -f $Attempt)
            $MetadataPath = Join-Path $CaseDirectory ("curl-{0}.log" -f $Attempt)
            $Output = @(& curl.exe --noproxy '' `
                --proxy ("http://127.0.0.1:{0}" -f $AttemptProxyPort) `
                --max-time 30 --silent --show-error --output $BodyPath `
                --write-out "`nHTTP_CODE=%{http_code}`n" `
                ("http://127.0.0.1:{0}/hello.txt" -f $TargetPort) 2>&1)
            $ExitCode = $LASTEXITCODE
            $Output | Set-Content -LiteralPath $MetadataPath -Encoding UTF8
            $Response = Read-CurlBodyEvidence $BodyPath $MetadataPath $ExpectedLiteralBody
            if ($ExitCode -ne 0 -or $Response.HttpCode -ne 200 -or
                -not $Response.BodyMatchesExpected) {
                throw "QUIC response evidence failed: exit=$ExitCode http=$($Response.HttpCode) bytes=$($Response.BodyBytes)"
            }
            $MihomoExited = Stop-OwnedProcess $MihomoIdentity
            if (-not $MihomoExited) { throw 'Mihomo cleanup identity verification failed' }
            $ServerEvidence = Read-QuicLogEvidence `
                -LogRoot $PreviewLogRoot -Protocol $Protocol `
                -MinimumSuccessCount $PreviewSuccessCount
            for ($LogAttempt = 0; $LogAttempt -lt 450 -and -not $ServerEvidence.Observed; $LogAttempt++) {
                Start-Sleep -Milliseconds 100
                $ServerEvidence = Read-QuicLogEvidence `
                    -LogRoot $PreviewLogRoot -Protocol $Protocol `
                    -MinimumSuccessCount $PreviewSuccessCount
            }
            if (-not $ServerEvidence.Observed) { throw 'QUIC server evidence timeout' }
            $Results.Add([ordered]@{
                    attempt = $Attempt
                    previewPid = $PreviewProcess.Id
                    mihomoPid = $Mihomo.Id
                    targetPid = $TargetProcess.Id
                    proxyPort = $AttemptProxyPort
                    quicPort = $QuicPort
                    targetPort = $TargetPort
                    exitCode = $ExitCode
                    elapsedSeconds = ((Get-Date) - $StartedAt).TotalSeconds
                    output = ($Output -join "`n")
                    expectedProtocol = $Protocol
                    httpCode = $Response.HttpCode
                    literalBodyExpected = $ExpectedLiteralBody
                    literalBodyMatch = [bool]$Response.BodyMatchesExpected
                    bodyPath = $Response.BodyPath
                    bodyBytes = $Response.BodyBytes
                    bodySha256 = $Response.BodySha256
                    responseMetadata = $Response.Metadata
                    serverLogObserved = [bool]$ServerEvidence.Observed
                    serverLogSuccessCount = $ServerEvidence.SuccessCount
                    serverLogMinimumCount = $ServerEvidence.MinimumSuccessCount
                    serverLogPath = $ServerEvidence.Path
                    serverLogExcerpt = $ServerEvidence.Excerpt
                    previewExecutable = $PreviewExecutable
                    previewSha256 = $PreviewSha256
                    previewConfig = $PreviewConfig
                    previewConfigSha256 = $PreviewConfigSha256
                    mihomoExecutable = $MihomoExecutable
                    mihomoSha256 = $MihomoSha256
                    configPath = $AttemptConfig
                    configSha256 = $AttemptConfigSha256
                    configAuditPath = $AttemptConfigAudit
                    configAuditSha256 = $AttemptConfigAuditSha256
                    previewConfigAudit = $PreviewConfigAudit
                    previewConfigAuditSha256 = $PreviewConfigAuditSha256
                    targetBodyPath = $TargetBodyPath
                    targetBodySha256 = $TargetBodySha256
                    cleanup = [ordered]@{
                        mihomoExited = $false
                        homeRemoved = $false
                        configRemoved = $false
                    }
                })
        }
        finally {
            $Exited = Stop-OwnedProcess $MihomoIdentity
            $HomeRemoved = Remove-TemporaryDirectory $AttemptHome
            $Result = $Results | Select-Object -Last 1
            $NeedsAdd = $null -eq $Result -or $Result.attempt -ne $Attempt
            if ($NeedsAdd) {
                $Result = [ordered]@{
                    attempt = $Attempt; exitCode = 1; expectedProtocol = $Protocol
                    httpCode = 0; literalBodyExpected = $ExpectedLiteralBody
                    literalBodyMatch = $false; bodyPath = $BodyPath; bodyBytes = 0; bodySha256 = ''
                    serverLogObserved = $false; serverLogSuccessCount = 0; serverLogMinimumCount = 0
                    serverLogPath = ''; serverLogExcerpt = ''; previewConfig = $PreviewConfig
                    previewConfigSha256 = $PreviewConfigSha256; previewConfigAudit = $PreviewConfigAudit
                    previewConfigAuditSha256 = $PreviewConfigAuditSha256; mihomoExecutable = $MihomoExecutable
                    mihomoSha256 = $MihomoSha256; configPath = $AttemptConfig
                    configSha256 = $AttemptConfigSha256; configAuditPath = $AttemptConfigAudit
                    configAuditSha256 = $AttemptConfigAuditSha256; targetBodyPath = $TargetBodyPath
                    targetBodySha256 = $TargetBodySha256
                }
            }
            $Result.cleanup = [ordered]@{ mihomoExited = [bool]$Exited
                homeRemoved = [bool]$HomeRemoved; configRemoved = -not (Test-Path $AttemptConfig) }
            if ($NeedsAdd) { [void]$Results.Add($Result) }
        }
    }
    $Headers = Get-OperationsCommandHeaders -Port $PreviewOperationsPort
    $DrainResponse = Invoke-RestMethod -Method Post -Uri $PreviewDrainUri -Headers $Headers -TimeoutSec 5
    $PreviewDrainRequested = $true
    $PreviewDrainStatus = [string]$DrainResponse.status
    $PreviewDrainMessage = [string]$DrainResponse.message
    if ($PreviewDrainStatus -ne 'accepted' -and $PreviewDrainStatus -ne 'completed') {
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
}
finally {
    $PreviewCleanup = Stop-OwnedProcess $PreviewIdentity
    $TargetCleanup = Stop-OwnedProcess $TargetIdentity
    $OwnedCleanup = $PreviewCleanup -and $TargetCleanup
    foreach ($Identity in $Started) {
        $OwnedCleanup = (Stop-OwnedProcess $Identity) -and $OwnedCleanup
    }
    if (Test-Path $PreviewConfig) { Remove-Item -LiteralPath $PreviewConfig -Force }
    $PreviewConfigRemoved = -not (Test-Path $PreviewConfig)
    foreach ($Result in $Results) {
        $Result.previewDrainUri = $PreviewDrainUri
        $Result.previewDrainRequested = [bool]$PreviewDrainRequested
        $Result.previewDrainStatus = $PreviewDrainStatus
        $Result.previewDrainMessage = $PreviewDrainMessage
        $Result.previewNaturalExit = [bool]$PreviewNaturalExit
        $Result.previewExitCode = $PreviewExitCode
        $Result.previewConfigAudit = $PreviewConfigAudit
        $Result.previewConfigAuditSha256 = $PreviewConfigAuditSha256
        $Result.mihomoTemplatePath = $MihomoTemplatePath
        $Result.mihomoTemplateSha256 = $MihomoTemplateSha256
        $Result.ownedProcessIdentities = @($Started | ForEach-Object {
                [ordered]@{ role = $_.Role; pid = $_.Pid; path = $_.Path
                    startTime = $_.StartTime.ToString('o') }
            })
        $Result.cleanup.previewConfigRemoved = [bool]$PreviewConfigRemoved
        $Result.cleanup.previewIdentityVerified = [bool]$PreviewCleanup
        $Result.cleanup.targetIdentityVerified = [bool]$TargetCleanup
        $Result.cleanup.ownedProcessIdentityVerified = [bool]$OwnedCleanup
    }
}

$Json = $Results | ConvertTo-Json -Depth 12
Write-Utf8NoBom (Join-Path $CaseDirectory 'results.json') $Json
$Json
if ($Results.Count -ne $RepeatCount -or @($Results | Where-Object {
            $_.exitCode -ne 0 -or $_.httpCode -ne 200 -or
            -not $_.literalBodyMatch -or -not $_.serverLogObserved -or
            -not $_.previewNaturalExit -or $_.previewExitCode -ne 0 -or
            -not $_.cleanup.ownedProcessIdentityVerified
        }).Count -gt 0) {
    exit 1
}
