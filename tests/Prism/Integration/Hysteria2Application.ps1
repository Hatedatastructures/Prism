[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$RepoRoot,
    [Parameter(Mandatory = $true)][string]$PrismExe,
    [Parameter(Mandatory = $true)][string]$Go,
    [Parameter(Mandatory = $true)][string]$OutputDirectory,
    [ValidateRange(1, 20)][int]$RepeatCount = 3
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'OperationsCommandAuth.ps1')
$App = $null
$RunDirectory = $null
$script:OutputRoot = $null
$script:RunId = $null

function Write-Evidence([string]$Message) {
    Write-Host $Message
    if ($script:EvidencePath) {
        Add-Content -LiteralPath $script:EvidencePath -Value $Message
    }
}

function Get-FreeTcpPort {
    $Listener = [System.Net.Sockets.TcpListener]::new(
        [System.Net.IPAddress]::Loopback, 0)
    try { $Listener.Start(); return [int]$Listener.LocalEndpoint.Port }
    finally { $Listener.Stop() }
}

function Get-FreeUdpPort {
    $Client = [System.Net.Sockets.UdpClient]::new(
        [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Loopback, 0))
    try { return [int]$Client.Client.LocalEndPoint.Port }
    finally { $Client.Dispose() }
}

function New-Hysteria2Configuration($Request) {
    $Config = [ordered]@{
        SchemaVersion = 1
        Runtime = @{ WorkerCount = 2; RequiredCapabilities = @(); SessionTimeout = 30000 }
        Listeners = @{
            Tcp = @(@{ Id = 'tcp-main'; Address = '127.0.0.1'; Port = $Request.TcpPort; Timeout = 5000 })
            Udp = @()
            Quic = @(@{ Id = 'quic-main'; Address = '127.0.0.1'; Port = $Request.QuicPort; Timeout = 5000 })
            Timeout = 5000
        }
        NativeTls = @{
            Enabled = $true; CertificateFile = $Request.Certificate; PrivateKeyFile = $Request.PrivateKey
        }
        Builtins = @()
        Protocols = @(
            @{ Id = 'protocol-socks5'; Name = 'socks5'; Builtin = 'socks5'; Requires = @() },
            @{ Id = 'protocol-hysteria2'; Name = 'hysteria2'; Builtin = 'hysteria2'; Requires = @(); Quic = @{
                Alpn = 'h3'; ServerName = 'hysteria'; CredentialSecretRef = 'secret/hysteria2/password'
                MaxStreams = 64; MaxDatagrams = 64
            }}
        )
        Carriers = @()
        ProtocolBindings = @(
            @{
                Id = 'binding-socks5'; ProtocolId = 'protocol-socks5'; TcpEnabled = $true
                UdpEnabled = $false; MuxModes = @(); Priority = 0; Recognition = @{}
            }
            @{
                Id = 'binding-hysteria2'; ProtocolId = 'protocol-hysteria2'; TcpEnabled = $false
                UdpEnabled = $true; MuxModes = @(); Priority = 0; Recognition = @{}
            }
        )
        Accounts = @(@{ Id = 'hysteria2'; SecretRef = 'secret/hysteria2/password'; Credential = $Request.Password })
        Routes = @()
        Dns = @{ Servers = @('1.1.1.1'); Timeout = 1000 }
        Logging = @{ Level = 'Trace'; RenderMode = 'CompactHuman'; Directory = $Request.RunDirectory
            FileName = 'prism-hysteria2.log'; Console = $false; RotateBytes = 67108864
            RotateFiles = 2; FlushIntervalMs = 100 }
        Trace = @{ IncludeCorrelation = $true; IncludeWorker = $true; IncludeSession = $true; IncludeStream = $false }
        Statistics = @{ Enabled = $true; Interval = 1000 }
        Operations = @{ Enabled = $true; Endpoint = "127.0.0.1:$($Request.OperationsPort)"; Timeout = 1000 }
        HotReload = @{ Enabled = $false; AckTimeout = 5000 }
        Shutdown = @{ Timeout = 10000 }
    }
    $Json = $Config | ConvertTo-Json -Depth 16
    $Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Request.Path, $Json, $Utf8NoBom)
}

function Invoke-GoClient($Request) {
    $Args = @('-server', "127.0.0.1:$($Request.QuicPort)", '-password', $Request.Password,
        '-mode', $Request.Mode)
    Push-Location (Join-Path $script:RepoRoot 'tests/Prism/Integration/Go')
    $PreviousErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $Output = & $script:Hysteria2Client @Args 2>&1 | Out-String
    }
    finally {
        $ErrorActionPreference = $PreviousErrorActionPreference
        Pop-Location
    }
    $ExitCode = $LASTEXITCODE
    [System.IO.File]::WriteAllText($Request.OutputPath, $Output)
    foreach ($Line in ($Output -split "`r?`n")) {
        if (-not [string]::IsNullOrWhiteSpace($Line)) { Write-Evidence "GO_$($Request.Name) $Line" }
    }
    if ($ExitCode -ne $Request.ExpectedExit -or
        ($Request.ExpectedExit -eq 0 -and $Output -notmatch 'PASS:')) {
        throw "Go Hysteria2 client $($Request.Name) failed with exit $ExitCode"
    }
    $Pattern = switch ($Request.Mode) {
        'bad-auth' { '(?m)^BAD_AUTH_CLOSE=.*egress=none target_bytes=0 TARGET_SHA256=[0-9a-f]{64} CLOSE_OWNER=GO_CLIENT$' }
        'tcp' { '(?m)^PAYLOAD TCP bytes=\d+ SHA256=[0-9a-f]{64} FIN_SENT=true PEER_EOF=true TARGET_BYTES=\d+ TARGET_SHA256=[0-9a-f]{64} CLOSE_OWNER=GO_CLIENT$' }
        'udp' { '(?m)^PAYLOAD UDP bytes=\d+ SHA256=[0-9a-f]{64} TARGET_PACKETS=1 TARGET_BYTES=\d+ TARGET_SHA256=[0-9a-f]{64} CLOSE_OWNER=GO_CLIENT$' }
        default { throw "Unknown Hysteria2 mode $($Request.Mode)" }
    }
    if ($Output -notmatch $Pattern) {
        throw "Go Hysteria2 client $($Request.Name) did not emit the required $($Request.Mode) evidence"
    }
}

function Wait-Ready($Request) {
    $Deadline = [DateTime]::UtcNow.AddSeconds(45)
    $Uri = "http://127.0.0.1:$($Request.OperationsPort)/Operations/Health"
    while ([DateTime]::UtcNow -lt $Deadline) {
        if ($Request.Process.HasExited) { throw "Prism exited during startup" }
        try {
            $Health = Invoke-RestMethod -Method Get -Uri $Uri -TimeoutSec 2
            if ($Health.value.ready -and $Health.value.quic_ready -and
                $Health.value.quic_socket_ready -and $Health.value.quic_protocol_ready) {
                Write-Evidence "READY pid=$($Request.Process.Id)"
                return
            }
        }
        catch { }
        Start-Sleep -Milliseconds 100
    }
    throw 'Prism did not become QUIC-ready'
}

function Stop-App($Request) {
    if ($null -eq $Request -or $Request.HasExited) { return }
    $Actual = Get-CimInstance Win32_Process -Filter "ProcessId = $($Request.Id)" -ErrorAction SilentlyContinue
    if (-not $Actual -or $Actual.Name -ne 'Prism.exe' -or
        -not [string]::Equals($Actual.ExecutablePath,$script:PrismPath,[StringComparison]::OrdinalIgnoreCase) -or
        $Actual.CreationDate.ToUniversalTime() -ne $script:AppStart) {
        Write-Evidence "CLEANUP_REFUSED pid=$($Request.Id)"
        return
    }
    try { $Request.Kill() } catch { }
    if (-not $Request.WaitForExit(10000)) {
        Write-Evidence "APP_CLEANUP_FAILED pid=$($Request.Id)"
        return
    }
    Write-Evidence "APP_CLEANUP_COMPLETE pid=$($Request.Id)"
}

function Request-ApplicationDrain($Request) {
    if ($null -eq $Request -or $Request.Process.HasExited) {
        return $false
    }
    $Uri = "http://127.0.0.1:$($Request.OperationsPort)/Operations/Drain?worker=0&stop_accepting=true&force=false"
    $Headers = Get-OperationsCommandHeaders -Port $Request.OperationsPort
    $Response = Invoke-RestMethod -Method Post -Uri $Uri -Headers $Headers -TimeoutSec 5
    $Status = [string]$Response.status
    $Message = [string]$Response.message
    Write-Evidence "DRAIN_RESPONSE status=$Status message=$Message"
    if ($Status -ne 'completed' -and $Status -ne 'accepted') {
        throw "Operations drain returned status $Status"
    }
    return $true
}

function Retain-RunArtifacts {
    if ($null -eq $RunDirectory -or -not (Test-Path -LiteralPath $RunDirectory -PathType Container)) {
        return
    }
    $RetainedDirectory = Join-Path $script:OutputRoot "hysteria2-app-$($script:RunId)-retained"
    if (Test-Path -LiteralPath $RetainedDirectory) {
        throw "Refusing to overwrite retained Hysteria2 evidence: $RetainedDirectory"
    }
    Copy-Item -LiteralPath $RunDirectory -Destination $RetainedDirectory -Recurse -Force
    Remove-Item -LiteralPath $RunDirectory -Recurse -Force
    Write-Host "RUN_ARTIFACTS_RETAINED=$RetainedDirectory RUN_DIRECTORY_REMOVED=true"
}

$script:EvidencePath = $null
try {
    $Repo = [System.IO.Path]::GetFullPath((Resolve-Path $RepoRoot).Path)
    $script:RepoRoot = $Repo
    $Prism = [System.IO.Path]::GetFullPath((Resolve-Path $PrismExe).Path)
    $script:PrismPath=$Prism
    $GoModule = Join-Path $Repo 'tests/Prism/Integration/Go/go.mod'
    $GoSource = Join-Path $Repo 'tests/Prism/Integration/Go/hysteria2/main.go'
    foreach ($Path in @($Prism, $Go, $GoModule, $GoSource,
                         (Join-Path $Repo 'cert.pem'), (Join-Path $Repo 'key.pem'))) {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
            throw "Required Application H2 runner input is missing: $Path"
        }
    }
    $script:OutputRoot = [System.IO.Path]::GetFullPath($OutputDirectory)
    if (-not (Test-Path -LiteralPath $script:OutputRoot -PathType Container)) {
        New-Item -ItemType Directory -Force -Path $script:OutputRoot | Out-Null
    }
    $script:OutputRoot = (Resolve-Path -LiteralPath $script:OutputRoot -ErrorAction Stop).Path
    $script:RunId = [Guid]::NewGuid().ToString('N')
    $RunDirectory = Join-Path $script:OutputRoot "hysteria2-app-$($script:RunId)"
    New-Item -ItemType Directory -Force -Path $RunDirectory | Out-Null
    $script:EvidencePath = Join-Path $RunDirectory 'evidence.txt'
    $Certificate = Join-Path $Repo 'cert.pem'
    $PrivateKey = Join-Path $Repo 'key.pem'
    $ConfigPath = Join-Path $RunDirectory 'prism-hysteria2.json'
    $TcpPort = Get-FreeTcpPort
    $OperationsPort = Get-FreeTcpPort
    $QuicPort = Get-FreeUdpPort
    $Password = 'hysteria2_application_password'
    New-Hysteria2Configuration ([pscustomobject]@{
        Path = $ConfigPath; RunDirectory = $RunDirectory; TcpPort = $TcpPort; QuicPort = $QuicPort
        OperationsPort = $OperationsPort; Certificate = $Certificate; PrivateKey = $PrivateKey; Password = $Password
    })
    Write-Evidence "RUN_DIRECTORY=$RunDirectory"
    Write-Evidence "PRISM_SHA256=$((Get-FileHash $Prism -Algorithm SHA256).Hash)"
    Write-Evidence "CONFIG_SHA256=$((Get-FileHash $ConfigPath -Algorithm SHA256).Hash)"
    Write-Evidence "GO_SOURCE_SHA256=$((Get-FileHash $GoSource -Algorithm SHA256).Hash)"
    Write-Evidence "GO_MOD_SHA256=$((Get-FileHash $GoModule -Algorithm SHA256).Hash)"
    Write-Evidence "RUNNER_SHA256=$((Get-FileHash $PSCommandPath -Algorithm SHA256).Hash)"
    Write-Evidence "PORTS tcp=$TcpPort quic=$QuicPort operations=$OperationsPort"
    Write-Evidence "REPEAT_COUNT=$RepeatCount MODE_ORDER=bad-auth>tcp>udp"
    $GoBinaryDirectory = Join-Path $Repo 'build/tests/Prism/Integration/Go'
    New-Item -ItemType Directory -Force -Path $GoBinaryDirectory | Out-Null
    $script:Hysteria2Client = Join-Path $GoBinaryDirectory 'PrismHysteria2GoClient.exe'
    Write-Evidence "GO_BUILD_TIME=$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')"
    & $Go -C (Join-Path $Repo 'tests/Prism/Integration/Go') build -mod=readonly -p 1 -o $script:Hysteria2Client ./hysteria2
    if($LASTEXITCODE -ne 0){throw "Go Hysteria2 build failed with exit $LASTEXITCODE"}
    Write-Evidence "GO_CLIENT_PATH=$script:Hysteria2Client"
    Write-Evidence "GO_CLIENT_SHA256=$((Get-FileHash -LiteralPath $script:Hysteria2Client -Algorithm SHA256).Hash)"

    $Env:PRISM_SECRET_SECRET_HYSTERIA2_PASSWORD = $Password
    $App = Start-Process -FilePath $Prism -ArgumentList "`"$ConfigPath`"" `
        -WindowStyle Hidden -WorkingDirectory $RunDirectory `
        -PassThru `
        -RedirectStandardOutput (Join-Path $RunDirectory 'prism.stdout.log') `
        -RedirectStandardError (Join-Path $RunDirectory 'prism.stderr.log')
    $script:AppStart=$App.StartTime.ToUniversalTime()
    Write-Evidence "APP_PID=$($App.Id) PATH=$Prism START=$($script:AppStart.ToString('o'))"
    Wait-Ready ([pscustomobject]@{ Process = $App; OperationsPort = $OperationsPort })
    foreach ($Round in 1..$RepeatCount) {
        Write-Evidence "ROUND_START=$Round"
        foreach ($Mode in @('bad-auth', 'tcp', 'udp')) {
            $PasswordForMode = if ($Mode -eq 'bad-auth') { 'wrong-password' } else { $Password }
            $Name = "ROUND_$('{0:D2}' -f $Round)_$($Mode.ToUpperInvariant())"
            Invoke-GoClient ([pscustomobject]@{
                Name = $Name; Go = $Go; QuicPort = $QuicPort; Mode = $Mode
                Password = $PasswordForMode; ExpectedExit = 0
                OutputPath = Join-Path $RunDirectory "$($Name.ToLowerInvariant()).stdout.log"
            })
        }
        Write-Evidence "ROUND_PASS=$Round"
    }
    if (-not (Request-ApplicationDrain ([pscustomobject]@{
                Process = $App; OperationsPort = $OperationsPort }))) {
        throw 'Hysteria2 Operations drain was not accepted'
    }
    if(-not $App.WaitForExit(45000)){throw 'Prism did not exit naturally after Hysteria2 Operations drain'}
    $App.Refresh()
    $ExitCode = $App.ExitCode
    Write-Evidence "APP_EXIT=$ExitCode PID=$($App.Id)"
    Write-Evidence 'APP_NATURAL_EXIT=true'
    Write-Evidence 'APP_CLEANUP_COMPLETE=true'
    if($ExitCode -ne 0){throw "Prism failed Hysteria2 shutdown with exit $ExitCode"}
}
catch {
    Write-Evidence "RUNNER_FAILURE=$($_.Exception.Message)"
    if ($RunDirectory) {
        foreach ($Path in @(
            (Join-Path $RunDirectory 'prism-hysteria2.log'),
            (Join-Path $RunDirectory 'prism.stdout.log'),
            (Join-Path $RunDirectory 'prism.stderr.log'))) {
            if (Test-Path -LiteralPath $Path -PathType Leaf) {
                Write-Evidence "TAIL_BEGIN=$Path"
                foreach ($Line in (Get-Content -LiteralPath $Path -Tail 80)) {
                    Write-Evidence "TAIL $Line"
                }
                Write-Evidence "TAIL_END=$Path"
            }
        }
    }
    throw
}
finally {
    Stop-App $App
    Remove-Item Env:PRISM_SECRET_SECRET_HYSTERIA2_PASSWORD -ErrorAction SilentlyContinue
    Retain-RunArtifacts
}
