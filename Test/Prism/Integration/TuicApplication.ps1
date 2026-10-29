[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$RepoRoot,
    [Parameter(Mandatory = $true)][string]$PrismExe,
    [Parameter(Mandatory = $true)][string]$TuicClient,
    [Parameter(Mandatory = $true)][string]$OutputDirectory,
    [ValidateRange(1, 20)][int]$Rounds = 20
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'OperationsCommandAuth.ps1')
$script:EvidencePath = $null
$script:OutputRoot = $null
$script:RunId = $null
$script:OwnedGoClients = [System.Collections.Generic.List[object]]::new()
$script:PendingReceiveTask = $null

function Write-Evidence([string]$Message) {
    [Console]::WriteLine($Message)
    if ($script:EvidencePath) {
        [System.IO.File]::AppendAllText(
            $script:EvidencePath, $Message + [Environment]::NewLine)
    }
}

function Quote-ProcessArgument([string]$Value) {
    if ($Value -notmatch '[\s"]') {
        return $Value
    }
    return '"' + $Value.Replace('"', '\"') + '"'
}

function Get-FreeTcpPort {
    $Listener = [System.Net.Sockets.TcpListener]::new(
        [System.Net.IPAddress]::Loopback, 0)
    try {
        $Listener.Start()
        return [int]$Listener.LocalEndpoint.Port
    }
    finally {
        $Listener.Stop()
    }
}

function Get-FreeUdpPort {
    $Endpoint = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Loopback, 0)
    $Socket = [System.Net.Sockets.UdpClient]::new($Endpoint)
    try {
        return [int]$Socket.Client.LocalEndPoint.Port
    }
    finally {
        $Socket.Dispose()
    }
}

function New-PrismConfiguration($Request) {
    $Config = [ordered]@{
        SchemaVersion = 1
        Runtime = [ordered]@{ WorkerCount = 2; RequiredCapabilities = @(); SessionTimeout = 30000 }
        Listeners = [ordered]@{
            Tcp = @(@{ Id = 'tcp-main'; Address = '127.0.0.1'; Port = $Request.TcpPort; Timeout = 5000 })
            Udp = @()
            Quic = @(@{ Id = 'quic-main'; Address = '127.0.0.1'; Port = $Request.QuicPort; Timeout = 5000 })
            Timeout = 5000
        }
        NativeTls = [ordered]@{
            Enabled = $true
            CertificateFile = $Request.CertificateFile
            PrivateKeyFile = $Request.PrivateKeyFile
        }
        Builtins = @()
        Protocols = @(
            @{ Id = 'protocol-socks5'; Name = 'socks5'; Builtin = 'socks5'; Requires = @() },
            @{
                Id = 'protocol-tuic'; Name = 'tuic'; Builtin = 'tuic'; Requires = @()
                Quic = @{
                    Alpn = 'h3'; ServerName = $Request.ServerName
                    CredentialSecretRef = 'secret/quic/password'
                    MaxStreams = 32; MaxDatagrams = 64; Uuid = $Request.Uuid
                }
            }
        )
        Carriers = @()
        ProtocolBindings = @(
            @{
                Id = 'binding-socks5'; ProtocolId = 'protocol-socks5'
                TcpEnabled = $true; UdpEnabled = $false; MuxModes = @(); Priority = 0
                Recognition = @{}
            }
        )
        Accounts = @(@{
            Id = 'local'; SecretRef = 'secret/quic/password'; Credential = $Request.Credential
        })
        Routes = @()
        Dns = @{ Servers = @('1.1.1.1'); Timeout = 1000 }
        Logging = @{
            Level = 'Trace'; RenderMode = 'CompactHuman'; Directory = $Request.RunDirectory
            FileName = 'prism-tuic.log'; Console = $true
            RotateBytes = 67108864; RotateFiles = 2; FlushIntervalMs = 100
        }
        Trace = @{
            IncludeCorrelation = $true; IncludeWorker = $true
            IncludeSession = $true; IncludeStream = $false
        }
        Statistics = @{ Enabled = $true; Interval = 1000 }
        Operations = @{
            Enabled = $true; Endpoint = "127.0.0.1:$($Request.OperationsPort)"; Timeout = 1000
        }
        HotReload = @{ Enabled = $false; AckTimeout = 5000 }
        Shutdown = @{ Timeout = 10000 }
    }
    $Json = $Config | ConvertTo-Json -Depth 16
    [System.IO.File]::WriteAllText(
        $Request.ConfigurationPath, $Json, [System.Text.UTF8Encoding]::new($false))
}

function Start-ManagedProcess($Request) {
    $StartInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $StartInfo.FileName = $Request.Executable
    $StartInfo.Arguments = $Request.Arguments
    $StartInfo.WorkingDirectory = $Request.WorkingDirectory
    $StartInfo.UseShellExecute = $false
    $StartInfo.CreateNoWindow = $true
    $StartInfo.RedirectStandardInput = [bool]$Request.RedirectInput
    $StartInfo.RedirectStandardOutput = $true
    $StartInfo.RedirectStandardError = $true
    foreach ($Key in $Request.Environment.Keys) {
        $StartInfo.EnvironmentVariables[$Key] = [string]$Request.Environment[$Key]
    }
    $Process = [System.Diagnostics.Process]::new()
    $Process.StartInfo = $StartInfo
    if (-not $Process.Start()) {
        throw "Failed to start process: $($Request.Executable)"
    }
    return [pscustomobject]@{
        Process = $Process
        Executable = [System.IO.Path]::GetFullPath($Request.Executable)
        StdoutTask = $Process.StandardOutput.ReadToEndAsync()
        StderrTask = $Process.StandardError.ReadToEndAsync()
        StdoutPath = $Request.StdoutPath
        StderrPath = $Request.StderrPath
        RedirectInput = [bool]$Request.RedirectInput
        Mode = $Request.Mode
    }
}

function Save-ProcessOutput($Request) {
    if (-not $Request.Process.HasExited) {
        return
    }
    $Request.Process.WaitForExit()
    $Stdout = $Request.StdoutTask.GetAwaiter().GetResult()
    $Stderr = $Request.StderrTask.GetAwaiter().GetResult()
    [System.IO.File]::WriteAllText($Request.StdoutPath, $Stdout)
    [System.IO.File]::WriteAllText($Request.StderrPath, $Stderr)
    return [pscustomobject]@{ ExitCode = $Request.Process.ExitCode; Stdout = $Stdout; Stderr = $Stderr }
}

function Write-TuicClientOutput($ProcessWrapper, $Result) {
    Write-Evidence "GO_MODE=$($ProcessWrapper.Mode) EXIT=$($Result.ExitCode)"
    foreach ($Line in ($Result.Stdout -split "`r?`n")) {
        if (-not [string]::IsNullOrWhiteSpace($Line)) {
            Write-Evidence "GO_STDOUT $Line"
        }
    }
    foreach ($Line in ($Result.Stderr -split "`r?`n")) {
        if (-not [string]::IsNullOrWhiteSpace($Line)) {
            Write-Evidence "GO_STDERR $Line"
        }
    }
}

function Get-ProcessImagePath($Request) {
    $Record = Get-CimInstance -ClassName Win32_Process `
        -Filter "ProcessId = $($Request.Process.Id)" -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($null -eq $Record -or [string]::IsNullOrWhiteSpace($Record.ExecutablePath)) {
        return $null
    }
    return [System.IO.Path]::GetFullPath($Record.ExecutablePath)
}

function Test-OwnedPrism($Request) {
    if ($Request.Process.HasExited) {
        return $true
    }
    $ActualPath = Get-ProcessImagePath $Request
    return $null -ne $ActualPath -and
        [string]::Equals($ActualPath, $Request.Executable, [StringComparison]::OrdinalIgnoreCase)
}

function Stop-OwnedPrism($Request) {
    if ($Request.Process.HasExited) {
        return
    }
    if (-not (Test-OwnedPrism $Request)) {
        Write-Evidence "APP_CLEANUP_REFUSED pid=$($Request.Process.Id) reason=process_path_mismatch"
        return
    }
    $Request.Process.Kill()
    if (-not $Request.Process.WaitForExit(10000)) {
        Write-Evidence "APP_CLEANUP_FAILED pid=$($Request.Process.Id)"
    }
}

function Wait-PrismReady($Request) {
    $Deadline = [DateTime]::UtcNow.AddSeconds($Request.TimeoutSeconds)
    $HealthUri = "http://127.0.0.1:$($Request.OperationsPort)/Operations/Health"
    while ([DateTime]::UtcNow -lt $Deadline) {
        if ($Request.Process.Process.HasExited) {
            $Request.Process.Process.WaitForExit()
            $Output = $Request.Process.StdoutTask.GetAwaiter().GetResult()
            $ErrorOutput = $Request.Process.StderrTask.GetAwaiter().GetResult()
            throw "Prism exited during startup: $($Request.Process.Process.ExitCode)`n$Output`n$ErrorOutput"
        }
        $ActualPath = Get-ProcessImagePath $Request.Process
        if ($null -ne $ActualPath -and
            -not [string]::Equals(
                $ActualPath, $Request.Process.Executable, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Prism PID $($Request.Process.Process.Id) did not match the launched executable path"
        }
        try {
            $Health = Invoke-RestMethod -Method Get -Uri $HealthUri -TimeoutSec 2
            $Value = $Health.value
            if ($Value.ready -and $Value.quic_ready -and $Value.quic_socket_ready -and
                $Value.quic_protocol_ready) {
                return $Health
            }
        }
        catch {
        }
        Start-Sleep -Milliseconds 100
    }
    throw "Prism did not publish QUIC-ready Operations health within $($Request.TimeoutSeconds)s"
}

function Start-TuicClient($Request) {
    $Arguments = @(
        '-server', $Request.Server
        '-servername', $Request.ServerName
        '-uuid', $Request.Uuid
        '-mode', $Request.Mode
        '-local-port', [string]$Request.LocalPort
        '-retry', [string]$Request.Retry
    )
    if ($Request.Mode -eq 'concurrent-bidi') {
        $Arguments += @('-streams', [string]$Request.Streams)
    }
    if ($Request.Mode -eq 'udp-pending') {
        $Arguments += @('-target', $Request.Target)
    }
    $CommandLine = ($Arguments | ForEach-Object { Quote-ProcessArgument ([string]$_) }) -join ' '
    $Client = Start-ManagedProcess ([pscustomobject]@{
        Executable = $Request.Executable; Arguments = $CommandLine
        WorkingDirectory = $Request.WorkingDirectory; RedirectInput = $true; Environment = @{}
        StdoutPath = $Request.StdoutPath; StderrPath = $Request.StderrPath; Mode = $Request.Mode
    })
    $script:OwnedGoClients.Add($Client)
    return $Client
}

function Stop-OwnedGoClient($Request) {
    if ($Request.Process.HasExited) {
        return
    }
    $ActualPath = Get-ProcessImagePath $Request
    if ($null -eq $ActualPath -or
        -not [string]::Equals($ActualPath, $Request.Executable, [StringComparison]::OrdinalIgnoreCase)) {
        Write-Evidence "GO_CLIENT_CLEANUP_REFUSED pid=$($Request.Process.Id) reason=process_path_mismatch"
        return
    }
    if ($Request.RedirectInput) {
        try {
            $Request.Process.StandardInput.Close()
        }
        catch {
        }
    }
    if (-not $Request.Process.WaitForExit(3000)) {
        $Request.Process.Kill()
        [void]$Request.Process.WaitForExit(5000)
    }
}

function Wait-TuicClient($ProcessWrapper, [int]$TimeoutMilliseconds) {
    if (-not $ProcessWrapper.Process.WaitForExit($TimeoutMilliseconds)) {
        Stop-OwnedGoClient $ProcessWrapper
        throw "TUIC Go client mode $($ProcessWrapper.Mode) timed out"
    }
    $Result = Save-ProcessOutput $ProcessWrapper
    Write-TuicClientOutput $ProcessWrapper $Result
    if ($Result.ExitCode -ne 0 -or $Result.Stdout -notmatch '(?m)^PASS:') {
        throw "TUIC Go client mode $($ProcessWrapper.Mode) failed with exit $($Result.ExitCode)"
    }
    return $Result
}

function Assert-TuicClientEvidence($Mode, [string]$Output) {
    $Patterns = switch ($Mode) {
        'tcp' { @('(?m)^PAYLOAD tcp_stream=\d+ bytes=\d+ SHA256=[0-9a-f]{64} FIN_SENT=true PEER_EOF=true FIN_OWNER=GO_CLIENT_STREAM\r?$') }
        'concurrent-bidi' { @('(?m)^PAYLOAD tcp_stream=\d+ bytes=\d+ SHA256=[0-9a-f]{64} FIN_SENT=true PEER_EOF=true FIN_OWNER=GO_CLIENT_STREAM\r?$') }
        'bad-auth' { @('(?m)^BAD_AUTH_CLOSE=.*payload_read=0 egress=none\r?$', '(?m)^PASS: bad credential silent timeout / no egress; target_payload_bytes=0 TARGET_SHA256=[0-9a-f]{64} CLOSE_OWNER=GO_CLIENT_QUIC\r?$') }
        'udp-only' { @('(?m)^PAYLOAD udp_only packets=1 bytes=\d+ SHA256=[0-9a-f]{64} TARGET_PACKETS=1 TARGET_BYTES=\d+ TARGET_SHA256=[0-9a-f]{64} CLOSE_OWNER=GO_CLIENT_QUIC\r?$') }
        'auth-close' { @('(?m)^AUTH_CLOSE_EGRESS=0 TARGET_BYTES=0 TARGET_SHA256=[0-9a-f]{64} CLOSE_OWNER=GO_CLIENT_QUIC\r?$') }
        'udp-pending' { @('(?m)^PENDING_UDP_SENT target=.* bytes=\d+ SHA256=[0-9a-f]{64}\r?$') }
        default { throw "Unknown TUIC evidence mode $Mode" }
    }
    foreach ($Pattern in $Patterns) {
        if ($Output -notmatch $Pattern) {
            throw "TUIC mode $Mode did not emit required evidence pattern $Pattern"
        }
    }
    if ($Mode -eq 'concurrent-bidi') {
        $StreamEvidence = [regex]::Matches(
            $Output,
            '(?m)^PAYLOAD tcp_stream=\d+ bytes=\d+ SHA256=[0-9a-f]{64} FIN_SENT=true PEER_EOF=true FIN_OWNER=GO_CLIENT_STREAM\r?$')
        if ($StreamEvidence.Count -ne 4) {
            throw "TUIC concurrent-bidi payload/FIN/EOF evidence count=$($StreamEvidence.Count), expected=4"
        }
    }
    if ($Mode -eq 'udp-pending') {
        $PendingEvidence = [regex]::Matches(
            $Output, '(?m)^PENDING_UDP_SENT target=.* bytes=\d+ SHA256=[0-9a-f]{64}\r?$')
        if ($PendingEvidence.Count -ne 1) {
            throw "TUIC udp-pending send evidence count=$($PendingEvidence.Count), expected=1"
        }
    }
    if ($Output -notmatch '(?m)CLOSE_OWNER=GO_CLIENT_QUIC') {
        throw "TUIC mode $Mode did not emit a QUIC close owner"
    }
}

function Invoke-TuicMode($Request) {
    $Request.LocalPort = Get-FreeUdpPort
    $Label = 'round-{0:D2}-{1}-{2}' -f $Request.Round, $Request.Phase, $Request.Mode
    $Request.StdoutPath = Join-Path $Request.WorkingDirectory "$Label.stdout.log"
    $Request.StderrPath = Join-Path $Request.WorkingDirectory "$Label.stderr.log"
    Write-Evidence "GO_MODE_START round=$($Request.Round) phase=$($Request.Phase) mode=$($Request.Mode) local_port=$($Request.LocalPort) stdout=$($Request.StdoutPath) stderr=$($Request.StderrPath)"
    $Client = Start-TuicClient $Request
    if ($Request.Mode -ne 'udp-pending') {
        $Client.Process.StandardInput.Close()
        $Result = Wait-TuicClient $Client $Request.TimeoutMilliseconds
        Assert-TuicClientEvidence $Request.Mode $Result.Stdout
        return
    }
    $ReceiveTask = $Request.Sink.ReceiveAsync()
    $script:PendingReceiveTask = $ReceiveTask
    $Deadline = [DateTime]::UtcNow.AddMilliseconds($Request.TimeoutMilliseconds)
    while (-not $ReceiveTask.IsCompleted -and [DateTime]::UtcNow -lt $Deadline) {
        if ($Client.Process.HasExited) {
            $Result = Save-ProcessOutput $Client
            Write-TuicClientOutput $Client $Result
            throw "TUIC Go client exited before pending UDP sink receipt (exit $($Result.ExitCode))"
        }
        $Remaining = [int][Math]::Ceiling(($Deadline - [DateTime]::UtcNow).TotalMilliseconds)
        $WaitMilliseconds = [Math]::Min(250, [Math]::Max(1, $Remaining))
        [void]$ReceiveTask.Wait($WaitMilliseconds)
    }
    if (-not $ReceiveTask.IsCompleted) {
        Stop-OwnedGoClient $Client
        if ($Client.Process.HasExited) {
            $Result = Save-ProcessOutput $Client
            Write-TuicClientOutput $Client $Result
        }
        else {
            Write-Evidence "GO_MODE=$($Client.Mode) EXIT=unobserved_after_timeout_cleanup"
        }
        throw 'Application egress did not reach the pending UDP sink'
    }
    $Datagram = $ReceiveTask.GetAwaiter().GetResult()
    $Payload = [System.Text.Encoding]::UTF8.GetString($Datagram.Buffer)
    if ($Payload -ne 'prism-tuic-pending-egress') {
        Stop-OwnedGoClient $Client
        throw "Unexpected pending UDP payload: $Payload"
    }
    Write-Evidence "PENDING_UDP_SINK_RECEIVED bytes=$($Datagram.Buffer.Length) peer=$($Datagram.RemoteEndPoint)"
    $Client.Process.StandardInput.AutoFlush = $true
    $Client.Process.StandardInput.WriteLine('close')
    $Result = Wait-TuicClient $Client $Request.TimeoutMilliseconds
    Assert-TuicClientEvidence $Request.Mode $Result.Stdout
    $ExtraReceiveTask = $Request.Sink.ReceiveAsync()
    if ($ExtraReceiveTask.Wait(250)) {
        $ExtraDatagram = $ExtraReceiveTask.GetAwaiter().GetResult()
        throw "Pending UDP egress was not exactly once: extra_bytes=$($ExtraDatagram.Buffer.Length)"
    }
    Write-Evidence "PENDING_UDP_SINK_COUNT=1 EXTRA_EGRESS=0 round=$($Request.Round)"
}

function Request-ApplicationDrain($Request) {
    if ($Request.Process.Process.HasExited) {
        return $false
    }
    if (-not (Test-OwnedPrism $Request.Process)) {
        Write-Evidence "APP_DRAIN_REFUSED pid=$($Request.Process.Process.Id) reason=process_path_mismatch"
        return $false
    }
    $Uri = "http://127.0.0.1:$($Request.OperationsPort)/Operations/Drain?worker=0&stop_accepting=true&force=false"
    try {
        $Headers = Get-OperationsCommandHeaders -Port $Request.OperationsPort
        $Response = Invoke-RestMethod -Method Post -Uri $Uri -Headers $Headers -TimeoutSec 5
        Write-Evidence "APP_DRAIN_RESPONSE status=$($Response.status) message=$($Response.message)"
        if ($Response.status -ne 'completed' -and $Response.status -ne 'accepted') {
            throw "Operations drain returned status $($Response.status)"
        }
        return $true
    }
    catch {
        Write-Evidence "APP_DRAIN_RESPONSE_UNAVAILABLE message=$($_.Exception.Message)"
        return $false
    }
}

function Wait-ApplicationExit($Request) {
    if (-not $Request.Process.Process.WaitForExit($Request.TimeoutMilliseconds)) {
        return $false
    }
    $Result = Save-ProcessOutput $Request.Process
    Write-Evidence "APP_EXIT=$($Result.ExitCode) PID=$($Request.Process.Process.Id)"
    return $Result.ExitCode -eq 0
}

function Write-UdpSessionEvidence($Request) {
    if (-not (Test-Path -LiteralPath $Request.LogPath)) {
        throw "UDP session summary log is missing: $($Request.LogPath)"
    }
    $Summaries = @((Select-String -LiteralPath $Request.LogPath -Pattern 'UdpSessionSummary').Line)
    foreach ($Summary in $Summaries) {
        Write-Evidence "UDP_SESSION_SUMMARY $Summary"
    }
    $PendingBytes = [System.Text.Encoding]::UTF8.GetByteCount('prism-tuic-pending-egress')
    $PendingPattern = "UdpSessionSummary.*\bDatagrams=1(?=\s|$).*\bUpBytes=$PendingBytes(?=\s|$).*\bDownBytes=0(?=\s|$)"
    $PendingMatches = @($Summaries | Where-Object { $_ -match $PendingPattern })
    if ($PendingMatches.Count -ne $Request.Rounds) {
        throw "Pending UDP close summaries=$($PendingMatches.Count), expected=$($Request.Rounds)"
    }
    $EchoPattern = 'UdpSessionSummary.*\bDatagrams=1(?=\s|$).*\bUpBytes=23(?=\s|$).*\bDownBytes=23(?=\s|$)'
    $EchoMatches = @($Summaries | Where-Object { $_ -match $EchoPattern })
    if ($EchoMatches.Count -ne $Request.Rounds) {
        throw "UDP-only echo summaries=$($EchoMatches.Count), expected=$($Request.Rounds)"
    }
    $ZeroPattern = 'UdpSessionSummary.*\bDatagrams=0(?=\s|$).*\bUpBytes=0(?=\s|$).*\bDownBytes=0(?=\s|$)'
    $ZeroMatches = @($Summaries | Where-Object { $_ -match $ZeroPattern })
    if (($PendingMatches.Count + $EchoMatches.Count + $ZeroMatches.Count) -ne $Summaries.Count) {
        throw 'Found a UDP session summary that was neither the expected pending/echo report nor an all-zero session'
    }
}

function Retain-RunArtifacts {
    if ($null -eq $RunDirectory -or -not (Test-Path -LiteralPath $RunDirectory -PathType Container)) {
        return
    }
    $RetainedDirectory = Join-Path $script:OutputRoot "tuic-app-$($script:RunId)-retained"
    if (Test-Path -LiteralPath $RetainedDirectory) {
        throw "Refusing to overwrite retained TUIC evidence: $RetainedDirectory"
    }
    Copy-Item -LiteralPath $RunDirectory -Destination $RetainedDirectory -Recurse -Force
    Remove-Item -LiteralPath $RunDirectory -Recurse -Force
    Write-Host "RUN_ARTIFACTS_RETAINED=$RetainedDirectory RUN_DIRECTORY_REMOVED=true"
}

$AppRequest = $null
$PendingSink = $null
$RunDirectory = $null
$DrainCompleted = $false

try {
    $RepoRoot = [System.IO.Path]::GetFullPath((Resolve-Path -LiteralPath $RepoRoot).Path)
    $PrismPath = [System.IO.Path]::GetFullPath((Resolve-Path -LiteralPath $PrismExe).Path)
    $GoClientPath = [System.IO.Path]::GetFullPath((Resolve-Path -LiteralPath $TuicClient).Path)
    if ([System.IO.Path]::GetFileName($PrismPath) -ne 'Prism.exe') {
        throw "Expected Prism.exe, got $PrismPath"
    }
    foreach ($Path in @($PrismPath, $GoClientPath)) {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
            throw "Required executable does not exist: $Path"
        }
    }

    $CertificateFile = Join-Path $RepoRoot 'cert.pem'
    $PrivateKeyFile = Join-Path $RepoRoot 'key.pem'
    foreach ($Path in @($CertificateFile, $PrivateKeyFile)) {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
            throw "Required test TLS file does not exist: $Path"
        }
    }

    $script:OutputRoot = [System.IO.Path]::GetFullPath($OutputDirectory)
    New-Item -ItemType Directory -Force -Path $script:OutputRoot | Out-Null
    $script:OutputRoot = (Resolve-Path -LiteralPath $script:OutputRoot -ErrorAction Stop).Path
    $script:RunId = [Guid]::NewGuid().ToString('N')
    $RunDirectory = Join-Path $script:OutputRoot "tuic-app-$($script:RunId)"
    New-Item -ItemType Directory -Force -Path $RunDirectory | Out-Null
    $script:EvidencePath = Join-Path $RunDirectory 'evidence.txt'
    [System.IO.File]::WriteAllText($script:EvidencePath, '')

    $TcpPort = Get-FreeTcpPort
    do { $OperationsPort = Get-FreeTcpPort } while ($OperationsPort -eq $TcpPort)
    $QuicPort = Get-FreeUdpPort
    do { $ClientUdpPort = Get-FreeUdpPort } while ($ClientUdpPort -eq $QuicPort)
    $Uuid = '123e4567-e89b-12d3-a456-426614174000'
    $Credential = 'tuic_password'
    $AccountCredential = 'interop-unused-tcp-credential'
    $ConfigurationPath = Join-Path $RunDirectory 'prism-tuic.json'
    New-PrismConfiguration ([pscustomobject]@{
        RunDirectory = $RunDirectory
        ConfigurationPath = $ConfigurationPath
        TcpPort = $TcpPort
        QuicPort = $QuicPort
        OperationsPort = $OperationsPort
        CertificateFile = $CertificateFile
        PrivateKeyFile = $PrivateKeyFile
        Credential = $AccountCredential
        Uuid = $Uuid
        ServerName = 'tuic'
    })

    $GoSource = Join-Path $RepoRoot 'Test\Prism\Integration\Go\tuic\main.go'
    $GoModule = Join-Path $RepoRoot 'Test\Prism\Integration\Go\go.mod'
    $StandaloneHarness = Join-Path $RepoRoot 'Test\Prism\Integration\Tuic.cpp'
    $ExeHash = (Get-FileHash -LiteralPath $PrismPath -Algorithm SHA256).Hash
    $ConfigHash = (Get-FileHash -LiteralPath $ConfigurationPath -Algorithm SHA256).Hash
    $GoHash = (Get-FileHash -LiteralPath $GoSource -Algorithm SHA256).Hash
    $GoModuleHash = (Get-FileHash -LiteralPath $GoModule -Algorithm SHA256).Hash
    $RunnerHash = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash
    $StandaloneHash = (Get-FileHash -LiteralPath $StandaloneHarness -Algorithm SHA256).Hash
    $GoBinaryHash = (Get-FileHash -LiteralPath $GoClientPath -Algorithm SHA256).Hash
    Write-Evidence "RUN_DIRECTORY=$RunDirectory"
    Write-Evidence "SOURCE_GO_SHA256=$GoHash"
    Write-Evidence "SOURCE_GO_MOD_SHA256=$GoModuleHash"
    Write-Evidence "SOURCE_RUNNER_SHA256=$RunnerHash"
    Write-Evidence "SOURCE_NATIVE_HARNESS_SHA256=$StandaloneHash"
    Write-Evidence "CONFIG_PATH=$ConfigurationPath"
    Write-Evidence "CONFIG_SHA256=$ConfigHash"
    Write-Evidence "PRISM_EXE_SHA256=$ExeHash"
    Write-Evidence "TUIC_GO_CLIENT_SHA256=$GoBinaryHash"
    Write-Evidence "CONTINUOUS_ROUNDS=$Rounds MODES_PER_ROUND=7 DIAL_ATTEMPTS_PER_CLIENT=1 RETRY=0"
    Write-Evidence "ALLOCATED_TCP_PORT=$TcpPort QUIC_UDP_PORT=$QuicPort CLIENT_UDP_PORT=$ClientUdpPort OPERATIONS_PORT=$OperationsPort"

    $AppRequest = Start-ManagedProcess ([pscustomobject]@{
        Executable = $PrismPath
        Arguments = Quote-ProcessArgument $ConfigurationPath
        WorkingDirectory = $RunDirectory
        RedirectInput = $false
        Environment = @{ PRISM_SECRET_SECRET_QUIC_PASSWORD = $Credential }
        StdoutPath = Join-Path $RunDirectory 'prism.stdout.log'
        StderrPath = Join-Path $RunDirectory 'prism.stderr.log'
        Mode = 'Prism'
    })
    $AppReadyRequest = [pscustomobject]@{
        Process = $AppRequest
        OperationsPort = $OperationsPort
        TimeoutSeconds = 45
    }
    $Health = Wait-PrismReady $AppReadyRequest
    $ActualAppPath = Get-ProcessImagePath $AppRequest
    if ($null -eq $ActualAppPath -or
        -not [string]::Equals($ActualAppPath, $PrismPath, [StringComparison]::OrdinalIgnoreCase)) {
        throw "READY process path mismatch: PID=$($AppRequest.Process.Id), actual=$ActualAppPath, expected=$PrismPath"
    }
    Write-Evidence "READY PID=$($AppRequest.Process.Id) EXE_PATH=$ActualAppPath EXE_SHA256=$ExeHash"
    Write-Evidence "READY_HEALTH ready=$($Health.value.ready) quic_ready=$($Health.value.quic_ready) socket=$($Health.value.quic_socket_ready) protocol=$($Health.value.quic_protocol_ready)"

    $ClientRequest = [pscustomobject]@{
        Executable = $GoClientPath
        WorkingDirectory = $RunDirectory
        Server = "127.0.0.1:$QuicPort"
        ServerName = 'tuic'
        Uuid = $Uuid
        LocalPort = $ClientUdpPort
        Mode = ''
        Round = 0
        Phase = ''
        Streams = 4
        Retry = 0
        Target = ''
        Sink = $null
        TimeoutMilliseconds = 60000
        StdoutPath = Join-Path $RunDirectory 'tuic-go.stdout.log'
        StderrPath = Join-Path $RunDirectory 'tuic-go.stderr.log'
    }
    $ModeOrder = @('tcp', 'bad-auth', 'tcp', 'concurrent-bidi', 'udp-only', 'auth-close', 'udp-pending')
    $PhaseOrder = @('auth-before', 'negative', 'auth-after', 'functional', 'functional', 'functional', 'pending-close')
    Write-Evidence "MODE_ORDER=$($ModeOrder -join '>')"
    for ($Round = 1; $Round -le $Rounds; ++$Round) {
        $ClientRequest.Round = $Round
        $ClientRequest.Target = ''
        $ClientRequest.Sink = $null
        Write-Evidence "ROUND_START=$Round"
        for ($ModeIndex = 0; $ModeIndex -lt $ModeOrder.Count; ++$ModeIndex) {
            $ClientRequest.Phase = $PhaseOrder[$ModeIndex]
            $ClientRequest.Mode = $ModeOrder[$ModeIndex]
            if ($ClientRequest.Mode -eq 'udp-pending') {
                do {
                    $PendingSink = [System.Net.Sockets.UdpClient]::new(
                        [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Loopback, 0))
                    $PendingPort = [int]$PendingSink.Client.LocalEndPoint.Port
                    if ($PendingPort -eq $ClientUdpPort -or $PendingPort -eq $QuicPort) {
                        $PendingSink.Dispose()
                        $PendingSink = $null
                    }
                } while ($null -eq $PendingSink)
                $ClientRequest.Target = "127.0.0.1:$PendingPort"
                $ClientRequest.Sink = $PendingSink
            }
            Invoke-TuicMode $ClientRequest
            if ($ClientRequest.Mode -eq 'udp-pending') {
                $PendingSink.Dispose()
                $PendingSink = $null
                $script:PendingReceiveTask = $null
            }
        }
        Write-Evidence "ROUND_PASS=$Round"
    }

    Write-Evidence 'APPLICATION_DRAIN_REQUESTED=true'
    $DrainAccepted = Request-ApplicationDrain ([pscustomobject]@{
        Process = $AppRequest
        OperationsPort = $OperationsPort
    })
    if (-not $DrainAccepted) {
        throw 'TUIC Operations drain request was not accepted'
    }
    $DrainCompleted = Wait-ApplicationExit ([pscustomobject]@{
        Process = $AppRequest
        TimeoutMilliseconds = 45000
    })
    if (-not $DrainCompleted) {
        throw 'Prism did not exit cleanly after Operations drain'
    }
    Write-Evidence 'APP_NATURAL_EXIT=true'
    Write-Evidence 'APP_CLEANUP_COMPLETE=true'
    Write-Evidence "APP_LOG_STDOUT=$($AppRequest.StdoutPath)"
    Write-Evidence "APP_LOG_STDERR=$($AppRequest.StderrPath)"
    Write-UdpSessionEvidence ([pscustomobject]@{
        LogPath = Join-Path $RunDirectory 'prism-tuic.log'
        Rounds = $Rounds
    })
    Write-Evidence "OWNED_CONFIG=$ConfigurationPath OWNED_LOG_DIRECTORY=$RunDirectory"
    Write-Evidence 'APPLICATION_TUIC_LEASES=not_exposed_by_Operations; covered_by=TuicConnectionLeaseTest'
    Write-Evidence 'PASS: Prism TUIC Application QUIC ingress interoperability completed'
}
catch {
    Write-Evidence "FAIL: $($_.Exception.Message)"
    throw
}
finally {
    if ($AppRequest -and -not $AppRequest.Process.HasExited) {
        try {
            Write-Evidence 'FINALLY_DRAIN_REQUESTED=true'
            [void](Request-ApplicationDrain ([pscustomobject]@{
                Process = $AppRequest
                OperationsPort = $OperationsPort
            }))
            [void]$AppRequest.Process.WaitForExit(20000)
        }
        catch {
        }
    }
    foreach ($Client in $script:OwnedGoClients) {
        try { Stop-OwnedGoClient $Client } catch { }
    }
    if ($PendingSink) {
        $PendingSink.Dispose()
        if ($script:PendingReceiveTask -and -not $script:PendingReceiveTask.IsCompleted) {
            try { $script:PendingReceiveTask.GetAwaiter().GetResult() | Out-Null } catch { }
        }
    }
    if ($AppRequest -and -not $AppRequest.Process.HasExited) {
        try {
            [void](Request-ApplicationDrain ([pscustomobject]@{
                Process = $AppRequest
                OperationsPort = $OperationsPort
            }))
            [void]$AppRequest.Process.WaitForExit(15000)
        }
        catch {
        }
    }
    if ($AppRequest -and -not $AppRequest.Process.HasExited) {
        try { Stop-OwnedPrism $AppRequest } catch { }
    }
    if ($AppRequest -and $AppRequest.Process.HasExited) {
        try { [void](Save-ProcessOutput $AppRequest) } catch { }
    }
    Retain-RunArtifacts
}
