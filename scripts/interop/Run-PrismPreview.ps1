param(
    [string]$PrismPreviewExe = '',
    [Alias('ConfigurationPath')][string]$Config = '',
    [string]$OutputDirectory = '',
    [int]$Port = 18081,
    [int]$ReadyTimeoutSeconds = 30,
    [string]$ReadyPattern = '(?m)^PrismPreview READY tcp_port=(?<port>\d+) udp_port=(?<udp_port>\d+) udp_ready=(?<udp_ready>true|false) quic_ready=(?<quic_ready>true|false) generation=(?<generation>\d+)(?:\s+quic_socket_ready=(?:true|false)\s+quic_handshake_ready=(?:true|false)\s+quic_protocol_ready=(?:true|false))?\s*$',
    [string]$SmokeClient = '',
    [string]$SmokeProtocol = 'socks5',
    [string]$SmokeTarget = '',
    [switch]$LibraryOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-PreviewEvidenceStatus {
    param(
        [Parameter(Mandatory = $true)][bool]$Ready,
        [Parameter(Mandatory = $true)][object[]]$Cases,
        [switch]$DependencyMissing
    )

    if ($DependencyMissing) {
        return 'environment-unavailable'
    }
    if (-not $Ready) {
        return 'protocol-failure'
    }
    if ($Cases.Count -eq 0 -or @($Cases | Where-Object { $_.status -ne 'pass' }).Count -gt 0) {
        return 'preview-only-blocked'
    }
    return 'pass'
}

function Get-PreviewModeObservations {
    param([AllowEmptyString()][string]$Text)

    return [ordered]@{
        strict = [bool]($Text -match '(?im)\b(strict|deterministic)\b')
        fallback = [bool]($Text -match '(?im)(?:^|[^A-Za-z0-9_])fallback(?:$|[^A-Za-z0-9_])|production_fallback')
    }
}

function Get-PreviewReadinessEvidence {
    param(
        [AllowEmptyString()][string]$Output,
        [Parameter(Mandatory = $true)][int]$ExpectedPort,
    [string]$Pattern = '(?m)^PrismPreview READY tcp_port=(?<port>\d+) udp_port=(?<udp_port>\d+) udp_ready=(?<udp_ready>true|false) quic_ready=(?<quic_ready>true|false) generation=(?<generation>\d+)(?:\s+quic_socket_ready=(?:true|false)\s+quic_handshake_ready=(?:true|false)\s+quic_protocol_ready=(?:true|false))?\s*$'
    )

    $Evidence = [ordered]@{
        ready_log = $false
        ready_port = $false
        tcp_port = $null
        udp_port = $null
        udp_ready = $false
        quic_ready = $false
        ready_generation = $null
    }
    $Match = [regex]::Match($Output, $Pattern)
    if (-not $Match.Success) {
        return $Evidence
    }

    $TcpPort = [int]$Match.Groups['port'].Value
    $Evidence.ready_log = $true
    $Evidence.ready_port = ($TcpPort -eq $ExpectedPort)
    $Evidence.tcp_port = $TcpPort
    $Evidence.udp_port = [int]$Match.Groups['udp_port'].Value
    $Evidence.udp_ready = $Match.Groups['udp_ready'].Value -eq 'true'
    $Evidence.quic_ready = $Match.Groups['quic_ready'].Value -eq 'true'
    $Evidence.ready_generation = [int64]$Match.Groups['generation'].Value
    return $Evidence
}

function Get-PreviewHashEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$ExecutablePath,
        [Parameter(Mandatory = $true)][string]$ConfigPath
    )

    $ExecutableInfo = Get-Item -LiteralPath $ExecutablePath -ErrorAction Stop
    $ConfigInfo = Get-Item -LiteralPath $ConfigPath -ErrorAction Stop
    return [ordered]@{
        algorithm = 'SHA256'
        executable_sha256 = (Get-FileHash -LiteralPath $ExecutablePath -Algorithm SHA256).Hash
        configuration_sha256 = (Get-FileHash -LiteralPath $ConfigPath -Algorithm SHA256).Hash
        executable_size_bytes = [int64]$ExecutableInfo.Length
        configuration_size_bytes = [int64]$ConfigInfo.Length
    }
}

function Remove-PreviewTemporaryDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return [ordered]@{ status = 'already-absent'; path = $Path; error = '' }
    }
    try {
        Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
        if (Test-Path -LiteralPath $Path) {
            return [ordered]@{ status = 'failed'; path = $Path; error = 'directory still exists after removal' }
        }
        return [ordered]@{ status = 'completed'; path = $Path; error = '' }
    } catch {
        return [ordered]@{ status = 'failed'; path = $Path; error = $_.Exception.Message }
    }
}

function Resolve-PreviewEvidencePath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$RepoRoot
    )

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return [System.IO.Path]::GetFullPath($Path)
    }
    return [System.IO.Path]::GetFullPath((Join-Path $RepoRoot $Path))
}

function Test-PreviewTcpPort {
    param(
        [Parameter(Mandatory = $true)][string]$TargetHost,
        [Parameter(Mandatory = $true)][int]$Port
    )

    $Client = [System.Net.Sockets.TcpClient]::new()
    try {
        $Async = $Client.BeginConnect($TargetHost, $Port, $null, $null)
        if (-not $Async.AsyncWaitHandle.WaitOne(500)) {
            return $false
        }
        $Client.EndConnect($Async)
        return $true
    } catch {
        return $false
    } finally {
        $Client.Dispose()
    }
}

function Test-PreviewOwnedTcpPort {
    param(
        [Parameter(Mandatory = $true)][int]$ProcessId,
        [Parameter(Mandatory = $true)][int]$Port
    )

    try {
        $Endpoints = @(Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction Stop)
        return @($Endpoints | Where-Object { $_.OwningProcess -eq $ProcessId }).Count -gt 0
    } catch {
        return $false
    }
}

function Stop-PreviewProcess {
    param(
        [Parameter(Mandatory = $true)][System.Diagnostics.Process]$Process,
        [int]$WaitMilliseconds = 5000
    )

    if ($Process.HasExited) {
        return 'already-exited'
    }

    try {
        if ($IsWindows) {
            & taskkill.exe /PID $Process.Id /T *> $null
        } else {
            & kill -TERM $Process.Id *> $null
        }
    } catch {
    }

    $Deadline = [DateTime]::UtcNow.AddMilliseconds($WaitMilliseconds)
    while (-not $Process.HasExited -and [DateTime]::UtcNow -lt $Deadline) {
        Start-Sleep -Milliseconds 100
    }
    if (-not $Process.HasExited) {
        Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
        return 'forced'
    }
    return 'graceful'
}

function Invoke-PreviewSmokeCase {
    param(
        [Parameter(Mandatory = $true)][string]$Executable,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$Mode,
        [Parameter(Mandatory = $true)][string]$OutputDirectory,
        [int]$TimeoutSeconds = 30
    )

    $SafeMode = $Mode -replace '[^A-Za-z0-9_.-]', '_'
    $StdoutPath = Join-Path $OutputDirectory ("smoke-{0}.stdout.log" -f $SafeMode)
    $StderrPath = Join-Path $OutputDirectory ("smoke-{0}.stderr.log" -f $SafeMode)
    $Watch = [System.Diagnostics.Stopwatch]::StartNew()
    $Process = $null
    $TimedOut = $false
    try {
        $Process = Start-Process -FilePath $Executable -ArgumentList $Arguments -PassThru -WindowStyle Hidden `
            -RedirectStandardOutput $StdoutPath -RedirectStandardError $StderrPath
        while (-not $Process.HasExited -and $Watch.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
            Start-Sleep -Milliseconds 100
        }
        if (-not $Process.HasExited) {
            $TimedOut = $true
            Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
        }
        $ExitCode = if ($TimedOut) { 124 } else { $Process.ExitCode }
        $Combined = ((Get-Content -LiteralPath $StdoutPath -Raw -ErrorAction SilentlyContinue),
                     (Get-Content -LiteralPath $StderrPath -Raw -ErrorAction SilentlyContinue) -join "`n")
        return [ordered]@{
            mode = $Mode
            status = if ($ExitCode -eq 0) { 'pass' } else { 'protocol-failure' }
            exit_code = $ExitCode
            command = ($Executable + ' ' + ($Arguments -join ' '))
            stdout = $StdoutPath
            stderr = $StderrPath
            output = $Combined
        }
    } catch {
        return [ordered]@{
            mode = $Mode
            status = 'environment-unavailable'
            exit_code = 127
            command = ($Executable + ' ' + ($Arguments -join ' '))
            stdout = $StdoutPath
            stderr = $StderrPath
            output = $_.Exception.Message
        }
    } finally {
        $Watch.Stop()
        if ($Process -and -not $Process.HasExited) {
            Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
        }
    }
}

if ($LibraryOnly) {
    return
}

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $RepoRoot 'build/preview-runner'
}
$OutputDirectory = Resolve-PreviewEvidencePath -Path $OutputDirectory -RepoRoot $RepoRoot
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$TempDirectory = Join-Path $OutputDirectory ('.tmp-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $TempDirectory -Force | Out-Null
$PublicStdoutPath = Join-Path $OutputDirectory 'prism-preview.stdout.log'
$PublicStderrPath = Join-Path $OutputDirectory 'prism-preview.stderr.log'

$Record = [ordered]@{
    schema = 'prism.preview-runner.v1'
    status = 'pending'
    mode = 'preview-only'
    executable = $PrismPreviewExe
    config = $Config
    command = $null
    source_sha = $null
    dirty = $null
    compiler = $null
    platform = [System.Runtime.InteropServices.RuntimeInformation]::OSDescription
    executable_sha256 = $null
    configuration_sha256 = $null
    hash_algorithm = 'SHA256'
    executable_size_bytes = $null
    configuration_size_bytes = $null
    port = $Port
    tcp_port = $null
    udp_port = $null
    udp_ready = $false
    quic_ready = $false
    pid = $null
    process_exit_code = $null
    ready_log = $false
    ready_port = $false
    ready_generation = $null
    mode_observations = [ordered]@{ strict = $false; fallback = $false }
    cases = @()
    shutdown = 'not-attempted'
    cleanup = 'pending'
    exit_code = 0
    cleanup_error = ''
    temporary_evidence_directory = $null
    stdout = $PublicStdoutPath
    stderr = $PublicStderrPath
    readiness = [ordered]@{
        log = $false
        tcp_socket = $false
        generation = $null
    }
    reason = ''
    generated_utc = [DateTime]::UtcNow.ToString('o')
}
$ServerProcess = $null
$StdoutPath = Join-Path $TempDirectory 'prism-preview.stdout.log'
$StderrPath = Join-Path $TempDirectory 'prism-preview.stderr.log'
$ExitCode = 0

try {
    if ([string]::IsNullOrWhiteSpace($PrismPreviewExe) -or [string]::IsNullOrWhiteSpace($Config)) {
        $Record.reason = 'PrismPreview executable and config are required'
        $Record.status = 'environment-unavailable'
        $ExitCode = 2
    } else {
        $ExePath = Resolve-PreviewEvidencePath -Path $PrismPreviewExe -RepoRoot $RepoRoot
        $ConfigPath = Resolve-PreviewEvidencePath -Path $Config -RepoRoot $RepoRoot
        $Record.executable = $ExePath
        $Record.config = $ConfigPath
        $Record.command = "`"$ExePath`" `"$ConfigPath`""
        $Record.source_sha = (& git -C $RepoRoot rev-parse HEAD 2>$null).Trim()
        $Record.dirty = [bool]((@(& git -C $RepoRoot status --porcelain 2>$null)).Count -gt 0)
        $CompilerCommand = Get-Command g++ -ErrorAction SilentlyContinue
        if ($CompilerCommand) {
            $Record.compiler = (& $CompilerCommand.Source --version 2>$null | Select-Object -First 1).Trim()
        }
        if (-not (Test-Path -LiteralPath $ExePath -PathType Leaf)) {
            $Record.reason = "PrismPreview executable not found: $ExePath"
            $Record.status = 'environment-unavailable'
            $ExitCode = 2
        } elseif (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
            $Record.reason = "PrismPreview config not found: $ConfigPath"
            $Record.status = 'environment-unavailable'
            $ExitCode = 2
        } else {
            $HashEvidence = Get-PreviewHashEvidence -ExecutablePath $ExePath -ConfigPath $ConfigPath
            $Record.executable_sha256 = $HashEvidence.executable_sha256
            $Record.configuration_sha256 = $HashEvidence.configuration_sha256
            $Record.executable_size_bytes = $HashEvidence.executable_size_bytes
            $Record.configuration_size_bytes = $HashEvidence.configuration_size_bytes
            $ServerProcess = Start-Process -FilePath $ExePath -ArgumentList @('"' + $ConfigPath + '"') `
                -WorkingDirectory $RepoRoot -PassThru -WindowStyle Hidden `
                -RedirectStandardOutput $StdoutPath -RedirectStandardError $StderrPath
            $Record.pid = $ServerProcess.Id
            $Deadline = [DateTime]::UtcNow.AddSeconds($ReadyTimeoutSeconds)
            while (-not $ServerProcess.HasExited -and [DateTime]::UtcNow -lt $Deadline) {
                $ServerOutput = ((Get-Content -LiteralPath $StdoutPath -Raw -ErrorAction SilentlyContinue),
                                 (Get-Content -LiteralPath $StderrPath -Raw -ErrorAction SilentlyContinue) -join "`n")
                $Readiness = Get-PreviewReadinessEvidence -Output $ServerOutput `
                    -ExpectedPort $Port -Pattern $ReadyPattern
                $Record.ready_log = $Readiness.ready_log
                $Record.tcp_port = $Readiness.tcp_port
                $Record.udp_port = $Readiness.udp_port
                $Record.udp_ready = $Readiness.udp_ready
                $Record.quic_ready = $Readiness.quic_ready
                $Record.ready_generation = $Readiness.ready_generation
                $SocketReady = $false
                if ($Readiness.ready_port) {
                    $SocketReady = Test-PreviewOwnedTcpPort -ProcessId $ServerProcess.Id -Port $Readiness.tcp_port
                    if (-not $SocketReady) {
                        $SocketReady = Test-PreviewTcpPort -TargetHost '127.0.0.1' -Port $Readiness.tcp_port
                    }
                }
                $Record.ready_port = $Readiness.ready_port -and $SocketReady
                $Record.readiness.log = $Record.ready_log
                $Record.readiness.tcp_socket = $Record.ready_port
                $Record.readiness.generation = $Record.ready_generation
                if ($Record.ready_log -and $Record.ready_port) {
                    break
                }
                Start-Sleep -Milliseconds 100
            }

            if (-not ($Record.ready_log -and $Record.ready_port)) {
                $Record.reason = 'PrismPreview did not produce a ready log and listening port within the timeout'
                $Record.status = 'protocol-failure'
                $ExitCode = 1
            } else {
                $ClientPath = $SmokeClient
                if ([string]::IsNullOrWhiteSpace($ClientPath)) {
                    $Candidates = @(
                        (Join-Path $RepoRoot 'build/tests/Preview/integration/InteropPrismL4.exe'),
                        (Join-Path $RepoRoot 'build/tests/Preview/integration/InteropPrismL4')
                    )
                    $ClientPath = $Candidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
                } else {
                    $ClientPath = Resolve-PreviewEvidencePath -Path $ClientPath -RepoRoot $RepoRoot
                }

                if ([string]::IsNullOrWhiteSpace($ClientPath) -or -not (Test-Path -LiteralPath $ClientPath -PathType Leaf)) {
                    $Record.status = 'preview-only-blocked'
                    $Record.cases = @([ordered]@{
                        mode = 'echo/authfail'
                        status = 'environment-unavailable'
                        exit_code = 127
                        reason = 'No local Preview smoke/interop client was available'
                    })
                    $Record.reason = 'Preview server was ready, but no local smoke client was available'
                } else {
                    $Address = "127.0.0.1:$Port"
                    $Cases = @()
                    $SmokeModes = if ($SmokeProtocol -eq 'http') {
                        @('echo')
                    } else {
                        @('echo', 'authfail')
                    }
                    foreach ($Mode in $SmokeModes) {
                        $SmokeArguments = if ($SmokeProtocol -eq 'http') {
                            @('-mode', 'client', '-addr', $Address)
                        } else {
                            @('-addr', $Address, '-proto', $SmokeProtocol, '-mode', $Mode)
                        }
                        if ($SmokeProtocol -eq 'http' -and -not [string]::IsNullOrWhiteSpace($SmokeTarget)) {
                            $SmokeArguments += @('-target', $SmokeTarget)
                        }
                        $Cases += Invoke-PreviewSmokeCase -Executable $ClientPath `
                            -Arguments $SmokeArguments `
                            -Mode $Mode -OutputDirectory $OutputDirectory
                    }
                    $Record.cases = @($Cases)
                    $AllOutput = (($Cases | ForEach-Object { $_.output }) -join "`n") + "`n" +
                        (Get-Content -LiteralPath $StdoutPath -Raw -ErrorAction SilentlyContinue) + "`n" +
                        (Get-Content -LiteralPath $StderrPath -Raw -ErrorAction SilentlyContinue)
                    $Record.mode_observations = Get-PreviewModeObservations -Text $AllOutput
                }
            }
        }
    }
} catch {
    $Record.status = 'protocol-failure'
    $Record.reason = $_.Exception.Message
    $ExitCode = 1
} finally {
    if ($ServerProcess) {
        $Record.shutdown = Stop-PreviewProcess -Process $ServerProcess
        try {
            $Record.process_exit_code = $ServerProcess.ExitCode
        } catch {
            $Record.process_exit_code = $null
        }
    }

    foreach ($EvidencePair in @(
        @{ Source = $StdoutPath; Destination = $PublicStdoutPath },
        @{ Source = $StderrPath; Destination = $PublicStderrPath }
    )) {
        if (Test-Path -LiteralPath $EvidencePair.Source -PathType Leaf) {
            try {
                Copy-Item -LiteralPath $EvidencePair.Source -Destination $EvidencePair.Destination -Force -ErrorAction Stop
            } catch {
                $Record.cleanup_error = $_.Exception.Message
            }
        }
    }

    if ($Record.status -eq 'environment-unavailable') {
        $Record.status = 'environment-unavailable'
    } elseif ($Record.status -eq 'protocol-failure') {
        $Record.status = 'protocol-failure'
    } else {
        $Record.status = Get-PreviewEvidenceStatus -Ready:($Record.ready_log -and $Record.ready_port) -Cases @($Record.cases)
    }

    if ($Record.status -eq 'protocol-failure' -and (Test-Path -LiteralPath $TempDirectory)) {
        $Record.cleanup = 'preserved-failure-evidence'
        $Record.temporary_evidence_directory = $TempDirectory
    } else {
        $CleanupResult = Remove-PreviewTemporaryDirectory -Path $TempDirectory
        $Record.cleanup = $CleanupResult.status
        if ($CleanupResult.status -eq 'failed') {
            $Record.cleanup_error = $CleanupResult.error
        }
    }
    if ($Record.status -eq 'protocol-failure') {
        $ExitCode = 1
    }
    $Record.exit_code = $ExitCode
    $Record.generated_utc = [DateTime]::UtcNow.ToString('o')
    try {
        $Record | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'summary.json') -Encoding UTF8
    } catch {
        $Record.cleanup = 'failed'
        $Record.cleanup_error = $_.Exception.Message
    }
}

Write-Output ("PrismPreview evidence: status={0}, ready_log={1}, tcp_port={2}, udp_port={3}, udp_ready={4}, quic_ready={5}, cases={6}" -f `
        $Record.status, $Record.ready_log, $Record.ready_port, $Record.udp_port,
        $Record.udp_ready, $Record.quic_ready, @($Record.cases).Count)
exit $ExitCode
