# 启动 Prism（显式配置路径）→ 运行协议兼容性测试（真实 quic-go 客户端）→ 停止 Prism
# 用法: powershell -File run_go_test.ps1 -GoExe <go-test-exe> -PrismExe <Prism.exe> -Config <configuration.json>
param(
    [Parameter(Mandatory = $true)][string]$GoExe,
    [Parameter(Mandatory = $true)][string]$PrismExe,
    [Parameter(Mandatory = $true)][string]$Config
)

$ResolvedPrismPath = (Resolve-Path -LiteralPath $PrismExe -ErrorAction Stop).Path
$ResolvedGoPath = (Resolve-Path -LiteralPath $GoExe -ErrorAction Stop).Path
$PrismName = [System.IO.Path]::GetFileName($ResolvedPrismPath)
if ($PrismName -ne "Prism.exe") {
    throw "Expected a Prism.exe path, got '$ResolvedPrismPath'"
}

$NormalizePath = {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) {
        return ""
    }
    return [System.IO.Path]::GetFullPath($Path).TrimEnd('\').ToLowerInvariant()
}

$ExpectedPrismPath = & $NormalizePath $ResolvedPrismPath

function Get-OwnedPrismProcess {
    param(
        [System.Diagnostics.Process]$ProcessValue,
        [string]$ExpectedPath,
        [scriptblock]$Normalize
    )
    if ($null -eq $ProcessValue) {
        return $null
    }
    $Snapshot = Get-CimInstance Win32_Process -Filter "ProcessId=$($ProcessValue.Id)" -ErrorAction SilentlyContinue
    if ($null -eq $Snapshot -or $Snapshot.Name -ne "Prism.exe") {
        return $null
    }
    $ActualPath = & $Normalize $Snapshot.ExecutablePath
    if ($ActualPath -ne $ExpectedPath) {
        return $null
    }
    return $Snapshot
}

$ExistingPrism = @(Get-CimInstance Win32_Process -Filter "Name='Prism.exe'" -ErrorAction SilentlyContinue)
if ($ExistingPrism.Count -gt 0) {
    $Details = $ExistingPrism | ForEach-Object {
        "PID=$($_.ProcessId) Path=$($_.ExecutablePath) CommandLine=$($_.CommandLine)"
    }
    throw "A pre-existing Prism.exe process is running; refusing to terminate it: $($Details -join '; ')"
}

$prism = $null
try {
    $logRoot = Join-Path $env:TEMP ("prism_gotest_" + [System.Guid]::NewGuid().ToString("N"))
    $stdoutLog = "$logRoot.stdout.log"
    $stderrLog = "$logRoot.stderr.log"
    Write-Output "PRISM_LOG=$stdoutLog"
    Write-Output "PRISM_ERROR_LOG=$stderrLog"
    $prism = Start-Process -FilePath $ResolvedPrismPath -ArgumentList $Config -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput $stdoutLog -RedirectStandardError $stderrLog
    $GoName = [System.IO.Path]::GetFileNameWithoutExtension($ResolvedGoPath)
    $RequiresTcp = $GoName -match 'vmess'

    # VMess/Sing-VMess 使用 TCP；Hysteria2/TUIC 使用 QUIC gateway。
    # QUIC readiness 要求日志、进程身份和连续稳定采样；Windows 没有
    # Get-NetUDPEndpoint 时退回日志条件，但仍保留连续采样。
    $ready = $false
    $ReadySamples = 0
    for ($i = 0; $i -lt 20; $i++) {
        Start-Sleep -Milliseconds 500
        if ($null -eq (Get-OwnedPrismProcess $prism $ExpectedPrismPath $NormalizePath)) {
            if ($prism.HasExited) {
                Write-Error "Prism exited early with code $($prism.ExitCode)"
            }
            else {
                Write-Error "Prism process identity changed while waiting for readiness"
            }
            exit 1
        }

        $tcp = netstat -ano | Select-String "TCP" | Select-String ":8081" |
            Select-String "LISTENING"
        $GatewayReady = $false
        if (Test-Path -LiteralPath $stdoutLog) {
            $GatewayReady = (Get-Content -LiteralPath $stdoutLog -Raw -ErrorAction SilentlyContinue) -match 'quic gateway listening'
        }

        if ($RequiresTcp) {
            $ReadyCondition = [bool]$tcp
        }
        else {
            $UdpObserved = $false
            $UdpReady = $false
            try {
                $UdpObserved = $true
                $UdpReady = @(Get-NetUDPEndpoint -LocalPort 8081 -ErrorAction Stop |
                    Where-Object { $_.OwningProcess -eq $prism.Id }).Count -gt 0
            }
            catch {
                $UdpObserved = $false
            }
            $ReadyCondition = $GatewayReady -and (!$UdpObserved -or $UdpReady)
        }

        if ($ReadyCondition) {
            $ReadySamples++
            if ($ReadySamples -ge 3) {
                $ready = $true
                break
            }
        }
        else {
            $ReadySamples = 0
        }
    }
    if (-not $ready) {
        Write-Error "Prism did not start listening within 10s"
        exit 1
    }

    & $ResolvedGoPath
    $GoExitCode = $LASTEXITCODE
    exit $GoExitCode
}
finally {
    if ($prism) {
        $Owned = Get-OwnedPrismProcess $prism $ExpectedPrismPath $NormalizePath
        if ($Owned) {
            Stop-Process -Id $prism.Id -Force -ErrorAction SilentlyContinue
            try {
                Wait-Process -Id $prism.Id -Timeout 10 -ErrorAction Stop
            }
            catch {
                if (-not $prism.HasExited) {
                    Write-Error "Owned Prism PID $($prism.Id) did not exit after cleanup"
                }
            }
        }
        elseif (-not $prism.HasExited) {
            Write-Error "Refusing cleanup because Prism PID $($prism.Id) no longer matches the owned executable path"
        }
    }
}
