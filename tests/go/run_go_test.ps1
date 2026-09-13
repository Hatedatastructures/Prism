# 启动 Prism（显式配置路径）→ 运行协议兼容性测试（真实 quic-go 客户端）→ 停止 Prism
# 用法: powershell -File run_go_test.ps1 -GoExe <go-test-exe> -PrismExe <Prism.exe> -Config <configuration.json>
param(
    [Parameter(Mandatory = $true)][string]$GoExe,
    [Parameter(Mandatory = $true)][string]$PrismExe,
    [Parameter(Mandatory = $true)][string]$Config
)

# 清理残留 Prism 进程（前序测试可能未完全退出）
Get-Process -Name Prism -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1

$prism = $null
try {
    $logRoot = Join-Path $env:TEMP ("prism_gotest_" + [System.Guid]::NewGuid().ToString("N"))
    $stdoutLog = "$logRoot.stdout.log"
    $stderrLog = "$logRoot.stderr.log"
    Write-Output "PRISM_LOG=$stdoutLog"
    Write-Output "PRISM_ERROR_LOG=$stderrLog"
    $prism = Start-Process -FilePath $PrismExe -ArgumentList $Config -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput $stdoutLog -RedirectStandardError $stderrLog
    $GoName = [System.IO.Path]::GetFileNameWithoutExtension($GoExe)
    $RequiresTcp = $GoName -match 'vmess'
    # 按 client 数据面等待对应 listener：VMess/Sing-VMess 使用 TCP，
    # Hysteria2/TUIC 使用 QUIC gateway。Windows UDP netstat 行不稳定，
    # QUIC client 使用 Prism 自己输出的 gateway-ready 日志作为就绪信号。
    $ready = $false
    for ($i = 0; $i -lt 20; $i++) {
        Start-Sleep -Milliseconds 500
        if ($prism.HasExited) {
            Write-Error "Prism exited early with code $($prism.ExitCode)"
            exit 1
        }
        $tcp = netstat -ano | Select-String "TCP" | Select-String ":8081" |
            Select-String "LISTENING"
        $GatewayReady = $false
        if (Test-Path -LiteralPath $stdoutLog) {
            $GatewayReady = (Get-Content -LiteralPath $stdoutLog -Raw -ErrorAction SilentlyContinue) -match 'quic gateway listening'
        }
        if (($RequiresTcp -and $tcp) -or (-not $RequiresTcp -and $GatewayReady)) {
            $ready = $true
            break
        }
    }
    if (-not $ready) {
        Write-Error "Prism did not start listening within 10s"
        exit 1
    }
    # QUIC 握手栈就绪需要额外时间（ngtcp2 会话初始化），等待后再启动 Go 客户端
    Start-Sleep -Milliseconds 800
    & $GoExe
    exit $LASTEXITCODE
}
finally {
    if ($prism -and -not $prism.HasExited) {
        Stop-Process -Id $prism.Id -Force -ErrorAction SilentlyContinue
    }
}
