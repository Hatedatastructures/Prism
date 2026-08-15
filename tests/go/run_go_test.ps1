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
    $log = Join-Path $env:TEMP ("prism_gotest_" + [System.Guid]::NewGuid().ToString("N") + ".log")
    Write-Output "PRISM_LOG=$log"
    $prism = Start-Process -FilePath $PrismExe -ArgumentList $Config -PassThru -WindowStyle Hidden -RedirectStandardOutput $log -RedirectStandardError $log
    # 轮询等待监听就绪（UDP 8081 由 Prism 绑定；以 TCP 监听为就绪信号）
    $ready = $false
    for ($i = 0; $i -lt 20; $i++) {
        Start-Sleep -Milliseconds 500
        if ($prism.HasExited) {
            Write-Error "Prism exited early with code $($prism.ExitCode)"
            exit 1
        }
        # 等待 QUIC gateway UDP 8081 就绪（netstat UDP 行无 LISTENING 标记，按进程 PID 匹配 UDP 行）
        $udp = netstat -ano | Select-String "UDP" | Select-String "8081" | Select-String ($prism.Id.ToString())
        if ($udp) {
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
