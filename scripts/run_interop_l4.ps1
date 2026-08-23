#Requires -Version 7.0
<#
.SYNOPSIS
    L4 生产对拍一键脚本：启动生产 Prism.exe，依次运行 preview 客户端互操作用例。
.DESCRIPTION
    流程：起 Prism.exe（configuration.json）→ 轮询入站端口可连 → 逐协议跑
    InteropPrismL4（echo 模式 ×5 + socks5 authfail）→ finally 收敛 Prism 进程。
    前置：build/ 目录已完成构建（build/src/Prism.exe 与 InteropPrismL4.exe 存在）。
.PARAMETER PrismExe
    生产可执行文件路径（相对仓库根）。
.PARAMETER InteropExe
    InteropPrismL4 测试可执行文件路径（相对仓库根）。
.PARAMETER Config
    Prism 配置文件路径。
.PARAMETER Addr
    Prism 入站地址（须与 configuration.json 一致）。
.PARAMETER WaitSecs
    等待 Prism 监听就绪的秒数。
.EXAMPLE
    pwsh scripts/run_interop_l4.ps1
.NOTES
    退出码：0 = 全部 PASS，1 = 存在 FAIL 或前置缺失。Prism 进程在 finally 中强制收敛。
#>
param(
    [string]$PrismExe = "build/src/Prism.exe",
    [string]$InteropExe = "build/tests/preview/integration/InteropPrismL4.exe",
    [string]$Config = "src/configuration.json",
    [string]$Addr = "127.0.0.1:18081",
    [int]$WaitSecs = 15
)
$ErrorActionPreference = "Stop"

$root = (Resolve-Path "$PSScriptRoot/..").Path
$prismPath = Join-Path $root $PrismExe
$interopPath = Join-Path $root $InteropExe
$configPath = Join-Path $root $Config

foreach ($f in @($prismPath, $interopPath, $configPath)) {
    if (-not (Test-Path $f)) {
        Write-Host "FAIL: 缺少前置文件 $f" -ForegroundColor Red
        exit 1
    }
}

$listenPort = [int]($Addr.Split(':')[1])
Write-Host "== 启动 Prism（$configPath，入站 $Addr）"
$proc = Start-Process -FilePath $prismPath -ArgumentList "`"$configPath`"" -PassThru `
                      -WorkingDirectory $root -WindowStyle Hidden
$failed = 0
try {
    $ready = $false
    for ($i = 0; $i -lt $WaitSecs * 10; ++$i) {
        if ($proc.HasExited) { throw "Prism 提前退出（code=$($proc.ExitCode)）" }
        Start-Sleep -Milliseconds 100
        $c = New-Object Net.Sockets.TcpClient
        try {
            $c.Connect("127.0.0.1", $listenPort)
            $ready = $c.Connected
        } catch {} finally { $c.Dispose() }
        if ($ready) { break }
    }
    if (-not $ready) { throw "Prism 未在 ${WaitSecs}s 内监听 127.0.0.1:$listenPort" }
    Write-Host "== Prism 就绪，开始对拍"

    foreach ($proto in @("socks5", "ss2022", "vless", "trojan", "vmess")) {
        Write-Host "-- [$proto] echo"
        & $interopPath -addr $Addr -proto $proto -mode echo
        if ($LASTEXITCODE -ne 0) {
            Write-Host "   FAIL: $proto echo" -ForegroundColor Red
            ++$failed
        }
    }

    Write-Host "-- [socks5] authfail"
    & $interopPath -addr $Addr -proto socks5 -mode authfail
    if ($LASTEXITCODE -ne 0) {
        Write-Host "   FAIL: socks5 authfail" -ForegroundColor Red
        ++$failed
    }

    if ($failed -eq 0) {
        Write-Host "== L4 interop 全部 PASS" -ForegroundColor Green
    } else {
        Write-Host "== L4 interop 失败 $failed 例" -ForegroundColor Red
    }
}
finally {
    if ($proc -and -not $proc.HasExited) {
        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    }
}
exit ($failed -eq 0 ? 0 : 1)
