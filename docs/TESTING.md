# 构建与测试

## 构建

项目使用 CMake 3.23+ 和 C++23。依赖由 CMake FetchContent 管理。首次配置示例：

```powershell
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
```

在 Windows PowerShell 中，每次构建前先检查上海时间。08:00–22:00 使用 16 个线程，22:00–08:00 使用 1 个线程：

```powershell
Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz'
cmake --build build --config Release --target Prism -j 16
```

夜间命令把 `-j 16` 改为 `-j 1`。产物为 `build/src/Prism.exe`（Windows）或 `build/src/Prism`（Linux）。

## 测试

默认启用功能测试。测试代码位于 `Test/Prism/`，共用 runner 和 fixture 位于 `Test/TestSupport/`。可先按当前 CTest 注册名筛选：

```powershell
ctest --test-dir build -R 'Configuration|Socks5' --output-on-failure
```

全量 CTest 示例：

```powershell
ctest --test-dir build --output-on-failure -j 1 --timeout 30
```

改动影响的 focused tests 通过后，再执行更大范围回归。CTest discovery 成功不等于测试已运行；构建成功也不等于真实请求、互操作或性能通过。

## 可选验收层

| CMake 选项 | 用途 | 默认值 |
| --- | --- | --- |
| `PRISM_BUILD_TESTING` | 配置 Prism 功能测试 | `ON` |
| `PRISM_ENABLE_INTEROP` | 注册外部客户端互操作矩阵，需要 PowerShell | `OFF` |
| `PRISM_ENABLE_BENCHMARK` | 启用已接线的协议基准、Integration/Layering 承载基准，以及启用实验测试时的实验性能目标；完整 `Test/Prism/Performance` 目录未接入 | `OFF` |
| `PRISM_ENABLE_STRESS` | 启用已接线的部分协议压力目标；完整 `Test/Prism/Stress` 目录未接入 | `OFF` |
| `PRISM_ENABLE_EXPERIMENT_TESTS` | 启用独立实验测试 | `OFF` |
| `PRISM_ENABLE_COVERAGE` | GCC/Clang 覆盖率编译 | `OFF` |
| `PRISM_ENABLE_ASAN` | GCC/Clang AddressSanitizer | `OFF` |

互操作矩阵由 `scripts/interop/Run-Matrix.ps1` 驱动；仅打开 CMake 选项不会代替实际运行和结果检查。性能、压力、互操作、Linux 和全量测试应分别记录命令、配置、源码版本、退出码与输出。

`Test/Prism/Performance` 与 `Test/Prism/Stress` 源码保留，但两个完整目录都未加入 `Test/Prism/CMakeLists.txt`。`PRISM_ENABLE_BENCHMARK` 单独控制已接线的协议基准及 `Integration/Layering` 承载基准；`PRISM_ENABLE_STRESS` 单独控制已接线的协议压力目标。这两个选项都不会把对应的完整目录接入构建。`Test/Experiments/Prism/Performance` 是独立实验路径，先由 `PRISM_ENABLE_EXPERIMENT_TESTS` 接入；其性能目标还要求 `PRISM_ENABLE_BENCHMARK=ON`。

`perf` 与 `stress` 标签按测试源文件名规则设置，不是可选 benchmark/stress 目标的完整清单；要确认实际注册目标，请以当前构建树的 CTest discovery 结果为准。

`Test/Prism/Integration/Matrix/RunCurrentMihomoCase.ps1`、`RunCurrentMihomoUdpCase.ps1` 和 `RunCurrentMihomoQuicCase.ps1` 是手动本机入口，目前没有注册为 CTest 用例，也不由 `Run-Matrix.ps1` 调用。它们要求 PowerShell 7.4 或更新版本；Windows PowerShell 5.1 和 PowerShell 7.0–7.3 不支持这些脚本使用的 `Start-Process -Environment` 参数。

实跑前可先执行 `Test/Prism/Integration/Matrix/RunnerContractTest.ps1 -StaticOnly` 与
`Test/Prism/Integration/Matrix/RunnerContractQuicTest.ps1`。前者校验 runner
的回环、随机端口、NoProxy、controller 证据与受控清理约束，后者只使用合成结果验证
QUIC 契约正反例；两者都不启动 Mihomo、Prism 或网络服务。

混合矩阵的独立实跑入口为
`Test/Prism/Integration/Matrix/RunCurrentMixedCase.ps1`。使用仓库内的
`PrismConfigurationMatrix.json`、`PrismClient.yaml` 和
`H:\Tools\Mihomo\1.19.32\mihomo.exe` 时，先确认脚本帮助中的参数，并将
`-CaseDirectory` 指定为单段标签；runner 会创建 `H:\PrismInteropResults-<token>-<label>`，
使用 `127.0.0.1`、随机端口和独立 controller。TCP、UDP、QUIC 专项入口仍分别使用三个
`RunCurrentMihomo*Case.ps1`，QUIC 入口只接受两个已固定的仓库内协议模板。
四个入口的端口参数均可用 `0`（默认值）请求自动分配；显式传入的正整数保持调用者选择。
runner 会核对 Prism 与 Mihomo 的凭据、受控 SNI/Servername，并让 Hysteria2 的
`Quic.Alpn` 与 Mihomo outbound 的 `alpn` 完全一致。

这些 runner 的 `-CaseDirectory` 参数接收由字母、数字、点、下划线和连字符组成的短标签，例如 `tcp-smoke`，不接收文件系统路径。每次运行都会在 `H:\` 根目录下创建新的 `PrismInteropResults-<GUID>-<标签>` 私有结果目录；目录 ACL 只授予当前用户、SYSTEM 和 Administrators。模板、证书、私钥和可执行文件必须解析为本地固定磁盘上的普通文件，不能经过 UNC、映射网络驱动器或 reparse point。完整完成的运行才写出 `results.json`；确认受管进程退出后，脚本会脱敏并保留日志。未完成的尝试可能没有 `results.json`；若无法确认进程已退出，活动日志和相关配置会保留，并将清理标记为失败。模板文件保持只读。

QUIC 响应正文只暂存在该 case 的 `target-root` 中，正常清理时随目录删除。QUIC Mihomo 用例只有在请求收到 HTTP 200、响应正文逐字节匹配本地 target fixture，并观察到 Prism 对应协议的服务端成功日志后才通过。
