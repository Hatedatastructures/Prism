# 构建与测试

## 第一次编译和运行测试

如果你只想构建 Prism 服务端并试用 SOCKS5 示例，请按[快速开始](Tutorial/GettingStarted.md)操作。本页讲的是开发者如何编译功能测试并运行 CTest。

下面几个名词的区别是：

- **配置（configure）**：CMake 读取项目，检查编译器和依赖，并生成本机的构建文件。
- **构建（build）**：编译源码并生成可执行文件。指定 `--target Prism` 只构建服务端，不会因此生成全部测试程序。
- **发现测试（discovery）**：CTest 从构建目录收集当前可运行的测试名称；发现出来不代表测试已经运行。
- **运行测试**：CTest 启动已构建的测试程序并检查退出结果。

在仓库根目录配置项目：

```powershell
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
```

要构建服务端和默认启用的功能测试目标，构建默认目标，不要只指定 `Prism`：

```powershell
Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz'
# 上海时间 08:00–22:00：
cmake --build build --config Release -j 16
# 上海时间 22:00–08:00：将线程数改成 -j 1。
```

`-j` 是并行编译线程数。项目要求每次构建前检查当前时间：白天最多使用 16 个线程，夜间只能用 1 个线程。首次构建可能需要 CMake 下载依赖，耗时会比后续构建长。

构建完成后先看 CTest 当前发现了什么，再选择运行范围：

```powershell
ctest --test-dir build -N
ctest --test-dir build -R 'Configuration|Socks5' --output-on-failure -j 1 --timeout 30
```

第一条只列出测试，不执行测试。第二条中的 `-R` 按测试名称的正则表达式筛选；`--output-on-failure` 只在失败时打印详细输出；`--timeout 30` 限制单个用例的最长运行时间为 30 秒。筛选名称需要以 `ctest -N` 的当前输出为准。

确认改动相关用例通过后，按项目验收要求再运行全量功能测试：

```powershell
ctest --test-dir build --output-on-failure -j 1 --timeout 30
```

如果 CTest 报告找不到测试程序，先确认你构建的是默认目标、而不是只构建了 `Prism`，并确认 `build/` 是当前源码配置生成的构建目录。不要把旧构建目录里的测试结果当成本次源码的结果。

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

互操作矩阵由 `Scripts/Interop/RunMatrix.ps1` 驱动；仅打开 CMake 选项不会代替实际运行和结果检查。性能、压力、互操作、Linux 和全量测试应分别记录命令、配置、源码版本、退出码与输出。

`Test/Prism/Performance` 与 `Test/Prism/Stress` 源码保留，但两个完整目录都未加入 `Test/Prism/CMakeLists.txt`。`PRISM_ENABLE_BENCHMARK` 单独控制已接线的协议基准及 `Integration/Layering` 承载基准；`PRISM_ENABLE_STRESS` 单独控制已接线的协议压力目标。这两个选项都不会把对应的完整目录接入构建。`Test/Experiments/Prism/Performance` 是独立实验路径，先由 `PRISM_ENABLE_EXPERIMENT_TESTS` 接入；其性能目标还要求 `PRISM_ENABLE_BENCHMARK=ON`。

`perf` 与 `stress` 标签按测试源文件名规则设置，不是可选 benchmark/stress 目标的完整清单；要确认实际注册目标，请以当前构建树的 CTest discovery 结果为准。

`Test/Prism/Integration/Matrix/RunCurrentMihomoCase.ps1`、`MihomoUdp.ps1` 和 `MihomoQuic.ps1` 是手动本机入口，目前没有注册为 CTest 用例，也不由 `RunMatrix.ps1` 调用。它们要求 Windows 上的 PowerShell 7.4 或更新版本；Windows PowerShell 5.1 和 PowerShell 7.0–7.3 不支持这些脚本使用的 `Start-Process -Environment` 参数。

实跑前可先执行 `Test/Prism/Integration/Matrix/RunnerContractTest.ps1 -StaticOnly` 与
`Test/Prism/Integration/Matrix/QuicRunnerTest.ps1`。前者校验 runner
的回环、随机端口、NoProxy、controller 证据与受控清理约束，后者只使用合成结果验证
QUIC 契约正反例；两者都不启动 Mihomo、Prism 或网络服务。

混合矩阵的独立实跑入口为
`Test/Prism/Integration/Matrix/RunCurrentMixedCase.ps1`。它读取仓库根目录的
`PrismConfigurationMatrix.json` 和 `PrismClient.yaml`，并通过 `-MihomoExecutable`
指定本机 Mihomo 程序。运行前确认脚本帮助中的参数，并将 `-CaseDirectory` 设为短标签：

```powershell
$env:PRISM_MIHOMO = '<本机 mihomo.exe 的完整路径>'
pwsh -File .\Test\Prism\Integration\Matrix\RunCurrentMixedCase.ps1 `
    -PrismTemplate .\PrismConfigurationMatrix.json `
    -MihomoTemplate .\PrismClient.yaml `
    -CaseDirectory mixed-smoke `
    -MihomoExecutable $env:PRISM_MIHOMO
```

runner 固定在 `H:\` 根目录创建 `PrismInteropResults-<token>-<label>`；当前脚本没有结果根目录参数。没有本地 H 盘的贡献者不能按下面命令直接运行，需要先准备该目录或另行修改 runner 实现。

每次运行会创建唯一的 `PrismInteropResults-<token>-<label>` 目录，
使用 `127.0.0.1`、随机端口和独立 controller。TCP、UDP、QUIC 专项入口仍分别使用三个
`RunCurrentMihomo*Case.ps1`，QUIC 入口只接受两个已固定的仓库内协议模板。
四个入口的端口参数均可用 `0`（默认值）请求自动分配；显式传入的正整数保持调用者选择。
runner 会核对 Prism 与 Mihomo 的凭据、受控 SNI/Servername，并让 Hysteria2 的
`Quic.Alpn` 与 Mihomo outbound 的 `alpn` 完全一致。

这些 runner 的 `-CaseDirectory` 参数接收由字母、数字、点、下划线和连字符组成的短标签，例如 `tcp-smoke`，不接收文件系统路径。每次运行都会在 `H:\` 根目录下创建新的 `PrismInteropResults-<GUID>-<标签>` 私有结果目录；目录 ACL 只授予当前用户、SYSTEM 和 Administrators。模板、证书、私钥和可执行文件必须解析为本地固定磁盘上的普通文件，不能经过 UNC、映射网络驱动器或 reparse point。完整完成的运行才写出 `results.json`；确认受管进程退出后，脚本会脱敏并保留日志。未完成的尝试可能没有 `results.json`；若无法确认进程已退出，活动日志和相关配置会保留，并将清理标记为失败。模板文件保持只读。

QUIC 响应正文只暂存在该 case 的 `target-root` 中，正常清理时随目录删除。QUIC Mihomo 用例只有在请求收到 HTTP 200、响应正文逐字节匹配本地 target fixture，并观察到 Prism 对应协议的服务端成功日志后才通过。
