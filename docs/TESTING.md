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

默认启用功能测试。测试代码位于 `tests/Prism/`，共用 runner 和 fixture 位于 `tests/TestSupport/`。可先按当前 CTest 注册名筛选：

```powershell
ctest --test-dir build -R 'Configuration|Socks5' --output-on-failure
```

全量 CTest 示例：

```powershell
ctest --test-dir build --output-on-failure -j 1 --timeout 60
```

改动影响的 focused tests 通过后，再执行更大范围回归。CTest discovery 成功不等于测试已运行；构建成功也不等于真实请求、互操作或性能通过。

## 可选验收层

| CMake 选项 | 用途 | 默认值 |
| --- | --- | --- |
| `PRISM_BUILD_TESTING` | 配置 Prism 功能测试 | `ON` |
| `PRISM_ENABLE_INTEROP` | 注册外部客户端互操作矩阵，需要 PowerShell | `OFF` |
| `PRISM_ENABLE_BENCHMARK` | 启用性能用例，CTest 标签 `perf` | `OFF` |
| `PRISM_ENABLE_STRESS` | 启用压力用例，CTest 标签 `stress` | `OFF` |
| `PRISM_ENABLE_EXPERIMENT_TESTS` | 启用独立实验测试 | `OFF` |
| `PRISM_ENABLE_COVERAGE` | GCC/Clang 覆盖率编译 | `OFF` |
| `PRISM_ENABLE_ASAN` | GCC/Clang AddressSanitizer | `OFF` |

互操作矩阵由 `scripts/interop/Run-Matrix.ps1` 驱动；仅打开 CMake 选项不会代替实际运行和结果检查。性能、压力、互操作、Linux 和全量测试应分别记录命令、配置、源码版本、退出码与输出。
