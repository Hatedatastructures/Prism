# 快速开始

## 环境

- CMake 3.23 或更新版本。
- C++23 编译器；项目依赖由 CMake FetchContent 获取。
- Windows 使用项目支持的 MinGW 工具链；Linux 使用 GCC 13+。

首次配置和构建使用仓库统一的 `build/`：

```powershell
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz'
cmake --build build --config Release --target Prism -j 16
```

每次构建前检查上海时间。08:00–22:00 使用 `-j 16`，22:00–08:00 使用 `-j 1`。完整限制和测试命令见[构建与测试](../TESTING.md)。

## 启动

构建输出位于 `build/src/`。Windows 运行 `build/src/Prism.exe`，Linux 运行 `build/src/Prism`。未提供参数时，程序读取可执行文件同目录的 `PrismConfiguration.json`；也可以显式提供配置文件路径：

```powershell
build/src/Prism.exe path/to/PrismConfiguration.json
```

CMake 构建后会把 `Prism/Application/Configuration/PrismConfiguration.json` 复制到可执行文件旁。启动前请检查监听地址、端口、凭据引用和证书文件路径。不要把真实凭据写入提交或日志。

## 验证

从 `docs/TESTING.md` 选择当前 CTest 注册名运行 focused test。构建或测试通过不代表真实客户端互操作和性能验收完成。
