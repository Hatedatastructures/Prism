# Preview 构建与分层验收

本文说明可复现的构建/测试入口和报告边界，不记录某一工作树的通过结果。开始构建前需获得当前任务授权，并按 `AGENTS.md` 检查上海时间。各验证记录必须绑定实际输入，不得从本页命令或 target 列表推断执行结果。

## 构建入口

使用仓库唯一的 `build/` 目录，Preview 默认程序 target 为 `PrismPreview`。首次配置和程序构建示例：

```powershell
cmake -B build -DCMAKE_BUILD_TYPE=Release
Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz'
cmake --build build --config Release --target PrismPreview -j 16
```

上海时间 08:00–22:00 使用 `-j 16`；22:00–08:00 强制 `-j 1`，构建前必须再次检查时间。程序输出到 `build/src/PrismPreview.exe`（Windows）或 `build/src/PrismPreview`（Linux）；CMake 将 Preview 配置模板复制到程序同目录。具体目标和唯一 CXX 入口见 `Preview/Application/CMakeLists.txt`。

Preview 生产实现按仓库规则保持 header-only，最终入口 `Preview/Application/Main/PreviewMain.hpp` 和 `Preview/Application/Startup/Start.hpp` 由 CMake 作为 CXX source 编译，不应被其它生产 header 或测试 include。不得用其他构建目录、旧二进制或 CMake 的历史 target graph 代替当前 `build/` 输入。

## 测试组织与调用

Preview 测试位于 `tests/Preview/`，其 CMake 子目录按配置、Account、Application、Boundary、Composition、协议、Runtime、Integration、Performance 与 Stress 等 owner 注册。先查询当前注册名，再运行精确范围：

```powershell
ctest --test-dir build -N -R '<当前注册名正则>'
ctest --test-dir build --output-on-failure -j 1 --timeout 30 -R '<当前注册名正则>'
```

源码修改后先构建对应测试 target，再运行该范围；全量测试按仓库规则使用 `ctest --test-dir build --output-on-failure -j 1 --timeout 30`。测试位置或注册成功不代表测试已执行，也不代表通过。异步测试应等待被测 owner、半关闭和真实关闭/drain 结束，不能通过停止事件循环掩盖遗留活动。

## 必须分开报告的验收层

1. **源码与结构：** 接口/所有权、include 方向、CMake target 方向、大小写和风格门禁。
2. **构建：** 当前 source/config 输入对应的 configure、compile、link 退出结果。
3. **Focused tests：** 当前注册名、实际 target、运行进程退出和原始结果。
4. **全量测试：** 当前 discovery、禁用用例、参与用例、失败/未运行和退出码。
5. **真实请求：** listener、认证正反、payload、字节计数、半关闭、cancel、close/drain 和自然退出。
6. **互操作与性能：** 第三方实现或同输入 benchmark，明确算法、负载和测量范围。

每层只报告它实际证明的内容。运行、互操作或性能记录需绑定源码版本、配置版本、二进制 hash、命令、时间、退出码和原始输出；源码变更、配置变更或 ABI 变化后不能复用旧二进制结论。历史记录保留原日期与范围，不升级成当前验收。
