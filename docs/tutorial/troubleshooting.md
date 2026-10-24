# 故障排查

## 监听地址或端口不可用

确认程序读取的是预期配置文件；检查绑定地址是否属于当前主机、端口是否已被其他进程占用，以及是否配置了冲突的 listener。使用 `127.0.0.1` 只接受本机连接；使用通配地址前先确认防火墙与网络暴露范围。

## 配置无法启动

从启动错误中的配置路径和字段路径开始检查。确认 JSON 语法、schema 版本、字段类型、引用 ID 和必填凭据来源；不要用旧版配置字段名套用当前 schema。

## 凭据解析失败

检查 `SecretRef` 规范化后的 `PRISM_SECRET_<NAME>` 环境变量是否存在且非空。环境变量属于启动 Prism 的进程；在终端设置变量不会自动更新已经运行的服务。

## Web catalog 或页面资源缺失

默认 `Prism` target 不会生成 Web catalog。先在仓库根目录安装 Web 依赖并显式构建 `PrismWeb`：

```powershell
npm ci --prefix Web
cmake --build build --config Release --target PrismWeb -j 16
```

构建后再检查 `build/Web/catalog.json`。22:00–08:00 构建时将 `-j 16` 改为 `-j 1`。最后确认 `Operations.WebDirectory` 指向包含 catalog 和页面资源的完整目录；相对路径按配置文件位置解析。

## 测试与运行结果不同

确认测试命令匹配当前 CTest 注册名，并记录正在使用的二进制和配置。CTest 注册或源码静态检查不证明真实请求、外部客户端互操作、压力或性能结果；这些验收层应分别执行和记录。命令见[构建与测试](../TESTING.md)。
