# Preview 配置操作指南

本页聚焦配置文件的日常修改、secret 注入和部署核对。权威字段列表、schema、默认模板及当前接线边界统一维护在 [Preview 配置](../preview/configuration.md)；Preview 启动/组合边界见 [Preview 总览](../preview/README.md)，跨模块责任见[仓库架构](../ARCHITECTURE.md)。

## 从匹配版本的模板开始

使用与程序来自同一 revision/build 的 `PreviewConfiguration.json`。模板是完整配置的起点；保留完整根对象，再修改实际需要的字段。不要把旧版配置中的 `agent`、`pool`、`protocol`、`multiplex` 或 `stealth` 结构拼进 Preview JSON。

把部署副本放在独立目录，保留一份可回滚版本。正式启动时建议显式传入配置文件的位置，避免依赖当前 shell 工作目录或误用可执行文件旁边的构建模板：

```powershell
& 'C:\Prism\PrismPreview.exe' 'C:\Prism\config\PreviewConfiguration.json'
```

程序把第一个位置参数作为配置路径；没有 `--config` 开关。未传参数时默认读取可执行文件同目录下的 `PreviewConfiguration.json`。证书和私钥等 Native TLS 相对路径以配置文件目录为基准。

## 修改前的核对顺序

1. 确认本次要启用的入口类型、地址、端口和协议能力。
2. 为每个 protocol 实例核对 `Id`、内建实现和必需能力；检查 binding 引用的 protocol/carrier 是否存在。
3. 核对 account credential 与 protocol 要求的格式。Carrier 的 path、Host、SNI、ALPN 和 Native TLS 文件属于不同配置责任，不要把它们当账户认证。
4. 限制监听到预期接口。只有在确认认证、防火墙和运维暴露后才扩大地址范围。
5. 保留修改前配置并记录新文件的 SHA-256；一次只改少量相关项，便于定位失败字段。

有关类型化模式选项、Mux/UDP 能力、引用校验和当前生产接线，请直接查阅[权威配置页](../preview/configuration.md)，避免复制过期示例。

## 用 SecretRef 注入凭据

入口把 `SecretRef` 转成环境变量名：`PRISM_PREVIEW_SECRET_` 前缀后，reference 的字母转大写，数字保留，其它字符换成下划线。比如：

```powershell
$env:PRISM_PREVIEW_SECRET_PROXY_PASSWORD = '实际密钥'
& 'C:\Prism\PrismPreview.exe' 'C:\Prism\config\PreviewConfiguration.json'
```

```bash
export PRISM_PREVIEW_SECRET_PROXY_PASSWORD='实际密钥'
./PrismPreview /etc/prism/PreviewConfiguration.json
```

环境变量值为空时视为未提供。规范化会造成名称碰撞，因此为每个 secret reference 选择唯一、稳定的名字。Secret 是进程环境的一部分，应按部署主机的权限管理；不要在诊断文本、工单截图或版本库中暴露它。

## 让程序验证配置

当前入口没有独立的 `--check` 模式。启动程序时会进入配置读取、schema/reference/capability 校验和 runtime 装配；若失败，保存完整 stderr 中的错误代码、字段路径和说明，再按权威配置页逐项检查。不要只凭 JSON 语法检查成功就认定 listener/carrier 已接线。

字段存在、能够解析和被当前生产路径消费是不同状态。涉及 Routes、Statistics、Operations、HotReload 或特定 carrier 时，先读[配置页](../preview/configuration.md)中相应的接线与证据说明；只有当前启动/请求行为提供的证据能支持部署结论。

## 修改后的请求验证

记录配置文件 hash、程序 hash、源码 revision、启动时间及 READY 中实际端口/readiness。用配置匹配的外部 client 分别执行：

- 正确凭据与错误凭据；
- 预期可达目标和受控失败目标；
- 若启用 UDP、QUIC、TLS carrier 或多 stream 场景，执行相应的真实数据面和关闭测试。

至少等一次真实请求完成后再回收实例。单次启动、READY 或 configuration test 只能支持它自身覆盖的层级，不能替代运行链路和互操作验证。

## 参考

- [Preview 配置（schema 与当前合同）](../preview/configuration.md)
- [Preview 总览](../preview/README.md)
- [部署指南](deployment.md)
- [仓库架构](../ARCHITECTURE.md)
