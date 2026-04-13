# Prism 文档

欢迎使用 Prism 文档！本文档站点提供完整的使用指南、开发参考和协议规范。

---

## 文档导航

### 用户指南

面向 Prism 使用者的入门和配置指南。

| 文档 | 说明 |
|------|------|
| [快速开始](tutorial/getting-started.md) | 5 分钟快速上手 Prism |
| [配置详解](tutorial/configuration.md) | 配置参数说明与性能调优 |
| [故障排除](tutorial/troubleshooting.md) | 常见问题排查与解决方案 |
| [常见问题](tutorial/faq.md) | FAQ 问答集 |

### 开发者指南

面向代码贡献者和深度开发者的技术文档。

| 文档 | 说明 |
|------|------|
| [架构设计](manual/architecture.md) | 架构能力分析、时序链、关键实现细节 |
| [模块设计](manual/modules.md) | front、worker、session、dispatch、pipeline、resolve、account 模块详解 |
| [运行时流程](manual/runtime.md) | Session 创建、协议检测、隧道转发、连接关闭流程 |
| [路由与分发](manual/routing.md) | Registry 单例模式、Handler 工厂、协议处理器注册 |
| [API 参考](manual/api.md) | 公开 API 入口与头文件组织 |
| [文档验真](manual/validation.md) | 文档验真规则与源码对应表 |

### 多路复用协议

smux/yamux 多路复用协议的设计与交互文档。

| 文档 | 说明 |
|------|------|
| [多路复用设计](multiplex/overview.md) | 模块架构、core/duct/parcel 组件、配置结构 |
| [smux 协议交互](multiplex/smux.md) | smux v1 帧格式、sing-mux 握手、与 mihomo 客户端完整交互流程 |
| [yamux 协议交互](multiplex/yamux.md) | yamux 帧格式、窗口流量控制、流创建两种路径、与 mihomo 客户端完整交互流程 |

### 协议文档

各协议的详细实现文档。

| 文档 | 说明 |
|------|------|
| [HTTP 协议](protocols/http.md) | HTTP 请求在 Prism 内的调用流程 |
| [SOCKS5 协议](protocols/socks5.md) | SOCKS5 协议握手、地址解析、连接建立 |
| [Trojan 协议](protocols/trojan.md) | Trojan 协议 SSL 握手、凭据验证、隧道转发 |
| [VLESS 协议](protocols/vless.md) | VLESS 二进制头部、UUID 认证、多路复用 |
| [Shadowsocks 2022](protocols/shadowsocks.md) | SS2022 AEAD 加密、BLAKE3 密钥派生、抗重放 |
| [TLS 协议](protocols/tls.md) | TLS 握手、内层协议探测、证书配置 |

### 参考资料

配置结构体、上下文、依赖关系等参考文档。

| 文档 | 说明 |
|------|------|
| [配置结构体](reference/config-structure.md) | config、server_context、worker_context、session_context 结构体详解 |
| [依赖关系](reference/dependencies.md) | 目录依赖图、运行时调用图、模块职责说明 |
| [架构图表](reference/diagrams/) | Mermaid 格式的运行时流程图和依赖关系图 |

### 示例配置

常用配置示例。

| 文档 | 说明 |
|------|------|
| [Clash 配置示例](examples/clash/) | Clash 代理客户端配置示例 |

### 项目管理

项目开发进度和贡献指南。

| 文档 | 说明 |
|------|------|
| [开发进度](project/progress.md) | 项目概况、版本状态、路线图、更新日志 |

---

## 快速链接

### 按角色查找

- **普通用户**：[快速开始](tutorial/getting-started.md) → [配置详解](tutorial/configuration.md) → [常见问题](tutorial/faq.md)
- **运维人员**：[配置详解](tutorial/configuration.md) → [故障排除](tutorial/troubleshooting.md)
- **开发者**：[架构设计](manual/architecture.md) → [模块设计](manual/modules.md) → [API 参考](manual/api.md)

### 按主题查找

- **协议实现**：[HTTP](protocols/http.md) | [SOCKS5](protocols/socks5.md) | [Trojan](protocols/trojan.md) | [VLESS](protocols/vless.md) | [Shadowsocks 2022](protocols/shadowsocks.md)
- **多路复用**：[架构设计](multiplex/overview.md) | [smux 交互](multiplex/smux.md) | [yamux 交互](multiplex/yamux.md)
- **核心流程**：[运行时流程](manual/runtime.md) | [路由与分发](manual/routing.md)
- **配置参考**：[配置结构体](reference/config-structure.md) | [依赖关系](reference/dependencies.md)

---

## 项目概况

Prism 是一个基于 Modern C++（C++23）的高性能代理引擎：

- **协议支持**：HTTP/HTTPS、SOCKS5、Trojan、VLESS、Shadowsocks 2022
- **技术栈**：Boost.Asio 协程、OpenSSL、PMR 内存管理
- **特性**：负载均衡、连接池、DNS 缓存、账户认证

详细开发进度请参阅 [开发进度](project/progress.md)。
