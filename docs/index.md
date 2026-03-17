# ForwardEngine 文档

欢迎使用 ForwardEngine 文档！本文档站点提供完整的使用指南、开发参考和协议规范。

---

## 文档导航

### 用户指南

面向 ForwardEngine 使用者的入门和配置指南。

| 文档 | 说明 |
|------|------|
| [快速开始](user-guide/getting-started.md) | 5 分钟快速上手 ForwardEngine |
| [配置详解](user-guide/configuration.md) | 配置参数说明与性能调优 |
| [故障排除](user-guide/troubleshooting.md) | 常见问题排查与解决方案 |
| [常见问题](user-guide/faq.md) | FAQ 问答集 |

### 开发者指南

面向代码贡献者和深度开发者的技术文档。

| 文档 | 说明 |
|------|------|
| [架构设计](developer-guide/architecture.md) | 架构能力分析、时序链、关键实现细节 |
| [模块设计](developer-guide/modules.md) | front、reactor、connection、dispatch、pipeline、distribution、account 模块详解 |
| [运行时流程](developer-guide/runtime.md) | Session 创建、协议检测、隧道转发、连接关闭流程 |
| [路由与分发](developer-guide/routing.md) | Registry 单例模式、Handler 工厂、协议处理器注册 |
| [API 参考](developer-guide/api.md) | 公开 API 入口与头文件组织 |
| [文档验真](developer-guide/validation.md) | 文档验真规则与源码对应表 |

### 协议文档

各协议的详细实现文档。

| 文档 | 说明 |
|------|------|
| [HTTP 协议](protocols/http.md) | HTTP 请求在 ForwardEngine 内的调用流程 |
| [SOCKS5 协议](protocols/socks5.md) | SOCKS5 协议握手、地址解析、连接建立 |
| [Trojan 协议](protocols/trojan.md) | Trojan 协议 SSL 握手、凭据验证、隧道转发 |

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

- **普通用户**：[快速开始](user-guide/getting-started.md) → [配置详解](user-guide/configuration.md) → [常见问题](user-guide/faq.md)
- **运维人员**：[配置详解](user-guide/configuration.md) → [故障排除](user-guide/troubleshooting.md)
- **开发者**：[架构设计](developer-guide/architecture.md) → [模块设计](developer-guide/modules.md) → [API 参考](developer-guide/api.md)

### 按主题查找

- **协议实现**：[HTTP](protocols/http.md) | [SOCKS5](protocols/socks5.md) | [Trojan](protocols/trojan.md)
- **核心流程**：[运行时流程](developer-guide/runtime.md) | [路由与分发](developer-guide/routing.md)
- **配置参考**：[配置结构体](reference/config-structure.md) | [依赖关系](reference/dependencies.md)

---

## 项目概况

ForwardEngine 是一个基于 Modern C++（C++23）的高性能代理引擎：

- **协议支持**：HTTP/HTTPS、SOCKS5、Trojan
- **技术栈**：Boost.Asio 协程、BoringSSL、PMR 内存管理
- **特性**：负载均衡、连接池、DNS 缓存、账户认证

详细开发进度请参阅 [开发进度](project/progress.md)。
