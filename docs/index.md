# Forward Engine Agent 文档

## 概述
本文档基于 forward-engine 源码事实编写，旨在帮助开发者理解 agent 模块的设计与实现。

## 文档目录

### 入门
- [overview.md](agent/overview.md) - 运行时概览：从进程启动到连接转发的完整时序链

### 核心概念
- [config.md](agent/config.md) - 配置与上下文：config、server_context、worker_context、session_context
- [architecture.md](agent/architecture.md) - 架构能力边界：已实现 vs 未实现的能力

### 模块设计
- [modules.md](agent/modules.md) - 模块设计：front、reactor、connection、dispatch、pipeline、distribution、account

### 运行机制
- [runtime.md](agent/runtime.md) - 运行时流程：session 生命周期、协议检测、隧道转发
- [routing.md](agent/routing.md) - 路由与分发：registry、handler、协议处理器

### 架构图
- [dependencies.md](agent/dependencies.md) - 依赖关系：物理目录依赖、运行时调用图
- [diagrams/runtime.mmd](agent/diagrams/runtime.mmd) - 运行时流程图（Mermaid）
- [diagrams/dependencies.mmd](agent/diagrams/dependencies.mmd) - 目录依赖图（Mermaid）

### API 参考
- [api.md](agent/api.md) - 公开 API：按 agent.hpp 组织的 API 入口

### 维护
- [validation.md](agent/validation.md) - 文档验真：验真规则与源码对应表

## 关键事实

### 已实现能力
- HTTP/HTTPS 代理（CONNECT 方法、普通请求转发）
- SOCKS5 代理（CONNECT、UDP_ASSOCIATE 命令）
- TLS 终止（握手后作为 HTTPS 处理）
- 反向代理（reverse_map 路由）
- 正向代理 Fallback（直连失败后转发）
- 负载均衡（基于评分的 Worker 选择）

### 未接入能力
- **Trojan 协议**：`config.trojan` 字段存在，但 `register_handlers()` 未注册 Trojan handler

### 行为差异
- listener 绑定 IPv4 + addressable.port（不使用 addressable.host）
- `async_forward` 先直连后 fallback 到 positive endpoint
- `reverse_map` 目标更偏向 IP literal
