# 项目开发进度与贡献指南

本文档记录了 ForwardEngine 的开发状态、路线图以及如何参与贡献。无论你是想了解项目进展，还是希望贡献代码，这里都能找到需要的信息。

## 项目概况

- **项目名称**：ForwardEngine
- **项目类型**：高性能代理引擎
- **核心技术**：C++23、Boost.Asio 协程、BoringSSL、PMR 内存管理
- **开发状态**：**稳定可用**，核心功能已完成
- **当前版本**：v0.8.0
- **最后更新**：2026年3月17日
- **主要依赖**：Boost(system)、BoringSSL、spdlog、glaze

---

## 当前版本状态（v0.8.0）

### 已完成的核心功能

#### 1. 代理协议支持

| 协议 | 完成度 | 状态 | 说明 |
|------|--------|------|------|
| **HTTP/HTTPS** | 100% | ✅ 完成 | HTTP 正向代理与 HTTPS `CONNECT` 隧道 |
| **SOCKS5 TCP** | 100% | ✅ 完成 | RFC 1928，支持 CONNECT 命令 |
| **SOCKS5 UDP** | 100% | ✅ 完成 | 支持 UDP ASSOCIATE 命令 |
| **TLS 终止** | 100% | ✅ 完成 | 服务端 TLS 握手，解密后按 HTTP 处理 |
| **Trojan 协议** | 100% | ✅ 完成 | Trojan over TLS 协议已接入运行链 |

#### 2. 核心架构模块

| 模块 | 完成度 | 说明 |
|------|--------|------|
| **协程驱动架构** | 100% | 基于 `net::awaitable` 的异步模型，无回调地狱 |
| **智能连接池** | 100% | TCP 连接复用，支持僵尸检测、空闲超时、端点缓存上限 |
| **协议自动识别** | 100% | 动态检测 HTTP / SOCKS5 / TLS 协议 |
| **路由分发系统** | 100% | 支持正向代理、反向代理、直连三种模式 |
| **双向隧道转发** | 100% | 优化的数据转发算法，支持优雅退出 |
| **负载均衡** | 100% | 基于评分的 Worker 选择，过载检测与滞后机制 |
| **DNS 缓存** | 100% | TCP/UDP 双模式解析，请求合并，TTL 管理 |
| **账户认证** | 100% | 写时复制、无锁读取、连接数限制、流量统计 |

#### 3. 基础设施

| 模块 | 完成度 | 说明 |
|------|--------|------|
| **内存管理** | 100% | PMR 策略，全局内存池 + 帧分配器 |
| **日志系统** | 100% | 基于 spdlog 的异步日志，支持文件轮转和级别控制 |
| **配置系统** | 100% | JSON 配置文件，支持证书、连接池、认证等配置 |
| **测试框架** | 100% | 完整的单元测试和集成测试覆盖 |

---

## 模块完成度详情

### Agent 模块 (`include/forward-engine/agent/`)

| 子模块 | 组件 | 完成度 | 说明 |
|--------|------|--------|------|
| **front** | listener | ✅ 100% | 监听端口，接受连接，亲和性计算，反压机制 |
| **front** | balancer | ✅ 100% | 加权评分选择，过载检测，全局反压 |
| **worker** | worker | ✅ 100% | 工作线程核心，管理 io_context、连接池、路由表 |
| **worker** | launch | ✅ 100% | 会话启动与跨线程连接分发 |
| **worker** | stats | ✅ 100% | 负载统计，EMA 平滑延迟测量 |
| **worker** | tls | ✅ 100% | TLS 上下文管理，证书加载 |
| **session** | session | ✅ 100% | 会话生命周期管理，协议检测分发 |
| **dispatch** | handler | ✅ 100% | 协议处理器抽象基类 |
| **dispatch** | registry | ✅ 100% | 处理器注册表，工厂模式 |
| **dispatch** | handlers | ✅ 100% | HTTP/SOCKS5/TLS/Unknown 处理器实现 |
| **pipeline** | protocols | ✅ 100% | HTTP/SOCKS5/TLS 协议处理管道 |
| **pipeline** | primitives | ✅ 100% | dial、preview、original_tunnel 原语 |
| **resolve** | router | ✅ 100% | 统一路由入口，整合仲裁器、解析器 |
| **resolve** | arbiter | ✅ 100% | 反向路由、直连路由、数据报路由 |
| **resolve** | tcpcache | ✅ 100% | TCP DNS 解析，缓存，请求合并 |
| **resolve** | udpcache | ✅ 100% | UDP DNS 解析，缓存 |
| **resolve** | coalescer | ✅ 100% | DNS 请求合并机制 |
| **account** | directory | ✅ 100% | 账户目录，写时复制，无锁读取 |
| **account** | entry | ✅ 100% | 账户运行时状态，连接数限制 |
| **account** | lease | ✅ 100% | RAII 连接数管理 |

### Protocol 模块 (`include/forward-engine/protocol/`)

| 协议 | 完成度 | 说明 |
|------|--------|------|
| **HTTP** | ✅ 100% | HTTP/1.1 请求/响应解析和序列化 |
| **SOCKS5** | ✅ 100% | RFC 1928 完整实现，支持 CONNECT、UDP ASSOCIATE |
| **Trojan** | ✅ 100% | Trojan over TLS 协议，密码验证 + 流量伪装 |
| **协议探测** | ✅ 100% | 动态检测 HTTP/SOCKS5/TLS 协议类型 |

### Channel 模块 (`include/forward-engine/channel/`)

#### transport 子模块

| 组件 | 完成度 | 说明 |
|------|--------|------|
| **transmission** | ✅ 100% | 传输层抽象接口 |
| **reliable** | ✅ 100% | TCP 可靠传输实现 |
| **unreliable** | ✅ 100% | UDP 不可靠传输实现 |
| **secure** | ✅ 100% | TLS 安全传输 |

#### pool 子模块

| 组件 | 完成度 | 说明 |
|------|--------|------|
| **source** | ✅ 100% | TCP 连接池，栈式缓存 + 僵尸检测 |

#### loader 子模块

| 组件 | 完成度 | 说明 |
|------|--------|------|
| **connector** | ✅ 100% | Socket 适配器，支持预读数据注入 |

### Memory 模块 (`include/forward-engine/memory/`)

| 组件 | 完成度 | 说明 |
|------|--------|------|
| **system** | ✅ 100% | 全局内存池系统 |
| **pooled_object** | ✅ 100% | 对象池基类模板 |
| **frame_arena** | ✅ 100% | 帧分配器，极速分配 |
| **PMR 容器** | ✅ 100% | string、vector、map 等别名 |

---

## 已知问题与限制

### 协议相关

| 限制 | 状态 | 说明 |
|------|------|------|
| SOCKS5 认证 | ⚠️ 待完成 | 仅支持无认证模式，用户名密码认证待实现 |

### 配置相关

| 限制 | 状态 | 说明 |
|------|------|------|
| Listener 绑定 | ⚠️ 待优化 | 当前仅绑定 IPv4，不支持 addressable.host |
| 反向代理热更新 | ⚠️ 待完成 | 修改配置后需重启生效 |
| reverse_map 域名 | ⚠️ 待优化 | 目标地址更偏向 IP Literal |

### 平台兼容性

| 平台 | 状态 | 说明 |
|------|------|------|
| Windows 11 | ✅ 已测试 | MinGW 工具链 |
| Linux | ⚠️ 需适配 | 部分路径配置需调整 |
| macOS | ⚠️ 基本支持 | 未全面测试 |
| ARM 架构 | ❌ 未验证 | 尚未测试 |

---

## 路线图规划

### 短期目标（v0.9.0）

| 任务 | 优先级 | 状态 |
|------|--------|------|
| SOCKS5 用户名密码认证 | 中 | 📋 计划中 |
| Listener 支持 IPv6 和 host 绑定 | 中 | 📋 计划中 |
| JSON 序列化接口完善 | 低 | 🔄 80% 完成 |

### 中期目标（v1.0.0）

| 任务 | 说明 |
|------|------|
| 配置热更新 | 修改配置后无需重启 |
| 性能监控接口 | 暴露连接数、流量、性能指标 |
| Docker 镜像 | 提供官方 Docker 镜像 |
| 包管理器支持 | vcpkg / Conan 集成 |

### 长期愿景

| 任务 | 说明 |
|------|------|
| 插件生态系统 | 支持第三方插件扩展 |
| 集群部署 | 多节点负载均衡和故障转移 |
| Web 管理界面 | 可视化配置和监控 |
| 协议扩展 | VMess、Shadowsocks 等协议支持 |

---

## 测试与验证

### 测试套件

```bash
# 运行所有测试
ctest --test-dir build_release --output-on-failure

# 关键测试用例
./build_release/test/session_test      # 会话生命周期
./build_release/test/socks5_test       # SOCKS5 协议
./build_release/test/connection_test   # 连接池复用
```

### 端到端验证

```bash
# HTTP/HTTPS 代理
curl -v -x http://127.0.0.1:8081 http://www.baidu.com
curl -v -x http://127.0.0.1:8081 https://www.baidu.com

# SOCKS5 代理
curl -v -x socks5://127.0.0.1:8081 http://www.baidu.com
```

---

## 质量指标

### 代码质量

- **编译警告**：零警告策略（`-Wall -Wextra -Werror`）
- **静态分析**：定期运行 Clang-Tidy 检查
- **代码审查**：所有更改必须通过 Pull Request 审查

### 性能指标

| 指标 | 目标 | 说明 |
|------|------|------|
| 代理转发延迟 | < 5ms | 本地测试 |
| 单核吞吐量 | > 10Gbps | 取决于硬件 |
| 连接内存占用 | < 8KB | 每连接 |

### 稳定性指标

| 指标 | 目标 |
|------|------|
| 测试通过率 | 100% |
| 崩溃率 | < 0.001% |

---

## 更新日志

### 2026年3月17日（下午）

**代码改进（Codex 审查问题修复）：**
- 修复 TLS 活跃流管理问题，添加 `active_stream_cancel/close` 回调
- 修复 HTTP/HTTPS 单次写入问题，添加 `async_write`/`async_read` 虚函数
- 修复协议配置未连接问题，SOCKS5/Trojan 现使用 `ctx.server.cfg` 配置
- UDP 传输层特化 `async_write`，避免不必要的循环

**架构优化：**
- `transmission` 类添加 `async_write`/`async_read` 虚函数，子类可特化
- `original_tunnel` 参数简化，使用 `session_context` 替代分散参数
- `original_tunnel` 添加 `complete_write` 开关，支持精细化控制

**文档更新：**
- 更新 `context.md`，添加新增字段文档

### 2026年3月17日

- 重构文档结构，按受众分离用户指南和开发者指南
- 新增 TLS 协议文档和上下文结构体文档
- 修正 trojan.md 文件名拼写错误
- 更新 README.md 文档链接

### 2026年2月14日

- 更新 README.md，简化目录结构
- 删除 Obscura 协议相关内容

### 2026年2月9日

- 优化协议流程文档，完善 HTTP、SOCKS5、Trojan 协议调用流程
- 更新配置示例，使用相对路径

### 2026年1月27日

- 解耦 `distributor` 模块，移除 JSON 依赖
- 完善反向代理配置加载逻辑
- 标准化错误码返回机制

---

## 许可证

ForwardEngine 采用 **MIT 许可证**，允许：

- ✅ 商业使用
- ✅ 修改和分发
- ✅ 私人使用
- ✅ 专利使用

要求：

- 📝 保留版权声明
- 📝 包含许可证副本

查看完整许可证：[LICENSE](../../LICENSE)

---

**感谢关注 ForwardEngine 的开发进展！** 🚀
