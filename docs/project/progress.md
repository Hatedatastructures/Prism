# 项目开发进度与贡献指南

本文档记录了 Prism 的开发状态、路线图以及如何参与贡献。无论你是想了解项目进展，还是希望贡献代码，这里都能找到需要的信息。

## 项目概况

- **项目名称**：Prism
- **项目类型**：高性能代理引擎
- **核心技术**：C++23、Boost.Asio 协程、BoringSSL、PMR 内存管理
- **开发状态**：**稳定可用**，核心功能已完成
- **当前版本**：v0.9.0
- **最后更新**：2026年4月11日
- **主要依赖**：Boost(system)、BoringSSL、spdlog、glaze

---

## 当前版本状态（v0.9.0）

### 已完成的核心功能

#### 1. 代理协议支持

| 协议 | 完成度 | 状态 | 说明 |
|------|--------|------|------|
| **HTTP/HTTPS** | 100% | ✅ 完成 | HTTP 正向代理与 HTTPS `CONNECT` 隧道 |
| **SOCKS5 TCP** | 100% | ✅ 完成 | RFC 1928，支持 CONNECT 命令 |
| **SOCKS5 UDP** | 100% | ✅ 完成 | 支持 UDP ASSOCIATE 命令 |
| **TLS 透明剥离** | 100% | ✅ 完成 | Session 层 TLS 握手 + 内层协议探测，Handler 无感 TLS |
| **Trojan 协议** | 100% | ✅ 完成 | Trojan over TLS 协议已接入运行链 |

#### 2. 核心架构模块

| 模块 | 完成度 | 说明 |
|------|--------|------|
| **协程驱动架构** | 100% | 基于 `net::awaitable` 的异步模型，无回调地狱 |
| **智能连接池** | 100% | TCP 连接复用，支持僵尸检测、空闲超时、端点缓存上限 |
| **协议自动识别** | 100% | 动态检测 HTTP/SOCKS5/TLS，TLS 剥离后二次探测内层协议 |
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

### Agent 模块 (`include/prism/agent/`)

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
| **dispatch** | handlers | ✅ 100% | HTTP/SOCKS5/Trojan/Unknown 处理器实现 |
| **pipeline** | protocols | ✅ 100% | HTTP/SOCKS5/Trojan 协议处理管道 |
| **pipeline** | primitives | ✅ 100% | dial、preview、tunnel 原语 |
| **resolve** | router | ✅ 100% | 统一路由入口，整合解析器、连接池 |
| **resolve** | recursor | ✅ 100% | DNS 解析门面，六阶段查询管道 |
| **resolve** | cache | ✅ 100% | DNS 正向/负向缓存，serve-stale |
| **resolve** | rules | ✅ 100% | 域名规则匹配，静态 IP/CNAME |
| **resolve** | coalescer | ✅ 100% | DNS 请求合并机制 |
| **account** | directory | ✅ 100% | 账户目录，写时复制，无锁读取 |
| **account** | entry | ✅ 100% | 账户运行时状态，连接数限制 |
| **account** | lease | ✅ 100% | RAII 连接数管理 |

### Protocol 模块 (`include/prism/protocol/`)

| 协议 | 完成度 | 说明 |
|------|--------|------|
| **HTTP** | ✅ 100% | HTTP/1.1 请求解析 (parser) + 协议处理 (relay)，零分配 |
| **SOCKS5** | ✅ 100% | RFC 1928 完整实现，支持 CONNECT、UDP ASSOCIATE |
| **Trojan** | ✅ 100% | Trojan over TLS 协议，密码验证 + 流量伪装 |
| **协议探测** | ✅ 100% | 外层 detect() + 内层 detect_inner() 双阶段探测 |

### Channel 模块 (`include/prism/channel/`)

#### transport 子模块

| 组件 | 完成度 | 说明 |
|------|--------|------|
| **transmission** | ✅ 100% | 传输层抽象接口 |
| **reliable** | ✅ 100% | TCP 可靠传输实现 |
| **unreliable** | ✅ 100% | UDP 不可靠传输实现 |
| **encrypted** | ✅ 100% | TLS 加密传输 |

#### connection 子模块

| 组件 | 完成度 | 说明 |
|------|--------|------|
| **pool** | ✅ 100% | TCP 连接池，栈式缓存 + 僵尸检测 |

#### adapter 子模块

| 组件 | 完成度 | 说明 |
|------|--------|------|
| **connector** | ✅ 100% | Socket 适配器，支持预读数据注入 |

### Memory 模块 (`include/prism/memory/`)

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
| SOCKS5 认证 | ✅ 已完成 | 支持用户名密码认证 (RFC 1929)，需配置 `socks5.enable_auth` 开启 |

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

### 短期目标（v0.9.x）

| 任务 | 优先级 | 状态 |
|------|--------|------|
| HTTP 协议模块重构（parser + relay） | - | ✅ 已完成 |
| TLS 传输层剥离架构 | - | ✅ 已完成 |
| Listener 支持 IPv6 和 host 绑定 | 中 | 计划中 |

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
| 协议扩展 | Shadowsocks 2022、VLESS、Reality、Hysteria2 等协议支持 |

---

## 测试与验证

### 测试套件

```bash
# 运行所有测试
ctest --test-dir build_release --output-on-failure

# 关键测试用例
./build_release/tests/Session       # 会话生命周期
./build_release/tests/Http          # HTTP 代理协议
./build_release/tests/Socks5        # SOCKS5 协议
./build_release/tests/Trojan        # Trojan 协议
./build_release/tests/Connection    # 连接池复用
./build_release/tests/HttpParser    # HTTP 解析器
./build_release/tests/Smux          # Smux 多路复用
./build_release/tests/Yamux         # Yamux 多路复用
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

- **编译警告**：持续优化中，逐步消除编译警告
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

### 2026年4月11日

**架构变更：**
- TLS 处理从 Trojan handler 上移到 Session 层，实现传输层剥离
- `protocol_type` 新增 `tls` 枚举值，`detect()` 不再将 0x16 绑定为 trojan
- 新增 `detect_inner()` 内层协议探测函数
- Trojan handler 瘦身约 40 行，移除 TLS 握手代码

**HTTP 协议重构：**
- 合并 header/request/response/deserialization/serialization 为 parser + relay
- 新增 HTTP parser 零分配解析和 relay 协议处理
- 支持明文 HTTP 和 TLS 内层 HTTP 双模式代理

**测试重构：**
- 测试文件统一重命名为 PascalCase
- 新增 HttpParser/DnsPacket/DnsRules/Crypto/Exception 等专项测试

**文档更新：**
- 全部文档流程图改为无框 ASCII 风格
- README 重写：快速开始、协议路线图、依赖项说明
- 多篇文档修正过时引用，同步代码库变更


---

## 许可证

Prism 采用 **MIT 许可证**，允许：

- 商业使用
- 修改和分发
- 私人使用
- 专利使用

要求：

- 保留版权声明
- 包含许可证副本

查看完整许可证：[LICENSE](../../LICENSE)

---

**感谢关注 Prism 的开发进展！**
