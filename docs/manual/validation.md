# 文档验真规则

本文档定义了 prism 项目文档的验真标准，确保文档内容与源码实现一致。

## 验真规则

### 规则 1：源码对应

每个关键结论至少对应一个源码文件。

- 文档中的技术声明必须有源码位置引用
- 引用格式：`文件路径:行号` 或 `文件路径`

**示例**：
```
HTTP 代理实现位于 src/protocol/http/ 目录
SOCKS5 握手逻辑见 src/protocol/socks5/stream.cpp
```

### 规则 2：协议支持以运行链为准

协议支持结论必须以运行链为准，而不是以 README 或配置字段为准。

- 配置字段存在 ≠ 功能已实现
- 必须检查 `dispatch::register_handlers()` 是否注册了对应处理器
- 必须验证从 listener → handler → protocol 的完整调用链

**验证步骤**：
1. 检查配置结构体是否定义字段
2. 检查 dispatch 是否注册 handler
3. 检查 handler 是否实际调用协议实现

### 规则 3：运行行为可用测试交叉核对

运行行为可用以下测试文件交叉核对：

| 测试文件 | 验证范围 |
|---------|---------|
| `tests/session.cpp` | 会话生命周期、连接管理 |
| `tests/connection_test.cpp` | 连接建立、数据传输 |
| `tests/socks5_test.cpp` | SOCKS5 协议行为 |
| `tests/trojan_test.cpp` | Trojan 协议实现 |
| `tests/integration_test.cpp` | 端到端集成行为 |

### 规则 4：区分三类能力

文档必须明确区分以下三类能力状态：

#### 1. 源码已实现

运行链完整接入，功能可用。

**判定标准**：
- 配置字段存在
- handler 已注册
- 协议实现完整
- 测试覆盖

#### 2. 仅配置声明

配置字段存在但运行链未接入。

**判定标准**：
- 配置结构体定义了字段
- dispatch 未注册对应 handler
- 或 handler 为空实现/占位符

#### 3. 源码声明但未接入

代码存在但未被调用。

**判定标准**：
- 源码文件/函数存在
- 无任何调用点
- 未被 dispatch 或其他模块引用

---

## 源码文件与文档章节对应表

| 文档章节 | 主要源码文件 |
|---------|-------------|
| overview.md | `src/main.cpp`, `src/prism/agent/front/listener.cpp`, `src/prism/agent/worker/launch.cpp`, `src/prism/agent/session/session.cpp` |
| config.md | `include/prism/agent/config.hpp`, `include/prism/agent/context.hpp` |
| architecture.md | 全局源码分析 |
| modules.md | `src/prism/agent/` 下各子目录源码 (worker, session, resolve, etc.) |
| runtime.md | `src/prism/agent/session/session.cpp`, `src/prism/agent/pipeline/protocols.cpp`, `src/prism/agent/pipeline/primitives.cpp` |
| routing.md | `include/prism/agent/dispatch/handler.hpp`, `include/prism/agent/dispatch/handlers.hpp`, `src/prism/resolve/router.cpp` |
| dependencies.md | `CMakeLists.txt`, 目录结构 |
| api.md | `include/prism/agent.hpp` |

---

## 已知事实清单

### 已确认实现

以下功能已验证运行链完整接入：

| 功能 | 源码位置 | 验证方式 |
|-----|---------|---------|
| HTTP/HTTPS 代理 | `src/protocol/http/`, `include/prism/protocol/http/` | handler 注册 + 测试 |
| SOCKS5 代理 | `src/protocol/socks5/`, `include/prism/protocol/socks5/` | handler 注册 + `tests/socks5_test.cpp` |
| TLS 终止 | `src/prism/agent/worker/tls.cpp`, `include/prism/agent/worker/tls.hpp` | 运行链接入 |
| 反向代理 | `src/prism/resolve/router.cpp`, `include/prism/resolve/router.hpp` | 运行链接入 |
| 负载均衡 | `src/prism/agent/front/balancer.cpp`, `include/prism/agent/front/balancer.hpp` | 运行链接入 |

### 已确认未接入

以下功能配置字段存在但运行链未接入：

| 功能 | 配置位置 | 未接入原因 |
|-----|---------|-----------|
| Trojan 协议 | `include/prism/protocol/trojan/config.hpp` | `dispatch::register_handlers()` 未注册 handler |

**说明**：Trojan 协议源码实现存在于 `src/protocol/trojan/` 目录，测试文件 `tests/trojan_test.cpp` 也存在，但 dispatch 未将其接入运行链。

### 已确认行为差异

以下行为与配置或文档描述存在差异：

| 项目 | 预期行为 | 实际行为 | 源码位置 |
|-----|---------|---------|---------|
| listener 绑定地址 | 绑定 `addressable.host` | 绑定 IPv4 | `src/prism/agent/front/listener.cpp` |
| async_forward 转发顺序 | 优先代理 | 先直连后 fallback | `src/prism/agent/pipeline/primitives.cpp` |
| reverse_map 目标解析 | 域名优先 | IP literal 优先 | `src/prism/resolve/router.cpp` |

---

## 验真流程

### 新功能文档验证

1. **配置验证**：检查 `config.hpp` 是否定义配置字段
2. **注册验证**：检查 `handlers.hpp` / dispatch 是否注册 handler
3. **实现验证**：检查对应源码文件是否存在实现
4. **测试验证**：检查 `tests/` 下是否有对应测试
5. **运行验证**：实际运行确认功能可用

### 已有文档审核

1. 按章节对照源码文件对应表
2. 逐项验证技术声明的源码位置
3. 标注能力状态（已实现/仅配置/未接入）
4. 更新已知事实清单

---

## 文档更新准则

1. **新增功能**：必须同时更新源码文件与文档章节对应表
2. **状态变更**：功能从「仅配置」变为「已实现」时，需更新已知事实清单
3. **行为差异**：发现新行为差异时，需记录到已确认行为差异表
4. **引用规范**：所有技术声明必须附带源码位置引用
