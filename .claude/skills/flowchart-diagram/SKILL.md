---
name: flowchart-diagram
description: ASCII 流程图规范。编写文档、注释、README 中任何流程图、数据流图、架构图时必须遵循此风格，保持视觉一致。
---

# Skill: ASCII 流程图规范

所有流程图、数据流图、架构图必须遵循以下风格规则，确保视觉统一、对齐整洁。

## 触发条件

- 编写文档中的流程图（`docs/` 下的 `.md` 文件）
- 编写代码注释中的流程图（`//` 或 Doxygen `@details` 里的 ASCII 图）
- 编写 skill 或 CLAUDE.md 中的架构说明图
- 用户要求画流程图、数据流图、架构图

## 基本规则

### 允许使用的字符

- 垂直线：`│`
- 水平线：`─`
- 下箭头：`▼`
- 右箭头：`→`
- 三通：`├─`（分支）、`└─`（末尾分支）
- 对齐空格：普通空格

### 禁止使用的字符

- **禁止**框线：`┌ ┐ └ ┘ ─ │` 组成的大框
- **禁止**圆角框
- **禁止**花括号框 `{ }` 包围大段文字
- **禁止**双线框 `╔ ╗ ╚ ╝`

### 间距与对齐

- 每层缩进使用 **3 空格**或 **7 空格**（取决于连接符位置）
- `▼` 下方必须紧跟下一节点，中间只留一个 `│` 行
- `→` 右侧紧跟文字，左侧用 `─` 连接到对齐位置
- `├─` 和 `└─` 的 `-` 后面紧跟文字
- 同一层的分支必须左对齐

## 示例

### 线性流程

```
客户端发送请求
       │
       ▼
  parse_request()
       │
       ▼
  authenticate()
       │
       ▼
  route_target()
       │
       ▼
  establish_tunnel()
```

### 分支流程

```
detect() ──── 看第一个字节
       │
       ├─ 0x05 ───────→ socks5 ───→ Socks5 handler
       │
       ├─ GET/POST/... ─→ http ────→ HTTP handler
       │
       └─ 0x16 ───────→ tls
                            │
                            ▼
                   ssl_handshake()
                            │
                            ▼
                   detect_inner()
                            │
                            ├─ http ──→ HTTP handler
                            │
                            └─ trojan → Trojan handler
```

### 会合流程

```
  路径 A ──→ 中间节点 ──→ 汇合点
                                ▲
  路径 B ──→ 中间节点 ──────────┘
```

### 对比流程（无框）

```
  HTTP over TLS       HTTP 明文        Trojan over TLS
  (Https 节点)        (Http 节点)      (Trojan 节点)
       │                  │                  │
  session 剥 TLS          │             session 剥 TLS
  inbound = encrypted     │             inbound = encrypted
       │                  │                  │
       ▼                  ▼                  ▼
  HTTP handler        HTTP handler      Trojan handler
  收到同样的 transport + preview，不知道外面有没有 TLS
```

## 反面示例（禁止）

```
禁止 ── 带框的图：
┌─────────────────┐
│   HTTP handler   │
│  ┌───────────┐  │
│  │  parse()  │  │
│  └───────────┘  │
└─────────────────┘
```

```
禁止 ── 对齐不整齐：
  detect()
   │
    ├─ socks5
      │
    └─ http
```

## 检查清单

写完图后逐项检查：

1. 所有 `│` 是否垂直对齐？
2. 所有 `▼` 下方是否有对应的 `│`？
3. `├─` 和 `└─` 是否左对齐？
4. 是否有框线（`┌┐└┘`）？有则删除
5. 同一层的节点是否在相同缩进层级？
6. `→` 两侧是否有恰当的间距？
