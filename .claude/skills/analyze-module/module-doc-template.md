## 文档格式规范

### 模块文档模板

```markdown
# {模块名} 模块详细设计

> {一句话描述模块核心功能}

## 模块职责

### 核心功能
- {功能1}
- {功能2}

### 边界定义
- **做什么：** {职责范围}
- **不做什么：** {边界}

### 架构位置
```
{上层模块}
    ↓
[{本模块}]
    ↓
{下层模块}
```

## 关键类和接口

### {类名1}

**职责：** {一句话描述}

**关键方法：**
- `method1()` — {功能}
- `method2()` — {功能}

**设计原理：**
- {为什么这样设计}

### {类名2}
...

## 文件结构

### 头文件

| 文件 | 职责 | 关键类 |
|------|------|--------|
| `{file1}.hpp` | {职责} | {类名} |
| `{file2}.hpp` | {职责} | {类名} |

### 源文件

| 文件 | 职责 | 关键函数 |
|------|------|----------|
| `{file1}.cpp` | {职责} | {函数名} |
| `{file2}.cpp` | {职责} | {函数名} |

### 文件依赖图

```
{file1}.hpp
    ↓
{file2}.hpp
    ↓
{file3}.cpp
```

## 模块依赖

### 依赖的模块（输入）

| 模块 | 依赖原因 | 关键接口 |
|------|----------|----------|
| {module1} | {原因} | {接口} |
| {module2} | {原因} | {接口} |

### 被依赖的模块（输出）

| 模块 | 依赖原因 | 提供的接口 |
|------|----------|------------|
| {module1} | {原因} | {接口} |
| {module2} | {原因} | {接口} |

### 依赖关系图

```
{upstream1} ──→ [{本模块}] ──→ {downstream1}
{upstream2} ──→ [{本模块}] ──→ {downstream2}
```

## 数据流

### 请求处理流程

```
1. {入口} → {处理1} → {处理2} → {出口}
2. {数据转换}
3. {状态变化}
```

### 关键调用链

```
{caller} → {method1} → {method2} → {callee}
```

### 数据转换

| 阶段 | 输入 | 输出 | 转换逻辑 |
|------|------|------|----------|
| {阶段1} | {输入} | {输出} | {逻辑} |
| {阶段2} | {输入} | {输出} | {逻辑} |

## 设计原理

### 关键设计决策

**决策1：{决策标题}**
- **选择：** {选择了什么}
- **原因：** {为什么这样选择}
- **权衡：** {牺牲了什么}

**决策2：{决策标题}**
- **选择：** {选择了什么}
- **原因：** {为什么这样选择}
- **权衡：** {牺牲了什么}

### 性能优化

| 优化点 | 技术 | 效果 |
|--------|------|------|
| {优化1} | {技术} | {效果} |
| {优化2} | {技术} | {效果} |

### 设计模式

- {模式1}：{应用场景}
- {模式2}：{应用场景}

## 关键代码片段

### {代码片段1标题}

```cpp
// {文件路径}
{代码内容}
```

**说明：**
- {这段代码做什么}
- {为什么这样写}

### {代码片段2标题}
...

## 相关页面

- [[{module1}]]
- [[{module2}]]
- [[{related-page}]]
```

## 质量控制

### 文档质量检查

**每个文档必须满足：**

1. **完整性** — 包含所有 8 个必要部分
2. **准确性** — 技术细节正确，代码片段可编译
3. **深度性** — 不仅描述"是什么"，还要解释"为什么"
4. **可追溯性** — 有文件路径、类名、方法名
5. **可链接性** — 至少 5 个 wikilinks
6. **可理解性** — AI 读完能理解模块设计

### 防止知识库污染

**以下情况拒绝写入：**

1. ❌ 分析不深入（仅描述表面功能）
2. ❌ 缺少设计原理（没有解释"为什么"）
3. ❌ 依赖关系不完整（缺少上下游模块）
4. ❌ 数据流不清晰（没有调用链）
5. ❌ 文件依赖缺失（没有头文件包含关系）

**如果发现上述情况：**

```markdown
## 分析拒绝

**原因：** {具体原因}

**建议：**
1. {改进建议 1}
2. {改进建议 2}

**何时可以重新分析：**
- {条件 1}
- {条件 2}
```

## 示例：完整分析流程

### 场景：分析 multiplex 模块

**步骤 1：确认分析范围**

```markdown
## 分析确认

1. 分析哪些模块？ multiplex
2. 分组方式？ 单独分析
3. 分析深度？ 详细
4. 输出路径？ H:/wiki/multiplex/detail.md
```

**步骤 2：读取源码**

```bash
# 读取头文件
ls include/prism/multiplex/
# multiplex.hpp, core.hpp, config.hpp, bootstrap.hpp, duct.hpp, parcel.hpp
# proto_a/config.hpp, proto_a/session.hpp, proto_a/frame.hpp
# proto_b/config.hpp, proto_b/session.hpp, proto_b/frame.hpp

# 读取源文件
ls src/project/multiplex/
# bootstrap.cpp, core.cpp, duct.cpp, parcel.cpp
# proto_a/session.cpp, proto_a/frame.cpp
# proto_b/session.cpp, proto_b/frame.cpp

# 读取测试文件
ls tests/ProtoA*.cpp tests/ProtoB*.cpp tests/Multiplex*.cpp
```

**步骤 3：分析模块**

```markdown
## 模块职责

### 核心功能
- 实现多种多路复用协议
- 在单个 TCP 连接上复用多个逻辑流
- 支持流控制和流量控制

### 边界定义
- **做什么：** 多路复用协议编解码、流管理、流量控制
- **不做什么：** 不处理 TLS 加密（由 channel 处理）、不处理协议识别（由 recognition 处理）

### 架构位置
```
pipeline
    ↓
[multiplex]
    ↓
channel
```

## 关键类和接口

### proto_a::frame

**职责：** 协议帧格式编解码

**关键方法：**
- `encode()` — 将帧编码为字节流
- `decode()` — 从字节流解码帧

**设计原理：**
- 使用固定 12 字节头 + 变长 payload
- 支持 4 种帧类型：SYN、FIN、PSH、NOP

...
```

**步骤 4：生成文档**

按模板生成完整文档。

**步骤 5：写入知识库**

```bash
# 创建目录
mkdir -p H:/wiki/multiplex/

# 写入文档
cat > H:/wiki/multiplex/detail.md << 'EOF'
{文档内容}
EOF
```

**步骤 6：更新索引**

```markdown
# 在 H:/wiki/index.md 中添加

## multiplex/ — 多路复用

- [[overview]] — 多种协议实现、帧格式、流管理、配置详解
- [[detail]] — multiplex 模块详细设计、依赖关系、数据流
```

## 快速参考

### 分析路径速查

```
模块类型        → 分析重点
─────────────────────────────────────
核心模块        → 会话管理、生命周期、配置加载
协议模块        → 编解码、状态机、错误处理
传输模块        → 连接池、复用、流量控制
伪装模块        → 握手流程、密钥交换、特征隐藏
支撑模块        → 内存分配、日志、错误处理
```

### 文件路径速查

```
内容类型        → 路径
─────────────────────────────────────
头文件          → include/prism/{module}/
源文件          → src/project/{module}/
测试文件        → tests/{module}*.cpp
配置文件        → src/configuration.json
文档输出        → H:/wiki/{module}/detail.md
```

### 必填字段速查

```
字段           → 说明
─────────────────────────────────────
title          → 模块名 + "模块详细设计"
created        → 创建日期
type           → module
tags           → [{module}, architecture, design]
related        → 相关模块链接（至少 5 个）
```

## 常见错误

### 错误 1：仅描述表面功能

**错误做法：**
```markdown
## 模块职责

multiplex 模块负责多路复用。
```

**正确做法：**
```markdown
## 模块职责

### 核心功能
- 实现多种多路复用协议
- 在单个 TCP 连接上复用多个逻辑流
- 支持流控制和流量控制
- 支持流优先级和权重

### 边界定义
- **做什么：** 多路复用协议编解码、流管理、流量控制
- **不做什么：** 不处理 TLS 加密（由 channel 处理）、不处理协议识别（由 recognition 处理）
```

### 错误 2：缺少设计原理

**错误做法：**
```markdown
## 关键类和接口

### proto_a::frame

**职责：** 协议帧格式编解码
```

**正确做法：**
```markdown
## 关键类和接口

### proto_a::frame

**职责：** 协议帧格式编解码

**设计原理：**
- 使用固定 12 字节头 + 变长 payload，便于零拷贝解析
- 支持 4 种帧类型：SYN（建立流）、FIN（关闭流）、PSH（数据推送）、NOP（心跳）
- 版本字段预留 1 字节，支持未来协议升级
```

### 错误 3：依赖关系不完整

**错误做法：**
```markdown
## 模块依赖

multiplex 依赖 channel。
```

**正确做法：**
```markdown
## 模块依赖

### 依赖的模块（输入）

| 模块 | 依赖原因 | 关键接口 |
|------|----------|----------|
| channel | 获取 TCP 连接 | `connection::dial()`, `connection::pool()` |
| memory | PMR 内存分配 | `memory::vector<T>`, `memory::string` |

### 被依赖的模块（输出）

| 模块 | 依赖原因 | 提供的接口 |
|------|----------|------------|
| pipeline | 协议流水线需要多路复用 | `multiplex::open_stream()`, `multiplex::accept_stream()` |
| protocol | 协议处理需要流接口 | `stream::read()`, `stream::write()` |

### 依赖关系图

```
pipeline ──→ [multiplex] ──→ channel
    ↑              ↑
    │              │
protocol        memory
```
```

### 错误 4：数据流不清晰

**错误做法：**
```markdown
## 数据流

数据从 pipeline 进入 multiplex，然后发送到 channel。
```

**正确做法：**
```markdown
## 数据流

### 请求处理流程

```
1. pipeline 调用 multiplex::open_stream()
2. multiplex 分配 stream_id
3. multiplex 构造 SYN 帧
4. multiplex 调用 channel::send() 发送 SYN 帧
5. 等待对端 ACK
6. 返回 stream 对象给 pipeline
7. pipeline 通过 stream::send() 发送数据
8. multiplex 构造 PSH 帧
9. multiplex 调用 channel::send() 发送 PSH 帧
```

### 关键调用链

```
pipeline::process()
    → multiplex::open_stream()
        → proto_a::session::syn(stream_id)
        → channel::send(frame)
        → wait_for_ack()
    → stream::send(data)
        → proto_a::session::push(stream_id, data)
        → channel::send(frame)
```

### 数据转换

| 阶段 | 输入 | 输出 | 转换逻辑 |
|------|------|------|----------|
| 打开流 | stream 请求 | SYN 帧 | 添加 12 字节头 + stream_id |
| 发送数据 | 应用数据 | PSH 帧 | 添加 12 字节头 + stream_id + 数据 |
| 接收帧 | 字节流 | 帧对象 | 解析 12 字节头 + 提取 payload |
```

## 总结

**核心原则：**

1. ✅ 深入分析，不仅描述"是什么"，还要解释"为什么"
2. ✅ 完整的依赖关系（上下游模块、文件依赖）
3. ✅ 清晰的数据流（调用链、数据转换）
4. ✅ 设计原理（关键决策、权衡取舍）
5. ✅ 关键代码片段（核心逻辑、重要配置）

**拒绝分析的情况：**

1. ❌ 分析不深入（仅描述表面功能）
2. ❌ 缺少设计原理（没有解释"为什么"）
3. ❌ 依赖关系不完整（缺少上下游模块）
4. ❌ 数据流不清晰（没有调用链）
5. ❌ 文件依赖缺失（没有头文件包含关系）
