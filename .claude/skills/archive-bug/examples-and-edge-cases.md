## 文件夹归档规则

### 何时创建子文件夹

**当同一模块/协议的 bug 超过 5 个时，创建子文件夹归类：**

```
H:/wiki/bugs/
├── submodule/               # 子模块相关 bug
│   ├── frame-parsing.md
│   ├── flow-control.md
│   └── version-negotiation.md
├── module/                  # 模块相关 bug
│   ├── handshake-timeout.md
│   └── key-rotation.md
├── memory/                  # 内存相关 bug
│   ├── pool-leak.md
│   └── arena-overflow.md
└── {other-bugs}.md          # 其他 bug
```

**子文件夹命名规则：**
- 使用模块名/协议名（小写）
- 与 `H:/wiki/` 下的目录结构保持一致

### 何时合并到现有文档

**当问题是对现有 bug 的变种或回归时，追加到现有文档：**

```markdown
## 变种/回归记录

### {YYYY-MM-DD}: {变种描述}
- 与原始 bug 的差异
- 修复方案
- commit: {hash}
```

## 特殊情况处理

### 1. 跨模块问题

**归档路径：** 归入主要影响的模块

**示例：**
- multiplex + memory 的问题 → 归入 `H:/wiki/bugs/multiplex-memory-issue.md`
- stealth + crypto 的问题 → 归入 `H:/wiki/bugs/stealth-crypto-issue.md`

**文档中必须链接到所有相关模块：**
```markdown
## 相关模块

- [[multiplex]]
- [[memory]]
- [[crypto]]
```

### 2. 客户端特定问题

**归档路径：** `H:/wiki/client/{client-name}/`

**示例：**
- `H:/wiki/client/client-name/config.md`
- `H:/wiki/client/client-name/version-negotiation.md`

**如果客户端目录不存在，创建并添加 README：**

```markdown
# {Client Name}

{Client description}

## 已知问题

- [[issue1]]
- [[issue2]]

## 配置模板

- [[config-template]]

## 兼容性矩阵

- [[compatibility-matrix]]
```

### 3. 配置问题

**归档路径：** `H:/wiki/client/` 或对应模块目录

**判断标准：**
- 如果是客户端配置问题 → `H:/wiki/client/`
- 如果是 Prism 配置问题 → `H:/wiki/agent/configuration.md` 或对应模块

### 4. 性能问题

**归档路径：** `H:/wiki/bugs/` + 对应模块目录

**文档结构：**
```markdown
## 性能基准

**修复前：**
- 延迟: {ms}
- 吞吐: {Mbps}
- 内存: {MB}

**修复后：**
- 延迟: {ms}
- 吞吐: {Mbps}
- 内存: {MB}

**提升：**
- 延迟降低: {percentage}
- 吞吐提升: {percentage}
- 内存优化: {percentage}
```

### 5. 安全问题

**归档路径：** `H:/wiki/bugs/` + `H:/wiki/stealth/` 或 `H:/wiki/crypto/`

**特殊处理：**
- 如果是伪装方案问题 → `H:/wiki/stealth/`
- 如果是加密问题 → `H:/wiki/crypto/`
- 如果是通用安全问题 → `H:/wiki/bugs/`

**文档中必须包含：**
```markdown
## 安全影响

**影响范围：**
- 可能被利用的场景
- 影响的用户群体

**严重程度：**
- CVSS 评分（如有）
- 实际利用难度

**修复优先级：**
- 紧急/高/中/低
```

## 质量控制

### 文档质量检查

**每个文档必须满足：**

1. **完整性** — 包含所有必要部分
2. **准确性** — 技术细节正确
3. **可追溯性** — 有 commit hash、测试结果
4. **可链接性** — 至少 3 个 wikilinks
5. **可搜索性** — 标题和 tags 准确

### 防止知识库污染

**以下情况拒绝写入：**

1. ❌ 信息不完整（缺少根因/修复/测试）
2. ❌ 未验证的猜测（不是确定的根因）
3. ❌ 临时方案（workaround，非永久修复）
4. ❌ 重复内容（已存在相同问题的记录）
5. ❌ 职责混乱（归档到错误的目录）

**如果发现上述情况：**

```markdown
## 归档拒绝

**原因：** {具体原因}

**建议：**
1. {改进建议 1}
2. {改进建议 2}

**何时可以重新归档：**
- {条件 1}
- {条件 2}
```

## 示例：完整归档流程

### 场景：修复帧解析错误

**步骤 1：确认归档条件**

```markdown
## 归档确认

1. 问题是否已解决？ 是
2. 是否已测试验证？ 是（运行 `ctest --test-dir build_release` 全部通过）
3. 用户是否确认归档？ 是
4. 问题类型是什么？ bug
```

**步骤 2：确定归档路径**

```
问题类型: bug
模块: multiplex
归档路径: H:/wiki/bugs/multiplex-frame-parsing.md
```

**步骤 3：创建文档**

```yaml
---
title: 帧解析错误导致连接断开
created: 2026-05-13
updated: 2026-05-13
type: bug
severity: major
modules: [multiplex, protocol]
status: fixed
fix_commit: abc1234
fix_date: 2026-05-13
related: [[multiplex-overview], [protocol-overview], [client-compat]]
---
```

**步骤 4：更新索引**

```markdown
# 在 H:/wiki/index.md 中添加

## bugs/ — Bug 记录

- [[multiplex-frame-parsing]] — 帧解析错误导致连接断开
```

```markdown
# 在 H:/wiki/log.md 中添加

## [2026-05-13] bug | 帧解析错误

- 创建: H:/wiki/bugs/multiplex-frame-parsing.md
- 原因: 帧版本字段解析错误导致客户端连接断开
- 修复: commit abc1234
- 相关: [[multiplex-overview]], [[protocol-overview]], [[client-compat]]
```

**步骤 5：验证**

```markdown
## 验证清单

- [x] 文件已创建在正确路径
- [x] frontmatter 格式正确
- [x] 正文包含所有必要部分
- [x] 至少 3 个 wikilinks
- [x] index.md 已更新
- [x] log.md 已更新
```

## 快速参考

### 归档路径速查

```
问题类型        → 归档目录
─────────────────────────────
代码 bug        → H:/wiki/bugs/
客户端对接      → H:/wiki/client/
模块设计        → H:/{module}/
协议实现        → H:/wiki/protocol/
伪装方案        → H:/wiki/stealth/
加密问题        → H:/wiki/crypto/
配置问题        → H:/wiki/client/ 或 H:/wiki/agent/
性能问题        → H:/wiki/bugs/ + 对应模块
安全问题        → H:/wiki/bugs/ + 对应模块
```

### 文件名速查

```
问题类型        → 文件名格式
─────────────────────────────
bug            → {module}-{description}.md
client         → {client}-{issue}.md
module         → {submodule}-{issue}.md
protocol       → {protocol}-{issue}.md
```

### 必填字段速查

```
字段           → 说明
─────────────────────────────
title          → 问题标题
created        → 创建日期
type           → bug/client/module/protocol
modules        → 影响的模块列表
status         → fixed/investigating/workaround
fix_commit     → 修复的 commit hash
related        → 相关页面链接（至少 3 个）
```

## 常见错误

### 错误 1：未测试就归档

**错误做法：**
```
用户: "这个 bug 修好了"
AI: *立即写入知识库*
```

**正确做法：**
```
用户: "这个 bug 修好了"
AI: "请先运行测试确认修复有效：
     ctest --test-dir build_release --output-on-failure

     测试通过后我再归档到知识库。"
```

### 错误 2：归档路径错误

**错误做法：**
```
问题: 客户端连接失败
归档: H:/wiki/bugs/client-connection-failure.md  ❌
```

**正确做法：**
```
问题: 客户端连接失败
归档: H:/wiki/client/client-connection-issue.md  ✅
```

### 错误 3：缺少相关链接

**错误做法：**
```markdown
## 相关模块

- 无
```

**正确做法：**
```markdown
## 相关模块

- [[multiplex]]
- [[protocol]]
- [[client-compat]]
```

### 错误 4：信息不完整

**错误做法：**
```markdown
## 根因

帧解析错误。

## 修复

修改了代码。
```

**正确做法：**
````markdown
## 根因

帧版本字段（1 字节）在大端序下解析错误，导致帧长度计算错误。

**代码位置：** `src/module/submodule/frame.cpp:47`

```cpp
// 修复前
auto version = buffer[0];

// 修复后
auto version = static_cast<std::uint8_t>(buffer[0]);
```

## 修复

**修改文件：**
- `src/module/submodule/frame.cpp` — 修复 version 字段解析
- `tests/FrameParsing.cpp` — 添加回归测试

**commit:** abc1234

**测试结果：**
```bash
ctest --test-dir build_release --output-on-failure
# 所有测试通过
```
````

## 总结

**核心原则：**

1. ✅ 确认修复有效后才归档
2. ✅ 按问题类型严格分类
3. ✅ 包含完整信息（现象→排查→根因→修复）
4. ✅ 添加相关链接（至少 3 个）
5. ✅ 更新索引和日志

**拒绝归档的情况：**

1. ❌ 未测试验证
2. ❌ 信息不完整
3. ❌ 归档路径错误
4. ❌ 临时方案
5. ❌ 重复内容
