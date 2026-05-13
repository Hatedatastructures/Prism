---
name: bug-to-wiki
description: Bug 修复和对接问题排查完成后，将经验记录到 Prism 技术文档知识库。仅在确认修复有效后触发，避免污染知识库。
---

# Skill: Bug 修复与对接问题归档到知识库

## 触发条件

**仅在以下条件全部满足时触发：**

1. ✅ Bug 已修复 **且** 测试通过（单元测试/集成测试/手动验证）
2. ✅ 对接问题已解决 **且** 客户端/服务端通信正常
3. ✅ 用户明确确认"可以记录到知识库"或"归档"

**绝不触发的情况：**

- ❌ 仍在排查中（未找到根因）
- ❌ 修复后未测试
- ❌ 用户说"先不记录"或"等一下"
- ❌ 临时 workaround（非永久修复）
- ❌ 仅修改文档/注释/格式（非功能性变更）

## 前置检查清单

在写入知识库前，必须确认以下所有项：

```markdown
## 修复确认清单

- [ ] Bug 描述清晰（现象可复现）
- [ ] 根因已定位（不是猜测）
- [ ] 修复代码已提交（有 commit hash）
- [ ] 相关测试已通过（列出测试命令和结果）
- [ ] 无回归问题（未引入新 bug）
- [ ] 用户确认可以归档
```

**如果有任何一项未满足，停止并告知用户原因。**

## 问题分类与归档路径

根据问题类型，严格归档到对应目录：

### 1. Bug 类（代码缺陷）

**归档路径：** `H:/wiki/bugs/`

**文件命名：** `{模块}-{简要描述}.md`

**示例：**
- `smux-frame-parsing-error.md` — smux 帧解析错误
- `reality-handshake-timeout.md` — Reality 握手超时
- `memory-pool-leak.md` — 内存池泄漏

**触发场景：**
- 代码逻辑错误
- 内存泄漏/越界
- 协议解析错误
- 并发竞争条件
- 性能退化

### 2. 对接类（客户端兼容性）

**归档路径：** `H:/wiki/client/`

**文件命名：** `{客户端}-{问题类型}.md`

**示例：**
- `mihomo-reality-compatibility.md` — mihomo 与 Prism Reality 兼容性
- `sing-box-smux-version.md` — sing-box smux 版本协商问题
- `clash-config-template.md` — Clash 配置模板

**触发场景：**
- 客户端连接失败
- 协议版本不匹配
- 配置格式差异
- 性能差异

### 3. 模块类（架构/设计问题）

**归档路径：** `H:/{模块名}/`

**文件命名：** `{子模块}-{问题类型}.md`

**示例：**
- `stealth/reality-key-rotation.md` — Reality 密钥轮换问题
- `multiplex/smux-flow-control.md` — smux 流控问题
- `crypto/aead-nonce-reuse.md` — AEAD nonce 重用问题

**触发场景：**
- 模块内部设计缺陷
- 接口不兼容
- 性能瓶颈
- 依赖升级导致的问题

### 4. 协议类（协议实现问题）

**归档路径：** `H:/wiki/protocol/` 或 `H:/wiki/stealth/`

**文件命名：** `{协议}-{问题类型}.md`

**示例：**
- `trojan-auth-mismatch.md` — Trojan 认证不匹配
- `shadowtls-session-reuse.md` — ShadowTLS 会话复用问题
- `ech-decryption-failure.md` — ECH 解密失败

**触发场景：**
- 协议格式解析错误
- 认证/加密问题
- 状态机错误
- 兼容性问题

## 文档格式规范

### Bug 记录格式

```yaml
---
title: {Bug 标题}
created: {YYYY-MM-DD}
updated: {YYYY-MM-DD}
type: bug
severity: critical | major | minor
modules: [{affected modules}]
status: fixed
fix_commit: {commit hash}
fix_date: {YYYY-MM-DD}
related: [{related pages}]
---
```

### 正文结构

```markdown
## 现象

**用户可见症状：**
- 具体描述用户看到的错误现象
- 错误信息/日志片段
- 复现步骤（如果有）

**影响范围：**
- 影响哪些功能
- 影响哪些客户端/平台
- 严重程度评估

## 排查过程

**第一步：初步分析**
- 收集的信息
- 初步判断

**第二步：深入排查**
- 使用的工具/方法
- 关键发现

**第三步：根因定位**
- 最终定位的代码位置
- 根本原因分析

## 根因

**技术原因：**
- 详细的技术原因分析
- 相关代码片段（如有）

**设计原因（如有）：**
- 为什么会出现这个问题
- 设计上的缺陷

## 修复

**修复方案：**
- 修改了哪些文件
- 修改内容摘要
- 关键代码变更

**修复验证：**
- 测试命令
- 测试结果
- 回归测试结果

## 预防措施

**如何避免类似问题：**
- 代码审查要点
- 测试覆盖建议
- 文档更新建议

## 相关模块

- [[module1]]
- [[module2]]
- [[related-page]]

## 参考资料

- 相关 issue/PR 链接
- 外部文档链接
```

### 对接问题记录格式

```yaml
---
title: {对接问题标题}
created: {YYYY-MM-DD}
updated: {YYYY-MM-DD}
type: client
client: {client name}
client_version: {version}
prism_version: {version}
status: resolved
related: [{related pages}]
---
```

### 正文结构

```markdown
## 问题描述

**现象：**
- 客户端连接 Prism 时的具体表现
- 错误信息/日志

**环境：**
- 客户端版本
- Prism 版本
- 操作系统/网络环境

## 排查过程

**第一步：配置检查**
- 检查的配置项
- 发现的差异

**第二步：协议分析**
- 抓包分析（如有）
- 协议版本对比

**第三步：兼容性测试**
- 测试的客户端版本
- 测试的 Prism 版本

## 根因

**兼容性原因：**
- 客户端与 Prism 的差异
- 协议版本/实现差异

## 解决方案

**配置调整：**
- 需要修改的配置项
- 配置模板

**代码修改（如有）：**
- Prism 侧的修改
- 客户端侧的建议

## 配置模板

```yaml
# 客户端配置示例
{配置内容}
```

## 兼容性矩阵

| 客户端版本 | Prism 版本 | 状态 | 备注 |
|-----------|-----------|------|------|
| {version} | {version} | ✅/❌ | {notes} |

## 相关页面

- [[client/{client-name}]]
- [[protocol/{protocol-name}]]
- [[stealth/{scheme-name}]]
```

## 写入流程

### 步骤 1：确认归档条件

```markdown
## 归档确认

1. 问题是否已解决？ {是/否}
2. 是否已测试验证？ {是/否}
3. 用户是否确认归档？ {是/否}
4. 问题类型是什么？ {bug/client/module/protocol}

如果任何一项为"否"，停止并告知用户。
```

### 步骤 2：确定归档路径

根据问题类型，选择归档目录：

```
问题类型 → 归档目录 → 文件名
─────────────────────────────────────
bug      → H:/wiki/bugs/ → {module}-{description}.md
client   → H:/wiki/client/ → {client}-{issue}.md
module   → H:/{module}/ → {submodule}-{issue}.md
protocol → H:/wiki/protocol/ → {protocol}-{issue}.md
stealth  → H:/wiki/stealth/ → {scheme}-{issue}.md
```

### 步骤 3：创建文档

1. 确定文件名（小写，连字符，无空格）
2. 创建 YAML frontmatter
3. 按格式填写正文
4. 添加相关页面链接（至少 3 个 `[[wikilinks]]`）

### 步骤 4：更新索引

**更新 `H:/wiki/index.md`：**

1. 在对应分类下添加新页面链接
2. 更新页面总数
3. 更新最后更新日期

**更新 `H:/wiki/log.md`：**

```markdown
## [{YYYY-MM-DD}] {action} | {description}

- {action}: {file path}
- 原因: {brief reason}
- 相关: {related pages}
```

### 步骤 5：验证

```markdown
## 验证清单

- [ ] 文件已创建在正确路径
- [ ] frontmatter 格式正确
- [ ] 正文包含所有必要部分
- [ ] 至少 3 个 wikilinks
- [ ] index.md 已更新
- [ ] log.md 已更新
```

## 文件夹归档规则

### 何时创建子文件夹

**当同一模块/协议的 bug 超过 5 个时，创建子文件夹归类：**

```
H:/wiki/bugs/
├── smux/                    # smux 相关 bug
│   ├── frame-parsing.md
│   ├── flow-control.md
│   └── version-negotiation.md
├── reality/                 # Reality 相关 bug
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
- smux + memory 的问题 → 归入 `H:/wiki/bugs/multiplex-smux-memory-issue.md`
- reality + crypto 的问题 → 归入 `H:/wiki/bugs/stealth-reality-crypto-issue.md`

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
- `H:/wiki/client/mihomo/reality-config.md`
- `H:/wiki/client/sing-box/smux-version.md`

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

### 场景：修复 smux 帧解析错误

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
模块: multiplex (smux)
归档路径: H:/wiki/bugs/multiplex-smux-frame-parsing.md
```

**步骤 3：创建文档**

```yaml
---
title: smux 帧解析错误导致连接断开
created: 2026-05-13
updated: 2026-05-13
type: bug
severity: major
modules: [multiplex, protocol]
status: fixed
fix_commit: abc1234
fix_date: 2026-05-13
related: [[multiplex-overview], [protocol-overview], [mihomo-meta]]
---
```

**步骤 4：更新索引**

```markdown
# 在 H:/wiki/index.md 中添加

## bugs/ — Bug 记录

- [[multiplex-smux-frame-parsing]] — smux 帧解析错误导致连接断开
```

```markdown
# 在 H:/wiki/log.md 中添加

## [2026-05-13] bug | smux 帧解析错误

- 创建: H:/wiki/bugs/multiplex-smux-frame-parsing.md
- 原因: smux version 字段解析错误导致 mihomo 客户端连接断开
- 修复: commit abc1234
- 相关: [[multiplex-overview]], [[protocol-overview]], [[mihomo-meta]]
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
问题: mihomo 连接 Prism 失败
归档: H:/wiki/bugs/mihomo-connection-failure.md  ❌
```

**正确做法：**
```
问题: mihomo 连接 Prism 失败
归档: H:/wiki/client/mihomo-connection-issue.md  ✅
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
- [[mihomo-meta]]
```

### 错误 4：信息不完整

**错误做法：**
```markdown
## 根因

smux 帧解析错误。

## 修复

修改了代码。
```

**正确做法：**
```markdown
## 根因

smux version 字段（1 字节）在大端序下解析错误，导致帧长度计算错误。

**代码位置：** `src/prism/multiplex/smux/frame.cpp:47`

```cpp
// 修复前
auto version = buffer[0];

// 修复后
auto version = static_cast<uint8_t>(buffer[0]);
```

## 修复

**修改文件：**
- `src/prism/multiplex/smux/frame.cpp` — 修复 version 字段解析
- `tests/Smux.cpp` — 添加回归测试

**commit:** abc1234

**测试结果：**
```bash
ctest --test-dir build_release --output-on-failure
# 所有测试通过
```
```

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
