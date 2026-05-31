---
name: archive-bug
description: Bug 修复或对接问题排查确认有效后，将经验记录到知识库。
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
- `frame-parsing-error.md` — 帧解析错误
- `handshake-timeout.md` — 握手超时
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
- `client-compatibility.md` — 客户端与服务端兼容性
- `client-version-negotiation.md` — 客户端版本协商问题
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
- `stealth/key-rotation.md` — 密钥轮换问题
- `multiplex/flow-control.md` — 流控问题
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
- `auth-mismatch.md` — 认证不匹配
- `session-reuse.md` — 会话复用问题
- `decryption-failure.md` — 解密失败

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

````markdown
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
````

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

---

## 详细参考

文件夹归档规则、特殊场景处理、完整示例流程、常见错误等详见 examples-and-edge-cases.md。
