---
name: map-config
description: 新增或修改 Prism 配置字段、Glaze 映射、默认值、校验或 configuration.json 时，审查配置闭环。
---

# 配置映射审计

## 当前配置链

配置相关代码主要位于：

- `include/prism/settings/settings.hpp`：配置结构和字段
- `include/prism/settings/loader/load.hpp`：加载入口
- `include/prism/settings/transformer/json.hpp`：JSON 转换
- `include/prism/settings/validator.hpp`：值域和组合校验
- `src/configuration.json`：默认配置示例

修改前必须读取这些文件和所属 CMake，确认实际字段名、嵌套关系和资源所有者。

## 接入步骤

1. 定义字段语义、单位、默认值、可选性和互斥关系。
2. 修改配置结构和 JSON 映射，确认字符串、数字、数组、对象和枚举的转换方式。
3. 将非法值、缺失值、重复值和组合冲突放入 validator，而不是让运行时静默修正。
4. 检查配置是否影响 process、worker、session 或协议级资源的生命周期。
5. 更新 `src/configuration.json`，不得写入真实凭据、私钥或开发者本机路径。
6. 增加映射、默认值、拒绝非法配置和兼容组合测试。

## 审计清单

- JSON 字段名与结构体映射一致。
- 默认值在配置加载、校验和运行时三处语义一致。
- 空字符串、零值、负值、超上限值和未知字段行为明确。
- 密码、UUID、PSK、私钥等敏感值不会被日志或错误文本回显。
- 配置变更同步更新文档、CMake 和聚合头，而不是只改示例 JSON。

## 验证

优先运行 settings/loader/validator 测试，再运行受影响协议的集成测试。若变更涉及资源上限或池策略，补充 `audit-memory` 或 `pool-audit` 审计。

## 相关 Skill

协议接入见 `protocol-handler`，敏感信息见 `leak-audit`，测试见 `write-test`。
