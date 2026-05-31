---
name: map-config
description: 添加或修改配置字段、新增 JSON 序列化映射、更新 configuration.json 时触发。
---

# Skill: 配置映射

## 触发条件

添加配置字段、修改 JSON 序列化映射、更新 configuration.json、新增子系统配置时。

## 配置管道

```
configuration.json（用户输入）
       │
       ▼
loader::load() → transformer::json::deserialize() → glz::read_json
       │
       ▼
psm::config（运行时聚合结构体）
       │
       ▼
各子系统读取对应子配置
```

关键文件:
- 配置文件: `src/configuration.json`
- 聚合类型: `include/prism/config.hpp`（psm::config + trace/pool 的 glz::meta）
- 加载入口: `include/prism/loader/load.hpp`
- JSON 包装: `include/prism/transformer/json.hpp`

## 添加字段的标准步骤

### Step 1: 定义配置结构体

在对应模块的 `config.hpp` 中添加字段:
```cpp
struct config
{
    memory::string field_name{"default_value"};  // memory::string 而非 std::string
    memory::vector<memory::string> items;        // PMR 容器
    std::int32_t timeout_ms{300};                // 类内初始化器提供默认值
    bool enabled{false};

    [[nodiscard]] auto enabled() const
        -> bool
    {
        return !field_name.empty();               // 根据实际字段判断
    }
};
```

约束:
- 字符串字段用 `memory::string`
- 容器字段用 `memory::vector` / `memory::map`
- 默认值通过类内初始化器提供
- 可选字段提供 `enabled()` 方法

### Step 2: 添加 glz::meta 映射

在对应模块的 `serialize.hpp` 中添加映射（**不放在 config.hpp**）:
```cpp
template <>
struct glz::meta<psm::module::config>
{
    using T = psm::module::config;
    static constexpr auto value = glz::object(
        "field_name", &T::field_name,
        "items",      &T::items,
        "timeout_ms", &T::timeout_ms,
        "enabled",    &T::enabled
    );
};
```

枚举类型用 `glz::enumerate`:
```cpp
template <>
struct glz::meta<psm::module::type>
{
    static constexpr auto value = glz::enumerate(
        "tcp",  psm::module::type::tcp,
        "udp",  psm::module::type::udp
    );
};
```

新增 `serialize.hpp` 文件需在 `config.hpp` 末尾 include。

### Step 3: 更新 configuration.json

在对应节添加新字段:
```json
{
    "module": {
        "field_name": "default_value",
        "timeout_ms": 300,
        "enabled": false
    }
}
```

### Step 4: 更新 psm::config 聚合

如果新增了整个配置节，需在 `include/prism/config.hpp` 中添加到 `psm::config`:
```cpp
struct config
{
    // ... 已有子配置
    module::config module;  // 新增
};
```

同时在 `config.hpp` 底部为 `psm::config` 的 `glz::meta` 添加新字段映射。

### Step 5: 编写测试

配置测试是同步的（不需要协程），直接用 void 函数：

```cpp
void TestDefaults()
{
    module::config cfg;
    runner.Check(cfg.timeout_ms == 300, "默认超时");
    runner.Check(cfg.field_name == "default_value", "默认 field_name");
}

void TestDeserialize()
{
    memory::string json = R"({"field_name": "test"})";
    module::config cfg;
    bool ok = transformer::json::deserialize(json, cfg);
    runner.Check(ok, "反序列化成功");
    runner.Check(cfg.field_name == "test", "已解析 field_name");
}
```

注意：`deserialize()` 返回 `bool`，应检查返回值。

## 映射文件索引

| 模块 | 映射文件 |
|------|----------|
| instance | `include/prism/instance/serialize.hpp` |
| multiplex | `include/prism/multiplex/serialize.hpp` |
| stealth | `include/prism/stealth/serialize.hpp` |
| dns | `include/prism/resolve/dns/serialize.hpp` |
| trace/pool/config | `include/prism/config.hpp`（底部） |

## 编写规则

1. **分离关注** — glz::meta 放 `serialize.hpp`，不放 `config.hpp`（避免污染模块头）
2. **PMR 兼容** — PMR 类型字段通过 `transformer::json::deserialize()` 包装以正确构造临时对象
3. **聚合同步** — 新增配置节必须同步更新 `psm::config` 聚合结构体和其 glz::meta
4. **默认值** — 必须在 config.hpp 中通过类内初始化器提供，不依赖 JSON 缺省
5. **敏感字段** — 密码、密钥等不得出现在日志输出中
6. **枚举覆盖** — glz::enumerate 映射必须覆盖所有枚举成员，不得遗漏
7. **新增 serialize.hpp** — 需在 `config.hpp` 末尾添加 include 以确保链接可见
