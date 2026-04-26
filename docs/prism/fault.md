# Fault 模块

**源码位置**: `include/prism/fault/`（header-only）

错误码体系。热路径使用 `fault::code` 枚举返回错误，不抛异常。与 `exception` 模块构成双轨错误处理。

## 文件结构

```
fault/
├── code.hpp        # fault::code 枚举（60+ 错误码）+ fault::describe()
├── compatible.hpp  # 错误兼容处理
└── handling.hpp    # fault::succeeded() / fault::failed() 判断函数
```

## 核心类型

| 类型 | 说明 |
|------|------|
| `fault::code` | 错误码枚举，覆盖 I/O、网络、协议、安全等 |
| `fault::describe(code)` | 获取错误描述字符串 |
| `fault::succeeded(code)` | 判断是否成功（等价于 `code == success`） |
| `fault::failed(code)` | 判断是否失败 |

## 使用约定

- **热路径**（数据转发、协议处理）：返回 `fault::code`，不抛异常
- **判断结果**：使用 `fault::succeeded(ec)` 或 `fault::failed(ec)`
- **冷路径**（启动配置、证书加载）：使用 `exception` 模块，快速失败

## 常见错误码

| 错误码 | 说明 |
|--------|------|
| `success` | 成功 |
| `timeout` | 超时 |
| `io_error` | I/O 错误 |
| `dns_failed` | DNS 解析失败 |
| `blocked` | 被规则拦截 |
| `parse_error` | 解析错误 |
| `not_supported` | 不支持的操作 |
| `crypto_error` | 加密操作失败 |
| `mux_*` | 多路复用相关错误 |

完整错误码列表见 `include/prism/fault/code.hpp`。
