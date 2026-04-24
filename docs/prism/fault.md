# Fault 模块

**源码位置**: `include/prism/fault/`

错误码体系。热路径使用 `fault::code` 枚举返回错误，不抛异常。

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
| `fault::code` | 错误码枚举 |
| `fault::describe(code)` | 获取错误描述字符串（定义于 code.hpp） |
| `fault::succeeded(code)` | 判断是否成功 |
| `fault::failed(code)` | 判断是否失败 |

完整错误码列表见 `include/prism/fault/code.hpp`，以下为常见值：

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
| ... | 完整列表见 code.hpp |
