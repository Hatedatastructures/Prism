# Exception 模块

**源码位置**: `include/prism/exception/`（header-only）

异常层次结构，用于启动/冷路径错误。与 `fault::code` 构成双轨错误处理。

## 文件结构

```
exception/
├── deviant.hpp     # 基类 exception::deviant
├── network.hpp     # 网络异常（connection_refused、timeout 等）
├── protocol.hpp    # 协议异常（invalid_header、unsupported_version 等）
└── security.hpp    # 安全异常（auth_failed、certificate_expired 等）
```

## 异常层次

```
exception::deviant
├── exception::network      # 网络层异常（连接失败、超时、DNS 失败）
├── exception::protocol     # 协议层异常（无效头部、不支持版本、解析错误）
└── exception::security     # 安全层异常（认证失败、证书过期、加密错误）
```

## 使用约定

- **热路径**（数据转发、协议处理）：使用 `fault::code` 枚举，不抛异常
- **冷路径**（启动配置、证书加载）：使用异常，快速失败
- 捕获异常时应记录日志并转换为 `fault::code` 返回

## 示例

```cpp
try {
    // 冷路径操作
} catch (const exception::network& e) {
    spdlog::error("network error: {}", e.what());
    return fault::code::io_error;
} catch (const exception::deviant& e) {
    spdlog::error("fatal: {}", e.what());
    throw; // 未预期的异常，重新抛出
}
```
