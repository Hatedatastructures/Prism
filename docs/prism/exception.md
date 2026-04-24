# Exception 模块

**源码位置**: `include/prism/exception/`

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
├── exception::network      # 网络层异常
├── exception::protocol     # 协议层异常
└── exception::security     # 安全层异常
```

## 使用约定

- **热路径**（数据转发、协议处理）：使用 `fault::code` 枚举，不抛异常
- **冷路径**（启动配置、证书加载）：使用异常，快速失败
