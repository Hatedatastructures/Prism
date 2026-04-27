# 配置详解

本文档详细说明 Prism 的配置参数、性能影响和调优建议。

配置文件位于 `src/configuration.json`，采用 JSON 格式。

---

## 配置结构

配置按模块分为 8 个顶层字段：

| JSON key | 说明 |
|----------|------|
| `agent` | 代理服务核心（监听、证书、认证、路由） |
| `pool` | 连接池 |
| `buffer` | 缓冲区 |
| `protocol` | 协议（socks5/trojan/vless/shadowsocks） |
| `multiplex` | 多路复用（smux/yamux） |
| `stealth` | 伪装（reality/shadowtls） |
| `dns` | DNS 解析 |
| `trace` | 日志追踪 |

---

## 监听配置

```json
{
  "agent": {
    "addressable": {
      "host": "0.0.0.0",
      "port": 8081
    }
  }
}
```

| 字段 | 默认值 | 说明 |
|------|--------|------|
| `host` | `0.0.0.0` | 监听地址 |
| `port` | `8081` | 监听端口 |

---

## TLS 证书配置

```json
{
  "agent": {
    "certificate": {
      "key": "C:\\path\\to\\key.pem",
      "cert": "C:\\path\\to\\cert.pem"
    }
  }
}
```

---

## 认证配置

```json
{
  "agent": {
    "authentication": {
      "users": [
        {
          "password": "prism",
          "uuid": "123e4567-e89b-12d3-a456-426614174000",
          "max_connections": 0
        }
      ]
    }
  }
}
```

| 字段 | 说明 |
|------|------|
| `password` | 密码（Trojan/HTTP/SOCKS5） |
| `uuid` | VLESS UUID |
| `max_connections` | 最大连接数，`0` 不限制 |

---

## 连接池配置

```json
{
  "pool": {
    "max_cache_per_endpoint": 32,
    "max_idle_seconds": 30,
    "connect_timeout_ms": 300,
    "cleanup_interval_sec": 20,
    "recv_buffer_size": 65536,
    "send_buffer_size": 65536,
    "tcp_nodelay": true,
    "keep_alive": true,
    "cache_ipv6": false
  }
}
```

### 参数详解

| 字段 | 默认值 | 说明 |
|------|--------|------|
| `max_cache_per_endpoint` | `32` | 每个目标端点最大缓存连接数 |
| `max_idle_seconds` | `30` | 空闲连接最大存活时间（秒），`src/configuration.json` 中调优为 240 |
| `connect_timeout_ms` | `300` | 连接超时（毫秒） |
| `cleanup_interval_sec` | `10` | 后台清理间隔（秒），`src/configuration.json` 中调优为 20 |
| `recv_buffer_size` | `65536` | 接收缓冲区大小（字节） |
| `send_buffer_size` | `65536` | 发送缓冲区大小（字节） |
| `tcp_nodelay` | `true` | 禁用 Nagle 算法 |
| `keep_alive` | `true` | 启用 TCP Keep-Alive |
| `cache_ipv6` | `false` | 是否缓存 IPv6 连接 |

### 性能影响

**`max_cache_per_endpoint`**：

| 值 | 影响 |
|----|------|
| 过小（<8） | 连接复用率低，频繁建立新连接 |
| 过大（>128） | 内存占用高 |
| 建议 | 16-64 |

**`connect_timeout_ms`**：

| 值 | 影响 |
|----|------|
| 过小（<100ms） | 正常网络波动也会超时 |
| 过大（>5000ms） | 故障节点检测慢 |
| 建议 | 国内 300-1000ms，跨国 2000-5000ms |

---

## 缓冲区配置

```json
{
  "buffer": {
    "size": 262144
  }
}
```

| 字段 | 默认值 | 说明 |
|------|--------|------|
| `size` | `262144` (256KB) | 传输缓冲区大小（字节） |

---

## 协议配置

### protocol.socks5

```json
{
  "protocol": {
    "socks5": {
      "enable_tcp": true,
      "enable_udp": true,
      "enable_bind": false,
      "udp_bind_port": 0,
      "udp_idle_timeout": 60,
      "udp_max_datagram": 65535,
      "enable_auth": true
    }
  }
}
```

### protocol.trojan

```json
{
  "protocol": {
    "trojan": {
      "enable_tcp": true,
      "enable_udp": true,
      "udp_idle_timeout": 60,
      "udp_max_datagram": 65535
    }
  }
}
```

### protocol.vless

```json
{
  "protocol": {
    "vless": {
      "enable_udp": true,
      "udp_idle_timeout": 60,
      "udp_max_datagram": 65535
    }
  }
}
```

### protocol.shadowsocks

```json
{
  "protocol": {
    "shadowsocks": {
      "psk": "5n5ESu953i/pjIp02oZvHA==",
      "method": "2022-blake3-aes-128-gcm",
      "enable_tcp": true,
      "enable_udp": false,
      "udp_idle_timeout": 60
    }
  }
}
```

---

## 多路复用配置

```json
{
  "multiplex": {
    "enabled": true,
    "smux": {
      "max_streams": 512,          // 代码默认 32
      "buffer_size": 65535,        // 代码默认 4096
      "keepalive_interval_ms": 30000,
      "udp_idle_timeout_ms": 60000,
      "udp_max_datagram": 65535
    },
    "yamux": {
      "max_streams": 256,          // 代码默认 32
      "buffer_size": 65535,        // 代码默认 4096
      "initial_window": 4194304,   // 代码默认 262144
      "enable_ping": true,
      "ping_interval_ms": 30000,
      "stream_open_timeout_ms": 30000,
      "stream_close_timeout_ms": 30000,
      "udp_idle_timeout_ms": 60000,
      "udp_max_datagram": 65535
    }
  }
}
```

### 性能影响

> `src/configuration.json` 中的值是生产环境调优值，不同于代码默认值。

**`buffer_size`**（关键参数）：

| 值 | 影响 |
|----|------|
| 过小（<16KB） | **严重性能问题**：吞吐量大幅下降 |
| 适中（32KB-128KB） | 平衡内存和性能 |
| 过大（>256KB） | 内存占用高 |
| 建议 | **至少 32KB，推荐 64KB** |

**`max_streams`**：

| 值 | 影响 |
|----|------|
| 过小（<32） | 并发受限 |
| 过大（>512） | 单连接压力大 |
| 建议 | 128-256 |

---

## 伪装配置

### stealth.reality

```json
{
  "stealth": {
    "reality": {
      "dest": "www.microsoft.com:443",
      "server_names": ["www.microsoft.com"],
      "private_key": "cGAv/vuH9mRJmvo4lqOwMZgR56mL4vMjBAwmVMS69Fw=",
      "short_ids": ["45587ac66ce007e4"]
    }
  }
}
```

### stealth.shadowtls

```json
{
  "stealth": {
    "shadowtls": {
      "version": 3,
      "password": "",
      "users": [
        { "name": "user1", "password": "secret1" }
      ],
      "handshake_dest": "www.google.com:443",
      "strict_mode": true,
      "handshake_timeout_ms": 5000
    }
  }
}
```

| 字段 | 默认值 | 说明 |
|------|--------|------|
| `version` | `3` | 协议版本（2 或 3） |
| `password` | - | v2 兼容密码 |
| `users` | `[]` | v3 多用户列表（name + password） |
| `handshake_dest` | - | 握手后端目标 host:port |
| `strict_mode` | `true` | 严格模式：仅 TLS 1.3 |
| `handshake_timeout_ms` | `5000` | 握手超时（毫秒） |

### stealth.restls

```json
{
  "stealth": {
    "restls": {
      "host": "www.bing.com:443",
      "password": "secret",
      "version_hint": "tls13",
      "restls_script": "300?100<1",
      "handshake_timeout_ms": 5000
    }
  }
}
```

| 字段 | 默认值 | 说明 |
|------|--------|------|
| `host` | - | TLS 后端目标 host:port |
| `password` | - | 认证密码 |
| `version_hint` | - | 版本提示：`tls12` 或 `tls13` |
| `restls_script` | - | 流量控制脚本（见下方说明） |
| `handshake_timeout_ms` | `5000` | 握手超时（毫秒） |

**Restls Script 语法**：
- `300?100`: 发送 300 字节，等待 100ms
- `400~100`: 等待 100ms 后发送 400 字节
- `<1`: 等待客户端数据

---

## DNS 配置

```json
{
  "dns": {
    "servers": [
      {
        "address": "223.5.5.5",
        "port": 53,
        "protocol": "udp",
        "timeout_ms": 1500
      },
      {
        "address": "119.29.29.29",
        "port": 53,
        "protocol": "udp",
        "timeout_ms": 1500
      }
    ],
    "mode": "first",
    "timeout_ms": 5000,
    "cache_enabled": true,
    "cache_size": 10000,
    "cache_ttl": 120,
    "serve_stale": true,
    "negative_ttl": 300,
    "ttl_min": 60,
    "ttl_max": 86400,
    "disable_ipv6": true
  }
}
```

### DNS 服务器配置

| 字段 | 默认值 | 说明 |
|------|--------|------|
| `address` | - | DNS 服务器地址 |
| `port` | `53` | DNS 服务器端口 |
| `protocol` | `udp` | 协议类型：`udp`/`tcp`/`tls`/`https` |
| `timeout_ms` | `5000` | 单次查询超时（毫秒） |

### 解析策略

| 字段 | 默认值 | 说明 |
|------|--------|------|
| `mode` | `fastest` | `first`（首个成功）/`fastest`（最低延迟）/`fallback`（顺序尝试） |
| `timeout_ms` | `5000` | 整体解析超时（毫秒） |

### 缓存配置

| 字段 | 默认值 | 说明 |
|------|--------|------|
| `cache_enabled` | `true` | 是否启用缓存 |
| `cache_size` | `10000` | 最大缓存条目数 |
| `cache_ttl` | `120` | 默认缓存时间（秒） |
| `serve_stale` | `true` | 过期后是否返回旧结果 |
| `negative_ttl` | `300` | 负缓存时间（秒） |
| `ttl_min` / `ttl_max` | `60` / `86400` | TTL 钳制范围 |
| `disable_ipv6` | `false` | 是否禁用 IPv6 |

---

## 日志配置

```json
{
  "trace": {
    "file_name": "forward.log",
    "path_name": "C:\\path\\to\\logs",
    "max_size": 67108864,
    "max_files": 8,
    "queue_size": 8192,
    "thread_count": 1,
    "enable_console": true,
    "enable_file": true,
    "log_level": "debug",
    "pattern": "[%Y-%m-%d %H:%M:%S.%e] [%5t] [%l] %v",
    "trace_name": "forward_engine"
  }
}
```

| 字段 | 默认值 | 说明 |
|------|--------|------|
| `file_name` | `prism.log` | 日志文件名 |
| `path_name` | `logs` | 日志目录 |
| `max_size` | `64MB` | 单文件最大大小 |
| `max_files` | `8` | 最大文件数 |
| `log_level` | `info` | `trace`/`debug`/`info`/`warn`/`error` |
| `enable_console` | `true` | 输出到控制台 |
| `enable_file` | `true` | 输出到文件 |

**性能提示**：`debug` 级别日志量大，高并发场景建议用 `info`。

---

完整配置示例参见 `src/configuration.json`。各字段默认值见上文各节说明。

---

## 性能调优建议

### 高并发短连接

- `pool.max_cache_per_endpoint`: 64-128
- `pool.max_idle_seconds`: 60-120（快速释放）
- `multiplex.smux.buffer_size`: 32KB

### 大文件下载

- `pool.recv/send_buffer_size`: 128KB-256KB
- `multiplex.smux.buffer_size`: 64KB-128KB（**关键**）
- `multiplex.smux.max_streams`: 64-128

### 低延迟敏感

- `pool.connect_timeout_ms`: 500-1000
- `dns.timeout_ms`: 1000
- `pool.tcp_nodelay`: true（必须开启）

### 内存受限

- `pool.max_cache_per_endpoint`: 8-16
- `multiplex.smux.buffer_size`: 16KB-32KB
- `dns.cache_size`: 1000-2000
