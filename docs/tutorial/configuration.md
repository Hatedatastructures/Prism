# 配置详解

本文档详细说明 Prism 的配置参数、性能影响和调优建议。

配置文件位于 `src/configuration.json`，采用 JSON 格式。

---

## 协议支持

### HTTP/HTTPS

- 功能：最常用的代理类型，支持普通 HTTP 和 HTTPS CONNECT 隧道
- 使用：浏览器、curl、wget 等工具直接支持
- 测试：`curl -x http://127.0.0.1:8081 http://example.com`

### SOCKS5

- 功能：通用传输层代理，支持 TCP CONNECT 和 UDP ASSOCIATE
- 特点：支持 IPv4/IPv6/域名地址，兼容游戏和聊天软件
- 测试：`curl -x socks5://127.0.0.1:8081 http://example.com`

### Trojan

- 功能：基于 TLS 的加密代理，流量看起来像普通 HTTPS
- 要求：需要有效 TLS 证书和密码配置
- 优势：对抗流量检测，保护隐私

### smux 多路复用

- 功能：单 TCP 连接承载多个独立子流
- 兼容：Mihomo/xtaci/smux v1 协议
- 优势：降低连接开销，提高连接密度，增加流量行为分析难度

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
| `host` | `0.0.0.0` | 监听地址，`0.0.0.0` 表示所有网卡，`127.0.0.1` 表示仅本机 |
| `port` | `8081` | 监听端口，建议使用 1024 以上端口避免权限问题 |

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

| 字段 | 说明 |
|------|------|
| `key` | 私钥文件路径（支持相对路径和绝对路径） |
| `cert` | 证书文件路径 |

**注意事项**：
- 自签名证书客户端需要配置 `skip-cert-verify: true`
- 生产环境建议使用 Let's Encrypt 等受信任证书

---

## 连接池配置

```json
{
  "agent": {
    "pool": {
      "max_cache_per_endpoint": 32,
      "max_idle_seconds": 240,
      "connect_timeout_ms": 300,
      "cleanup_interval_sec": 20,
      "recv_buffer_size": 65536,
      "send_buffer_size": 65536,
      "tcp_nodelay": true,
      "keep_alive": true,
      "cache_ipv6": false
    }
  }
}
```

### 参数详解

| 字段 | 默认值 | 说明 |
|------|--------|------|
| `max_cache_per_endpoint` | `32` | 每个目标端点最大缓存连接数 |
| `max_idle_seconds` | `240` | 空闲连接最大存活时间（秒） |
| `connect_timeout_ms` | `300` | 连接超时时间（毫秒） |
| `cleanup_interval_sec` | `20` | 后台清理间隔（秒） |
| `recv_buffer_size` | `65536` | 接收缓冲区大小（字节） |
| `send_buffer_size` | `65536` | 发送缓冲区大小（字节） |
| `tcp_nodelay` | `true` | 禁用 Nagle 算法 |
| `keep_alive` | `true` | 启用 TCP Keep-Alive |
| `cache_ipv6` | `false` | 是否缓存 IPv6 连接 |

### 性能影响

**`max_cache_per_endpoint`**：

| 值 | 影响 |
|----|------|
| 过小（<8） | 连接复用率低，频繁建立新连接，延迟增加 |
| 过大（>128） | 内存占用高，可能占用过多文件描述符 |
| 建议 | 根据并发量设置，一般 16-64 即可 |

**`connect_timeout_ms`**：

| 值 | 影响 |
|----|------|
| 过小（<100ms） | 正常网络波动也会超时，连接失败率上升 |
| 过大（>5000ms） | 故障节点检测慢，用户等待时间长 |
| 建议 | 国内网络 300-1000ms，跨国网络 2000-5000ms |

**`recv/send_buffer_size`**：

| 值 | 影响 |
|----|------|
| 过小（<8KB） | 高吞吐场景系统调用频繁，CPU 开销大 |
| 过大（>256KB） | 内存占用高，延迟可能略微增加 |
| 建议 | 64KB 是通用选择，大文件传输可设 128KB-256KB |

---

## 多路复用配置

```json
{
  "agent": {
    "mux": {
      "enabled": true,
      "smux": {
        "max_streams": 256,
        "buffer_size": 65535,
        "keepalive_interval_ms": 30000,
        "udp_idle_timeout_ms": 60000,
        "udp_max_datagram": 65535
      },
      "yamux": {
        "max_streams": 32,
        "buffer_size": 4096,
        "initial_window": 262144,
        "enable_ping": true,
        "ping_interval_ms": 30000,
        "stream_open_timeout_ms": 30000,
        "stream_close_timeout_ms": 30000,
        "udp_idle_timeout_ms": 60000,
        "udp_max_datagram": 65535
      }
    }
  }
}
```

smux 和 yamux 拥有各自独立的配置，互不影响。sing-mux 协商时客户端选择协议，
服务端使用对应的配置参数。

### smux 参数详解

| 字段 | 默认值 | 说明 |
|------|--------|------|
| `max_streams` | `32` | 单个 mux 会话最大子流数 |
| `buffer_size` | `4096` | 子流读写缓冲区大小（字节），实际限制 min(buffer_size, 65535) |
| `keepalive_interval_ms` | `30000` | 保活心跳间隔（毫秒），0 表示禁用 |
| `udp_idle_timeout_ms` | `60000` | UDP 管道空闲超时（毫秒） |
| `udp_max_datagram` | `65535` | UDP 数据报最大长度（字节） |

### yamux 参数详解

| 字段 | 默认值 | 说明 |
|------|--------|------|
| `max_streams` | `32` | 单个 mux 会话最大子流数 |
| `buffer_size` | `4096` | 子流读写缓冲区大小（字节） |
| `initial_window` | `262144` | 初始流窗口大小（字节），控制单流吞吐量 |
| `enable_ping` | `true` | 是否启用心跳 |
| `ping_interval_ms` | `30000` | 心跳间隔（毫秒） |
| `stream_open_timeout_ms` | `30000` | 流打开超时（毫秒） |
| `stream_close_timeout_ms` | `30000` | 流关闭超时（毫秒） |
| `udp_idle_timeout_ms` | `60000` | UDP 管道空闲超时（毫秒） |
| `udp_max_datagram` | `65535` | UDP 数据报最大长度（字节） |

### 性能影响

**`buffer_size`**（关键参数）：

| 值 | 影响 |
|----|------|
| 过小（<16KB） | **严重性能问题**：系统调用频繁，吞吐量大幅下降 |
| 适中（32KB-128KB） | 平衡内存和性能 |
| 过大（>256KB） | 内存占用高，多流场景可能内存紧张 |
| 建议 | **至少 32KB，推荐 64KB** |

**`max_streams`**：

| 值 | 影响 |
|----|------|
| 过小（<32） | 并发受限，需要更多底层连接 |
| 过大（>512） | 单连接压力大，故障影响面大 |
| 建议 | 128-256 是合理范围 |

---

## DNS 配置

```json
{
  "agent": {
    "dns": {
      "servers": [
        {
          "address": "114.114.114.114",
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
}
```

### DNS 服务器配置

| 字段 | 默认值 | 说明 |
|------|--------|------|
| `address` | - | DNS 服务器地址 |
| `port` | `53` | DNS 服务器端口 |
| `protocol` | `udp` | 协议类型：`udp`/`tcp`/`tls`/`https` |
| `timeout_ms` | `1500` | 单次查询超时（毫秒） |

### 解析策略

| 字段 | 默认值 | 说明 |
|------|--------|------|
| `mode` | `first` | 解析模式：`first`（最快响应）、`fastest`（最低延迟）、`fallback`（顺序尝试） |
| `timeout_ms` | `5000` | 整体解析超时（毫秒） |

### 缓存配置

| 字段 | 默认值 | 说明 |
|------|--------|------|
| `cache_enabled` | `true` | 是否启用缓存 |
| `cache_size` | `10000` | 最大缓存条目数 |
| `cache_ttl` | `120` | 默认缓存时间（秒） |
| `serve_stale` | `true` | 过期后是否返回旧结果 |
| `negative_ttl` | `300` | 负面缓存时间（秒） |
| `ttl_min` | `60` | TTL 最小值（秒） |
| `ttl_max` | `86400` | TTL 最大值（秒） |
| `disable_ipv6` | `false` | 是否禁用 IPv6 |

### 性能影响

**`timeout_ms`**：

| 值 | 影响 |
|----|------|
| 过小（<500ms） | 网络波动时频繁超时，解析失败率上升 |
| 过大（>3000ms） | 故障服务器拖慢整体响应 |
| 建议 | 1000-2000ms 是合理范围 |

**`cache_size`**：

| 值 | 影响 |
|----|------|
| 过小（<1000） | 缓存命中率低，频繁查询上游 |
| 过大（>50000） | 内存占用高，清理开销增加 |
| 建议 | 根据访问域名数量设置，一般 5000-20000 |

---

## 日志配置

```json
{
  "trace": {
    "file_name": "forward.log",
    "path_name": "C:\\Users\\C1373\\Desktop\\code\\prism\\logs",
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

### 参数详解

| 字段 | 默认值 | 说明 |
|------|--------|------|
| `file_name` | `forward.log` | 日志文件名 |
| `path_name` | `./logs` | 日志目录路径 |
| `max_size` | `67108864` (64MB) | 单文件最大大小 |
| `max_files` | `8` | 最大文件数量 |
| `queue_size` | `8192` | 异步日志队列大小 |
| `thread_count` | `1` | 日志写入线程数 |
| `enable_console` | `true` | 是否输出到控制台 |
| `enable_file` | `true` | 是否输出到文件 |
| `log_level` | `info` | 日志级别：`trace`/`debug`/`info`/`warn`/`error` |
| `pattern` | 见配置 | 日志格式 |

### 日志级别说明

| 级别 | 适用场景 |
|------|---------|
| `trace` | 开发调试，输出所有细节 |
| `debug` | 调试诊断，包含连接建立、DNS 解析等 |
| `info` | 生产环境，记录重要事件和统计 |
| `warn` | 仅警告和错误 |
| `error` | 仅错误 |

**性能提示**：`debug` 级别日志量大，高并发场景可能影响性能，生产环境建议使用 `info`。

---

## 认证配置

```json
{
  "agent": {
    "authentication": {
      "credentials": ["prism"],
      "users": [
        {
          "credential": "prism",
          "max_connections": 0
        }
      ]
    }
  }
}
```

### 参数详解

| 字段 | 说明 |
|------|------|
| `credentials` | 允许的密码列表（明文，内部转为 SHA224） |
| `users[].credential` | 用户密码 |
| `users[].max_connections` | 最大连接数限制，`0` 表示不限制 |

---

## 完整配置示例

```json
{
  "agent": {
    "addressable": {
      "host": "0.0.0.0",
      "port": 8081
    },
    "certificate": {
      "key": "C:\\path\\to\\key.pem",
      "cert": "C:\\path\\to\\cert.pem"
    },
    "authentication": {
      "credentials": ["your_password"],
      "users": [
        {
          "credential": "your_password",
          "max_connections": 0
        }
      ]
    },
    "pool": {
      "max_cache_per_endpoint": 32,
      "max_idle_seconds": 240,
      "connect_timeout_ms": 1000,
      "recv_buffer_size": 65536,
      "send_buffer_size": 65536,
      "tcp_nodelay": true,
      "keep_alive": true
    },
    "mux": {
      "enabled": true,
      "max_streams": 256,
      "buffer_size": 65536,
      "keepalive_interval_ms": 30000
    },
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
      "cache_enabled": true,
      "cache_size": 10000,
      "disable_ipv6": true
    }
  },
  "trace": {
    "enable_console": true,
    "enable_file": true,
    "log_level": "info"
  }
}
```

---

## 性能调优建议

### 场景一：高并发短连接

- `pool.max_cache_per_endpoint`: 64-128（提高复用率）
- `pool.max_idle_seconds`: 60-120（快速释放）
- `mux.buffer_size`: 32KB（减少内存占用）

### 场景二：大文件下载

- `pool.recv/send_buffer_size`: 128KB-256KB
- `mux.buffer_size`: 64KB-128KB（**关键**）
- `mux.max_streams`: 64-128（避免单连接过载）

### 场景三：低延迟敏感

- `pool.connect_timeout_ms`: 500-1000
- `dns.timeout_ms`: 1000
- `pool.tcp_nodelay`: true（必须开启）

### 场景四：内存受限

- `pool.max_cache_per_endpoint`: 8-16
- `mux.buffer_size`: 16KB-32KB
- `dns.cache_size`: 1000-2000