# 配置详解

本文档详细说明 Prism 的配置参数和调优建议。

## 协议支持详解

### HTTP/HTTPS 代理

- **功能**：最常用的代理类型，支持普通 HTTP 和 HTTPS CONNECT 隧道
- **使用**：浏览器、curl、wget 等工具直接支持
- **配置**：无需特殊配置，开箱即用

### SOCKS5 代理

- **功能**：通用传输层代理，支持 TCP 连接
- **特点**：支持 IPv4/IPv6/域名地址，兼容游戏和聊天软件
- **测试**：`curl -x socks5://127.0.0.1:8081 http://example.com`

### Trojan 代理

- **功能**：基于 TLS 的加密代理，流量看起来像普通 HTTPS
- **要求**：需要有效 TLS 证书和密码配置
- **优势**：对抗流量检测，保护隐私

---

## 配置文件说明

### 代理服务配置

```json
{
  "agent": {
    "addressable": {
      "host": "0.0.0.0",
      "port": 8081
    },
    "certificate": {
      "cert": "./cert.pem",
      "key": "./key.pem"
    }
  }
}
```

| 字段 | 说明 |
|------|------|
| `addressable.host` | 监听地址，`0.0.0.0` 表示所有接口 |
| `addressable.port` | 监听端口 |
| `certificate.cert` | TLS 证书文件（相对路径） |
| `certificate.key` | 私钥文件（相对路径） |

### 连接池配置

```json
{
  "agent": {
    "pool": {
      "max_cache_per_endpoint": 32,
      "max_idle_seconds": 30
    }
  }
}
```

| 字段 | 默认值 | 说明 |
|------|--------|------|
| `max_cache_per_endpoint` | 32 | 每个目标最大缓存连接数 |
| `max_idle_seconds` | 30 | 连接最大空闲时间（秒） |

### 日志配置

```json
{
  "trace": {
    "enable_console": true,
    "enable_file": true,
    "log_level": "info",
    "pattern": "[%Y-%m-%d %H:%M:%S.%e][%l] %v",
    "trace_name": "forward_engine",
    "path_name": "./logs"
  }
}
```

可选字段与默认值（见 `include/prism/trace/config.hpp`）：

| 字段 | 默认值 | 说明 |
|------|--------|------|
| `file_name` | `forward.log` | 日志文件名 |
| `max_size` | 64MB | 单个日志文件最大大小 |
| `max_files` | 8 | 日志文件最大数量 |
| `queue_size` | 8192 | 异步日志队列大小 |
| `thread_count` | 1 | 日志线程数 |

---

## 性能优化建议

### 连接池调优

| 场景 | 建议配置 |
|------|---------|
| **高并发** | 增加 `max_cache_per_endpoint`，缩短 `max_idle_seconds` |
| **低内存** | 减少 `max_cache_per_endpoint`，延长空闲时间 |
| **稳定场景** | 保持默认值，平衡性能和内存 |

### 系统优化

**Windows**：

```powershell
netsh int tcp set global autotuninglevel=normal
```

**Linux**：

```bash
echo "net.ipv4.tcp_tw_reuse = 1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

### 监控指标

- **活动连接数**：当前处理的连接数量
- **请求速率**：每秒请求数
- **流量统计**：流入/流出字节数
- **连接池命中率**：复用效率
