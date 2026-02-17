# HTTP/HTTPS 服务器使用说明

## 概述

这是一个高性能的 HTTP/HTTPS 服务器，基于 Boost.Asio 和 C++20 协程实现，支持协议自动检测、原子统计、优雅关闭等生产级特性。

## 特性

- ✅ 同时支持 HTTP 和 HTTPS 连接（同一端口）
- ✅ 协议自动检测（TLS 握手前 3 字节识别）
- ✅ 原子统计器（总请求数、活跃连接数、流量统计）
- ✅ 健康检查端点（`/health` 返回 JSON 统计）
- ✅ 优雅关闭（等待所有连接完成）
- ✅ 并发连接数限制（防止资源耗尽）
- ✅ 纯协程驱动，无锁设计
- ✅ 零开销原则（遵循 ForwardEngine 性能军规）

## 编译

### 依赖项

- Boost.Asio (>= 1.70)
- Boost.Beast (>= 1.70)
- OpenSSL (>= 1.1.1)
- C++20 编译器

### 编译命令

#### Windows (MinGW)

```bash
g++ -std=c++20 -O2 -DNDEBUG server.cpp -o server.exe ^
    -Ic:/bin/boost/include ^
    -Lc:/bin/boost/lib ^
    -Lc:/bin/openssl/lib ^
    -lboost_system -lboost_coroutine -lssl -lcrypto -lws2_32 -lcrypt32
```

#### Linux

```bash
g++ -std=c++20 -O2 -DNDEBUG server.cpp -o server \
    -lboost_system -lboost_coroutine -lssl -lcrypto -lpthread
```

## 证书生成

服务器需要 SSL 证书才能支持 HTTPS。使用提供的脚本生成自签名证书：

### Windows

```cmd
generate_cert.bat
```

### Linux

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes \
    -subj "/C=CN/ST=Beijing/L=Beijing/O=ForwardEngine/OU=Development/CN=localhost"
```

**注意**: 生成的证书仅用于测试，不要在生产环境中使用。

## 运行

```bash
# Windows
server.exe

# Linux
./server
```

服务器默认监听端口 `8000`，使用 `cert.pem` 和 `key.pem` 作为 SSL 证书。

## 测试

### HTTP 端点

```bash
# 基础测试
curl http://localhost:8000/
curl http://localhost:8000/1m
curl http://localhost:8000/10m

# 健康检查
curl http://localhost:8000/health
```

### HTTPS 端点

```bash
# 基础测试（忽略证书验证）
curl -k https://localhost:8000/
curl -k https://localhost:8000/1m
curl -k https://localhost:8000/10m

# 健康检查
curl -k https://localhost:8000/health
```

### 健康检查响应示例

```json
{
  "total_requests": 1234,
  "active_connections": 56,
  "bytes_sent": 987654321,
  "bytes_received": 123456789
}
```

### 压力测试

```bash
# 使用 Apache Bench 进行压力测试
ab -n 10000 -c 100 http://localhost:8000/
ab -n 10000 -c 100 https://localhost:8000/ -k

# 使用 wrk 进行压力测试
wrk -t4 -c100 -d30s http://localhost:8000/
wrk -t4 -c100 -d30s https://localhost:8000/ -s
```

## 端点说明

| 端点 | 方法 | 描述 | 响应 |
|------|------|------|------|
| `/` | GET | 基础测试 | `OK` |
| `/1m` | GET | 返回 1MB 数据 | 1MB 字符 'A' |
| `/10m` | GET | 返回 10MB 数据 | 10MB 字符 'B' |
| `/health` | GET | 健康检查 | JSON 统计信息 |

## 配置

### 修改监听端口

在 `main()` 函数中修改 `port` 变量：

```cpp
unsigned short port = 8080;  // 修改为你想要的端口
```

### 修改证书路径

在 `main()` 函数中修改证书路径：

```cpp
const std::string cert_file = "path/to/cert.pem";
const std::string key_file = "path/to/key.pem";
```

### 修改并发连接数限制

修改 `MAX_CONCURRENT_CONNECTIONS` 常量：

```cpp
constexpr size_t MAX_CONCURRENT_CONNECTIONS = 10000;
```

## 优雅关闭

按下 `Ctrl+C` 可以优雅关闭服务器：

1. 停止接受新连接
2. 等待现有连接完成处理
3. 输出最终统计信息
4. 退出程序

## 性能调优建议

### 网络参数

- **TCP_NODELAY**: 已启用，减少小数据包延迟
- **发送缓冲区**: 256KB
- **接收缓冲区**: 256KB
- **连接超时**: 30 秒（读取）、120 秒（写入）

### 内存优化

- 使用固定大小缓冲区，避免堆分配
- 复用 `flat_buffer`，减少内存碎片
- 原子操作避免锁竞争

### 并发优化

- 使用线程本地内存池（PMR）
- 协程驱动，无阻塞操作
- 并发连接数限制防止资源耗尽

### 编译优化

- 使用 `-O2` 或 `-O3` 优化级别
- 使用 `-DNDEBUG` 禁用断言
- 启用 LTO（链接时优化）: `-flto`

## 故障排除

### 证书错误

**错误**: `handshake failure: certificate verify failed`

**解决**:
- 确保证书文件 `cert.pem` 和 `key.pem` 存在
- 确保证书格式正确（PEM 格式）
- 使用 `-k` 参数跳过证书验证（仅用于测试）

### 端口占用

**错误**: `bind: Address already in use`

**解决**:
- 检查端口是否被其他程序占用
- 修改监听端口
- 在 Linux 上使用 `lsof -i :8000` 查看占用进程

### 编译错误

**错误**: `undefined reference to 'boost::...'`

**解决**:
- 确保已安装 Boost 库
- 检查编译器能找到 Boost 头文件和库文件
- 添加正确的链接选项

### 性能问题

**症状**: 高延迟或低吞吐量

**解决**:
- 检查网络带宽和延迟
- 调整缓冲区大小
- 增加工作线程数
- 使用性能分析工具（如 perf、Intel VTune）

## 架构设计

### 调用关系

```
main()
  └─> do_listen() [协程]
      ├─> detect_protocol() [协程]
      ├─> ssl_stream_wrapper + do_session() [协程] (HTTPS)
      └─> tcp_stream_wrapper + do_session() [协程] (HTTP)
          └─> server_stats::increment_requests/add_bytes_*()
```

### 核心组件

1. **server_stats**: 原子统计器
2. **ssl_stream_wrapper**: HTTPS 流封装
3. **tcp_stream_wrapper**: HTTP 流封装
4. **detect_protocol**: 协议自动检测
5. **do_session**: 会话处理器模板协程

## 性能军规遵循

✅ **零开销原则**
- 使用 `final` 标记支持编译器去虚拟化
- 固定大小缓冲区，避免堆分配
- 模板特化避免运行时开销

✅ **内存管理**
- 热路径无堆分配
- 原子操作避免锁竞争
- 侵入式管理（裸指针 + 引用）

✅ **数据零拷贝**
- 使用 `std::string_view` 传递路径
- `flat_buffer` 复用
- 响应体引用预分配字符串

✅ **异步与协程**
- 无阻塞操作
- 无锁设计（原子操作）
- 协程驱动（`co_await`）

## 许可证

本项目遵循 ForwardEngine 项目的许可证。

## 联系方式

如有问题或建议，请联系项目维护者。
