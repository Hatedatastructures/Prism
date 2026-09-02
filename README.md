<div align="center">
  <h1>Prism</h1>
  <p>基于 C++23 的跨平台服务端代理。</p>
</div>

Prism 面向多协议接入、高并发转发和可组合传输场景，采用 Boost.Asio 协程处理网络 I/O，支持单端口统一接入与协议识别。

## 功能特性

- **协议支持**：HTTP、SOCKS5、Trojan、VLESS、VMess、Shadowsocks 2022、AnyTLS、TrustTunnel、WebSocket、XHTTP、gRPC、Hysteria2 和 TUIC v5
- **单端口接入**：在同一监听入口识别不同协议，并按配置进入对应的认证、拨号和转发流程
- **传输能力**：支持 TCP、UDP，以及面向流和数据报的协议适配
- **传输伪装**：支持 Reality、ShadowTLS、Restls、AnyTLS、WebSocket、XHTTP、gRPC、TrustTunnel 和 ECH
- **多路复用**：支持 smux、yamux 和 h2mux，可配置流数量、窗口、缓冲区和保活策略
- **异步 DNS**：支持规则匹配、地址重写、缓存、负缓存和可配置的 UDP/TCP/TLS/HTTPS 上游
- **运行时模型**：基于 C++23 协程、Boost.Asio 和 PMR 内存资源，覆盖监听、worker、session、relay 和优雅停机
- **跨平台**：支持 Windows 和 Linux

## 工作方式

```text
listener
  -> balancer
  -> worker
  -> session
  -> protocol recognition
  -> handshake / transport camouflage
  -> protocol handler
  -> outbound dial
  -> bidirectional relay
```

连接进入 listener 后由 balancer 分配到 worker。session 负责协议识别和生命周期管理，具体协议负责认证与数据格式，outbound 和 relay 负责建立上游连接并转发流量。

## 构建

### 环境要求

- C++23 编译器（GCC 13+，Windows 推荐 MinGW）
- CMake 3.23+
- Git

### Release 构建

```bash
git clone https://github.com/Hatedatastructures/Prism.git
cd Prism
cmake -B build -DCMAKE_BUILD_TYPE=Release -DPRISM_ENABLE_BENCHMARK=OFF -DPRISM_ENABLE_STRESS=OFF
cmake --build build --config Release
```

### 可选构建项

```text
PRISM_ENABLE_BENCHMARK=ON  构建性能测试
PRISM_ENABLE_STRESS=ON     构建压力测试
PRISM_ENABLE_COVERAGE=ON   启用代码覆盖率
PRISM_ENABLE_ASAN=ON       启用 AddressSanitizer
```

## 配置

默认配置模板位于 `src/configuration.json`。配置至少包含监听地址、认证用户、证书或密钥、协议开关，以及可选的伪装、多路复用和 DNS 设置。

```bash
cp src/configuration.json build/src/
```

程序默认读取可执行文件同目录下的 `configuration.json`，也可以通过命令行传入配置文件路径：

```bash
./build/src/Prism /path/to/configuration.json
```

启动前请替换示例中的密码、UUID、PSK、证书、私钥和本机路径。字段说明与完整示例见[配置说明](docs/tutorial/configuration.md)。

## 运行

```bash
./build/src/Prism
```

默认监听端口由 `agent.addressable.port` 配置。生产部署时请限制配置文件权限，并按系统防火墙规则开放对应端口。

## 测试

运行默认功能测试：

```bash
ctest --test-dir build --output-on-failure -j1 --timeout 30
```

运行 Go 互操作测试（需要 Go 1.22+）：

```bash
ctest --test-dir build -R GoCompat --output-on-failure -j1
```

性能测试和压力测试需要在配置阶段显式开启对应选项，详细命令见[性能报告](docs/performance-report.md)。

## 文档

- [快速开始](docs/tutorial/getting-started.md)
- [配置说明](docs/tutorial/configuration.md)
- [部署指南](docs/tutorial/deployment.md)
- [架构说明](docs/ARCHITECTURE.md)
- [故障排查](docs/tutorial/troubleshooting.md)
- [性能报告](docs/performance-report.md)

## 许可证

[MIT](LICENSE)
