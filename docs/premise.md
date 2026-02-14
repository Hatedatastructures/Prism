# ForwardEngine 技术概述与使用指南

欢迎使用 ForwardEngine！本文档既是项目的技术概述，也是面向新手的实用指南。无论你是普通用户还是开发者，都能在这里找到需要的信息。

## 快速开始（5分钟上手）

### 第一步：下载与安装
**方法一：预编译版本（推荐新手）**
1. 从项目的 [Release 页面](https://github.com/Hatedatastructures/forward-engine/releases) 下载对应系统的二进制文件
2. 解压到任意目录
3. 双击 `Forward.exe`（Windows）或 `./forward`（Linux）运行

**方法二：从源码编译（开发者）**
```bash
git clone https://github.com/Hatedatastructures/forward-engine.git
cd ForwardEngine
```

### 第二步：基本配置
配置文件位于 `src/configuration.json`，最基本的配置如下：
```json
{
  "agent": {
    "addressable": {
      "host": "localhost",
      "port": 8081
    }
  }
}
```

### 第三步：启动与测试
1. **启动程序**：运行 `Forward.exe`
2. **测试代理**：打开命令行，输入：
   ```cmd
   curl -v -x http://127.0.0.1:8081 http://www.baidu.com
   ```
3. **设置浏览器**：在浏览器代理设置中填入 `127.0.0.1:8081`

看到网页内容表示代理工作正常！

## 项目是什么？

ForwardEngine 是一个基于 Modern C++（C++23）的高性能代理引擎，可以理解为"网络中转站"：

- **接收**你的网络请求（浏览器、游戏、应用程序）
- **转发**到目标网站或服务器
- **返回**结果给你

### 它能做什么？
- **网页浏览代理**：HTTP/HTTPS 代理，保护隐私
- **游戏/软件代理**：SOCKS5 代理，支持各类应用程序
- **加密隧道**：Trojan 协议，流量加密伪装

### 典型使用场景
- **开发测试**：本地调试网络应用
- **隐私保护**：隐藏真实 IP 地址
- **网络加速**：优化特定网站访问
- **内容控制**：家庭或企业网络管理

## 核心架构概览

### 整体工作流程
```
客户端 → ForwardEngine（协议识别） → 路由分发 → 上游服务器
       ↑                              ↓
       ←──────── 双向转发 ←─────────
```

### 关键模块简介
1. **协议识别**：自动识别 HTTP、SOCKS5、Trojan 协议
2. **路由分发**：决定请求是正向代理、反向代理还是直连
3. **连接池**：复用 TCP 连接，提高性能
4. **隧道转发**：高效的双向数据搬运

### 技术特点
- **协程驱动**：基于 Boost.Asio 协程，无回调地狱
- **内存优化**：统一 PMR 内存管理，减少碎片
- **连接复用**：智能连接池，减少握手开销
- **协议完整**：支持主流代理协议

## 详细技术指南

### 协议支持详解

#### HTTP/HTTPS 代理
- **功能**：最常用的代理类型，支持普通 HTTP 和 HTTPS CONNECT 隧道
- **使用**：浏览器、curl、wget 等工具直接支持
- **配置**：无需特殊配置，开箱即用

#### SOCKS5 代理
- **功能**：通用传输层代理，支持 TCP 连接
- **特点**：支持 IPv4/IPv6/域名地址，兼容游戏和聊天软件
- **测试**：`curl -x socks5://127.0.0.1:8081 http://example.com`

#### Trojan 代理
- **功能**：基于 TLS 的加密代理，流量看起来像普通 HTTPS
- **要求**：需要有效 TLS 证书和密码配置
- **优势**：对抗流量检测，保护隐私

### 配置详解

#### 代理服务配置
```json
{
  "agent": {
    "addressable": {
      "host": "0.0.0.0",  // 监听地址，0.0.0.0 表示所有接口
      "port": 8081        // 监听端口
    },
    "certificate": {
      "cert": "./cert.pem",  // TLS 证书文件（相对路径）
      "key": "./key.pem"     // 私钥文件（相对路径）
    }
  }
}
```

#### 连接池配置
```json
{
  "agent": {
    "pool": {
      "max_cache_per_endpoint": 32,  // 每个目标最大缓存连接数
      "max_idle_seconds": 60          // 连接最大空闲时间（秒）
    }
  }
}
```

#### 日志配置
```json
{
  "trace": {
    "enable_console": true,
    "enable_file": true,
    "log_level": "info",  // trace/debug/info/warn/error/critical
    "pattern": "[%Y-%m-%d %H:%M:%S.%e][%l] %v",
    "trace_name": "forward_engine",
    "path_name": "./logs"
  }
}
```

可选字段与默认值（见 `include/forward-engine/trace/config.hpp`）：
- `file_name`：`forward.log`
- `max_size`：64MB
- `max_files`：8
- `queue_size`：8192
- `thread_count`：1

### 性能优化建议

#### 连接池调优
- **高并发场景**：增加 `max_cache_per_endpoint`，缩短 `max_idle_seconds`
- **低内存场景**：减少 `max_cache_per_endpoint`，延长空闲时间
- **稳定场景**：保持默认值，平衡性能和内存

#### 系统优化
**Windows**：
```powershell
netsh int tcp set global autotuninglevel=normal
```

**Linux**：
```bash
echo "net.ipv4.tcp_tw_reuse = 1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

#### 监控指标
- **活动连接数**：当前处理的连接数量
- **请求速率**：每秒请求数
- **流量统计**：流入/流出字节数
- **连接池命中率**：复用效率

## 故障排除

### 常见问题速查

#### Q1：程序启动失败
- **检查运行环境**：确认 `c:/bin` 依赖库已配置正确
- **查看日志**：检查 `logs/` 目录下的错误信息
- **端口占用**：修改配置中的端口号

#### Q2：无法连接代理
- **确认服务运行**：`tasklist | findstr Forward.exe`
- **检查防火墙**：允许代理端口通过
- **测试连接**：`telnet 127.0.0.1 8081`

#### Q3：速度慢
- **调整连接池**：减少空闲时间，增加缓存数量
- **检查网络**：测试直连速度
- **系统优化**：调整 TCP 参数

#### Q4：证书问题
- **生成证书**：使用 OpenSSL 生成有效证书
- **检查路径**：确保证书文件存在且有读取权限
- **格式验证**：确保证书为 PEM 格式

### 日志分析技巧
1. **按级别过滤**：重点关注 error 和 warn 级别
2. **按时间搜索**：查找特定时间段的日志
3. **关键词搜索**：搜索特定 IP、域名或错误代码
4. **模式识别**：寻找重复出现的错误模式

### 调试模式
启用详细日志：
```json
{
  "trace": {
    "log_level": "debug",
    "enable_console": true
  }
}
```

## 深入学习

### 核心代码模块
建议按以下顺序阅读源码（路径相对 `include/forward-engine/`）：

1. **`agent/worker.hpp`**：入口组件，初始化 `source/distributor/session` 并启动 accept 循环
2. **`agent/session.hpp`**：单连接会话对象，负责协议识别与调度到具体 handler
3. **`agent/handler.hpp`**：协议处理协程集合（HTTP/SOCKS5/Trojan），负责握手、路由与启动转发
4. **`agent/validator.hpp`**：认证与会话限流（如 Trojan 密码校验、连接数限制）
5. **`protocol/analysis.hpp`**：协议识别与目标解析（从 HTTP/字符串等提取 `host:port`）
6. **`agent/distributor.hpp`**：路由分发（正向/反向/直连）
7. **`transport/source.hpp`**：TCP 连接池（上游连接复用与健康检查）
8. **`transport/transmission.hpp`**：核心传输接口抽象
9. **`transport/reliable.hpp`**：TCP 传输实现
10. **`protocol/` 目录**：HTTP/SOCKS5/Trojan 等协议细节实现

### 关键概念深入

#### 协程与异步
项目使用 `net::awaitable<void>` 协程组织异步流程：
- `co_spawn`：投递协程任务到事件循环
- `co_await`：等待异步操作完成
- `use_awaitable`：将异步操作转换为协程形式

#### 内存管理
采用 PMR（Polymorphic Memory Resource）策略：
- `memory::current_resource()`：获取当前内存资源
- `memory::string` / `memory::vector`：项目统一容器别名
- `frame_arena`：请求级临时对象分配器

#### 隧道转发
双向转发的关键设计：
- **正确退出**：一端关闭时通知另一端及时退出
- **资源回收**：使用智能指针确保连接正确回收
- **错误处理**：区分正常断开和异常错误

### 测试验证
运行测试确保理解正确：
```bat
:: 运行所有测试（推荐）
ctest --test-dir build_release --output-on-failure

:: 你也可以只跑单个用例（名称以 ctest -N 输出为准）
ctest --test-dir build_release -R session_test --output-on-failure
```

关键测试用例（用于定位模块）：
- `session_test`：验证隧道转发与退出语义
- `socks5_test`：验证 SOCKS5 握手与数据回显
- `trojan_test`：验证 Trojan 握手与密码验证
- `connection_test`：验证连接池复用逻辑

## 常见问题（精选）

### 安装运行类
**Q：双击程序没反应？**
A：可能缺少运行库，安装 Visual C++ Redistributable，或以管理员身份运行。

**Q：如何查看错误信息？**
A：使用命令行运行程序，或查看 `logs/` 目录下的日志文件。

**Q：如何让程序在后台运行？**
A：Windows 可使用 `Start-Process -WindowStyle Hidden`，Linux 可使用 `nohup`。

### 配置使用类
**Q：配置文件在哪里？**
A：`src/configuration.json`，修改后需要重启程序。

**Q：如何修改代理端口？**
A：修改配置中的 `agent.addressable.port` 字段。

**Q：如何启用调试日志？**
A：将 `trace.log_level` 改为 `"debug"`。

### 网络连接类
**Q：浏览器提示"无法连接代理服务器"？**
A：确认服务正在运行，检查防火墙，测试 `telnet 127.0.0.1 端口`。

**Q：只有本机能连接，其他电脑不行？**
A：将 `host` 改为 `"0.0.0.0"`，检查防火墙和路由器设置。

**Q：连接经常断开？**
A：调整连接池的 `max_idle_seconds`，增加 `max_cache_per_endpoint`。

### 性能安全类
**Q：使用代理后网速变慢？**
A：优化连接池配置，调整系统 TCP 参数，检查网络状况。

**Q：如何保护代理不被滥用？**
A：使用防火墙限制 IP，配置认证，监控日志，定期更新。

**Q：发现可疑连接怎么办？**
A：立即修改端口，查看日志追踪来源，防火墙屏蔽可疑 IP。

---

## 许可证与致谢

### 许可证
ForwardEngine 采用 **MIT 许可证**，允许商业使用、修改和分发，但需要保留版权声明。

### 联系与支持
- **问题反馈**：GitHub Issues
- **功能建议**：GitHub Discussions
- **安全漏洞**：通过安全渠道报告

---

**ForwardEngine - 为现代网络而生的高性能代理引擎** 🚀

如果本文档未能解决你的问题，请查阅其他文档或提交 issue。祝你使用愉快！
