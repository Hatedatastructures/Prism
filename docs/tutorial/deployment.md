# 生产环境部署指南

本指南说明 Prism 在生产环境中的编译、部署、运维和监控方案。

---

## 系统要求

### 硬件最低配置

| 资源 | 最低要求 | 推荐配置 |
|------|----------|----------|
| CPU | 2 核 | 4 核及以上（worker 线程数 = CPU 核心数 - 1） |
| 内存 | 512 MB | 2 GB 及以上 |
| 磁盘 | 100 MB（二进制 + 日志） | 1 GB（含日志轮转空间） |

### 操作系统

| 系统 | 版本要求 | 备注 |
|------|----------|------|
| Windows | Windows 10 1809+ / Server 2019+ | MinGW 静态链接，无运行时依赖 |
| Linux | glibc 2.31+（Ubuntu 20.04+ / Debian 11+ / CentOS 8+） | 需 GCC 13+ |

### 编译工具链

| 工具 | 版本要求 |
|------|----------|
| C++ 编译器 | GCC 13+ / MinGW（C++23） |
| CMake | 3.23+ |
| Git | 2.0+ |
| Make / Ninja | 任选其一 |

### 网络要求

- 首次构建需网络（FetchContent 自动下载 Boost、BoringSSL、spdlog、glaze、BLAKE3）
- 运行时需开放代理监听端口（默认 8081）并访问 DNS 和上游目标

---

## 从源码编译

### Release 构建（生产环境推荐）

```bash
git clone https://github.com/Hatedatastructures/Prism.git
cd Prism

cmake -B build_release -DCMAKE_BUILD_TYPE=Release
cmake --build build_release --config Release
```

Release 模式启用 `-O3` 优化，并通过 `--gc-sections` 裁剪未使用符号。

### 关闭可选组件

```bash
cmake -B build_release \
    -DCMAKE_BUILD_TYPE=Release \
    -DPRISM_ENABLE_BENCHMARK=OFF \
    -DPRISM_ENABLE_STRESS=OFF
```

### 交叉编译（ARM64 示例）

```bash
# Debian/Ubuntu: sudo apt install gcc-13-aarch64-linux-gnu
cmake -B build_arm64 \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_COMPILER=aarch64-linux-gnu-gcc-13 \
    -DCMAKE_CXX_COMPILER=aarch64-linux-gnu-g++-13 \
    -DPRISM_ENABLE_BENCHMARK=OFF \
    -DPRISM_ENABLE_STRESS=OFF
cmake --build build_arm64 --config Release
```

### 编译产物

| 文件 | 路径 |
|------|------|
| 主程序 | `build_release/src/Prism`（Windows 下为 `Prism.exe`） |
| 测试套件 | `build_release/tests/` |
| 基准测试 | `build_release/benchmarks/`（需 `PRISM_ENABLE_BENCHMARK=ON`） |

### 验证构建

```bash
ctest --test-dir build_release --output-on-failure
```

---

## 安装与部署

### Linux 二进制安装

```bash
sudo cp build_release/src/Prism /usr/local/bin/prism
sudo chmod +x /usr/local/bin/prism
sudo mkdir -p /etc/prism /var/log/prism /var/lib/prism
sudo cp src/configuration.json /etc/prism/configuration.json
```

### Windows 部署目录

```
C:\Prism\
  ├── Prism.exe
  ├── configuration.json
  ├── logs\
  ├── cert.pem    # TLS 证书（如需要）
  └── key.pem     # TLS 私钥（如需要）
```

### 配置文件准备

生产环境需修改以下关键配置：

1. 监听地址端口：`agent.addressable`
2. TLS 证书：`agent.certificate`
3. 认证凭据：设置强密码和 UUID
4. 日志级别：生产环境使用 `info`
5. 日志路径：指定到专用目录

详细配置说明参见 [配置详解](configuration.md)。

> **注意**：`configuration_path` 硬编码在 `src/main.cpp` 中，部署时需修改为实际路径。

### systemd 服务配置（Linux）

创建 `/etc/systemd/system/prism.service`：

```ini
[Unit]
Description=Prism High-Performance Proxy Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=prism
Group=prism
WorkingDirectory=/var/lib/prism
ExecStart=/usr/local/bin/prism
Restart=on-failure
RestartSec=5
LimitNOFILE=65535

# 安全加固
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/prism /etc/prism
PrivateTmp=true
Environment=HOME=/var/lib/prism

[Install]
WantedBy=multi-user.target
```

启用服务：

```bash
sudo useradd -r -s /usr/sbin/nologin -d /var/lib/prism prism
sudo chown -R prism:prism /var/log/prism /var/lib/prism
sudo chown prism:prism /etc/prism/configuration.json
sudo chmod 600 /etc/prism/configuration.json

sudo systemctl daemon-reload
sudo systemctl enable prism
sudo systemctl start prism
```

### Windows 服务注册（NSSM）

```powershell
nssm install Prism "C:\Prism\Prism.exe"
nssm set Prism AppDirectory "C:\Prism"
nssm set Prism Start SERVICE_AUTO_START
nssm set Prism AppStdout "C:\Prism\logs\stdout.log"
nssm set Prism AppStderr "C:\Prism\logs\stderr.log"
nssm set Prism AppRotateFiles 1
nssm set Prism AppRotateBytes 10485760
nssm start Prism
```

或使用 SC 命令：

```powershell
sc create Prism binPath= "C:\Prism\Prism.exe" start= auto DisplayName= "Prism Proxy Server"
sc failure Prism reset= 86400 actions= restart/5000/restart/10000/restart/30000
sc start Prism
```

### 防火墙配置

```bash
# Linux (ufw)
sudo ufw allow 8081/tcp
sudo ufw allow 8081/udp

# Linux (firewalld)
sudo firewall-cmd --permanent --add-port=8081/tcp
sudo firewall-cmd --permanent --add-port=8081/udp
sudo firewall-cmd --reload
```

```powershell
# Windows
netsh advfirewall firewall add rule name="Prism Proxy" dir=in action=allow protocol=TCP localport=8081
netsh advfirewall firewall add rule name="Prism Proxy UDP" dir=in action=allow protocol=UDP localport=8081
```

---

## Docker 部署

### Dockerfile（多阶段构建）

```dockerfile
# === 阶段一：构建 ===
FROM ubuntu:22.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    software-properties-common \
    && add-apt-repository -y ppa:ubuntu-toolchain-r/test \
    && apt-get update && apt-get install -y --no-install-recommends \
    g++-13 cmake git make ninja-build \
    && rm -rf /var/lib/apt/lists/*

ENV CC=gcc-13 CXX=g++-13

WORKDIR /build
COPY . .

RUN cmake -B build_release \
    -DCMAKE_BUILD_TYPE=Release -GNinja \
    -DPRISM_ENABLE_BENCHMARK=OFF \
    -DPRISM_ENABLE_STRESS=OFF \
    && cmake --build build_release --config Release

# === 阶段二：运行 ===
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates && rm -rf /var/lib/apt/lists/*

RUN groupadd -r prism && useradd -r -g prism -d /home/prism -s /sbin/nologin prism

COPY --from=builder /build/build_release/src/Prism /usr/local/bin/prism
COPY src/configuration.json /etc/prism/configuration.json

RUN mkdir -p /var/log/prism /etc/prism/certs \
    && chown -R prism:prism /var/log/prism /etc/prism

WORKDIR /home/prism
EXPOSE 8081/tcp 8081/udp
USER prism
ENTRYPOINT ["/usr/local/bin/prism"]
```

### docker-compose.yml

```yaml
version: "3.8"

services:
  prism:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: prism
    restart: unless-stopped
    ports:
      - "8081:8081/tcp"
      - "8081:8081/udp"
    volumes:
      - ./config/configuration.json:/etc/prism/configuration.json:ro
      - ./certs:/etc/prism/certs:ro
      - ./logs:/var/log/prism
    environment:
      - TZ=Asia/Shanghai
    deploy:
      resources:
        limits:
          cpus: "4.0"
          memory: 2G
        reservations:
          cpus: "1.0"
          memory: 512M
    healthcheck:
      test: ["CMD-SHELL", "nc -z localhost 8081 || exit 1"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 10s
    logging:
      driver: json-file
      options:
        max-size: "50m"
        max-file: "5"
```

### 使用方法

```bash
docker-compose up -d --build    # 构建并启动
docker-compose logs -f prism    # 查看日志
docker-compose restart prism    # 重启服务
docker-compose down             # 停止服务
```

---

## 反向代理集成

### Nginx

```nginx
# TCP 流代理（4 层，推荐用于 Trojan/VLESS）
stream {
    upstream prism_backend {
        server 127.0.0.1:8081;
    }

    server {
        listen 443 ssl;
        ssl_certificate     /etc/letsencrypt/live/example.com/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;
        ssl_protocols       TLSv1.2 TLSv1.3;
        proxy_pass prism_backend;
    }
}

# HTTP 反向代理（7 层，用于 HTTP/SOCKS5）
http {
    upstream prism_http {
        server 127.0.0.1:8081;
        keepalive 64;
    }

    server {
        listen 443 ssl;
        server_name prism.example.com;

        ssl_certificate     /etc/letsencrypt/live/prism.example.com/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/prism.example.com/privkey.pem;
        ssl_protocols       TLSv1.2 TLSv1.3;
        ssl_ciphers         HIGH:!aNULL:!MD5;

        location / {
            proxy_pass http://prism_http;
            proxy_http_version 1.1;
            proxy_set_header Host              $host;
            proxy_set_header X-Real-IP         $remote_addr;
            proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_connect_timeout 60s;
            proxy_read_timeout    600s;
            proxy_send_timeout    600s;
        }
    }
}
```

> Trojan/VLESS 使用 4 层 stream 转发，由 Prism 自身处理 TLS。HTTP/SOCKS5 可使用 7 层 http 反向代理。

### Caddy

```
# HTTPS 自动证书（HTTP 代理场景）
prism.example.com {
    reverse_proxy localhost:8081
}

# TCP 透传（Trojan/VLESS 场景）
prism.example.com:443 {
    reverse_proxy localhost:8081
    tls {
        protocols tls1.2 tls1.3
    }
}
```

---

## TLS 证书管理

### 自签名证书（测试环境）

```bash
# RSA 4096
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=example.com"

# ECDSA（更小更快）
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=example.com"
```

自签名证书需客户端配置 `skip-cert-verify: true`。

### Let's Encrypt（生产环境推荐）

```bash
# standalone 模式（需停止 80 端口服务）
sudo certbot certonly --standalone -d prism.example.com --agree-tos --email admin@example.com

# webroot 模式（已有 Web 服务时）
sudo certbot certonly --webroot -w /var/www/html -d prism.example.com --agree-tos --email admin@example.com
```

证书路径：

```
/etc/letsencrypt/live/prism.example.com/
  ├── fullchain.pem  # cert 字段
  └── privkey.pem    # key 字段
```

自动续期钩子：

```bash
# /etc/letsencrypt/renewal-hooks/deploy/restart-prism.sh
#!/bin/bash
systemctl restart prism
```

```bash
sudo chmod +x /etc/letsencrypt/renewal-hooks/deploy/restart-prism.sh
sudo certbot renew --dry-run  # 验证续期流程
```

---

## 多环境配置

### 目录结构

```
/etc/prism/
  ├── configuration.json          # 当前生效（符号链接）
  ├── environments/
  │   ├── development.json
  │   ├── staging.json
  │   └── production.json
  └── certs/
      ├── cert.pem
      └── key.pem
```

### 环境切换

```bash
sudo ln -sf /etc/prism/environments/production.json /etc/prism/configuration.json
sudo systemctl restart prism
```

### 生产环境配置要点

```json
{
  "agent": {
    "addressable": { "host": "0.0.0.0", "port": 8081 },
    "limit": { "concurrences": 2048, "blacklist": true },
    "authentication": {
      "users": [
        {
          "password": "<强密码>",
          "uuid": "<随机 UUID>",
          "max_connections": 100
        }
      ]
    },
    "pool": {
      "max_cache_per_endpoint": 64,
      "max_idle_seconds": 60,
      "connect_timeout_ms": 1000
    },
    "dns": {
      "servers": [
        { "address": "223.5.5.5", "port": 53, "protocol": "udp", "timeout_ms": 1500 },
        { "address": "119.29.29.29", "port": 53, "protocol": "udp", "timeout_ms": 1500 }
      ],
      "cache_enabled": true,
      "cache_size": 10000
    }
  },
  "trace": {
    "log_level": "info",
    "enable_console": false,
    "enable_file": true,
    "max_size": 67108864,
    "max_files": 16
  }
}
```

### 配置安全

- 配置文件权限设为 `600`，仅运行用户可读
- 使用配置管理系统（Ansible、Vault）管理敏感凭据
- 不要将生产配置提交到版本控制

---

## 日志轮转与运维监控

### 日志配置

```json
{
  "trace": {
    "file_name": "forward.log",
    "path_name": "/var/log/prism",
    "max_size": 67108864,
    "max_files": 16,
    "queue_size": 8192,
    "thread_count": 1,
    "enable_console": true,
    "enable_file": true,
    "log_level": "info",
    "pattern": "[%Y-%m-%d %H:%M:%S.%e] [%5t] [%l] %v",
    "trace_name": "forward_engine"
  }
}
```

| 参数 | 推荐值 | 说明 |
|------|--------|------|
| `max_size` | 64 MB | 单文件上限 |
| `max_files` | 8-16 | 历史文件数 |
| `log_level` | `info` | 生产环境避免 `debug` |
| `enable_console` | `false`（systemd 部署时） | 交给 journald |

### logrotate（Linux）

创建 `/etc/logrotate.d/prism`：

```conf
/var/log/prism/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
    size 100M
    maxage 30
}
```

### 健康检查

```bash
# 端口探测
nc -zv localhost 8081

# 代理功能测试
curl -x http://127.0.0.1:8081 -I http://example.com --connect-timeout 5
```

### 监控指标

| 指标 | 获取方式 | 告警阈值 |
|------|---------|---------|
| 进程存活 | `pgrep -x prism` | 进程不存在 |
| 端口监听 | `nc -z localhost 8081` | 端口不通 |
| 内存使用 | `/proc/<pid>/status` VmRSS | 超物理内存 80% |
| 文件描述符 | `ls /proc/<pid>/fd \| wc -l` | 接近 `ulimit -n` 的 80% |
| 连接数 | `ss -s` | 接近系统文件描述符限制 |
| 日志错误率 | `[error]` 出现频率 | 持续出现 |

---

## 启动检查清单

### 网络安全

- [ ] 监听端口已配置，非必要时不在公网暴露管理端口
- [ ] 防火墙规则已配置，仅开放必要端口
- [ ] TLS 证书已部署且未过期
- [ ] 生产环境使用受信任 CA 签发的证书

### 认证与访问控制

- [ ] 已修改默认密码，使用强密码
- [ ] 已配置独立的 VLESS UUID
- [ ] `max_connections` 已设置合理上限
- [ ] `agent.limit.blacklist` 已启用
- [ ] Shadowsocks PSK 已更换为随机密钥

### 配置安全

- [ ] 配置文件权限 `600`
- [ ] `configuration_path` 已修改为生产环境路径
- [ ] 日志路径指向专用目录

### 日志与监控

- [ ] 日志级别 `info`
- [ ] 日志轮转已配置
- [ ] 健康检查已部署
- [ ] systemd `Restart=on-failure`

### 系统安全

- [ ] 以非 root 用户运行
- [ ] `LimitNOFILE=65535`
- [ ] 内核参数已优化（见下方）
- [ ] 证书自动续期已配置

---

## 内核参数调优（Linux）

写入 `/etc/sysctl.d/99-prism.conf`：

```ini
fs.file-max = 1048576
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_max_syn_backlog = 65535
```

```bash
sudo sysctl -p /etc/sysctl.d/99-prism.conf
```

---

## 常见部署问题

### 编译阶段

| 问题 | 原因 | 解决方案 |
|------|------|---------|
| FetchContent 下载超时 | 网络问题 | 手动下载依赖包到 `_deps/` |
| GCC 版本不足 | C++23 需要 GCC 13+ | 安装 `g++-13` |
| BoringSSL 编译失败 | 缺少构建工具 | 确保 `make` 或 `ninja` 已安装 |

### 运行阶段

| 问题 | 原因 | 解决方案 |
|------|------|---------|
| 端口占用 | 其他进程占用 | `netstat -tlnp \| grep 8081` |
| TLS 握手失败 | 证书路径或格式错误 | 检查 `agent.certificate` 路径 |
| 连接被拒绝 | 防火墙阻止 | 检查防火墙规则 |
| 内存持续增长 | 连接泄漏 | 检查日志中 session 创建/销毁配对 |
| 日志磁盘写满 | 轮转未配置 | 配置 `trace.max_size` 和 `max_files` |
