# 生产环境部署指南

## 系统要求

| 资源 | 最低 | 推荐 |
|------|------|------|
| CPU | 2 核 | 4 核及以上 |
| 内存 | 512 MB | 2 GB 及以上 |
| 系统 | Windows 10+ / Server 2019+, Linux glibc 2.31+ (Ubuntu 20.04+) | |
| 编译器 | GCC 13+ / MinGW (C++23) | |
| CMake | 3.23+ | |

## 从源码编译

```bash
git clone https://github.com/Hatedatastructures/Prism.git
cd Prism
cmake -B build_release -DCMAKE_BUILD_TYPE=Release
cmake --build build_release --config Release
# 可选: 关闭基准测试和压力测试
# cmake -B build_release -DCMAKE_BUILD_TYPE=Release -DPRISM_ENABLE_BENCHMARK=OFF -DPRISM_ENABLE_STRESS=OFF
```

验证构建:

```bash
ctest --test-dir build_release --output-on-failure
```

产物: `build_release/src/Prism` (Windows: `Prism.exe`)

## 安装

### Linux

```bash
sudo cp build_release/src/Prism /usr/local/bin/prism
sudo mkdir -p /etc/prism /var/log/prism
sudo cp src/configuration.json /etc/prism/configuration.json
sudo chmod 600 /etc/prism/configuration.json
```

### Windows

```
C:\Prism\
  ├── Prism.exe
  ├── configuration.json
  └── logs\
```

### systemd 服务

`/etc/systemd/system/prism.service`:

```ini
[Unit]
Description=Prism Proxy Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=prism
Group=prism
ExecStart=/usr/local/bin/prism
Restart=on-failure
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
```

```bash
sudo useradd -r -s /usr/sbin/nologin -d /var/lib/prism prism
sudo chown -R prism:prism /var/log/prism /etc/prism
sudo systemctl daemon-reload
sudo systemctl enable --now prism
```

### Windows 服务

```powershell
sc create Prism binPath= "C:\Prism\Prism.exe" start= auto DisplayName= "Prism Proxy Server"
sc start Prism
```

### 防火墙

```bash
# Linux
sudo ufw allow 8081/tcp
```

```powershell
# Windows
netsh advfirewall firewall add rule name="Prism" dir=in action=allow protocol=TCP localport=8081
```

## Docker

```dockerfile
FROM ubuntu:22.04 AS builder
RUN apt-get update && apt-get install -y --no-install-recommends g++-13 cmake git make
ENV CC=gcc-13 CXX=g++-13
WORKDIR /build
COPY . .
RUN cmake -B build_release -DCMAKE_BUILD_TYPE=Release -DPRISM_ENABLE_BENCHMARK=OFF -DPRISM_ENABLE_STRESS=OFF \
    && cmake --build build_release --config Release

FROM ubuntu:22.04
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/build_release/src/Prism /usr/local/bin/prism
COPY src/configuration.json /etc/prism/configuration.json
EXPOSE 8081
ENTRYPOINT ["/usr/local/bin/prism"]
```

```bash
docker build -t prism .
docker run -d -p 8081:8081 -v ./config:/etc/prism:ro prism
```

## TLS 证书

自签名（测试）:

```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=example.com"
```

Let's Encrypt（生产）:

```bash
sudo certbot certonly --standalone -d prism.example.com
# 证书路径填入 agent.certificate.key / agent.certificate.cert
```

## 健康检查

```bash
nc -zv localhost 8081
curl -x http://127.0.0.1:8081 -I http://example.com --connect-timeout 5
```

## 启动检查清单

- [ ] 防火墙已配置，仅开放必要端口
- [ ] 已修改默认密码、UUID、Shadowsocks PSK
- [ ] `max_connections` 已设置上限
- [ ] 配置文件权限 `600`，非 root 用户运行
- [ ] TLS 证书已部署且未过期
- [ ] 日志级别设为 `info`，日志轮转已配置
- [ ] systemd `Restart=on-failure` 已启用

## 常见问题

| 问题 | 原因 | 解决方案 |
|------|------|---------|
| 端口占用 | 其他进程占用 | `netstat -tlnp \| grep 8081` |
| TLS 握手失败 | 证书路径或格式错误 | 检查 `agent.certificate` 路径 |
| 连接被拒绝 | 防火墙阻止 | 检查防火墙规则 |
| 编译失败 | GCC 版本不足 | 安装 `g++-13` |
