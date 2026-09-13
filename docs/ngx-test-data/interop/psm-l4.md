# L4 生产对拍记录：preview client ↔ 生产 Prism server

> 更新日期：2026-08-20
> 工具：`tests/preview/integration/InteropPrismL4.cpp`（独立可执行，非 gtest，已注册 `InteropPrismL4` target）
> 服务端：生产 `build/src/Prism.exe` + 临时配置（监听 127.0.0.1:18081，关闭 hysteria2/tuic 规避 PE 重定位溢出）。该配置含本机测试凭据，每次对拍临时生成、测完即删，不入库。

## 对拍矩阵

| 协议 | echo | authfail | 说明 |
|---|---|---|---|
| SOCKS5 | ✅ PASS | ✅ PASS | 用户名密码认证 + CONNECT + 回环 echo |
| Shadowsocks 2022 | ✅ PASS | ✅ PASS | 标准 base64 PSK 配置；PSK 错误被拒绝 |
| VLESS | ❌ FAIL（生产识别器，fresh 2026-09-11） | ✅ PASS | echo 5 秒后 EOF；首包仍未进入明确 VLESS 路径 |
| Trojan | ❌ FAIL（生产识别器，fresh 2026-09-11） | ✅ PASS | 首包被生产 SS2022 fallback 误解密，返回 `auth_failed` |
| VMess | ✅ PASS（fresh 2026-09-11） | ✅ PASS | 当前重建生产二进制的 VMess fallback echo 已通过；历史 fallback 静态报告不再作为当前必现结论 |

## 运行方式

```text
# 启动生产 Prism（18081）
# 配置需临时生成（监听 18081、protocol 启用被测协议、关闭 hysteria2/tuic）
build/src/Prism.exe <临时配置路径>

# 对拍单个协议（退出码 0 = PASS）
build/tests/preview/integration/InteropPrismL4.exe -addr 127.0.0.1:18081 -proto socks5 -mode echo
build/tests/preview/integration/InteropPrismL4.exe -addr 127.0.0.1:18081 -proto ss2022 -mode echo
build/tests/preview/integration/InteropPrismL4.exe -addr 127.0.0.1:18081 -proto vless -mode authfail
```

参数：`-proto socks5|vless|trojan|vmess|ss2022`，`-mode echo|authfail`；另有 `-mode echoserver -port N` 提供固定端口 echo，供 SS2022 等对拍复用。

## SS2022 对拍期间修复的 preview 缺陷

- 标准事实（sing-shadowsocks v0.2.12 / Prism / mihomo 一致）：服务端响应 = server salt(16) + 固定头裸块(43) + 总是跟一个 AEAD 块；`payloadLen==0` 时该块为 16B 空块。
- 修复 1（`conn.hpp` 客户端 `write_handshake`）：按标准读取 server salt + 裸块固定头，校验 requestSalt 回显；`payloadLen==0` 时消费 16B 空块。
- 修复 2（`codec.hpp`）：`chunk_codec::open_raw` 增加“认证判定”重载——空明文认证成功后同样推进 nonce，避免数据面 nonce 失步（原实现对空明文一律当失败、不推进 nonce）。
- 修复 3（`conn.hpp` 服务端 `send_success`）：响应改为 salt + 固定头 + 空块，与标准 readResponse 对齐，保证 preview↔preview 自环与对外行为一致。

## 生产识别器缺口（阻塞 vless/trojan echo）

`src/prism/handshake/recognition/probe/analyzer.cpp` 只识别 SOCKS5/TLS/HTTP，其余一律回退 shadowsocks。Fresh L4 中 VLESS/Trojan 首包仍未获得明确路由：VLESS 以 EOF 结束，Trojan 出现 `decrypt fixed header failed: crypto_error (expected 11 plain bytes, got 27 enc bytes)`；当前 VMess echo 已通过。属于生产 TODO（`logs/issues.md` T-1），不应在 preview 侧绕行修复。

## 回归证据（2026-08-20）

- L4 对拍：socks5/ss2022 echo+authfail、vless/trojan/vmess authfail 全部 PASS（本记录）。
- 2026-09-11 fresh L4：socks5/ss2022/vmess echo PASS，vless/trojan echo FAIL；失败日志保存在临时运行目录之外的本次终端输出，生产目录未修改。
- preview SS2022 回归 18/18：TcpListener.SS2022 4、SS2022Udp 3、Ss2022CodecDeep 5、Ss2022ConnErrorMatrix 2、Ss2022DgramSession 3、GoldenVector.SS2022UdpPacketRoundtrip 1。
