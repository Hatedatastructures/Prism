---
name: dpi-audit
description: 修改 TLS ClientHello、ServerHello、ALPN、SNI、ECH 或 TLS 伪装方案时，审查实际握手兼容性和可观察差异。
---

# TLS 可观察性审计

## 审计原则

只审查当前实现真实产生的 TLS 字段、扩展、长度、顺序和协商结果。不要把某个浏览器版本、JA4 指纹或 ML-KEM 参数当作永恒标准，除非目标协议和测试明确要求。

## 审计步骤

1. 找到 ClientHello/ServerHello 读取、解析、生成和转发的实际代码。
2. 核对 record、handshake、extension、key share、ALPN 和 SNI 的长度与边界。
3. 检查客户端、服务端和回落路径各自允许的 ALPN/SNI 语义，避免把角色要求混用。
4. 检查 ECH、TLS 伪装和识别器失败时的状态转换、缓冲区和关闭顺序。
5. 检查异常握手不会回显内部实现、密钥材料或软件标识。
6. 用实际抓包、TLS 测试和互操作结果验证判断。

## 不做的假设

- 不固定要求某个浏览器指纹或某种扩展顺序。
- 不凭记忆填写后量子 key share 长度，长度必须来自当前规范或库定义。
- 不把“更像浏览器”当作协议兼容性证明。
- 不因 DPI 目标改变认证、证书验证或错误处理的安全边界。

## 验证

覆盖标准 TLS、各启用方案、ALPN 不匹配、SNI 路由、ECH 失败、截断 record 和异常关闭。报告列出实际字段、证据来源、兼容性结论和剩余风险。

## 相关 Skill

识别/回落见 `probe-audit`，密码学见 `crypto-audit`，敏感输出见 `leak-audit`。
