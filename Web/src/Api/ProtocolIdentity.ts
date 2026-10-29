/** @brief API v2 的 ProtocolType 编码，与 Contract/Ingress/Protocol.hpp 顺序一致。 */
const ProtocolCodes = ['unknown', 'http', 'socks5', 'trojan', 'vless', 'shadowsocks', 'vmess', 'hysteria2', 'tuic', 'tls', 'anytls', 'trusttunnel'] as const;
export function CanonicalProtocol(Value: string): string {
    if (/^\d+$/.test(Value)) return ProtocolCodes[Number(Value)] ?? `unknown (${Value})`;
    const Name = Value.toLowerCase();
    return ProtocolCodes.includes(Name as typeof ProtocolCodes[number]) ? Name : `unknown (${Value})`;
}

/** @brief 将 API v2 协议枚举名映射到统计历史使用的数值键。 */
export function ProtocolHistoryTypeKey(Value: string): string | null {
    const Name = CanonicalProtocol(Value);
    const Key = ProtocolCodes.indexOf(Name as typeof ProtocolCodes[number]);
    return Key > 0 ? String(Key) : null;
}
