/** @brief API v2 的 ProtocolType 编码，与 Contract/Ingress/Protocol.hpp 顺序一致。 */
const ProtocolCodes = ['unknown', 'http', 'socks5', 'trojan', 'vless', 'shadowsocks', 'vmess', 'hysteria2', 'tuic', 'tls', 'anytls', 'trusttunnel'] as const;
export function CanonicalProtocol(Value: string): string {
    if (/^\d+$/.test(Value)) return ProtocolCodes[Number(Value)] ?? `unknown (${Value})`;
    const Name = Value.toLowerCase();
    return ProtocolCodes.includes(Name as typeof ProtocolCodes[number]) ? Name : `unknown (${Value})`;
}
