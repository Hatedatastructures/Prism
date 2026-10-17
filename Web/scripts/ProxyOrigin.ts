/** @brief 仅将同源本机开发请求映射到固定本机服务的 Origin；外部来源保持不可信。 */
export function TrustedProxyOrigin(
    Headers: Readonly<{ origin?: string | undefined; host?: string | undefined }>, Target: string,
): string | null {
    if (!Headers.origin || !Headers.host) return null;
    const LocalHosts = new Set(['127.0.0.1', 'localhost', '[::1]']);
    try {
        const Origin = new URL(Headers.origin);
        const Destination = new URL(Target);
        if (Origin.protocol !== 'http:' || Origin.origin !== Headers.origin ||
            !LocalHosts.has(Origin.hostname) || Origin.host !== Headers.host.toLowerCase()) return null;
        if (Destination.protocol !== 'http:' || !LocalHosts.has(Destination.hostname) ||
            Destination.username || Destination.password || Destination.pathname !== '/' ||
            Destination.search || Destination.hash) return null;
        return Destination.origin;
    } catch { return null; }
}
