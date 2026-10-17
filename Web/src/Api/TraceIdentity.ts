const StageNames: Readonly<Record<string, string>> = {
    'tcp.accepted': 'TCP 已接收', 'worker.dispatch.accepted': 'Worker 已接收派发',
    'session.admission.started': 'Session 准入开始', 'session.started': 'Session 已启动',
    'carrier.probe.started': '承载探测开始', 'carrier.probe.completed': '承载探测完成',
    'recognition.started': '协议识别开始', 'recognition.completed': '协议识别完成',
    'protocol.accept.started': '协议接入开始', 'protocol.accept.completed': '协议接入完成',
    'authentication.confirmed': '身份认证已确认', 'outbound.resolve_dial.started': '出站解析与拨号开始',
    'outbound.resolve_dial.completed': '出站解析与拨号完成', 'relay.started': '双向转发开始',
    'relay.first_upload_byte': '首批上行有效载荷写出', 'relay.first_download_byte': '首批下行有效载荷写出',
    'relay.completed': '双向转发完成', 'session.closed': 'Session 已关闭',
};
/** @brief 按真实成功写出埋点命名，不推导上游首读或 TTFB；未知阶段保留原始名。 */
export function TraceStageLabel(Name: string): string { return StageNames[Name] ?? Name; }
