const EventNames: Readonly<Record<string, string>> = {
    data: '流量观测', started: '运行已启动', failed: '运行失败', session_closed: 'Session 已关闭',
    stream_closed: 'Stream 已关闭', task_completed: 'Task 已完成', task_canceled: 'Task 已取消',
    worker_drained: 'Worker 已排空', generation_reloaded: '配置 Generation 已发布',
    operation_accepted: '管理操作已受理', operation_completed: '管理操作已完成', operation_failed: '管理操作失败',
};
/** @brief 仅翻译已知正式类型，未知事件保留原始名字，原始 Kind 始终独立保存。 */
export function EventLabel(Kind: string): string { return EventNames[Kind] ?? Kind; }
