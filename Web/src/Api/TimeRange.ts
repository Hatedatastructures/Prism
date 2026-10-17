export const TimeRanges = [{ Id: '15m', Label: '最近 15 分钟', Ms: 900_000 }, { Id: '1h', Label: '最近 1 小时', Ms: 3_600_000 },
    { Id: '24h', Label: '最近 24 小时', Ms: 86_400_000 }, { Id: '7d', Label: '最近 7 天', Ms: 604_800_000 }, { Id: '30d', Label: '最近 30 天', Ms: 2_592_000_000 }];
export function ResolveTimeRange(Input: Readonly<{ Range: string; From: string; To: string; Now: number }>) {
    const Fixed = Input.Range === 'custom', Relative = TimeRanges.find(Value => Value.Id === Input.Range);
    const End = Fixed ? Date.parse(Input.To) : Input.Now;
    const Begin = Fixed ? Date.parse(Input.From) : End - (Relative?.Ms ?? 0);
    let InvalidReason: string | null = null;
    if (!Fixed && !Relative) InvalidReason = '不支持的时间范围，请重新选择。';
    else if (Fixed && (!Input.From || !Input.To)) InvalidReason = '请选择完整的开始与结束时间。';
    else if (!Number.isFinite(Begin) || !Number.isFinite(End)) InvalidReason = '开始或结束时间无效，请重新选择。';
    else if (Begin >= End) InvalidReason = '结束时间必须晚于开始时间。';
    else if (End - Begin > 2_592_000_000) InvalidReason = '查询区间不能超过 30 天，请缩短时间范围。';
    const Valid = InvalidReason === null;
    return { Range: Input.Range, Fixed, Valid, InvalidReason, From: Valid ? new Date(Begin).toISOString() : '', To: Valid ? new Date(End).toISOString() : '',
        Key: Fixed ? `${Input.Range}:${Input.From}:${Input.To}` : Input.Range };
}
