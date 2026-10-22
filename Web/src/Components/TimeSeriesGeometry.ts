export type TimeSeriesPoint = Readonly<{ Time: number }>;

/** @brief 按时间选择最近的采样点；等距时保留左侧点，避免悬浮在缺口边缘跳动。 */
export function NearestTimeIndex(Times: readonly number[], Target: number): number {
    if (Times.length === 0) return -1;
    if (!Number.isFinite(Target)) return -1;
    if (Target <= (Times[0] ?? 0)) return 0;
    if (Target >= (Times[Times.length - 1] ?? 0)) return Times.length - 1;
    let Low = 0;
    let High = Times.length - 1;
    while (Low < High) {
        const Middle = Math.floor((Low + High) / 2);
        if ((Times[Middle] ?? 0) < Target) Low = Middle + 1;
        else High = Middle;
    }
    const Before = Low - 1;
    return Target - (Times[Before] ?? 0) > (Times[Low] ?? 0) - Target ? Low : Before;
}

/** @brief 按时间顺序切分有限值，缺测不连接、不补零。 */
export function FiniteTimeSegments<Point extends TimeSeriesPoint>(
    Points: readonly Point[],
    Value: (Point: Point) => number | null,
): readonly (readonly Point[])[] {
    const Segments: Point[][] = [];
    let Current: Point[] = [];
    for (const Point of Points) {
        const CurrentValue = Value(Point);
        if (CurrentValue !== null && Number.isFinite(CurrentValue)) {
            Current.push(Point);
        } else if (Current.length > 0) {
            Segments.push(Current);
            Current = [];
        }
    }
    if (Current.length > 0) Segments.push(Current);
    return Segments;
}

/** @brief 生成从零开始的整齐线性刻度，保证包含最大值。 */
export function LinearTicks(Max: number, TargetCount = 4): readonly number[] {
    const SafeMax = Number.isFinite(Max) && Max > 0 ? Max : 1;
    const RawStep = SafeMax / Math.max(1, TargetCount);
    const Magnitude = 10 ** Math.floor(Math.log10(RawStep));
    const Normalized = RawStep / Magnitude;
    const Step = (Normalized <= 1 ? 1 : Normalized <= 2 ? 2 : Normalized <= 2.5 ? 2.5 : Normalized <= 5 ? 5 : 10) * Magnitude;
    const Top = Math.ceil(SafeMax / Step) * Step;
    const Ticks: number[] = [];
    for (let Index = 0; Index * Step <= Top + Step * 0.001; Index += 1) Ticks.push(Index * Step);
    return Ticks;
}

/** @brief X 轴刻度对齐真实采样，避免日期标签与悬浮读数错位。 */
export function TimeTickIndices(Points: readonly TimeSeriesPoint[], TargetCount = 5): readonly number[] {
    if (Points.length === 0) return [];
    if (Points.length === 1) return [0];
    const Times = Points.map(Point => Point.Time);
    const Start = Times[0] ?? 0;
    const End = Times[Times.length - 1] ?? Start;
    const Indices = new Set<number>([0, Points.length - 1]);
    for (let Tick = 0; Tick < TargetCount; Tick += 1) {
        const Target = Start + (End - Start) * Tick / Math.max(1, TargetCount - 1);
        const Index = NearestTimeIndex(Times, Target);
        if (Index >= 0) Indices.add(Index);
    }
    return [...Indices].sort((Left, Right) => Left - Right);
}
