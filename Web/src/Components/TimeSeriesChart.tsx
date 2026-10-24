import { useEffect, useId, useMemo, useRef, useState } from 'react';
import type { KeyboardEvent, PointerEvent, ReactNode } from 'react';
import { FiniteTimeSegments, LinearTicks, NearestTimeIndex, TimeTickIndices } from './TimeSeriesGeometry';
import type { TimeSeriesPoint } from './TimeSeriesGeometry';

export type TimeSeriesSeries<Point extends TimeSeriesPoint> = Readonly<{
    Key: string;
    Label: string;
    Color: string;
    Value: (Point: Point) => number | null;
    Format: (Value: number) => string;
    Area?: boolean;
}>;

type TimeSeriesChartProps<Point extends TimeSeriesPoint> = Readonly<{
    Points: readonly Point[];
    Series: readonly TimeSeriesSeries<Point>[];
    AriaLabel: string;
    FormatTime: (Time: number) => string;
    FormatAxis: (Value: number) => string;
    ActiveSeries?: string | null;
}>;

const Margin = { Top: 14, Right: 14, Bottom: 30, Left: 46 } as const;

export function TimeSeriesChart<Point extends TimeSeriesPoint>(Input: TimeSeriesChartProps<Point>): ReactNode {
    const UniqueId = useId().replace(/:/g, '');
    const ContainerRef = useRef<HTMLDivElement>(null);
    const [Size, SetSize] = useState({ Width: 0, Height: 0 });
    const [HoverIndex, SetHoverIndex] = useState<number | null>(null);
    const [Pinned, SetPinned] = useState(false);
    const DragRef = useRef<Readonly<{ StartIndex: number; Moved: boolean }> | null>(null);
    const Times = useMemo(() => Input.Points.map(Point => Point.Time), [Input.Points]);
    useEffect(() => {
        const Node = ContainerRef.current;
        if (!Node) return;
        const Observer = new ResizeObserver(Entries => {
            const Box = Entries[0]?.contentRect;
            if (Box) SetSize({ Width: Box.width, Height: Box.height });
        });
        Observer.observe(Node);
        return () => Observer.disconnect();
    }, []);
    const InnerWidth = Math.max(0, Size.Width - Margin.Left - Margin.Right);
    const InnerHeight = Math.max(0, Size.Height - Margin.Top - Margin.Bottom);
    const TimeMin = Times[0] ?? 0;
    const TimeMax = Times[Times.length - 1] ?? TimeMin;
    const TimeSpan = TimeMax - TimeMin || 1;
    const Values = useMemo(() => Input.Series.flatMap(Series => Input.Points
        .map(Point => Series.Value(Point))
        .filter((Value): Value is number => Value !== null && Number.isFinite(Value))), [Input.Points, Input.Series]);
    const MaxValue = Values.length > 0 ? Math.max(...Values) : 1;
    const Ticks = useMemo(() => LinearTicks(MaxValue, 4), [MaxValue]);
    const YMax = Ticks[Ticks.length - 1] ?? 1;
    const TickIndices = useMemo(() => TimeTickIndices(Input.Points, 5), [Input.Points]);
    const X = (Time: number): number => Margin.Left + ((Time - TimeMin) / TimeSpan) * InnerWidth;
    const Y = (Value: number): number => Margin.Top + InnerHeight - Math.max(0, Math.min(1, Value / YMax)) * InnerHeight;
    const Hovered = HoverIndex === null ? null : Input.Points[HoverIndex] ?? null;
    const HoverX = Hovered ? X(Hovered.Time) : null;
    const ActiveKey = Input.ActiveSeries ?? null;
    function ResolveIndex(ClientX: number): number {
        const Node = ContainerRef.current;
        if (!Node || Times.length === 0) return -1;
        const Box = Node.getBoundingClientRect();
        const Pixel = Math.max(Margin.Left, Math.min(Box.width - Margin.Right, ClientX - Box.left));
        return NearestTimeIndex(Times, TimeMin + ((Pixel - Margin.Left) / Math.max(1, InnerWidth)) * TimeSpan);
    }
    function HandlePointerMove(Event: PointerEvent<HTMLDivElement>): void {
        const Index = ResolveIndex(Event.clientX);
        if (Index < 0) return;
        if (DragRef.current) {
            if (Index !== DragRef.current.StartIndex) DragRef.current = { StartIndex: DragRef.current.StartIndex, Moved: true };
            return;
        }
        if (!Pinned) SetHoverIndex(Index);
    }
    function HandlePointerDown(Event: PointerEvent<HTMLDivElement>): void {
        const Index = ResolveIndex(Event.clientX);
        if (Index < 0) return;
        Event.currentTarget.setPointerCapture(Event.pointerId);
        DragRef.current = { StartIndex: Index, Moved: false };
        SetHoverIndex(Index);
        SetPinned(true);
    }
    function HandlePointerUp(Event: PointerEvent<HTMLDivElement>): void {
        const Drag = DragRef.current;
        DragRef.current = null;
        if (Event.currentTarget.hasPointerCapture(Event.pointerId)) Event.currentTarget.releasePointerCapture(Event.pointerId);
        if (!Drag?.Moved) return;
        const EndIndex = ResolveIndex(Event.clientX);
        if (EndIndex >= 0) SetHoverIndex(EndIndex);
    }
    function HandlePointerLeave(): void {
        DragRef.current = null;
        if (!Pinned) SetHoverIndex(null);
    }
    function HandleKeyDown(Event: KeyboardEvent<HTMLDivElement>): void {
        if (Times.length === 0) return;
        if (Event.key === 'Escape') {
            SetPinned(false);
            SetHoverIndex(null);
            return;
        }
        if (Event.key === 'Enter' || Event.key === ' ') {
            Event.preventDefault();
            SetPinned(Value => !Value);
            return;
        }
        if (Event.key !== 'ArrowLeft' && Event.key !== 'ArrowRight') return;
        Event.preventDefault();
        const Current = HoverIndex ?? (Event.key === 'ArrowLeft' ? Times.length - 1 : 0);
        const Step = Event.key === 'ArrowLeft' ? -1 : 1;
        const Next = Math.max(0, Math.min(Times.length - 1, Current + Step));
        SetHoverIndex(Next);
    }
    if (Size.Width <= 0 || Size.Height <= 0) return <div ref={ContainerRef} className="time-series-chart" aria-hidden="true" />;
    return <div ref={ContainerRef} className="time-series-chart" role="group" tabIndex={0}
        aria-label={`${Input.AriaLabel}。使用左右方向键查看采样点，Enter 固定读数，Escape 清除。`}
        onKeyDown={HandleKeyDown} onPointerDown={HandlePointerDown} onPointerLeave={HandlePointerLeave}
        onPointerMove={HandlePointerMove} onPointerUp={HandlePointerUp}>
        <svg className="time-series-chart__svg" width={Size.Width} height={Size.Height} aria-hidden="true">
            <defs>
                {Input.Series.map(Series => <linearGradient id={`${UniqueId}-fill-${Series.Key}`} key={Series.Key} x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor={Series.Color} stopOpacity=".14" />
                    <stop offset="72%" stopColor={Series.Color} stopOpacity=".025" />
                    <stop offset="100%" stopColor={Series.Color} stopOpacity="0" />
                </linearGradient>)}
                <linearGradient id={`${UniqueId}-crosshair`} x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="var(--plot-cursor)" stopOpacity="0" />
                    <stop offset="10%" stopColor="var(--plot-cursor)" stopOpacity=".8" />
                    <stop offset="90%" stopColor="var(--plot-cursor)" stopOpacity=".8" />
                    <stop offset="100%" stopColor="var(--plot-cursor)" stopOpacity="0" />
                </linearGradient>
                <clipPath id={`${UniqueId}-band`}>
                    <rect height={InnerHeight + 12} width={34} x={(HoverX ?? 0) - 17} y={Margin.Top - 6} />
                </clipPath>
            </defs>
            <g className="time-series-chart__grid">
                {Ticks.map(Tick => <line key={Tick} x1={Margin.Left} x2={Size.Width - Margin.Right}
                    y1={Y(Tick)} y2={Y(Tick)} />)}
            </g>
            <g className="time-series-chart__axis">
                {Ticks.map(Tick => <text key={Tick} x={Margin.Left - 9} y={Y(Tick)}
                    textAnchor="end" dominantBaseline="middle">{Input.FormatAxis(Tick)}</text>)}
                {TickIndices.map(Index => {
                    const Point = Input.Points[Index];
                    if (!Point) return null;
                    const TickX = X(Point.Time);
                    const Distance = HoverX === null ? Number.POSITIVE_INFINITY : Math.abs(TickX - HoverX);
                    const Opacity = Distance < 28 ? 0 : Distance < 54 ? (Distance - 28) / 26 : 1;
                    return <text key={Point.Time} x={TickX} y={Size.Height - 9}
                        textAnchor={Index === 0 ? 'start' : Index === Input.Points.length - 1 ? 'end' : 'middle'}
                        style={{ opacity: Opacity, transition: 'opacity 160ms ease' }}>{Input.FormatTime(Point.Time)}</text>;
                })}
            </g>
            <g className="time-series-chart__series">
                {Input.Series.map(Series => {
                    const Segments = FiniteTimeSegments(Input.Points, Series.Value);
                    const ClassName = ActiveKey !== null && ActiveKey !== Series.Key ? 'is-dimmed' : ActiveKey === Series.Key ? 'is-focused' : '';
                    return <g key={Series.Key} className={ClassName}>
                        {Series.Area === true && Segments.map((Segment, Index) => Segment.length > 1
                            ? <path key={`area-${Index}`} className="time-series-chart__area" fill={`url(#${UniqueId}-fill-${Series.Key})`}
                                d={AreaPath(Segment, Series.Value, X, Y, Margin.Top + InnerHeight)} />
                            : null)}
                        {Segments.map((Segment, Index) => Segment.length > 1
                            ? <path key={`line-${Index}`} className="time-series-chart__line" stroke={Series.Color}
                                d={LinePath(Segment, Series.Value, X, Y)} />
                            : <circle key={`dot-${Index}`} cx={X(Segment[0]?.Time ?? TimeMin)} cy={Y(Series.Value(Segment[0] as Point) ?? 0)} r={2.25} fill={Series.Color} />)}
                    </g>;
                })}
            </g>
            {HoverX !== null && <g className="time-series-chart__hover" clipPath={`url(#${UniqueId}-band)`}>
                {Input.Series.map(Series => FiniteTimeSegments(Input.Points, Series.Value).map((Segment, Index) =>
                    Segment.length > 1 ? <path key={`${Series.Key}-bright-${Index}`} className="time-series-chart__highlight"
                        stroke={Series.Color} d={LinePath(Segment, Series.Value, X, Y)} /> : null))}
            </g>}
            {HoverX !== null && <g className="time-series-chart__crosshair">
                <rect x={HoverX - .5} y={Margin.Top} width={1} height={InnerHeight} fill={`url(#${UniqueId}-crosshair)`} />
                {Input.Series.map(Series => {
                    const Value = Hovered ? Series.Value(Hovered) : null;
                    if (Value === null || !Number.isFinite(Value)) return null;
                    return <g key={Series.Key} className="time-series-chart__dot">
                        <circle cx={HoverX} cy={Y(Value)} r={8} fill={Series.Color} opacity=".16" />
                        <circle cx={HoverX} cy={Y(Value)} r={4} fill={Series.Color} stroke="var(--surface)" strokeWidth={2} />
                    </g>;
                })}
            </g>}
        </svg>
        {Hovered && HoverX !== null && <div className={`chart-tooltip time-series-chart__tooltip${Pinned ? ' is-pinned' : ''}`}
            style={{ left: Math.max(94, Math.min(Size.Width - 94, HoverX)) }}>
            <span className="chart-tooltip__time">{Input.FormatTime(Hovered.Time)}{Pinned ? ' · 已固定' : ''}</span>
            {Input.Series.map(Series => {
                const Value = Series.Value(Hovered);
                return Value === null || !Number.isFinite(Value) ? null : <div className="chart-tooltip__row" key={Series.Key}>
                    <span><i style={{ background: Series.Color }} />{Series.Label}</span>
                    <strong>{Series.Format(Value)}</strong>
                </div>;
            })}
        </div>}
    </div>;
}

function LinePath<Point extends TimeSeriesPoint>(
    Points: readonly Point[],
    Value: (Point: Point) => number | null,
    X: (Time: number) => number,
    Y: (Value: number) => number,
): string {
    return Points.map((Point, Index) => {
        const Reading = Value(Point);
        return `${Index === 0 ? 'M' : 'L'}${X(Point.Time).toFixed(2)},${Y(Reading ?? 0).toFixed(2)}`;
    }).join(' ');
}

function AreaPath<Point extends TimeSeriesPoint>(
    Points: readonly Point[],
    Value: (Point: Point) => number | null,
    X: (Time: number) => number,
    Y: (Value: number) => number,
    Baseline: number,
): string {
    const Line = LinePath(Points, Value, X, Y);
    const First = Points[0];
    const Last = Points[Points.length - 1];
    if (!First || !Last) return '';
    return `${Line} L${X(Last.Time).toFixed(2)},${Baseline.toFixed(2)} L${X(First.Time).toFixed(2)},${Baseline.toFixed(2)} Z`;
}
