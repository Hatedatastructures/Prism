/**
 * @file Trace.hpp
 * @brief Preview 扩展日志渲染的 trace 字段选择。
 */

#pragma once

namespace Preview::Statistics
{

    /** @brief 扩展渲染时需要输出的兼容 trace 字段。 */
    struct TraceSelection final
    {
        bool IncludeCorrelation{true};
        bool IncludeWorker{true};
        bool IncludeSession{true};
        bool IncludeStream{false};
    };

} // namespace Preview::Statistics
