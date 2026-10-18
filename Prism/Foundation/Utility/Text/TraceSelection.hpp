/** @file TraceSelection.hpp
 * @brief 中立观察字段选择；不依赖统计或日志后端。
 */
#pragma once

namespace Prism::Text
{
    /** @brief 只控制观察输出，不改变业务身份与权限。 */
    struct TraceSelection final
    {
        bool IncludeCorrelation{true}; ///< 输出关联身份。
        bool IncludeWorker{true}; ///< 输出 worker 身份。
        bool IncludeSession{true}; ///< 输出 session 身份。
        bool IncludeStream{false}; ///< 输出 stream 身份。
    };
}
