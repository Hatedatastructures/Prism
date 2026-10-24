/** @file EventJson.hpp @brief 管理事件 severity、详情与丢失区间的 JSON owner。 */
#pragma once

#include <Prism/Operations/Models.hpp>
#include <Prism/Operations/Http/JsonWriter.hpp>
#include <Prism/Statistics/EventRing.hpp>
#include <Prism/Statistics/Types.hpp>

#include <string_view>

namespace Prism::Operations::HttpDetail
{
    /** @brief 映射事件环记录的实际分类。 */
    [[nodiscard]] auto EventKindName(
        const Prism::Statistics::EventKind Value) -> std::string_view;

    /** @brief 映射事件环记录的实际目标作用域。 */
    [[nodiscard]] auto EventScopeName(
        const Prism::Statistics::Scope Value) -> std::string_view;

    /** @brief 映射 EventRing producer 显式写入的真实 severity 枚举。 */
    [[nodiscard]] auto EventSeverityName(
        const Prism::Statistics::EventSeverity Value) -> std::string_view;

    /** @brief 同步编码事件值；输入只在本次写入期间借用，不持有事件或日志 owner。 */
    [[nodiscard]] auto AppendEvent(
        JsonWriter &Writer,
        const EventSnapshot &Value,
        const bool IncludeDetails) -> bool;

    /** @brief 输出真实事件页和丢失区间，并明确服务端 severity 过滤不可用。 */
    [[nodiscard]] auto AppendEventPage(
        JsonWriter &Writer,
        const Prism::Statistics::EventPage &Page,
        const bool IncludeDetails) -> bool;
}
