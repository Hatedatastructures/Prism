/** @file TrafficJsonSupport.hpp @brief Operations JSON owner 共用的私有 ID 编码辅助。 */
#pragma once

#include <Prism/Operations/Http/JsonWriter.hpp>

namespace Prism::Operations::HttpDetail
{
    /** @brief 将强类型 ID 按 JSON decimal-string 合同编码。 */
    template <typename Id>
    [[nodiscard]] inline auto AppendId(JsonWriter &Writer, const Id Value) -> bool
    {
        return Writer.Decimal(Value.Value());
    }
}
