/** @file JsonPrimitives.hpp @brief Operations JSON 值编码与数组分隔的共享无状态 owner。 */
#pragma once

#include <Preview/Operations/Http/JsonWriter.hpp>

namespace Preview::Operations::HttpDetail
{
    /** @brief 输出下一个数组项的分隔符；不持有 writer 之外的状态。 */
    [[nodiscard]] inline auto AppendComma(JsonWriter &Writer, bool &First) -> bool
    {
        if (!First && !Writer.Append(","))
        {
            return false;
        }
        First = false;
        return true;
    }

    /** @brief 将强类型 ID 按 JSON decimal-string 合同编码。 */
    template <typename Id>
    [[nodiscard]] inline auto AppendId(JsonWriter &Writer, const Id Value) -> bool
    {
        return Writer.Decimal(Value.Value());
    }
}
