/** @file ConfigurationResultJson.hpp @brief 有界配置问题和实际重启字段列表的唯一JSON编码。 */
#pragma once
#include <Prism/Operations/Models.hpp>
#include <Prism/Operations/Routes/JsonPrimitives.hpp>
namespace Prism::Operations::HttpDetail
{
    /** @brief 同步借用命令结果；上限拒绝，不截断、不制造额外问题或重启字段。 */
    [[nodiscard]] inline auto AppendConfigurationOutcome(JsonWriter& Writer,
        const CommandResult& Result) -> bool
    {
        if (Result.ConfigurationIssues.size() > 64 || Result.RestartRequiredFields.size() > 64 ||
            !Writer.Append(",") || !Writer.Key("configuration_issues") || !Writer.Append("[")) return false;
        bool First = true;
        for (const auto& Issue : Result.ConfigurationIssues)
        {
            if (!AppendComma(Writer, First) || !Writer.Append("{") || !Writer.Key("code") ||
                !Writer.String(Issue.Code) || !Writer.Append(",") || !Writer.Key("path") ||
                !Writer.String(Issue.Path) || !Writer.Append(",") || !Writer.Key("message") ||
                !Writer.String(Issue.Message) || !Writer.Append("}")) return false;
        }
        if (!Writer.Append("],") || !Writer.Key("restart_required_fields") || !Writer.Append("[")) return false;
        First = true;
        for (const auto& Field : Result.RestartRequiredFields)
            if (!AppendComma(Writer, First) || !Writer.String(Field)) return false;
        return Writer.Append("]");
    }
}
