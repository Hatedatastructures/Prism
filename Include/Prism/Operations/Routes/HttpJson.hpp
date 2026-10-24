/**
 * @file HttpJson.hpp
 * @brief Operations HTTP JSON writer 和响应 framing 接口。
 * @details 该 owner 只负责有界 JSON 文本和 HTTP/1.1 管理响应，不拥有路由或网络连接。
 */
#pragma once

#include <Prism/Operations/Models.hpp>

#include <optional>
#include <string>
#include <string_view>

namespace Prism::Operations::HttpDetail
{
    [[nodiscard]] auto QueryStatusName(QueryStatus Value) -> std::string_view;
    [[nodiscard]] auto StatusFor(QueryStatus Status) noexcept -> int;
    [[nodiscard]] auto StatusFor(CommandStatus Status) noexcept -> int;
    [[nodiscard]] auto SerializeQuery(const QueryResult& Result, bool IncludeDetails)
        -> std::optional<std::string>;
    [[nodiscard]] auto SerializeCommand(const CommandResult& Result)
        -> std::optional<std::string>;
    [[nodiscard]] auto MakeResponse(int Status, std::string Body) -> std::string;
    [[nodiscard]] auto MakeErrorResponse(
        int Status, std::string_view Message, Prism::RequestId Correlation = {}) -> std::string;
} // namespace Prism::Operations::HttpDetail
