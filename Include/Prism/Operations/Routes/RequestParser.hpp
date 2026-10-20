/**
 * @file RequestParser.hpp
 * @brief Operations HTTP/1.1 请求头解析 owner。
 * @details 解析结果只借用调用方缓冲区；不拥有 socket、路由或业务状态。
 */

#pragma once

#include <Prism/Operations/HttpRequest.hpp>

#include <charconv>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <system_error>

namespace Prism::Operations::RequestParserDetail
{

    enum class ParseStatus : std::uint8_t
    {
        Complete,
        Incomplete,
        Malformed,
        Oversized,
    };

    [[nodiscard]] auto ToLower(const char Value) noexcept -> char;

    [[nodiscard]] auto EqualsInsensitive(const std::string_view Left,
        const std::string_view Right) noexcept -> bool;

    [[nodiscard]] auto IsTokenCharacter(const char Value) noexcept -> bool;

    [[nodiscard]] auto IsFieldValueCharacter(const char Value) noexcept -> bool;

    [[nodiscard]] auto Trim(const std::string_view Value) noexcept -> std::string_view;

    template <typename Value>
    [[nodiscard]] inline auto ParseUnsigned(const std::string_view Text, Value &Result) -> bool
    {
        if (Text.empty())
        {
            return false;
        }
        Value Parsed{};
        const auto *First = Text.data();
        const auto *Last = First + Text.size();
        const auto [End, Error] = std::from_chars(First, Last, Parsed, 10);
        if (Error != std::errc{} || End != Last)
        {
            return false;
        }
        Result = Parsed;
        return true;
    }

    /** @brief 解析唯一 HTTP/1.1 请求行；输出借用调用者的原始请求缓冲。 */
    [[nodiscard]] auto ReadRequestLine(std::string_view RequestLine,
        HttpRequest &Request) -> ParseStatus;

    /** @brief 持有单个请求头块的字段唯一性与输出借用视图。 */
    struct HeaderBlockParser final
    {
        HttpRequest &Request;
        bool HostSeen{false};
        bool OriginSeen{false};
        bool AuthorizationSeen{false};
        bool ContentLengthSeen{false};
        bool ContentTypeSeen{false};
        bool TransferEncodingSeen{false};
        bool CorrelationSeen{false};
        std::size_t HeaderCount{0};

        [[nodiscard]] auto ReadLine(const std::string_view Line) -> ParseStatus;

        [[nodiscard]] auto Finish() const noexcept -> ParseStatus;
    };

    /** @brief 验证完整请求头块，拒绝重复关键头、非零 body 和 transfer encoding。 */
    [[nodiscard]] auto ReadHeaderBlock(std::string_view HeaderBlock,
        HttpRequest &Request) -> ParseStatus;

} // namespace Prism::Operations::RequestParserDetail

namespace Prism::Operations::RequestParserDetail
{

    [[nodiscard]] auto ParseRequestHeaders(const std::string_view Raw,
        HttpRequest &Request) -> ParseStatus;

    [[nodiscard]] auto ParseRequest(const std::string_view Raw,
        HttpRequest &Request) -> ParseStatus;

} // namespace Prism::Operations::RequestParserDetail
