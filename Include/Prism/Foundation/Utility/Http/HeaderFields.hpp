/**
 * @file HeaderFields.hpp
 * @brief HTTP/1.1 请求头字段视图与 framing 元数据
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

namespace Prism::Http11::HeaderFields
{
    inline constexpr std::size_t MaxHeaderBlockBytes = 65536;

    struct Field final
    {
        std::string_view Name;
        std::string_view RawValue;
    };

    struct Parsed final
    {
        std::vector<Field> Fields;
        std::vector<std::string_view> ConnectionOptions;
        std::string_view Host;
        std::string_view ProxyAuthorization;
        bool HasContentLength{false};
        std::uint64_t ContentLength{0}; ///< 已验证的 Content-Length 数值（不借用输入）
        bool HasTransferEncoding{false};
        bool FinalTransferCodingChunked{false};
        bool HasUpgrade{false};
        std::string_view ContentType; ///< 首个 Content-Type 的已裁剪值；重复出现视为非法。

        [[nodiscard]] auto ConnectionContains(std::string_view Name) const noexcept -> bool;
        /** @brief 以大小写不敏感方式核对 Content-Type；未提供时返回 false。 */
        [[nodiscard]] auto ContentTypeIs(std::string_view Expected) const noexcept -> bool;
    };

    [[nodiscard]] auto Parse(std::string_view HeaderBlock) -> std::optional<Parsed>;
} // namespace Prism::Http11::HeaderFields
