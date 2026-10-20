/**
 * @file ForwardResponseFields.hpp
 * @brief HTTP/1.1 响应头字段与 trailer 语法
 * @details 只提供响应语义所需的字段 framing 元数据。请求侧的认证、Host
 *          和逐跳字段策略不在此接口内。
 */

#pragma once

#include <Prism/Foundation/Error.hpp>

#include <cstddef>
#include <cstdint>
#include <expected>
#include <string_view>

namespace Prism::Http11
{

    /**
     * @brief 响应字段块、chunk 行和 trailer 单块上限
     */
    inline constexpr std::size_t MaxResponseHeaderBlockBytes = 65536U;

    /**
     * @struct ForwardResponseFields
     * @brief 已验证的响应 framing 元数据
     */
    struct ForwardResponseFields final
    {
        bool HasContentLength{false};
        std::uint64_t ContentLength{0};
        std::size_t ContentLengthFieldCount{0};
        bool HasTransferEncoding{false};
        bool FinalTransferCodingChunked{false};
        std::size_t TransferCodingCount{0};
        std::size_t ContentTypeFieldCount{0};
        std::string_view ContentType; ///< 借用解析输入；由调用方保证字段块生命周期

        /** @brief 按大小写不敏感方式核对 media type，并忽略参数。 */
        [[nodiscard]] auto ContentTypeIs(std::string_view Expected) const noexcept -> bool;
    };

    /**
     * @brief 解析响应头字段
     * @param Block 不含最终空行的响应头字段块
     * @param IgnoreBodyFraming HEAD/1xx/204/304/101 等无实体响应语义
     * @return 已验证的响应 framing 元数据或协议错误
     */
    [[nodiscard]] auto ParseResponseHeaders(std::string_view Block, bool IgnoreBodyFraming)
        -> std::expected<ForwardResponseFields, Error>;

    /**
     * @brief 验证 chunked trailer 字段块
     * @param Block 不含最终空行的 trailer 字段块
     * @return Error::None 或字段/禁用 trailer 错误
     */
    [[nodiscard]] auto ValidateResponseTrailers(std::string_view Block) noexcept -> Error;

} // namespace Prism::Http11
