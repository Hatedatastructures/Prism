/**
 * @file Sha224.hpp
 * @brief 固定输出 SHA224 凭据编码。
 */
#pragma once

#include <Prism/Foundation/Utility/Crypto/Operation.hpp>
#include <array>
#include <cstddef>
#include <expected>
#include <string_view>

namespace Prism::Crypto
{
    /**
     * @brief 计算字符串的 SHA224 十六进制凭据；输入同步借用，结果拥有 56 个字符。
     * @details 不分配字符串；逐步检查摘要操作，临时原始摘要和上下文在返回时擦除。
     *          无取消、半关闭、最终关闭或 executor 行为；失败不提供伪造凭据。
     */
    [[nodiscard]] auto Sha224(std::string_view Input)
        -> std::expected<std::array<char, 56>, Fault::Failure>;

    /** @brief 同步检查借用文本是否全部为十六进制字符，不分配或拥有资源。 */
    [[nodiscard]] auto IsHex(std::string_view Text) noexcept -> bool;

    /**
     * @brief 将借用凭据规范为调用者拥有的 56 字符值；已编码内容保持原字节。
     * @return 明文转换的 SHA224 失败原样返回；无取消、关闭和 executor 行为。
     */
    [[nodiscard]] auto NormalizeCredential(std::string_view Credential)
        -> std::expected<std::array<char, 56>, Fault::Failure>;
}
