/**
 * @file CredentialCodec.hpp
 * @brief Trojan 密码凭据派生
 * @details 只拥有密码到 SHA-224 十六进制 wire 凭据的无状态转换。
 */

#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

#include <Prism/Protocols/Trojan/Types.hpp>

namespace Prism::Trojan
{

    namespace Detail
    {

        /**
         * @brief 计算 SHA-224 摘要
         * @param Data 输入数据
         * @return 28 字节摘要
         */
        [[nodiscard]] auto Sha224(std::span<const std::uint8_t> Data)
            -> std::array<std::uint8_t, 28>;

    } // namespace Detail

    /**
     * @brief 计算密码凭据（SHA-224 十六进制 56 字符）
     * @param Password 密码
     * @return 56 字符十六进制凭据
     */
    [[nodiscard]] auto Credential(std::string_view Password) -> std::string;

} // namespace Prism::Trojan
