/**
 * @file CredentialCodec.hpp
 * @brief Trojan 密码凭据派生
 * @details 只拥有密码到 SHA-224 十六进制 wire 凭据的无状态转换。
 */

#pragma once

#include <openssl/evp.h>

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

#include <Preview/Foundation/ByteSpan.hpp>
#include <Preview/Protocols/Trojan/Types.hpp>

namespace Preview::Trojan
{

    namespace Detail
    {

        /**
         * @brief 计算 SHA-224 摘要
         * @param Data 输入数据
         * @return 28 字节摘要
         */
        [[nodiscard]] inline auto Sha224(std::span<const std::uint8_t> Data)
            -> std::array<std::uint8_t, 28>
        {
            std::array<std::uint8_t, 28> Output{};
            unsigned int Length = 0;
            EVP_Digest(
                Data.data(),
                Data.size(),
                Output.data(),
                &Length,
                EVP_sha224(),
                nullptr);
            return Output;
        }

    } // namespace Detail

    /**
     * @brief 计算密码凭据（SHA-224 十六进制 56 字符）
     * @param Password 密码
     * @return 56 字符十六进制凭据
     */
    [[nodiscard]] inline auto Credential(std::string_view Password) -> std::string
    {
        const auto Hash = Detail::Sha224(AsU8Span(Password));
        std::string Output;
        Output.reserve(CredentialLen);
        static constexpr char Hex[] = "0123456789abcdef";
        for (const auto Byte : Hash)
        {
            Output.push_back(Hex[(Byte >> 4) & 0x0F]);
            Output.push_back(Hex[Byte & 0x0F]);
        }
        return Output;
    }

} // namespace Preview::Trojan
