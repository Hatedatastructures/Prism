/**
 * @file sha224.hpp
 * @brief SHA224 哈希工具
 * @details 提供基于 OpenSSL 的 SHA224 哈希计算功能，用于 Trojan 协议凭据处理。
 */
#pragma once

#include <prism/core/memory/container.hpp>

#include <openssl/sha.h>

#include <array>
#include <cctype>
#include <cstdint>
#include <string>
#include <string_view>


namespace psm::crypto
{

    /**
     * @brief 计算字符串的 SHA224 哈希值
     * @param input 输入字符串
     * @return 56 字节的十六进制哈希字符串
     */
    [[nodiscard]] inline auto sha224(const std::string_view input)
        -> memory::string
    {
        std::array<std::uint8_t, SHA224_DIGEST_LENGTH> hash{};
        SHA224(reinterpret_cast<const std::uint8_t *>(input.data()), input.size(), hash.data());

        memory::string result{memory::current_resource()};
        result.reserve(56);
        for (const auto byte : hash)
        {
            constexpr char hex_chars[] = "0123456789abcdef";
            result.push_back(hex_chars[(byte >> 4) & 0x0F]);
            result.push_back(hex_chars[byte & 0x0F]);
        }
        return result;
    }

    /**
     * @brief 检查字符串是否为有效的十六进制字符串
     * @param str 输入字符串
     * @return 如果字符串只包含十六进制字符则返回 true
     */
    [[nodiscard]] inline auto is_hex(const std::string_view str)
        -> bool
    {
        for (const auto c : str)
        {
            if (!std::isxdigit(static_cast<std::uint8_t>(c)))
            {
                return false;
            }
        }
        return true;
    }

    /**
     * @brief 将凭据转换为 SHA224 哈希（如果还不是哈希）
     * @param credential 凭据字符串（可能是明文或已哈希）
     * @return 56 字节的十六进制哈希字符串
     * @details 如果输入已经是 56 字节的十六进制字符串，直接返回；
     * 否则计算其 SHA224 哈希值。
     */
    [[nodiscard]] inline auto normalize_credential(const std::string_view credential)
        -> memory::string
    {
        if (credential.size() == 56 && is_hex(credential))
        {
            return memory::string{credential, memory::current_resource()};
        }
        return sha224(credential);
    }
}
