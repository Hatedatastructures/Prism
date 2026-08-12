/**
 * @file codec.hpp
 * @brief TrustTunnel 认证编解码（纯函数）
 * @details 对齐 mihomo transport/trusttunnel/protocol.go 与
 * C++ src/prism/handshake/trusttunnel/scheme.cpp：
 *          - basic_auth：Basic base64(user:pass)
 *          - parse_basic_auth：解析校验 "Basic <base64>"
 * @note 参考 TrustTunnel 协议规范。
 */

#pragma once

#include <common/core/error.hpp>
#include <common/trusttunnel/types.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace psmtest::trusttunnel
{

    /// base64 编码表（标准，RFC 4648）
    inline constexpr char base64_table[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    /**
     * @brief 构造 Basic Auth 头值
     * @param user 用户名
     * @param pass 密码
     * @return "Basic base64(user:pass)"
     */
    [[nodiscard]] inline auto basic_auth(std::string_view user, std::string_view pass)
        -> std::string
    {
        const std::string raw = std::string(user) + ":" + std::string(pass);
        std::string enc;
        enc.reserve((raw.size() + 2) / 3 * 4);
        std::size_t i = 0;
        for (; i + 2 < raw.size(); i += 3)
        {
            const auto n = static_cast<std::uint32_t>(static_cast<std::uint8_t>(raw[i])) << 16 |
                           static_cast<std::uint32_t>(static_cast<std::uint8_t>(raw[i + 1])) << 8 |
                           static_cast<std::uint8_t>(raw[i + 2]);
            enc.push_back(base64_table[(n >> 18) & 0x3F]);
            enc.push_back(base64_table[(n >> 12) & 0x3F]);
            enc.push_back(base64_table[(n >> 6) & 0x3F]);
            enc.push_back(base64_table[n & 0x3F]);
        }
        if (i + 1 == raw.size())
        {
            const auto n = static_cast<std::uint32_t>(static_cast<std::uint8_t>(raw[i])) << 16;
            enc.push_back(base64_table[(n >> 18) & 0x3F]);
            enc.push_back(base64_table[(n >> 12) & 0x3F]);
            enc.push_back('=');
            enc.push_back('=');
        }
        else if (i + 2 == raw.size())
        {
            const auto n = static_cast<std::uint32_t>(static_cast<std::uint8_t>(raw[i])) << 16 |
                           static_cast<std::uint32_t>(static_cast<std::uint8_t>(raw[i + 1])) << 8;
            enc.push_back(base64_table[(n >> 18) & 0x3F]);
            enc.push_back(base64_table[(n >> 12) & 0x3F]);
            enc.push_back(base64_table[(n >> 6) & 0x3F]);
            enc.push_back('=');
        }
        return std::string(basic_prefix) + enc;
    }

    /**
     * @brief 解析校验 Basic Auth 头值
     * @param authorization "Basic <base64>"
     * @param user 输出用户名
     * @param pass 输出密码
     * @return true = 解析成功
     */
    [[nodiscard]] inline auto parse_basic_auth(std::string_view authorization,
                                               std::string &user, std::string &pass) -> bool
    {
        if (authorization.size() < basic_prefix.size() ||
            authorization.substr(0, basic_prefix.size()) != basic_prefix)
            return false;
        const auto encoded = authorization.substr(basic_prefix.size());
        if (encoded.empty())
            return false;

        // base64 解码
        auto val = [](char c) -> int
        {
            if (c >= 'A' && c <= 'Z')
                return c - 'A';
            if (c >= 'a' && c <= 'z')
                return c - 'a' + 26;
            if (c >= '0' && c <= '9')
                return c - '0' + 52;
            if (c == '+')
                return 62;
            if (c == '/')
                return 63;
            return -1;
        };
        std::string raw;
        std::uint32_t acc = 0;
        int bits = 0;
        for (const char c : encoded)
        {
            if (c == '=')
                break;
            const int v = val(c);
            if (v < 0)
                return false;
            acc = (acc << 6) | static_cast<std::uint32_t>(v);
            bits += 6;
            if (bits >= 8)
            {
                bits -= 8;
                raw.push_back(static_cast<char>((acc >> bits) & 0xFF));
            }
        }
        const auto colon = raw.find(':');
        if (colon == std::string::npos)
            return false;
        user = raw.substr(0, colon);
        pass = raw.substr(colon + 1);
        return true;
    }

    /**
     * @brief 校验 Basic Auth（服务端侧）
     * @param authorization 客户端头值
     * @param expect_user 期望用户名
     * @param expect_pass 期望密码
     * @return true = 匹配
     */
    [[nodiscard]] inline auto verify_basic_auth(std::string_view authorization,
                                                std::string_view expect_user,
                                                std::string_view expect_pass) -> bool
    {
        std::string user, pass;
        if (!parse_basic_auth(authorization, user, pass))
            return false;
        return user == expect_user && pass == expect_pass;
    }

} // namespace psmtest::trusttunnel
