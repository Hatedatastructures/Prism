/**
 * @file Codec.hpp
 * @brief TrustTunnel 认证编解码（纯函数）
 * @details 对齐 mihomo transport/trusttunnel/Protocol.go 与
 * C++ src/prism/handshake/trusttunnel/scheme.cpp：
 *          - BasicAuth：Basic base64(user:pass)
 *          - ParseBasicAuth：解析校验 "Basic <base64>"
 * @note 参考 TrustTunnel 协议规范。
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include <preview/Foundation/Error.hpp>
#include <preview/Protocols/Trusttunnel/Types.hpp>

namespace Preview::Trusttunnel
{

    /// base64 编码表（标准，RFC 4648）
    inline constexpr char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    /**
     * @brief 构造 Basic Auth 头值
     * @param user 用户名
     * @param pass 密码
     * @return "Basic base64(user:pass)"
     */
    [[nodiscard]] inline auto BasicAuth(std::string_view user, std::string_view pass) -> std::string
    {
        const std::string raw = std::string(user) + ":" + std::string(pass);
        std::string enc;
        enc.reserve((raw.size() + 2) / 3 * 4);
        std::size_t I = 0;
        for (; I + 2 < raw.size(); I += 3)
        {
            const auto N = static_cast<std::uint32_t>(static_cast<std::uint8_t>(raw[I])) << 16 |
                           static_cast<std::uint32_t>(static_cast<std::uint8_t>(raw[I + 1])) << 8 |
                           static_cast<std::uint8_t>(raw[I + 2]);
            enc.push_back(base64_table[(N >> 18) & 0x3F]);
            enc.push_back(base64_table[(N >> 12) & 0x3F]);
            enc.push_back(base64_table[(N >> 6) & 0x3F]);
            enc.push_back(base64_table[N & 0x3F]);
        }
        if (I + 1 == raw.size())
        {
            const auto N = static_cast<std::uint32_t>(static_cast<std::uint8_t>(raw[I])) << 16;
            enc.push_back(base64_table[(N >> 18) & 0x3F]);
            enc.push_back(base64_table[(N >> 12) & 0x3F]);
            enc.push_back('=');
            enc.push_back('=');
        }
        else if (I + 2 == raw.size())
        {
            const auto N = static_cast<std::uint32_t>(static_cast<std::uint8_t>(raw[I])) << 16 |
                           static_cast<std::uint32_t>(static_cast<std::uint8_t>(raw[I + 1])) << 8;
            enc.push_back(base64_table[(N >> 18) & 0x3F]);
            enc.push_back(base64_table[(N >> 12) & 0x3F]);
            enc.push_back(base64_table[(N >> 6) & 0x3F]);
            enc.push_back('=');
        }
        return std::string(BasicPrefix) + enc;
    }

    /**
     * @brief 解析校验 Basic Auth 头值
     * @param authorization "Basic <base64>"
     * @param user 输出用户名
     * @param pass 输出密码
     * @return true = 解析成功
     */
    [[nodiscard]] inline auto ParseBasicAuth(std::string_view authorization, std::string &user,
                                               std::string &pass) -> bool
    {
        if (authorization.size() < BasicPrefix.size() ||
            authorization.substr(0, BasicPrefix.size()) != BasicPrefix)
        {
            return false;
        }
        const auto Encoded = authorization.substr(BasicPrefix.size());
        if (Encoded.empty())
        {
            return false;
        }

        // base64 解码
        auto Val = [](char c) -> int
        {
            if (c >= 'A' && c <= 'Z')
            {
                return c - 'A';
            }
            if (c >= 'a' && c <= 'z')
            {
                return c - 'a' + 26;
            }
            if (c >= '0' && c <= '9')
            {
                return c - '0' + 52;
            }
            if (c == '+')
            {
                return 62;
            }
            if (c == '/')
            {
                return 63;
            }
            return -1;
        };
        std::string raw;
        std::uint32_t Acc = 0;
        int Bits = 0;
        for (const char c : Encoded)
        {
            if (c == '=')
            {
                break;
            }
            const int V = Val(c);
            if (V < 0)
            {
                return false;
            }
            Acc = (Acc << 6) | static_cast<std::uint32_t>(V);
            Bits += 6;
            if (Bits >= 8)
            {
                Bits -= 8;
                raw.push_back(static_cast<char>((Acc >> Bits) & 0xFF));
            }
        }
        const auto Colon = raw.find(':');
        if (Colon == std::string::npos)
        {
            return false;
        }
        user = raw.substr(0, Colon);
        pass = raw.substr(Colon + 1);
        return true;
    }

    /**
     * @brief 校验 Basic Auth（服务端侧）
     * @param authorization 客户端头值
     * @param ExpectUser 期望用户名
     * @param ExpectPass 期望密码
     * @return true = 匹配
     */
    [[nodiscard]] inline auto VerifyBasicAuth(std::string_view authorization, std::string_view ExpectUser,
                                                std::string_view ExpectPass) -> bool
    {
        std::string user, pass;
        if (!ParseBasicAuth(authorization, user, pass))
        {
            return false;
        }
        return user == ExpectUser && pass == ExpectPass;
    }

} // namespace Preview::Trusttunnel
