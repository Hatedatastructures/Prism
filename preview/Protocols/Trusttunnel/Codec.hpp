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
#include <span>
#include <string>
#include <string_view>

#include <preview/Foundation/Error.hpp>
#include <preview/Foundation/Authenticator.hpp>
#include <preview/Foundation/Utility/Crypto/Base64.hpp>
#include <preview/Protocols/Trusttunnel/Types.hpp>

namespace Preview::Trusttunnel
{

    /// base64 编码表（标准，RFC 4648）
    inline constexpr char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    /**
     * @brief 构造 Basic Auth 头值
     * @param Username 用户名
     * @param Password 密码
     * @return "Basic base64(user:pass)"
     */
    [[nodiscard]] inline auto BasicAuth(
        std::string_view Username,
        std::string_view Password) -> std::string
    {
        const std::string Raw = std::string(Username) + ":" + std::string(Password);
        std::string Encoded;
        Encoded.reserve((Raw.size() + 2) / 3 * 4);
        std::size_t Index = 0;
        for (; Index + 2 < Raw.size(); Index += 3)
        {
            const auto Value = static_cast<std::uint32_t>(static_cast<std::uint8_t>(Raw[Index])) << 16 |
                               static_cast<std::uint32_t>(static_cast<std::uint8_t>(Raw[Index + 1])) << 8 |
                               static_cast<std::uint8_t>(Raw[Index + 2]);
            Encoded.push_back(base64_table[(Value >> 18) & 0x3F]);
            Encoded.push_back(base64_table[(Value >> 12) & 0x3F]);
            Encoded.push_back(base64_table[(Value >> 6) & 0x3F]);
            Encoded.push_back(base64_table[Value & 0x3F]);
        }
        if (Index + 1 == Raw.size())
        {
            const auto Value = static_cast<std::uint32_t>(static_cast<std::uint8_t>(Raw[Index])) << 16;
            Encoded.push_back(base64_table[(Value >> 18) & 0x3F]);
            Encoded.push_back(base64_table[(Value >> 12) & 0x3F]);
            Encoded.push_back('=');
            Encoded.push_back('=');
        }
        else if (Index + 2 == Raw.size())
        {
            const auto Value = static_cast<std::uint32_t>(static_cast<std::uint8_t>(Raw[Index])) << 16 |
                               static_cast<std::uint32_t>(static_cast<std::uint8_t>(Raw[Index + 1])) << 8;
            Encoded.push_back(base64_table[(Value >> 18) & 0x3F]);
            Encoded.push_back(base64_table[(Value >> 12) & 0x3F]);
            Encoded.push_back(base64_table[(Value >> 6) & 0x3F]);
            Encoded.push_back('=');
        }
        return std::string(BasicPrefix) + Encoded;
    }

    /**
     * @brief 解析校验 Basic Auth 头值
     * @param Authorization "Basic <base64>"
     * @param Username 输出用户名
     * @param Password 输出密码
     * @return true = 解析成功
     */
    [[nodiscard]] inline auto ParseBasicAuth(
        std::string_view Authorization,
        std::string &Username,
        std::string &Password) -> bool
    {
        if (Authorization.size() < BasicPrefix.size() ||
            Authorization.substr(0, BasicPrefix.size()) != BasicPrefix)
        {
            return false;
        }
        const auto Encoded = Authorization.substr(BasicPrefix.size());
        if (Encoded.empty())
        {
            return false;
        }

        const auto Raw = Preview::Crypto::Base64Decode(Encoded);
        if (Raw.empty())
        {
            return false;
        }
        const auto Canonical = Preview::Crypto::Base64Encode(
            std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t *>(Raw.data()),
                Raw.size()));
        if (Canonical != Encoded)
        {
            return false;
        }
        const auto Colon = Raw.find(':');
        if (Colon == std::string::npos)
        {
            return false;
        }
        Username = Raw.substr(0, Colon);
        Password = Raw.substr(Colon + 1);
        return true;
    }

    /**
     * @brief 校验 Basic Auth（服务端侧）
     * @param Authorization 客户端头值
     * @param ExpectUser 期望用户名
     * @param ExpectPass 期望密码
     * @return true = 匹配
     */
    [[nodiscard]] inline auto VerifyBasicAuth(
        std::string_view Authorization,
        std::string_view ExpectUser,
        std::string_view ExpectPass) -> bool
    {
        std::string Username;
        std::string Password;
        if (!ParseBasicAuth(Authorization, Username, Password))
        {
            return false;
        }
        const auto UserMatches = Preview::ConstantTimeEqual(Username, ExpectUser);
        const auto PasswordMatches = Preview::ConstantTimeEqual(Password, ExpectPass);
        return UserMatches && PasswordMatches;
    }

} // namespace Preview::Trusttunnel
