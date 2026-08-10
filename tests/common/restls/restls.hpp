/**
 * @file restls.hpp
 * @brief Restls 认证原语（客户端 + 服务端）
 * @details 纯逻辑（无锁）：
 *          1. 握手摘要派生：HMAC-SHA256(password, ClientHello 相关字节)
 *          2. 认证请求/响应字节构造
 *          命名空间 psm_test::restls，参考 metacubex/restls-client-go。
 */

#pragma once

#include <common/common.hpp>

#include <openssl/evp.h>
#include <openssl/hmac.h>

namespace psm_test::restls
{

    /// HMAC-SHA256 摘要（32 字节）
    [[nodiscard]] inline auto hmac_sha256(const std::string_view password,
                                          const view data) -> std::array<std::uint8_t, 32>
    {
        std::array<std::uint8_t, 32> out{};
        unsigned int len = 0;
        HMAC(EVP_sha256(), password.data(), static_cast<int>(password.size()),
             data.data(), data.size(), out.data(), &len);
        return out;
    }

    /// 派生握手认证密钥（HMAC-SHA256(password, 握手字节流)）
    [[nodiscard]] inline auto derive_auth_key(const std::string_view password,
                                              const view handshake) -> std::array<std::uint8_t, 32>
    {
        return hmac_sha256(password, handshake);
    }

    /// 构造认证载荷：[版本 1B][认证密钥 32B]
    [[nodiscard]] inline auto build_auth_payload(const std::uint8_t version,
                                                 const view auth_key) -> buffer
    {
        byte_writer w;
        w.write_u8(version);
        w.write_bytes(auth_key);
        return w.data();
    }

    /// 解析认证载荷
    struct auth_payload
    {
        std::uint8_t version{0};
        std::array<std::uint8_t, 32> auth_key{};
        bool valid{false};
    };

    [[nodiscard]] inline auto parse_auth_payload(const view data) -> auth_payload
    {
        auth_payload p;
        if (data.size() != 1 + 32)
            return p;
        p.version = data[0];
        std::copy(data.begin() + 1, data.end(), p.auth_key.begin());
        p.valid = true;
        return p;
    }

    /// 校验认证密钥（服务端）：比对计算值与收到的密钥
    [[nodiscard]] inline auto verify_auth(const std::string_view password, const view handshake,
                                          const view received_key) -> bool
    {
        if (received_key.size() != 32)
            return false;
        const auto calc = derive_auth_key(password, handshake);
        return std::memcmp(calc.data(), received_key.data(), 32) == 0;
    }

} // namespace psm_test::restls
