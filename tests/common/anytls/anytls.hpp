/**
 * @file anytls.hpp
 * @brief AnyTLS 认证原语（客户端 + 服务端）
 * @details 纯逻辑（无锁）：
 *          1. 认证帧 = [长度 2B][载荷]（TLS 握手后首个应用层帧）
 *          2. 会话密钥派生（HKDF-SHA256，RFC 5869）
 *          命名空间 psm_test::anytls，参考 mihomo transport/anytls。
 */

#pragma once

#include <common/common.hpp>

#include <openssl/evp.h>
#include <openssl/hmac.h>

namespace psm_test::anytls
{

    namespace detail
    {

        /// HKDF-Extract：PRK = HMAC-SHA256(salt, ikm)
        inline auto hkdf_extract(const view salt, const view ikm) -> std::array<std::uint8_t, 32>
        {
            std::array<std::uint8_t, 32> prk{};
            unsigned int len = 0;
            HMAC(EVP_sha256(), salt.data(), static_cast<int>(salt.size()),
                 ikm.data(), ikm.size(), prk.data(), &len);
            return prk;
        }

        /// HKDF-Expand：OKM = T(1) || T(2) || ...
        inline auto hkdf_expand(const view prk, const std::string_view info,
                                const std::size_t out_len) -> buffer
        {
            buffer out(out_len);
            std::array<std::uint8_t, 32> t{};
            std::size_t t_len = 0;
            std::size_t done = 0;
            std::uint8_t counter = 1;
            byte_writer info_buf;
            info_buf.write_bytes(info);
            while (done < out_len)
            {
                HMAC_CTX *ctx = HMAC_CTX_new();
                if (!ctx)
                    return {};
                HMAC_Init_ex(ctx, prk.data(), static_cast<int>(prk.size()), EVP_sha256(), nullptr);
                if (t_len > 0)
                    HMAC_Update(ctx, t.data(), t_len);
                HMAC_Update(ctx, info_buf.data().data(), info_buf.size());
                HMAC_Update(ctx, &counter, 1);
                unsigned int len = 0;
                HMAC_Final(ctx, t.data(), &len);
                HMAC_CTX_free(ctx);
                t_len = len;
                const auto n = std::min(out_len - done, static_cast<std::size_t>(t_len));
                std::copy(t.begin(), t.begin() + static_cast<std::ptrdiff_t>(n),
                          out.begin() + static_cast<std::ptrdiff_t>(done));
                done += n;
                ++counter;
            }
            return out;
        }

    } // namespace detail

    /// HKDF-SHA256 派生会话密钥
    /// @param tls_secret TLS 会话密钥（ikm）
    /// @param salt 盐（空表示全零 32 字节）
    /// @param info 上下文信息
    /// @param out_len 输出长度
    [[nodiscard]] inline auto derive_session_key(const view tls_secret, const view salt,
                                                 const std::string_view info,
                                                 const std::size_t out_len) -> buffer
    {
        std::array<std::uint8_t, 32> zero_salt{};
        const auto salt_view = salt.empty() ? view(zero_salt) : salt;
        const auto prk = detail::hkdf_extract(salt_view, tls_secret);
        return detail::hkdf_expand(prk, info, out_len);
    }

    /// 构造认证帧：[长度 2B][载荷]
    [[nodiscard]] inline auto build_auth_frame(const view payload) -> buffer
    {
        byte_writer w;
        w.write_u16(static_cast<std::uint16_t>(payload.size()));
        w.write_bytes(payload);
        return w.data();
    }

    /// 解析认证帧：[长度 2B][载荷]
    struct auth_frame
    {
        std::size_t payload_offset{0};
        bool valid{false};
    };

    [[nodiscard]] inline auto parse_auth_frame(const view data) -> auth_frame
    {
        auth_frame frame;
        if (data.size() < 2)
            return frame;
        const auto len = static_cast<std::size_t>((data[0] << 8) | data[1]);
        if (data.size() < 2 + len)
            return frame;
        frame.payload_offset = 2;
        frame.valid = true;
        return frame;
    }

} // namespace psm_test::anytls
