/**
 * @file codec.hpp
 * @brief ShadowTLS v3 认证编解码（纯函数）
 * @details 对齐 sing-shadowtls v3_client.go / v3_conn.go：
 *          - generate_session_id：HMAC-SHA1(password, clientHello 前段 + sessionID
 *            + clientHello 后段)[:4] 塞入 session_id 末尾
 *          - verify_client_hello：校验 ClientHello session_id 内 HMAC
 *          - frame_hmac：HMAC-SHA1(password, serverRandom + tag + payload)[:4]
 *          - kdf：SHA256(password + serverRandom)，用于流加密密钥
 * @note 参考 sing-shadowtls v3 协议规范。
 */

#pragma once

#include <common/core/error.hpp>
#include <common/stealth/shadowtls/types.hpp>

#include <openssl/crypto.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string_view>
#include <vector>

namespace psmtest::shadowtls
{

    /**
     * @brief 生成 session_id（客户端侧）
     * @param password 密码
     * @param client_hello 不含 TLS 头的握手数据
     * @param session_id 输出 session_id（32 字节，末尾 4 字节为 HMAC）
     * @details 对齐 sing v3 generateSessionID：前 28 字节随机，
     * 后 4 字节 = HMAC-SHA1(password, hello[:sidStart] + sid + hello[sidEnd:])[:4]。
     */
    [[nodiscard]] inline auto generate_session_id(std::string_view password,
                                                  std::span<const std::uint8_t> client_hello,
                                                  std::span<std::uint8_t, tls_session_id_sz> session_id)
        -> error
    {
        if (client_hello.size() < session_id_start + tls_session_id_sz)
            return error::bad_length;

        // HMAC-SHA1(password, client_hello[:sidStart] + sessionID + client_hello[sidEnd:])[:4]
        HMAC_CTX *ctx = HMAC_CTX_new();
        if (!ctx)
            return error::io_error;
        HMAC_Init_ex(ctx, password.data(), static_cast<int>(password.size()), EVP_sha1(), nullptr);
        HMAC_Update(ctx, client_hello.data(), session_id_start);
        HMAC_Update(ctx, session_id.data(), tls_session_id_sz);
        HMAC_Update(ctx, client_hello.data() + session_id_start + tls_session_id_sz,
                    client_hello.size() - session_id_start - tls_session_id_sz);
        std::array<std::uint8_t, EVP_MAX_MD_SIZE> md{};
        std::uint32_t md_len = 0;
        HMAC_Final(ctx, md.data(), &md_len);
        HMAC_CTX_free(ctx);

        std::memcpy(session_id.data() + tls_session_id_sz - hmac_size, md.data(), hmac_size);
        return error::none;
    }

    /**
     * @brief 校验 ClientHello（服务端侧）
     * @param password 密码
     * @param client_hello 含 TLS 头的完整消息
     * @return true = session_id HMAC 校验通过
     * @details 对齐 sing v3 / C++ verify_client_hello：
     * HMAC-SHA1(password, hello[5:] 且 session_id 末尾 4 字节置零)[:4] == session_id 末尾 4 字节。
     */
    [[nodiscard]] inline auto verify_client_hello(std::string_view password,
                                                  std::span<const std::byte> client_hello)
        -> bool
    {
        constexpr std::size_t min_len =
            tls_hdrsize + 1 + 3 + 2 + tls_rnd_size + 1 + tls_session_id_sz;
        if (client_hello.size() < min_len)
            return false;
        const auto *raw = reinterpret_cast<const std::uint8_t *>(client_hello.data());
        if (raw[0] != 0x16 || raw[tls_hdrsize] != hs_type_clienthello)
            return false;
        const std::size_t sid_len_idx = tls_hdrsize + 1 + 3 + 2 + tls_rnd_size;
        if (raw[sid_len_idx] != tls_session_id_sz)
            return false;

        // 构造 HMAC 数据：hello[5:] 且 session_id 末尾 4 字节置零
        const std::size_t data_size = client_hello.size() - tls_hdrsize;
        std::vector<std::uint8_t> hmac_data(data_size);
        std::memcpy(hmac_data.data(), raw + tls_hdrsize, data_size);
        const std::size_t hmac_offset_in_data = session_id_start + tls_session_id_sz - hmac_size;
        std::memset(hmac_data.data() + hmac_offset_in_data, 0, hmac_size);

        // 期望 HMAC
        HMAC_CTX *ctx = HMAC_CTX_new();
        if (!ctx)
            return false;
        HMAC_Init_ex(ctx, password.data(), static_cast<int>(password.size()), EVP_sha1(), nullptr);
        HMAC_Update(ctx, hmac_data.data(), hmac_data.size());
        std::array<std::uint8_t, EVP_MAX_MD_SIZE> md{};
        std::uint32_t md_len = 0;
        HMAC_Final(ctx, md.data(), &md_len);
        HMAC_CTX_free(ctx);

        // 客户端 tag
        const std::size_t client_hmac_offset = sid_len_idx + 1 + tls_session_id_sz - hmac_size;
        return CRYPTO_memcmp(md.data(), raw + client_hmac_offset, hmac_size) == 0;
    }

    /**
     * @brief 计算帧 HMAC（post-handshake 认证）
     * @param password 密码
     * @param server_random 32 字节 server random
     * @param tag 标签（'C' 客户端 / 'S' 服务端）
     * @param payload 载荷
     * @return 4 字节 HMAC
     */
    [[nodiscard]] inline auto frame_hmac(std::string_view password,
                                         std::span<const std::uint8_t> server_random,
                                         char tag,
                                         std::span<const std::uint8_t> payload)
        -> std::array<std::uint8_t, hmac_size>
    {
        HMAC_CTX *ctx = HMAC_CTX_new();
        if (!ctx)
            return {};
        HMAC_Init_ex(ctx, password.data(), static_cast<int>(password.size()), EVP_sha1(), nullptr);
        HMAC_Update(ctx, server_random.data(), server_random.size());
        const auto tag_byte = static_cast<std::uint8_t>(tag);
        HMAC_Update(ctx, &tag_byte, 1);
        HMAC_Update(ctx, payload.data(), payload.size());
        std::array<std::uint8_t, EVP_MAX_MD_SIZE> md{};
        std::uint32_t md_len = 0;
        HMAC_Final(ctx, md.data(), &md_len);
        HMAC_CTX_free(ctx);

        std::array<std::uint8_t, hmac_size> out{};
        std::memcpy(out.data(), md.data(), hmac_size);
        return out;
    }

    /**
     * @brief 派生流密钥（对齐 sing v3 kdf）
     * @param password 密码
     * @param server_random 32 字节 server random
     * @return SHA256(password + serverRandom)
     */
    [[nodiscard]] inline auto kdf(std::string_view password,
                                  std::span<const std::uint8_t> server_random)
        -> std::array<std::uint8_t, 32>
    {
        SHA256_CTX ctx;
        SHA256_Init(&ctx);
        SHA256_Update(&ctx, password.data(), password.size());
        SHA256_Update(&ctx, server_random.data(), server_random.size());
        std::array<std::uint8_t, 32> out{};
        SHA256_Final(out.data(), &ctx);
        return out;
    }

    /**
     * @brief 字节异或（对齐 sing v3 xorSlice，用于流加密）
     * @param data 待异或数据（原地）
     * @param key 密钥
     */
    inline auto xor_slice(std::span<std::uint8_t> data, std::span<const std::uint8_t> key) -> void
    {
        if (key.empty())
            return;
        for (std::size_t i = 0; i < data.size(); ++i)
            data[i] ^= key[i % key.size()];
    }

} // namespace psmtest::shadowtls
