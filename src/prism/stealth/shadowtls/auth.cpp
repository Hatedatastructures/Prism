/**
 * @file auth.cpp
 * @brief ShadowTLS v3 认证逻辑实现
 * @details 使用 OpenSSL 的 HMAC-SHA1 和 SHA256 实现 ShadowTLS v3 认证。
 * 认证算法完全参照 sing-shadowtls v3_server.go。
 */

#include <prism/stealth/shadowtls/auth.hpp>
#include <prism/stealth/shadowtls/constants.hpp>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>
#include <cstring>
#include <vector>

namespace psm::stealth::shadowtls
{
    auto compute_hmac(const std::string_view key, const std::span<const std::byte> data)
        -> std::array<std::uint8_t, 4>
    {
        std::array<std::uint8_t, 4> result{};
        unsigned int len = 0;

        HMAC(EVP_sha1(),
             key.data(), static_cast<int>(key.size()),
             reinterpret_cast<const unsigned char *>(data.data()), data.size(),
             result.data(), &len);

        return result;
    }

    auto verify_client_hello(std::span<const std::byte> client_hello, const std::string_view password) -> bool
    {
        // 最小长度检查: TLS Header(5) + Handshake Header(4) + Version(2) +
        //   Random(32) + SessionID Length(1) + SessionID(32) = 76
        constexpr std::size_t min_len = tls_header_size + 1 + 3 + 2 + tls_random_size + 1 + tls_session_id_size;
        if (client_hello.size() < min_len)
        {
            return false;
        }

        const auto *raw = reinterpret_cast<const std::uint8_t *>(client_hello.data());

        // TLS 记录类型必须是 Handshake (0x16)
        if (raw[0] != content_type_handshake)
        {
            return false;
        }

        // 握手类型必须是 ClientHello (0x01)
        // TLS Header(5) 之后是 Handshake Header，第 1 字节是 handshake type
        if (raw[5] != handshake_type_client_hello)
        {
            return false;
        }

        // SessionID 长度必须是 32
        if (raw[session_id_length_index] != tls_session_id_size)
        {
            return false;
        }

        // 构建用于 HMAC 计算的数据：
        // ClientHello 去掉 TLS header，SessionID 中 HMAC 位置填 0
        const std::size_t data_size = client_hello.size() - tls_header_size;
        std::vector<std::uint8_t> hmac_data(data_size);
        for (std::size_t i = 0; i < data_size; ++i)
        {
            hmac_data[i] = static_cast<std::uint8_t>(client_hello[tls_header_size + i]);
        }

        // 将 SessionID 中的 HMAC 部分（最后 4 字节）填 0
        constexpr std::size_t hmac_offset_in_data = session_id_length_index + 1 + tls_session_id_size - hmac_size - tls_header_size;
        std::memset(hmac_data.data() + hmac_offset_in_data, 0, hmac_size);

        // 计算 HMAC-SHA1
        const auto span = std::span(reinterpret_cast<const std::byte *>(hmac_data.data()),hmac_data.size());
        const auto expected = compute_hmac(password, span);

        // 提取客户端 SessionID 中的 HMAC 标签
        constexpr std::size_t client_hmac_offset = session_id_length_index + 1 + tls_session_id_size - hmac_size;
        std::array<std::uint8_t, 4> client_tag{};
        std::memcpy(client_tag.data(), raw + client_hmac_offset, hmac_size);

        // 恒定时间比较
        return CRYPTO_memcmp(expected.data(), client_tag.data(), hmac_size) == 0;
    }

    auto verify_frame_hmac(const std::string_view password,const std::span<const std::byte> server_random,
                           const std::span<const std::byte> payload,
                           const std::span<const std::uint8_t, 4> client_hmac) -> bool
    {
        // HMAC-SHA1(password, serverRandom + "C" + payload)[:4]
        HMAC_CTX *ctx = HMAC_CTX_new();
        if (!ctx)
        {
            return false;
        }

        HMAC_Init_ex(ctx, password.data(), static_cast<int>(password.size()), EVP_sha1(), nullptr);
        HMAC_Update(ctx, reinterpret_cast<const unsigned char *>(server_random.data()), server_random.size());

        constexpr unsigned char tag_c = 'C';
        HMAC_Update(ctx, &tag_c, 1);

        HMAC_Update(ctx, reinterpret_cast<const unsigned char *>(payload.data()), payload.size());

        std::array<std::uint8_t, EVP_MAX_MD_SIZE> md{};
        unsigned int md_len = 0;
        HMAC_Final(ctx, md.data(), &md_len);
        HMAC_CTX_free(ctx);

        return CRYPTO_memcmp(md.data(), client_hmac.data(), hmac_size) == 0;
    }

    auto compute_write_hmac(const std::string_view password,const std::span<const std::byte> server_random,
                            const std::span<const std::byte> payload)
        -> std::array<std::uint8_t, 4>
    {
        // HMAC-SHA1(password, serverRandom + "S" + payload)[:4]
        HMAC_CTX *ctx = HMAC_CTX_new();
        if (!ctx)
        {
            return {};
        }

        HMAC_Init_ex(ctx, password.data(), static_cast<int>(password.size()), EVP_sha1(), nullptr);
        HMAC_Update(ctx, reinterpret_cast<const unsigned char *>(server_random.data()), server_random.size());

        constexpr unsigned char tag_s = 'S';
        HMAC_Update(ctx, &tag_s, 1);

        HMAC_Update(ctx, reinterpret_cast<const unsigned char *>(payload.data()), payload.size());

        std::array<std::uint8_t, EVP_MAX_MD_SIZE> md{};
        unsigned int md_len = 0;
        HMAC_Final(ctx, md.data(), &md_len);
        HMAC_CTX_free(ctx);

        std::array<std::uint8_t, 4> result{};
        std::memcpy(result.data(), md.data(), hmac_size);
        return result;
    }

    auto compute_write_key(const std::string_view password,const std::span<const std::byte> server_random)
        -> std::vector<std::uint8_t>
    {
        // SHA256(password + serverRandom)
        SHA256_CTX sha_ctx;
        SHA256_Init(&sha_ctx);
        SHA256_Update(&sha_ctx, password.data(), password.size());
        SHA256_Update(&sha_ctx, server_random.data(),server_random.size());

        std::vector<std::uint8_t> key(SHA256_DIGEST_LENGTH);
        SHA256_Final(key.data(), &sha_ctx);
        return key;
    }
} // namespace psm::stealth::shadowtls
