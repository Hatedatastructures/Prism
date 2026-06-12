#include <prism/stealth/facade/shadowtls/util/auth.hpp>

#include <prism/stealth/facade/shadowtls/util/constants.hpp>
#include <prism/trace.hpp>

#include <openssl/crypto.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include <cstdint>
#include <cstring>
#include <vector>

using namespace psm::trace;

namespace psm::stealth::shadowtls
{

    auto compute_hmac(const std::string_view key, const std::byte *data, const std::size_t data_len)
        -> std::array<std::uint8_t, 4>
    {
        std::array<std::uint8_t, EVP_MAX_MD_SIZE> md{};
        std::uint32_t len = 0;

        // 安全：SSL HMAC API 要求 uint8_t*，byte 数据仅读取用于计算
        HMAC(EVP_sha1(),
             key.data(), static_cast<int>(key.size()),
             reinterpret_cast<const std::uint8_t *>(data), data_len,
             md.data(), &len);

        std::array<std::uint8_t, 4> result{};
        std::memcpy(result.data(), md.data(), hmac_size);
        return result;
    }


    auto verify_client_hello(std::span<const std::byte> client_hello, const std::string_view password)
        -> bool
    {
        // 最小长度检查: TLS Header(5) + Handshake Header(4) + Version(2) +
        //   Random(32) + SessionID Length(1) + SessionID(32) = 76
        constexpr std::size_t min_len = tls_hdrsize + 1 + 3 + 2 + tls_rndsize + 1 + tls_session_id_sz;
        if (client_hello.size() < min_len)
        {
            return false;
        }

        // 安全：将 byte 缓冲区转为 uint8_t 解析 ClientHello 字段，二进制兼容
        const auto *raw = reinterpret_cast<const std::uint8_t *>(client_hello.data());

        if (raw[0] != content_handshake)
        {
            return false;
        }

        if (raw[5] != hs_type_clienthello)
        {
            return false;
        }

        if (raw[session_id_len_idx] != tls_session_id_sz)
        {
            return false;
        }

        const std::size_t data_size = client_hello.size() - tls_hdrsize;
        memory::vector<std::uint8_t> hmac_data(data_size, memory::current_resource());
        for (std::size_t i = 0; i < data_size; ++i)
        {
            hmac_data[i] = static_cast<std::uint8_t>(client_hello[tls_hdrsize + i]);
        }

        // 将 SessionID 中的 HMAC 部分（最后 4 字节）填 0
        constexpr std::size_t hmac_offset_in_data = session_id_len_idx + 1 + tls_session_id_sz - hmac_size - tls_hdrsize;
        std::memset(hmac_data.data() + hmac_offset_in_data, 0, hmac_size);

        // 安全：将 uint8_t HMAC 数据数组转为 byte 指针传给 compute_hmac，二进制兼容
        const auto expected = compute_hmac(password, reinterpret_cast<const std::byte *>(hmac_data.data()), hmac_data.size());

        constexpr std::size_t client_hmac_offset = session_id_len_idx + 1 + tls_session_id_sz - hmac_size;
        std::array<std::uint8_t, 4> client_tag{};
        std::memcpy(client_tag.data(), raw + client_hmac_offset, hmac_size);

        {
            trace::debug("verify_client_hello: data_size={}, hmac_offset={}, ch_size={}",
                data_size, hmac_offset_in_data, client_hello.size());
        }

        return CRYPTO_memcmp(expected.data(), client_tag.data(), hmac_size) == 0;
    }


    auto verify_frame_hmac(const verify_input &in) -> bool
    {
        const auto &password = in.password;
        const auto &server_random = in.server_random;
        const auto &payload = in.payload;
        const auto &client_hmac = in.client_hmac;
        // HMAC-SHA1(password, serverRandom + "C" + payload)[:4]
        // 参照 sing-shadowtls hmacVerify（含 "C" 标签）
        HMAC_CTX *ctx = HMAC_CTX_new();
        if (!ctx)
        {
            return false;
        }

        HMAC_Init_ex(ctx, password.data(), static_cast<int>(password.size()), EVP_sha1(), nullptr);
        // 安全：SSL HMAC API 要求 uint8_t*，byte span 数据仅读取
        HMAC_Update(ctx, reinterpret_cast<const std::uint8_t *>(server_random.data()), server_random.size());

        constexpr std::uint8_t tag_c = 'C';
        HMAC_Update(ctx, &tag_c, 1);

        // 安全：SSL HMAC API 要求 uint8_t*，byte span 数据仅读取
        HMAC_Update(ctx, reinterpret_cast<const std::uint8_t *>(payload.data()), payload.size());

        std::array<std::uint8_t, EVP_MAX_MD_SIZE> md{};
        std::uint32_t md_len = 0;
        HMAC_Final(ctx, md.data(), &md_len);
        HMAC_CTX_free(ctx);

        return CRYPTO_memcmp(md.data(), client_hmac.data(), hmac_size) == 0;
    }


    auto compute_write_hmac(const std::string_view password, const std::span<const std::byte> server_random, const std::span<const std::byte> payload)
        -> std::array<std::uint8_t, 4>
    {
        // HMAC-SHA1(password, serverRandom + "S" + payload)[:4]
        // 参照 sing-shadowtls hmacAdd（含 "S" 标签，用于 post-handshake 写入）
        HMAC_CTX *ctx = HMAC_CTX_new();
        if (!ctx)
        {
            return {};
        }

        HMAC_Init_ex(ctx, password.data(), static_cast<int>(password.size()), EVP_sha1(), nullptr);
        // 安全：SSL HMAC API 要求 uint8_t*，byte span 数据仅读取
        HMAC_Update(ctx, reinterpret_cast<const std::uint8_t *>(server_random.data()), server_random.size());

        constexpr std::uint8_t tag_s = 'S';
        HMAC_Update(ctx, &tag_s, 1);

        // 安全：SSL HMAC API 要求 uint8_t*，byte span 数据仅读取
        HMAC_Update(ctx, reinterpret_cast<const std::uint8_t *>(payload.data()), payload.size());

        std::array<std::uint8_t, EVP_MAX_MD_SIZE> md{};
        std::uint32_t md_len = 0;
        HMAC_Final(ctx, md.data(), &md_len);
        HMAC_CTX_free(ctx);

        std::array<std::uint8_t, 4> result{};
        std::memcpy(result.data(), md.data(), hmac_size);
        return result;
    }


    auto compute_write_key(const std::string_view password,const std::span<const std::byte> server_random)
        -> memory::vector<std::uint8_t>
    {
        // SHA256(password + serverRandom)
        SHA256_CTX sha_ctx;
        SHA256_Init(&sha_ctx);
        SHA256_Update(&sha_ctx, password.data(), password.size());
        SHA256_Update(&sha_ctx, server_random.data(),server_random.size());

        memory::vector<std::uint8_t> key(SHA256_DIGEST_LENGTH, memory::current_resource());
        SHA256_Final(key.data(), &sha_ctx);
        return key;
    }
} // namespace psm::stealth::shadowtls
