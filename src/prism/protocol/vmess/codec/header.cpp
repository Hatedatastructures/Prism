/**
 * @file header.cpp
 * @brief VMess 指令头与响应头编解码实现
 */

#include <prism/protocol/vmess/codec/header.hpp>
#include <prism/protocol/vmess/codec/auth.hpp>
#include <prism/protocol/vmess/codec/kdf.hpp>

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <chrono>
#include <cstring>

namespace psm::protocol::vmess::codec
{

    namespace
    {
        /// 指令头明文长度（不含地址与校验和）
        constexpr std::size_t header_base_len = 38;

        /// 使用显式 key/nonce/AAD 执行 AES-128-GCM 加密
        [[nodiscard]] auto gcm_seal(
            std::span<const std::uint8_t, 16> key, std::span<const std::uint8_t, 12> nonce,
            std::span<const std::uint8_t> aad, std::span<const std::uint8_t> plain,
            std::span<std::uint8_t> out) -> bool
        {
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            if (!ctx)
                return false;
            int len = 0;
            bool ok = EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr)
                && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr) == 1
                && EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data())
                && EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(), static_cast<int>(aad.size()));
            if (ok)
            {
                int total = 0;
                ok = EVP_EncryptUpdate(ctx, out.data(), &len, plain.data(), static_cast<int>(plain.size()))
                    && (total = len, true)
                    && EVP_EncryptFinal_ex(ctx, out.data() + len, &len)
                    && (total += len, true)
                    && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, out.data() + total) == 1;
            }
            EVP_CIPHER_CTX_free(ctx);
            return ok;
        }

        /// 使用显式 key/nonce/AAD 执行 AES-128-GCM 解密
        [[nodiscard]] auto gcm_open(
            std::span<const std::uint8_t, 16> key, std::span<const std::uint8_t, 12> nonce,
            std::span<const std::uint8_t> aad, std::span<const std::uint8_t> cipher,
            std::span<std::uint8_t> out) -> bool
        {
            if (cipher.size() < 16)
                return false;
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            if (!ctx)
                return false;
            int len = 0;
            bool ok = EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr)
                && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr) == 1
                && EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data())
                && EVP_DecryptUpdate(ctx, nullptr, &len, aad.data(), static_cast<int>(aad.size()))
                && EVP_DecryptUpdate(ctx, out.data(), &len, cipher.data(), static_cast<int>(cipher.size() - 16))
                && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16,
                                       const_cast<std::uint8_t *>(cipher.data() + cipher.size() - 16)) == 1
                && EVP_DecryptFinal_ex(ctx, out.data() + len, &len) > 0;
            EVP_CIPHER_CTX_free(ctx);
            return ok;
        }

        /// 逐字节 AES-128-CFB 加密（BoringSSL 无 EVP CFB，手写实现）
        [[nodiscard]] auto cfb128_encrypt(
            const std::span<const std::uint8_t, 16> key, const std::span<const std::uint8_t, 16> iv,
            const std::span<const std::uint8_t> in, const std::span<std::uint8_t> out) -> bool
        {
            AES_KEY aes_key;
            if (AES_set_encrypt_key(key.data(), 128, &aes_key) != 0)
                return false;
            std::array<std::uint8_t, 16> iv_buf{};
            std::array<std::uint8_t, 16> enc{};
            std::memcpy(iv_buf.data(), iv.data(), 16);
            int num = 0;
            for (std::size_t i = 0; i < in.size(); ++i)
            {
                if (num == 0)
                    AES_encrypt(iv_buf.data(), enc.data(), &aes_key);
                out[i] = static_cast<std::uint8_t>(in[i] ^ enc[num]);
                iv_buf[num] = out[i];
                num = (num + 1) & 15;
            }
            return true;
        }

        /// 序列化地址段（mihomo 顺序：port 2B + addrType 1B + addr），返回写入字节数
        [[nodiscard]] auto write_address(
            const psm::protocol::common::address &addr, const std::uint16_t port,
            const std::span<std::uint8_t> out) -> std::size_t
        {
            const auto visitor = [&out, port]<typename A>(const A &arg) -> std::size_t
            {
                using type = std::decay_t<A>;
                if constexpr (std::is_same_v<type, psm::protocol::common::ipv4_address>)
                {
                    out[0] = static_cast<std::uint8_t>(port >> 8);
                    out[1] = static_cast<std::uint8_t>(port & 0xFF);
                    out[2] = static_cast<std::uint8_t>(address_type::ipv4);
                    std::memcpy(out.data() + 3, arg.bytes.data(), 4);
                    return 7;
                }
                else if constexpr (std::is_same_v<type, psm::protocol::common::ipv6_address>)
                {
                    out[0] = static_cast<std::uint8_t>(port >> 8);
                    out[1] = static_cast<std::uint8_t>(port & 0xFF);
                    out[2] = static_cast<std::uint8_t>(address_type::ipv6);
                    std::memcpy(out.data() + 3, arg.bytes.data(), 16);
                    return 19;
                }
                else
                {
                    out[0] = static_cast<std::uint8_t>(port >> 8);
                    out[1] = static_cast<std::uint8_t>(port & 0xFF);
                    out[2] = static_cast<std::uint8_t>(address_type::domain);
                    out[3] = arg.length;
                    std::memcpy(out.data() + 4, arg.value.data(), arg.length);
                    return 4 + arg.length;
                }
            };
            return std::visit(visitor, addr);
        }

        /// 解析地址段（mihomo 顺序：port 2B + addrType 1B + addr），返回消耗字节数
        [[nodiscard]] auto read_address(
            const std::span<const std::uint8_t> in,
            psm::protocol::common::address &addr, std::uint16_t &port) -> std::size_t
        {
            if (in.size() < 3)
                return 0;
            port = static_cast<std::uint16_t>((in[0] << 8) | in[1]);
            switch (in[2])
            {
            case static_cast<std::uint8_t>(address_type::ipv4):
            {
                if (in.size() < 7)
                    return 0;
                psm::protocol::common::ipv4_address ip{};
                std::memcpy(ip.bytes.data(), in.data() + 3, 4);
                addr = ip;
                return 7;
            }
            case static_cast<std::uint8_t>(address_type::ipv6):
            {
                if (in.size() < 19)
                    return 0;
                psm::protocol::common::ipv6_address ip{};
                std::memcpy(ip.bytes.data(), in.data() + 3, 16);
                addr = ip;
                return 19;
            }
            case static_cast<std::uint8_t>(address_type::domain):
            {
                if (in.size() < 4)
                    return 0;
                const auto len = in[3];
                if (len == 0 || in.size() < 4U + len)
                    return 0;
                psm::protocol::common::domain_address dom{};
                dom.length = len;
                std::memcpy(dom.value.data(), in.data() + 4, len);
                addr = dom;
                return 4 + len;
            }
            default:
                return 0;
            }
        }
    } // namespace

    auto seal_request(
        const std::span<const std::uint8_t, 16> cmd_key, const request_header &header,
        const std::span<std::uint8_t> out) -> fault::code
    {
        // 组装明文指令头（38 + H + padding + 4）
        std::array<std::uint8_t, 256> plain{};
        plain[0] = version;
        std::memcpy(plain.data() + 1, header.request_nonce.data(), 16);
        std::memcpy(plain.data() + 17, header.request_key.data(), 16);
        plain[33] = header.response_header;
        plain[34] = header.option;
        plain[35] = static_cast<std::uint8_t>(header.security & 0x0F); // padding=0
        plain[36] = 0;
        plain[37] = header.command;
        std::size_t used = header_base_len;
        if (header.command != static_cast<std::uint8_t>(command::mux))
        {
            const auto n = write_address(header.destination, header.port,
                                         std::span<std::uint8_t>(plain.data() + used, plain.size() - used));
            if (n == 0)
                return fault::code::unsupported_address;
            used += n;
        }
        const auto checksum = fnv1a_32(std::span<const std::uint8_t>(plain.data(), used));
        for (std::size_t i = 0; i < 4; ++i)
            plain[used + i] = static_cast<std::uint8_t>(checksum >> (8 * (3 - i)));
        used += 4;

        // 生成连接随机数
        std::array<std::uint8_t, 8> conn_nonce{};
        if (RAND_bytes(conn_nonce.data(), conn_nonce.size()) != 1)
            return fault::code::crypto_error;

        // 认证头
        const auto ts = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        auto auth_ec = seal_auth_header(cmd_key, ts,
            std::span<std::uint8_t, 16>(out.data(), 16));
        if (fault::failed(auth_ec))
            return auth_ec;

        // 长度块：GCM(key=KDF(cmdKey,Key_Length,authID,connNonce), nonce=..., AAD=authID, plain=used)
        std::span<const std::uint8_t, 16> auth_id(out.data(), 16);
        const auto len_key = kdf(cmd_key, kdf_header_len_key, auth_id, conn_nonce);
        const auto len_nonce = kdf(cmd_key, kdf_header_len_nonce, auth_id, conn_nonce);
        std::array<std::uint8_t, 2> len_plain{ static_cast<std::uint8_t>(used >> 8), static_cast<std::uint8_t>(used & 0xFF) };
        std::span<std::uint8_t> len_out(out.data() + 16, 18);
        if (!gcm_seal(std::span<const std::uint8_t, 16>(len_key.data(), 16),
                      std::span<const std::uint8_t, 12>(len_nonce.data(), 12),
                      auth_id, len_plain, len_out))
            return fault::code::crypto_error;

        // 连接随机数 + 指令头载荷
        std::memcpy(out.data() + 34, conn_nonce.data(), 8);
        const auto head_key = kdf(cmd_key, kdf_header_key, auth_id, conn_nonce);
        const auto head_nonce = kdf(cmd_key, kdf_header_nonce, auth_id, conn_nonce);
        std::span<std::uint8_t> head_out(out.data() + 42, used + 16);
        if (!gcm_seal(std::span<const std::uint8_t, 16>(head_key.data(), 16),
                      std::span<const std::uint8_t, 12>(head_nonce.data(), 12),
                      auth_id, std::span<const std::uint8_t>(plain.data(), used), head_out))
            return fault::code::crypto_error;
        return fault::code::success;
    }

    auto open_len_block(
        const std::span<const std::uint8_t, 16> cmd_key,
        const std::span<const std::uint8_t, 16> auth_id,
        const std::span<const std::uint8_t, 18> len_block,
        const std::span<const std::uint8_t, 8> conn_nonce, std::size_t &header_len) -> fault::code
    {
        const auto len_key = kdf(cmd_key, kdf_header_len_key, auth_id, conn_nonce);
        const auto len_nonce = kdf(cmd_key, kdf_header_len_nonce, auth_id, conn_nonce);
        std::array<std::uint8_t, 2> len_plain{};
        if (!gcm_open(std::span<const std::uint8_t, 16>(len_key.data(), 16),
                      std::span<const std::uint8_t, 12>(len_nonce.data(), 12),
                      auth_id, std::span<const std::uint8_t>(len_block.data(), 18), len_plain))
            return fault::code::crypto_error;
        header_len = static_cast<std::size_t>((len_plain[0] << 8) | len_plain[1]);
        if (header_len < header_base_len)
            return fault::code::bad_message;
        return fault::code::success;
    }

    auto open_payload(
        const std::span<const std::uint8_t, 16> cmd_key,
        const std::span<const std::uint8_t, 16> auth_id,
        const std::span<const std::uint8_t, 8> conn_nonce,
        const std::span<const std::uint8_t> payload_block, request_header &header) -> fault::code
    {
        if (payload_block.size() < 16)
            return fault::code::bad_message;
        const auto head_key = kdf(cmd_key, kdf_header_key, auth_id, conn_nonce);
        const auto head_nonce = kdf(cmd_key, kdf_header_nonce, auth_id, conn_nonce);
        std::array<std::uint8_t, 256> plain{};
        const std::size_t header_len = payload_block.size() - 16;
        if (!gcm_open(std::span<const std::uint8_t, 16>(head_key.data(), 16),
                      std::span<const std::uint8_t, 12>(head_nonce.data(), 12),
                      auth_id, payload_block,
                      std::span<std::uint8_t>(plain.data(), header_len)))
            return fault::code::crypto_error;

        // 解析明文（跳过后 4 字节校验和，服务端不验证）
        header.version = plain[0];
        if (header.version != version)
            return fault::code::bad_message;
        std::memcpy(header.request_nonce.data(), plain.data() + 1, 16);
        std::memcpy(header.request_key.data(), plain.data() + 17, 16);
        header.response_header = plain[33];
        header.option = plain[34];
        header.security = plain[35] & 0x0F;
        header.command = plain[37];

        if (header.command != static_cast<std::uint8_t>(command::mux))
        {
            const auto n = read_address(
                std::span<const std::uint8_t>(plain.data() + header_base_len,
                                              header_len - header_base_len),
                header.destination, header.port);
            if (n == 0)
                return fault::code::bad_message;
        }
        return fault::code::success;
    }

    auto open_request(
        const std::span<const std::uint8_t, 16> cmd_key,
        const std::span<const std::uint8_t> first_packet,
        std::array<std::uint8_t, 8> &conn_nonce, request_header &header) -> fault::code
    {
        if (first_packet.size() < aead_min_header_len)
            return fault::code::bad_message;

        std::span<const std::uint8_t, 16> auth_id(first_packet.data(), 16);
        std::size_t header_len = 0;
        const auto len_ec = open_len_block(
            cmd_key, auth_id,
            std::span<const std::uint8_t, 18>(first_packet.data() + 16, 18),
            std::span<const std::uint8_t, 8>(first_packet.data() + 34, 8),
            header_len);
        if (fault::failed(len_ec))
            return len_ec;
        if (first_packet.size() < 42U + header_len + 16)
            return fault::code::bad_message;
        return open_payload(
            cmd_key, auth_id, std::span<const std::uint8_t, 8>(first_packet.data() + 34, 8),
            first_packet.subspan(42, header_len + 16), header);
    }

    auto build_response(
        const std::span<const std::uint8_t, 16> request_key,
        const std::span<const std::uint8_t, 16> request_nonce,
        const std::uint8_t response_header, const std::uint8_t option, const bool legacy,
        const std::span<std::uint8_t> out) -> fault::code
    {
        if (out.size() < 38)
            return fault::code::bad_message;

        std::array<std::uint8_t, 4> resp_plain{ response_header, option, 0, 0 };

        if (legacy)
        {
            // legacy：AES-128-CFB(key=MD5(requestKey), IV=MD5(requestNonce))
            std::array<std::uint8_t, 16> key{};
            std::array<std::uint8_t, 16> iv{};
            unsigned int len = 0;
            EVP_Digest(request_key.data(), 16, key.data(), &len, EVP_md5(), nullptr);
            EVP_Digest(request_nonce.data(), 16, iv.data(), &len, EVP_md5(), nullptr);
            if (!cfb128_encrypt(key, iv, resp_plain,
                                out.first(4)))
                return fault::code::crypto_error;
            return fault::code::success;
        }

        // AEAD：双段 GCM
        std::array<std::uint8_t, 16> resp_key{};
        std::array<std::uint8_t, 16> resp_nonce{};
        std::array<std::uint8_t, 32> key_hash{};
        std::array<std::uint8_t, 32> nonce_hash{};
        SHA256(request_key.data(), 16, key_hash.data());
        SHA256(request_nonce.data(), 16, nonce_hash.data());
        std::memcpy(resp_key.data(), key_hash.data(), 16);
        std::memcpy(resp_nonce.data(), nonce_hash.data(), 16);

        const auto len_key = kdf(std::span<const std::uint8_t>(resp_key.data(), 16), kdf_resp_len_key);
        const auto len_nonce = kdf(std::span<const std::uint8_t>(resp_nonce.data(), 16), kdf_resp_len_iv);
        std::array<std::uint8_t, 2> len_plain{ 0, 4 };
        if (!gcm_seal(std::span<const std::uint8_t, 16>(len_key.data(), 16),
                      std::span<const std::uint8_t, 12>(len_nonce.data(), 12),
                      {}, len_plain, out.first(18)))
            return fault::code::crypto_error;

        const auto head_key = kdf(std::span<const std::uint8_t>(resp_key.data(), 16), kdf_resp_key);
        const auto head_nonce = kdf(std::span<const std::uint8_t>(resp_nonce.data(), 16), kdf_resp_iv);
        if (!gcm_seal(std::span<const std::uint8_t, 16>(head_key.data(), 16),
                      std::span<const std::uint8_t, 12>(head_nonce.data(), 12),
                      {}, resp_plain, out.subspan(18, 20)))
            return fault::code::crypto_error;
        return fault::code::success;
    }

} // namespace psm::protocol::vmess::codec
