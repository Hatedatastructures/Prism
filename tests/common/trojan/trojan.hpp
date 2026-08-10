/**
 * @file trojan.hpp
 * @brief Trojan 协议编解码（客户端 + 服务端）
 * @details 纯逻辑（无锁无 I/O）：
 *          请求头 = SHA224(password) 十六进制 56 字节 + CRLF
 *                    + ATYP + ADDR + PORT + CRLF
 *          响应头 = CRLF（服务端确认）
 *          命名空间 psm_test::trojan，参考 mihomo transport/trojan。
 */

#pragma once

#include <common/common.hpp>
#include <common/socks5/socks5.hpp>

#include <openssl/evp.h>

namespace psm_test::trojan
{

    inline constexpr std::size_t hash_hex_len = 56; ///< SHA224 十六进制长度

    /// 计算 SHA224 十六进制摘要（OpenSSL）
    [[nodiscard]] inline auto sha224_hex(const std::string_view password) -> std::string
    {
        std::array<std::uint8_t, 28> digest{};
        unsigned int digest_len = 0;
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        if (!ctx)
            return {};
        EVP_DigestInit_ex(ctx, EVP_sha224(), nullptr);
        EVP_DigestUpdate(ctx, password.data(), password.size());
        EVP_DigestFinal_ex(ctx, digest.data(), &digest_len);
        EVP_MD_CTX_free(ctx);
        std::string hex;
        hex.reserve(hash_hex_len);
        for (const auto b : digest)
        {
            hex.push_back("0123456789abcdef"[b >> 4]);
            hex.push_back("0123456789abcdef"[b & 0x0F]);
        }
        return hex;
    }

    using address = socks5::address;

    /**
     * @class client
     * @brief Trojan 客户端（请求头构造 + 响应解析）
     */
    class client
    {
    public:
        explicit client(const std::string_view password)
            : hash_(sha224_hex(password))
        {
        }

        /**
         * @brief 构造握手头（SHA224 摘要 + CRLF + 地址 + CRLF）
         * @param dst 目标地址
         * @param udp 是否 UDP 关联（UDP 头 = CRLF + 地址 + CRLF，无摘要）
         */
        [[nodiscard]] auto handshake(const address &dst, const bool udp = false) const -> buffer
        {
            byte_writer w;
            if (!udp)
                w.write_bytes(hash_);
            w.write_u8('\r');
            w.write_u8('\n');
            encode_address(w, dst);
            w.write_u8('\r');
            w.write_u8('\n');
            return w.data();
        }

        /// 解析服务端响应头（CRLF）
        [[nodiscard]] static auto parse_response(const view resp) -> bool
        {
            return resp.size() >= 2 && resp[0] == '\r' && resp[1] == '\n';
        }

    private:
        std::string hash_;

        static auto encode_address(byte_writer &out, const address &addr) -> void
        {
            out.write_u8(addr.type);
            if (addr.type == atyp::ipv4)
            {
                out.write_bytes(ipv4_bytes(addr.host));
            }
            else if (addr.type == atyp::ipv6)
            {
                out.write_bytes(ipv6_bytes(addr.host));
            }
            else
            {
                out.write_u8(static_cast<std::uint8_t>(addr.host.size()));
                out.write_bytes(addr.host);
            }
            out.write_u16(addr.port);
        }

        static auto ipv4_bytes(const std::string_view host) -> std::array<std::uint8_t, 4>
        {
            std::array<std::uint8_t, 4> out{};
            std::size_t n = 0, start = 0;
            for (std::size_t i = 0; i <= host.size() && n < 4; ++i)
            {
                if (i == host.size() || host[i] == '.')
                {
                    std::uint32_t v = 0;
                    for (std::size_t j = start; j < i; ++j)
                        v = v * 10 + static_cast<std::uint32_t>(host[j] - '0');
                    out[n++] = static_cast<std::uint8_t>(v);
                    start = i + 1;
                }
            }
            return out;
        }

        static auto ipv6_bytes(const std::string_view host) -> std::array<std::uint8_t, 16>
        {
            std::array<std::uint8_t, 16> out{};
            std::size_t n = 0, start = 0;
            for (std::size_t i = 0; i <= host.size() && n < 16; ++i)
            {
                if (i == host.size() || host[i] == ':')
                {
                    std::uint16_t v = 0;
                    for (std::size_t j = start; j < i; ++j)
                    {
                        const char c = host[j];
                        v = static_cast<std::uint16_t>(
                            v * 16 + (c >= 'a' ? c - 'a' + 10 : c - '0'));
                    }
                    out[n++] = static_cast<std::uint8_t>(v >> 8);
                    out[n++] = static_cast<std::uint8_t>(v & 0xFF);
                    start = i + 1;
                }
            }
            return out;
        }
    };

    /**
     * @class server
     * @brief Trojan 服务端（请求头解析 + 校验）
     */
    class server
    {
    public:
        explicit server(const std::string_view password)
            : hash_(sha224_hex(password))
        {
        }

        /// 解析结果
        struct request
        {
            address dst;
            bool valid{false};
        };

        /// 解析握手头（56 字节摘要 + CRLF + 地址 + CRLF）
        [[nodiscard]] auto parse(const view data) const -> request
        {
            request req;
            if (data.size() < hash_hex_len + 4)
                return req;
            const auto hash = std::string_view(
                reinterpret_cast<const char *>(data.data()), hash_hex_len);
            if (hash != hash_)
                return req;
            std::size_t off = hash_hex_len;
            if (data[off] != '\r' || data[off + 1] != '\n')
                return req;
            off += 2;
            byte_reader r(data.subspan(off));
            if (!socks5::parse_address(r, req.dst))
                return req;
            if (r.remaining() < 2 || data[data.size() - 2] != '\r' || data[data.size() - 1] != '\n')
                return req;
            req.valid = true;
            return req;
        }

        /// 响应头（CRLF）
        [[nodiscard]] static auto response() -> buffer
        {
            return buffer{'\r', '\n'};
        }

    private:
        std::string hash_;
    };

} // namespace psm_test::trojan
