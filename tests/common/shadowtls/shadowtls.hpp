/**
 * @file shadowtls.hpp
 * @brief ShadowTLS v3 认证编解码（客户端 + 服务端）
 * @details 纯逻辑（无锁）：
 *          1. 握手期间所有收发字节喂 HMAC-SHA1(password)
 *          2. 客户端首个数据块 = [0x17 0x03 0x03][len 2B][hash 20B][payload]
 *          3. 服务端对相同握手流计算 HMAC-SHA1 校验 hash
 *          命名空间 psm_test::shadowtls，参考 mihomo transport/shadowtls。
 */

#pragma once

#include <common/common.hpp>

#include <openssl/evp.h>
#include <openssl/hmac.h>

namespace psm_test::shadowtls
{

    inline constexpr std::size_t hash_len = 20; ///< SHA1 摘要长度
    inline constexpr std::uint8_t record_type = 0x17; ///< TLS Application Data
    inline constexpr std::uint8_t record_major = 0x03;
    inline constexpr std::uint8_t record_minor = 0x03;

    /// 计算认证哈希：HMAC-SHA1(password, 握手字节流)
    [[nodiscard]] inline auto compute_hash(const std::string_view password,
                                           const view handshake) -> std::array<std::uint8_t, hash_len>
    {
        std::array<std::uint8_t, hash_len> out{};
        unsigned int len = 0;
        HMAC(EVP_sha1(), password.data(), static_cast<int>(password.size()),
             handshake.data(), handshake.size(), out.data(), &len);
        return out;
    }

    /// 构造首个数据包：[17 03 03][len 2B][hash 20B][payload]
    [[nodiscard]] inline auto build_first_packet(const std::string_view password,
                                                 const view handshake, const view payload) -> buffer
    {
        const auto hash = compute_hash(password, handshake);
        byte_writer w;
        w.write_u8(record_type);
        w.write_u8(record_major);
        w.write_u8(record_minor);
        w.write_u16(static_cast<std::uint16_t>(hash.size() + payload.size()));
        w.write_bytes(hash);
        w.write_bytes(payload);
        return w.data();
    }

    /// 解析首个数据包（剥离 TLS 记录头 + hash），返回 hash 与载荷偏移
    struct first_packet
    {
        std::array<std::uint8_t, hash_len> hash{};
        std::size_t payload_offset{0};
        bool valid{false};
    };

    [[nodiscard]] inline auto parse_first_packet(const view data) -> first_packet
    {
        first_packet pkt;
        if (data.size() < 3 + 2 + hash_len)
            return pkt;
        if (data[0] != record_type || data[1] != record_major || data[2] != record_minor)
            return pkt;
        const auto total = static_cast<std::size_t>((data[3] << 8) | data[4]);
        if (total != data.size() - 5)
            return pkt;
        std::copy(data.begin() + 5, data.begin() + 5 + hash_len, pkt.hash.begin());
        pkt.payload_offset = 5 + hash_len;
        pkt.valid = true;
        return pkt;
    }

    /// 校验认证哈希（服务端）：比对计算值与收到的 hash
    [[nodiscard]] inline auto verify(const std::string_view password, const view handshake,
                                     const view received_hash) -> bool
    {
        if (received_hash.size() != hash_len)
            return false;
        const auto calc = compute_hash(password, handshake);
        return std::memcmp(calc.data(), received_hash.data(), hash_len) == 0;
    }

} // namespace psm_test::shadowtls
