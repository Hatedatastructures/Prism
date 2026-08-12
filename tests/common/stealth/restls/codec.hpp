/**
 * @file codec.hpp
 * @brief Restls 认证编解码（纯函数，BLAKE3）
 * @details 对齐 C++ include/prism/handshake/restls/crypto.hpp 与
 * restls-client-go：
 *          - derive_secret：BLAKE3 derive_key(secret_ctx, password) → 32B
 *          - compute_server_mask：BLAKE3 keyed(secret, server_random) → 16B
 *          - compute_auth_mac：BLAKE3 keyed(secret, server_random + dir +
 *            counter + [client_finished] + tls_header + payload) → 8B
 *          - compute_mask：BLAKE3 keyed(secret, server_random + dir +
 *            counter + plaintext_sample[:32]) → 4B
 * @note 参考 restls-client-go 协议规范。
 */

#pragma once

#include <common/core/error.hpp>
#include <common/stealth/restls/types.hpp>

#include <blake3.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace psmtest::restls
{

    /**
     * @brief 从密码派生 RestlsSecret
     * @param password 认证密码
     * @return 32 字节 RestlsSecret
     * @details BLAKE3 derive_key 模式，context = "restls-traffic-key"。
     */
    [[nodiscard]] inline auto derive_secret(std::string_view password)
        -> std::array<std::uint8_t, 32>
    {
        blake3_hasher hasher;
        blake3_hasher_init_derive_key(&hasher, secret_ctx.data());
        blake3_hasher_update(&hasher, reinterpret_cast<const std::uint8_t *>(password.data()),
                             password.size());
        std::array<std::uint8_t, 32> secret{};
        blake3_hasher_finalize(&hasher, secret.data(), secret.size());
        return secret;
    }

    /**
     * @brief 计算服务端认证掩码
     * @param secret RestlsSecret（32 字节）
     * @param server_random TLS ServerHello 随机数（32 字节）
     * @return 16 字节认证掩码
     * @details BLAKE3 keyed(secret, server_random)，输出截断 16 字节。
     */
    [[nodiscard]] inline auto compute_server_mask(
        std::span<const std::uint8_t, 32> secret,
        std::span<const std::uint8_t, 32> server_random)
        -> std::array<std::uint8_t, hs_maclen>
    {
        blake3_hasher hasher;
        blake3_hasher_init_keyed(&hasher, secret.data());
        blake3_hasher_update(&hasher, server_random.data(), server_random.size());
        std::array<std::uint8_t, hs_maclen> mask{};
        blake3_hasher_finalize(&hasher, mask.data(), mask.size());
        return mask;
    }

    /**
     * @brief 计算应用数据认证 MAC
     * @param secret RestlsSecret（32 字节）
     * @param server_random TLS 随机数（32 字节）
     * @param direction 数据流方向
     * @param counter 记录计数器
     * @param client_finished 客户端 Finished 消息（仅首次 c2s，否则为空）
     * @param tls_header TLS 记录头（5 字节）
     * @param payload_after_mac auth_mac 之后的所有数据
     * @return 8 字节认证 MAC
     * @details 输入序列：server_random + dir + counter(8B BE) +
     * [client_finished] + tls_header + payload_after_mac。
     */
    [[nodiscard]] inline auto compute_auth_mac(
        std::span<const std::uint8_t, 32> secret,
        std::span<const std::uint8_t, 32> server_random,
        flow_direction direction,
        std::uint64_t counter,
        std::span<const std::uint8_t> client_finished,
        std::span<const std::uint8_t> tls_header,
        std::span<const std::uint8_t> payload_after_mac)
        -> std::array<std::uint8_t, appdata_maclen>
    {
        blake3_hasher hasher;
        blake3_hasher_init_keyed(&hasher, secret.data());
        blake3_hasher_update(&hasher, server_random.data(), server_random.size());
        const auto dir = direction == flow_direction::to_client ? dir_toclient : dir_toserver;
        blake3_hasher_update(&hasher, reinterpret_cast<const std::uint8_t *>(dir.data()),
                             dir.size());
        std::array<std::uint8_t, 8> counter_bytes{};
        for (std::size_t i = 0; i < 8; ++i)
            counter_bytes[i] = static_cast<std::uint8_t>((counter >> (56 - 8 * i)) & 0xFF);
        blake3_hasher_update(&hasher, counter_bytes.data(), counter_bytes.size());
        if (!client_finished.empty())
            blake3_hasher_update(&hasher, client_finished.data(), client_finished.size());
        blake3_hasher_update(&hasher, tls_header.data(), tls_header.size());
        blake3_hasher_update(&hasher, payload_after_mac.data(), payload_after_mac.size());
        std::array<std::uint8_t, appdata_maclen> mac{};
        blake3_hasher_finalize(&hasher, mac.data(), mac.size());
        return mac;
    }

    /**
     * @brief 计算数据掩码（XOR 掩码，基于明文）
     * @param secret RestlsSecret（32 字节）
     * @param server_random TLS 随机数（32 字节）
     * @param direction 数据流方向
     * @param counter 记录计数器
     * @param plaintext_sample 明文数据样本（XOR 之前，最多 32 字节）
     * @return 4 字节 XOR 掩码
     * @details 输入序列：server_random + dir + counter(8B BE) + sample[:32]。
     */
    [[nodiscard]] inline auto compute_mask(
        std::span<const std::uint8_t, 32> secret,
        std::span<const std::uint8_t, 32> server_random,
        flow_direction direction,
        std::uint64_t counter,
        std::span<const std::uint8_t> plaintext_sample)
        -> std::array<std::uint8_t, mask_len>
    {
        blake3_hasher hasher;
        blake3_hasher_init_keyed(&hasher, secret.data());
        blake3_hasher_update(&hasher, server_random.data(), server_random.size());
        const auto dir = direction == flow_direction::to_client ? dir_toclient : dir_toserver;
        blake3_hasher_update(&hasher, reinterpret_cast<const std::uint8_t *>(dir.data()),
                             dir.size());
        std::array<std::uint8_t, 8> counter_bytes{};
        for (std::size_t i = 0; i < 8; ++i)
            counter_bytes[i] = static_cast<std::uint8_t>((counter >> (56 - 8 * i)) & 0xFF);
        blake3_hasher_update(&hasher, counter_bytes.data(), counter_bytes.size());
        const auto sample_len = std::min(plaintext_sample.size(), std::size_t{32});
        if (sample_len > 0)
            blake3_hasher_update(&hasher, plaintext_sample.data(), sample_len);
        std::array<std::uint8_t, mask_len> mask{};
        blake3_hasher_finalize(&hasher, mask.data(), mask.size());
        return mask;
    }

} // namespace psmtest::restls
