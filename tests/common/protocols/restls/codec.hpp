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

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

#include <blake3.h>
#include <common/core/error.hpp>
#include <common/protocols/restls/types.hpp>

namespace preview::restls
{

    /**
     * @brief 从密码派生 RestlsSecret
     * @param password 认证密码
     * @return 32 字节 RestlsSecret
     * @details BLAKE3 derive_key 模式，context = "restls-traffic-key"。
     */
    [[nodiscard]] inline auto derive_secret(std::string_view password) -> std::array<std::uint8_t, 32>
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
    [[nodiscard]] inline auto compute_server_mask(std::span<const std::uint8_t, 32> secret,
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
    /// 认证 MAC 输入（对齐主库 auth_mac_input）
    struct auth_mac_input
    {
        std::span<const std::uint8_t, 32> secret;            ///< RestlsSecret（32 字节）
        std::span<const std::uint8_t, 32> server_random;     ///< TLS 随机数（32 字节）
        flow_direction direction{flow_direction::to_client}; ///< 数据流方向
        std::uint64_t counter{0};                            ///< 记录计数器
        std::span<const std::uint8_t> client_finished;       ///< 客户端 Finished（首次 c2s）
        std::span<const std::uint8_t> tls_header;            ///< TLS 记录头（5 字节）
        std::span<const std::uint8_t> payload_after_mac;     ///< auth_mac 之后的数据
    };

    /**
     * @brief 计算应用数据认证 MAC
     * @param in 输入参数
     * @return 8 字节认证 MAC
     * @details 输入序列：server_random + dir + counter(8B BE) +
     * [client_finished] + tls_header + payload_after_mac。
     */
    [[nodiscard]] inline auto compute_auth_mac(const auth_mac_input &in)
        -> std::array<std::uint8_t, appdata_maclen>
    {
        blake3_hasher hasher;
        blake3_hasher_init_keyed(&hasher, in.secret.data());
        blake3_hasher_update(&hasher, in.server_random.data(), in.server_random.size());
        std::string_view dir;
        if (in.direction == flow_direction::to_client)
        {
            dir = dir_toclient;
        }
        else
        {
            dir = dir_toserver;
        }
        blake3_hasher_update(&hasher, reinterpret_cast<const std::uint8_t *>(dir.data()), dir.size());
        std::array<std::uint8_t, 8> counter_bytes{};
        for (std::size_t i = 0; i < 8; ++i)
        {
            counter_bytes[i] = static_cast<std::uint8_t>((in.counter >> (56 - 8 * i)) & 0xFF);
        }
        blake3_hasher_update(&hasher, counter_bytes.data(), counter_bytes.size());
        if (!in.client_finished.empty())
        {
            blake3_hasher_update(&hasher, in.client_finished.data(), in.client_finished.size());
        }
        blake3_hasher_update(&hasher, in.tls_header.data(), in.tls_header.size());
        blake3_hasher_update(&hasher, in.payload_after_mac.data(), in.payload_after_mac.size());
        std::array<std::uint8_t, appdata_maclen> mac{};
        blake3_hasher_finalize(&hasher, mac.data(), mac.size());
        return mac;
    }

    /// 掩码输入（对齐主库 mask_input）
    struct mask_input
    {
        std::span<const std::uint8_t, 32> secret;            ///< RestlsSecret（32 字节）
        std::span<const std::uint8_t, 32> server_random;     ///< TLS 随机数（32 字节）
        flow_direction direction{flow_direction::to_client}; ///< 数据流方向
        std::uint64_t counter{0};                            ///< 记录计数器
        std::span<const std::uint8_t> plaintext_sample;      ///< 明文样本（XOR 之前）
    };

    /**
     * @brief 计算数据掩码（XOR 掩码，基于明文）
     * @param in 输入参数
     * @return 4 字节 XOR 掩码
     * @details 输入序列：server_random + dir + counter(8B BE) + sample[:32]。
     */
    [[nodiscard]] inline auto compute_mask(const mask_input &in) -> std::array<std::uint8_t, mask_len>
    {
        blake3_hasher hasher;
        blake3_hasher_init_keyed(&hasher, in.secret.data());
        blake3_hasher_update(&hasher, in.server_random.data(), in.server_random.size());
        std::string_view dir;
        if (in.direction == flow_direction::to_client)
        {
            dir = dir_toclient;
        }
        else
        {
            dir = dir_toserver;
        }
        blake3_hasher_update(&hasher, reinterpret_cast<const std::uint8_t *>(dir.data()), dir.size());
        std::array<std::uint8_t, 8> counter_bytes{};
        for (std::size_t i = 0; i < 8; ++i)
        {
            counter_bytes[i] = static_cast<std::uint8_t>((in.counter >> (56 - 8 * i)) & 0xFF);
        }
        blake3_hasher_update(&hasher, counter_bytes.data(), counter_bytes.size());
        const auto sample_len = std::min(in.plaintext_sample.size(), std::size_t{32});
        if (sample_len > 0)
        {
            blake3_hasher_update(&hasher, in.plaintext_sample.data(), sample_len);
        }
        std::array<std::uint8_t, mask_len> mask{};
        blake3_hasher_finalize(&hasher, mask.data(), mask.size());
        return mask;
    }

} // namespace preview::restls
