/**
 * @file crypto.hpp
 * @brief Restls 密码学原语
 * @details 基于 BLAKE3 keyed mode 构建 Restls 协议所需的认证和掩码原语。
 * Restls 不使用传统 HMAC，而是使用 BLAKE3 的 keyed hash 模式
 * （blake3_hasher_init_keyed）作为 MAC 构造。
 *
 * 密钥派生链：
 *   RestlsSecret = BLAKE3-DeriveKey("restls-traffic-key", password)
 *   所有后续操作（auth_mac, mask, server_mask）均以 RestlsSecret 为密钥。
 *
 * 应用数据帧布局（TLS 1.3）：
 *   [TLS Header 5B][auth_mac 8B][masked_len 2B][masked_cmd 2B][data][padding]
 *   appdata_offset = 12 (auth_mac + mask)
 *   auth_hdrlen = 12 (appdata_maclen + mask_len)
 *
 * 命令类型：0x0000=Data, 0x0001=Close, 0x0002="restls-random-response"
 */
#pragma once

#include <prism/crypto/blake3.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <string_view>


namespace psm::stealth::restls
{


    constexpr std::size_t tls_hdrsize = 5;
    constexpr std::size_t tls_rndsize = 32;
    constexpr std::size_t hs_maclen = 16;
    constexpr std::size_t appdata_maclen = 8;
    constexpr std::size_t mask_len = 4;
    constexpr std::size_t auth_hdrlen = appdata_maclen + mask_len; // 12
    constexpr std::size_t appdata_offset = auth_hdrlen;            // 12
    constexpr std::size_t appdata_lenoff = appdata_maclen;         // 8
    constexpr std::size_t max_plaintext = 16384;

    // 方向字符串（固定 16 字节）
    constexpr std::string_view dir_toclient = "server-to-client";
    constexpr std::string_view dir_toserver = "client-to-server";

    /**
     * @brief 数据流方向
     * @details 用于标识当前操作的数据流方向。
     */
    enum class flow_direction : std::uint8_t
    {
        to_server,  ///< 客户端到服务端方向
        to_client   ///< 服务端到客户端方向
    };

    // Restls 密钥派生上下文
    constexpr std::string_view secret_ctx = "restls-traffic-key";

    // Restls 命令
    constexpr std::uint16_t cmd_data = 0x0000;
    constexpr std::uint16_t cmd_close = 0x0001;
    constexpr std::uint16_t cmd_randresp = 0x0002;

    // magic 字符串用于随机响应帧
    constexpr std::string_view randresp_magic = "restls-random-response";


    /**
     * @brief 从密码派生 RestlsSecret
     * @details 使用 BLAKE3 derive_key 模式，以 "restls-traffic-key" 为上下文，
     * 从密码派生 32 字节的 RestlsSecret。所有后续认证操作均以此为密钥。
     * @param password 认证密码
     * @return 32 字节 RestlsSecret
     */
    [[nodiscard]] inline auto derive_secret(std::string_view password)
        -> std::array<std::uint8_t, 32>
    {
        const auto material = std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t *>(password.data()), password.size());
        std::array<std::uint8_t, 32> secret;
        psm::crypto::derive_key(secret_ctx, material, secret);
        return secret;
    }


    /**
     * @brief 计算服务端认证掩码
     * @details 使用 BLAKE3 keyed mode 计算握手阶段的 server_mask，
     * 用于 XOR 后端返回的第一个加密 TLS 记录，实现服务端身份验证。
     * 输出截断为 hs_maclen (16) 字节。
     * @param secret RestlsSecret（32 字节）
     * @param server_random TLS ServerHello 中的 server_random（32 字节）
     * @return 16 字节认证掩码
     */
    [[nodiscard]] inline auto compute_server_mask(
        std::span<const std::uint8_t, 32> secret,
        std::span<const std::uint8_t, 32> server_random)
        -> std::array<std::uint8_t, hs_maclen>
    {
        auto hasher = psm::crypto::keyed_hasher(secret);
        blake3_hasher_update(&hasher, server_random.data(), server_random.size());
        std::array<std::uint8_t, hs_maclen> mask;
        blake3_hasher_finalize(&hasher, mask.data(), mask.size());
        return mask;
    }


    /**
     * @brief compute_auth_mac 的输入参数集
     * @details 将 compute_auth_mac 的 7 个参数聚合为单一结构体，
     * 避免函数签名字过长，提升可读性和可维护性。
     */
    struct auth_mac_input
    {
        std::span<const std::uint8_t, 32> secret;          ///< RestlsSecret（32 字节）
        std::span<const std::uint8_t, 32> server_random;   ///< TLS server_random（32 字节）
        flow_direction direction;                           ///< 数据流方向
        std::uint64_t counter;                              ///< 记录计数器
        std::span<const std::uint8_t> client_finished;     ///< 客户端 Finished 消息（仅首次 c2s，否则为空）
        std::span<const std::uint8_t> tls_header;          ///< TLS 记录头（5 字节）
        std::span<const std::uint8_t> payload_after_mac;   ///< auth_mac 之后的所有数据
    };

    /**
     * @brief compute_mask 的输入参数集
     * @details 将 compute_mask 的 5 个参数聚合为单一结构体，
     * 避免函数签名字过长，提升可读性和可维护性。
     */
    struct mask_input
    {
        std::span<const std::uint8_t, 32> secret;          ///< RestlsSecret（32 字节）
        std::span<const std::uint8_t, 32> server_random;   ///< TLS server_random（32 字节）
        flow_direction direction;                           ///< 数据流方向
        std::uint64_t counter;                              ///< 记录计数器
        std::span<const std::uint8_t> plaintext_sample;    ///< 明文数据样本（从 appdata_offset 开始，最多 32 字节）
    };


    /**
     * @brief 计算应用数据认证 MAC
     * @details 使用 BLAKE3 keyed mode 计算每条记录的认证标签。
     * 输出截断为 appdata_maclen (8) 字节。
     *
     * 输入序列（严格按序）：
     * 1. input.server_random（32 字节）
     * 2. direction_string（16 字节）
     * 3. input.counter（8 字节 big-endian）
     * 4. input.client_finished（仅首次 c2s 写入，完整加密 TLS record 含 header）
     * 5. input.tls_header（5 字节 TLS 1.3 记录头）
     * 6. input.payload_after_mac（masked_len + masked_cmd + data + padding）
     *
     * @param input 认证 MAC 输入参数集
     * @return 8 字节认证 MAC
     */
    [[nodiscard]] inline auto compute_auth_mac(const auth_mac_input &input)
        -> std::array<std::uint8_t, appdata_maclen>
    {
        auto hasher = psm::crypto::keyed_hasher(input.secret);

        // 1. server_random
        blake3_hasher_update(&hasher, input.server_random.data(), input.server_random.size());

        // 2. direction string
        std::string_view dir;
        if (input.direction == flow_direction::to_client)
        {
            dir = dir_toclient;
        }
        else
        {
            dir = dir_toserver;
        }
        blake3_hasher_update(&hasher, reinterpret_cast<const std::uint8_t *>(dir.data()), dir.size());

        // 3. counter (big-endian 64-bit)
        std::array<std::uint8_t, 8> counter_bytes{};
        for (std::size_t i = 0; i < 8; ++i)
        {
            counter_bytes[i] = static_cast<std::uint8_t>((input.counter >> (56 - 8 * i)) & 0xFF);
        }
        blake3_hasher_update(&hasher, counter_bytes.data(), counter_bytes.size());

        // 4. client_finished（仅首次 c2s）
        if (!input.client_finished.empty())
        {
            blake3_hasher_update(&hasher, input.client_finished.data(), input.client_finished.size());
        }

        // 5. tls_header
        blake3_hasher_update(&hasher, input.tls_header.data(), input.tls_header.size());

        // 6. payload after mac
        blake3_hasher_update(&hasher, input.payload_after_mac.data(), input.payload_after_mac.size());

        std::array<std::uint8_t, appdata_maclen> mac;
        blake3_hasher_finalize(&hasher, mac.data(), mac.size());
        return mac;
    }


    /**
     * @brief 计算数据掩码
     * @details 使用 BLAKE3 keyed mode 计算每条记录的 XOR 掩码，
     * 用于编解码 masked_len 和 masked_cmd 字段。
     * 输出截断为 mask_len (4) 字节。
     *
     * 输入序列（严格按序）：
     * 1. input.server_random（32 字节）
     * 2. direction_string（16 字节）
     * 3. input.counter（8 字节 big-endian）
     * 4. input.plaintext_sample（明文数据，XOR 之前，最多 32 字节）
     *
     * @note mask 基于明文计算（XOR 之前），与 auth_mac 基于密文计算不同。
     * @param input 掩码输入参数集
     * @return 4 字节 XOR 掩码
     */
    [[nodiscard]] inline auto compute_mask(const mask_input &input)
        -> std::array<std::uint8_t, mask_len>
    {
        auto hasher = psm::crypto::keyed_hasher(input.secret);

        // 1. server_random
        blake3_hasher_update(&hasher, input.server_random.data(), input.server_random.size());

        // 2. direction string
        std::string_view dir;
        if (input.direction == flow_direction::to_client)
        {
            dir = dir_toclient;
        }
        else
        {
            dir = dir_toserver;
        }
        blake3_hasher_update(&hasher, reinterpret_cast<const std::uint8_t *>(dir.data()), dir.size());

        // 3. counter (big-endian 64-bit)
        std::array<std::uint8_t, 8> counter_bytes{};
        for (std::size_t i = 0; i < 8; ++i)
        {
            counter_bytes[i] = static_cast<std::uint8_t>((input.counter >> (56 - 8 * i)) & 0xFF);
        }
        blake3_hasher_update(&hasher, counter_bytes.data(), counter_bytes.size());

        // 4. plaintext sample (XOR 之前的明文数据，最多 32 字节)
        const std::size_t sample_len = std::min(input.plaintext_sample.size(), std::size_t{32});
        if (sample_len > 0)
        {
            blake3_hasher_update(&hasher, input.plaintext_sample.data(), sample_len);
        }

        std::array<std::uint8_t, mask_len> mask;
        blake3_hasher_finalize(&hasher, mask.data(), mask.size());
        return mask;
    }


    /**
     * @brief 用掩码对数据进行就地 XOR
     * @details 将 data 从 offset 开始与 mask 循环异或。
     * 用于 server_mask XOR 和 masked_len/masked_cmd 编解码。
     * @param data 待 XOR 的数据（就地修改）
     * @param mask XOR 掩码
     * @param offset data 中的起始偏移
     */
    inline void xor_with_mask(
        std::span<std::uint8_t> data,
        std::span<const std::uint8_t> mask,
        std::size_t offset = 0) noexcept
    {
        for (std::size_t i = offset; i < data.size(); ++i)
        {
            data[i] ^= mask[(i - offset) % mask.size()];
        }
    }
} // namespace psm::stealth::restls
