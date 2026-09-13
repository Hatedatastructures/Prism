/**
 * @file Codec.hpp
 * @brief Restls 认证编解码（纯函数，BLAKE3）
 * @details 对齐 C++ include/prism/handshake/restls/crypto.hpp 与
 * restls-Client-go：
 *          - DeriveSecret：BLAKE3 DeriveKey(SecretCtx, Password) → 32B
 *          - ComputeServerMask：BLAKE3 keyed(Secret, ServerRandom) → 16B
 *          - ComputeAuthMac：BLAKE3 keyed(Secret, ServerRandom + direction +
 *            counter + [ClientFinished] + TlsHeader + Payload) → 8B
 *          - ComputeMask：BLAKE3 keyed(Secret, ServerRandom + direction +
 *            counter + PlaintextSample[:32]) → 4B
 * @note AuthMacInput/MaskInput 的公共字段名称保持兼容。
 * @note 参考 restls-Client-go 协议规范。
 */

#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

#include <blake3.h>
#include <preview/Foundation/Error.hpp>
#include <preview/Protocols/Restls/Types.hpp>

namespace Preview::Restls
{

    /**
     * @brief 从密码派生 RestlsSecret
     * @param Password 认证密码
     * @return 32 字节 RestlsSecret
     * @details BLAKE3 DeriveKey 模式，Context = "restls-traffic-key"。
     */
    [[nodiscard]] inline auto DeriveSecret(std::string_view Password)
        -> std::array<std::uint8_t, 32>
    {
        blake3_hasher Hasher;
        blake3_hasher_init_derive_key(&Hasher, SecretCtx.data());
        blake3_hasher_update(&Hasher, reinterpret_cast<const std::uint8_t *>(Password.data()),
                             Password.size());
        std::array<std::uint8_t, 32> Secret{};
        blake3_hasher_finalize(&Hasher, Secret.data(), Secret.size());
        return Secret;
    }

    /**
     * @brief 计算服务端认证掩码
     * @param Secret RestlsSecret（32 字节）
     * @param ServerRandom TLS ServerHello 随机数（32 字节）
     * @return 16 字节认证掩码
     * @details BLAKE3 keyed(Secret, ServerRandom)，输出截断 16 字节。
     */
    [[nodiscard]] inline auto ComputeServerMask(
        std::span<const std::uint8_t, 32> Secret,
        std::span<const std::uint8_t, 32> ServerRandom)
        -> std::array<std::uint8_t, HsMaclen>
    {
        blake3_hasher Hasher;
        blake3_hasher_init_keyed(&Hasher, Secret.data());
        blake3_hasher_update(&Hasher, ServerRandom.data(), ServerRandom.size());
        std::array<std::uint8_t, HsMaclen> Mask{};
        blake3_hasher_finalize(&Hasher, Mask.data(), Mask.size());
        return Mask;
    }

    /**
     * @brief 计算应用数据认证 MAC
     * @param Secret RestlsSecret（32 字节）
     * @param ServerRandom TLS 随机数（32 字节）
     * @param Direction 数据流方向
     * @param Counter 记录计数器
     * @param ClientFinished 客户端 Finished 消息（仅首次 c2s，否则为空）
     * @param TlsHeader TLS 记录头（5 字节）
     * @param PayloadAfterMac auth_mac 之后的所有数据
     * @return 8 字节认证 MAC
     * @details 输入序列：ServerRandom + direction + counter(8B BE) +
     * [ClientFinished] + TlsHeader + PayloadAfterMac。
     */
    /// 认证 MAC 输入（对齐主库 AuthMacInput）
    struct AuthMacInput
    {
        std::span<const std::uint8_t, 32> Secret;            ///< RestlsSecret（32 字节）
        std::span<const std::uint8_t, 32> ServerRandom;     ///< TLS 随机数（32 字节）
        FlowDirection direction{FlowDirection::ToClient}; ///< 数据流方向
        std::uint64_t counter{0};                            ///< 记录计数器
        std::span<const std::uint8_t> ClientFinished;       ///< 客户端 Finished（首次 c2s）
        std::span<const std::uint8_t> TlsHeader;            ///< TLS 记录头（5 字节）
        std::span<const std::uint8_t> PayloadAfterMac;     ///< auth_mac 之后的数据
    };

    /**
     * @brief 计算应用数据认证 MAC
     * @param Input 输入参数
     * @return 8 字节认证 MAC
     * @details 输入序列：ServerRandom + direction + counter(8B BE) +
     * [ClientFinished] + TlsHeader + PayloadAfterMac。
     */
    [[nodiscard]] inline auto ComputeAuthMac(const AuthMacInput &Input)
        -> std::array<std::uint8_t, AppdataMaclen>
    {
        blake3_hasher Hasher;
        blake3_hasher_init_keyed(&Hasher, Input.Secret.data());
        blake3_hasher_update(&Hasher, Input.ServerRandom.data(), Input.ServerRandom.size());
        std::string_view Direction;
        if (Input.direction == FlowDirection::ToClient)
        {
            Direction = DirToclient;
        }
        else
        {
            Direction = DirToserver;
        }
        blake3_hasher_update(
            &Hasher,
            reinterpret_cast<const std::uint8_t *>(Direction.data()),
            Direction.size());
        std::array<std::uint8_t, 8> CounterBytes{};
        for (std::size_t I = 0; I < 8; ++I)
        {
            CounterBytes[I] = static_cast<std::uint8_t>((Input.counter >> (56 - 8 * I)) & 0xFF);
        }
        blake3_hasher_update(&Hasher, CounterBytes.data(), CounterBytes.size());
        if (!Input.ClientFinished.empty())
        {
            blake3_hasher_update(
                &Hasher,
                Input.ClientFinished.data(),
                Input.ClientFinished.size());
        }
        blake3_hasher_update(&Hasher, Input.TlsHeader.data(), Input.TlsHeader.size());
        blake3_hasher_update(&Hasher, Input.PayloadAfterMac.data(), Input.PayloadAfterMac.size());
        std::array<std::uint8_t, AppdataMaclen> Mac{};
        blake3_hasher_finalize(&Hasher, Mac.data(), Mac.size());
        return Mac;
    }

    /// 掩码输入（对齐主库 MaskInput）
    struct MaskInput
    {
        std::span<const std::uint8_t, 32> Secret;            ///< RestlsSecret（32 字节）
        std::span<const std::uint8_t, 32> ServerRandom;     ///< TLS 随机数（32 字节）
        FlowDirection direction{FlowDirection::ToClient}; ///< 数据流方向
        std::uint64_t counter{0};                            ///< 记录计数器
        std::span<const std::uint8_t> PlaintextSample;      ///< 明文样本（XOR 之前）
    };

    /**
     * @brief 计算数据掩码（XOR 掩码，基于明文）
     * @param Input 输入参数
     * @return 4 字节 XOR 掩码
     * @details 输入序列：ServerRandom + direction + counter(8B BE) + Sample[:32]。
     */
    [[nodiscard]] inline auto ComputeMask(const MaskInput &Input)
        -> std::array<std::uint8_t, MaskLen>
    {
        blake3_hasher Hasher;
        blake3_hasher_init_keyed(&Hasher, Input.Secret.data());
        blake3_hasher_update(&Hasher, Input.ServerRandom.data(), Input.ServerRandom.size());
        std::string_view Direction;
        if (Input.direction == FlowDirection::ToClient)
        {
            Direction = DirToclient;
        }
        else
        {
            Direction = DirToserver;
        }
        blake3_hasher_update(
            &Hasher,
            reinterpret_cast<const std::uint8_t *>(Direction.data()),
            Direction.size());
        std::array<std::uint8_t, 8> CounterBytes{};
        for (std::size_t I = 0; I < 8; ++I)
        {
            CounterBytes[I] = static_cast<std::uint8_t>((Input.counter >> (56 - 8 * I)) & 0xFF);
        }
        blake3_hasher_update(&Hasher, CounterBytes.data(), CounterBytes.size());
        const auto SampleLen = std::min(Input.PlaintextSample.size(), std::size_t{32});
        if (SampleLen > 0)
        {
            blake3_hasher_update(&Hasher, Input.PlaintextSample.data(), SampleLen);
        }
        std::array<std::uint8_t, MaskLen> Mask{};
        blake3_hasher_finalize(&Hasher, Mask.data(), Mask.size());
        return Mask;
    }

} // namespace Preview::Restls
