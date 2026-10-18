/**
 * @file Blake3.hpp
 * @brief BLAKE3 摘要、密钥化摘要与无动态输出的密钥派生。
 * @details 输入借用到返回，输出由调用者或值结果拥有；无取消、关闭或 executor 行为。
 */
#pragma once

#include <Prism/Foundation/Utility/Crypto/Operation.hpp>
#include <blake3.h>
#include <array>
#include <cstdint>
#include <expected>
#include <span>
#include <string_view>

namespace Prism::Crypto
{
    /**
     * @brief 在调用者拥有的 span 中派生 BLAKE3 密钥，输入只同步借用。
     * @details Context 和 Material 必须在返回前有效，Output 不与输入重叠。
     *          BLAKE3 原生接口无失败返回值；本接口不动态分配，临时状态立即擦除。
     */
    inline auto DeriveKey(const std::string_view Context, const std::span<const std::uint8_t> Material,
                          const std::span<std::uint8_t> Output) -> void
    {
        blake3_hasher Hasher{};
        const SecretScope Cleanup{{reinterpret_cast<std::uint8_t *>(&Hasher), sizeof(Hasher)}};
        blake3_hasher_init_derive_key_raw(&Hasher, Context.data(), Context.size());
        blake3_hasher_update(&Hasher, Material.data(), Material.size());
        blake3_hasher_finalize(&Hasher, Output.data(), Output.size());
    }

    /**
     * @brief 从同步借用的 32 字节密钥创建调用者拥有的 BLAKE3 状态。
     * @return 非法密钥长度返回 InvalidArgument；成功状态的最终秘密擦除由调用者负责。
     */
    [[nodiscard]] inline auto KeyedHasher(const std::span<const std::uint8_t> Key)
        -> std::expected<blake3_hasher, Fault::Failure>
    {
        if (Key.size() != BLAKE3_KEY_LEN)
        {
            return std::unexpected(Fault::Failure{Fault::Code::InvalidArgument, {}});
        }
        blake3_hasher Hasher{};
        const SecretScope Cleanup{{reinterpret_cast<std::uint8_t *>(&Hasher), sizeof(Hasher)}};
        blake3_hasher_init_keyed(&Hasher, Key.data());
        return Hasher;
    }

    /** @brief 同步计算密钥化 BLAKE3；结果拥有摘要，错误原样传播，临时状态擦除。 */
    [[nodiscard]] inline auto KeyedHash(const std::span<const std::uint8_t> Key,
                                      const std::span<const std::uint8_t> Data)
        -> std::expected<std::array<std::uint8_t, 32>, Fault::Failure>
    {
        auto Hasher = KeyedHasher(Key);
        if (!Hasher)
        {
            return std::unexpected(Hasher.error());
        }
        const SecretScope Cleanup{{reinterpret_cast<std::uint8_t *>(&*Hasher), sizeof(*Hasher)}};
        blake3_hasher_update(&*Hasher, Data.data(), Data.size());
        std::array<std::uint8_t, 32> Output{};
        const SecretScope OutputCleanup{Output};
        blake3_hasher_finalize(&*Hasher, Output.data(), Output.size());
        return Output;
    }

    /** @brief 计算普通 BLAKE3；输入同步借用，返回拥有型摘要，原生算法无失败分支。 */
    [[nodiscard]] inline auto Hash(const std::span<const std::uint8_t> Data) -> std::array<std::uint8_t, 32>
    {
        blake3_hasher Hasher{};
        const SecretScope Cleanup{{reinterpret_cast<std::uint8_t *>(&Hasher), sizeof(Hasher)}};
        blake3_hasher_init(&Hasher);
        blake3_hasher_update(&Hasher, Data.data(), Data.size());
        std::array<std::uint8_t, 32> Output{};
        blake3_hasher_finalize(&Hasher, Output.data(), Output.size());
        return Output;
    }
}
