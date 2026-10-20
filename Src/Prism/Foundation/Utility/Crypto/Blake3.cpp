/**
 * @file Blake3.cpp
 * @brief BLAKE3 摘要与密钥派生实现。
 */
#include <Prism/Foundation/Utility/Crypto/Blake3.hpp>

namespace Prism::Crypto
{
    auto DeriveKey(const std::string_view Context, const std::span<const std::uint8_t> Material,
        const std::span<std::uint8_t> Output) -> void
    {
        blake3_hasher Hasher{};
        const SecretScope Cleanup{{reinterpret_cast<std::uint8_t *>(&Hasher), sizeof(Hasher)}};
        blake3_hasher_init_derive_key_raw(&Hasher, Context.data(), Context.size());
        blake3_hasher_update(&Hasher, Material.data(), Material.size());
        blake3_hasher_finalize(&Hasher, Output.data(), Output.size());
    }

    auto KeyedHasher(const std::span<const std::uint8_t> Key)
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

    auto KeyedHash(const std::span<const std::uint8_t> Key,
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

    auto Hash(const std::span<const std::uint8_t> Data) -> std::array<std::uint8_t, 32>
    {
        blake3_hasher Hasher{};
        const SecretScope Cleanup{{reinterpret_cast<std::uint8_t *>(&Hasher), sizeof(Hasher)}};
        blake3_hasher_init(&Hasher);
        blake3_hasher_update(&Hasher, Data.data(), Data.size());
        std::array<std::uint8_t, 32> Output{};
        blake3_hasher_finalize(&Hasher, Output.data(), Output.size());
        return Output;
    }
} // namespace Prism::Crypto
