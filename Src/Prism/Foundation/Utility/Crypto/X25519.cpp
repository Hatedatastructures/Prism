/**
 * @file X25519.cpp
 * @brief X25519 密钥推导与共享秘密实现。
 */
#include <Prism/Foundation/Utility/Crypto/X25519.hpp>

#include <Prism/Foundation/Utility/Crypto/Random.hpp>
#include <openssl/curve25519.h>
#include <openssl/err.h>

namespace Prism::Crypto
{
    auto DerivePubkey(const std::span<const std::uint8_t> PrivateKey)
        -> std::expected<std::array<std::uint8_t, X25519Klen>, Fault::Failure>
    {
        if (PrivateKey.size() != X25519Klen)
        {
            return std::unexpected(Fault::Failure{Fault::Code::InvalidArgument, {}});
        }
        std::array<std::uint8_t, X25519Klen> PublicKey{};
        X25519_public_from_private(PublicKey.data(), PrivateKey.data());
        return PublicKey;
    }

    auto GenerateKeypair() -> std::expected<X25519Keypair, Fault::Failure>
    {
        X25519Keypair Keypair;
        const SecretScope Cleanup{Keypair.PrivateKey};
        const auto Random = FillRandom(Keypair.PrivateKey);
        if (!Random)
        {
            return std::unexpected(Random.error());
        }
        const auto PublicKey = DerivePubkey(Keypair.PrivateKey);
        if (!PublicKey)
        {
            return std::unexpected(PublicKey.error());
        }
        Keypair.PublicKey = *PublicKey;
        return Keypair;
    }

    auto X25519(const std::span<const std::uint8_t> PrivateKey,
        const std::span<const std::uint8_t> PeerPubkey)
        -> std::expected<std::array<std::uint8_t, X25519Slen>, Fault::Failure>
    {
        if (PrivateKey.size() != X25519Klen || PeerPubkey.size() != X25519Klen)
        {
            return std::unexpected(Fault::Failure{Fault::Code::InvalidArgument, {}});
        }
        std::array<std::uint8_t, X25519Slen> SharedSecret{};
        const SecretScope Cleanup{SharedSecret};
        ERR_clear_error();
        if (::X25519(SharedSecret.data(), PrivateKey.data(), PeerPubkey.data()) != 1)
        {
            return std::unexpected(Detail::NativeFailure(Fault::Code::Kexfail));
        }
        std::uint8_t Combined = 0;
        for (const auto Byte : SharedSecret)
        {
            Combined |= Byte;
        }
        if (Combined == 0)
        {
            return std::unexpected(Fault::Failure{Fault::Code::Kexfail, {}});
        }
        return SharedSecret;
    }
} // namespace Prism::Crypto
