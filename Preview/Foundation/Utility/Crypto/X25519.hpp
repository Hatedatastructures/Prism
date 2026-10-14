/**
 * @file X25519.hpp
 * @brief X25519 值结果与密钥对生成。
 * @details 输入同步借用，成功 expected 拥有输出密钥；调用者负责最终秘密擦除。
 *          原语无取消、半关闭、连接关闭或 executor 行为。
 */
#pragma once

#include <Preview/Foundation/Utility/Crypto/Random.hpp>
#include <openssl/curve25519.h>
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>

namespace Preview::Crypto
{
    /** @brief X25519 密钥字节数。 */
    constexpr std::size_t X25519Klen = 32;
    /** @brief X25519 共享秘密字节数。 */
    constexpr std::size_t X25519Slen = 32;
    /** @brief Ed25519 公钥字节数。 */
    constexpr std::size_t Ed25519Klen = 32;
    /** @brief Ed25519 完整私钥字节数，包含种子与公钥。 */
    constexpr std::size_t Ed25519Plen = 64;

    /** @brief 调用者拥有的 X25519 私钥与公钥，最终秘密擦除由调用者负责。 */
    struct X25519Keypair final
    {
        std::array<std::uint8_t, X25519Klen> PrivateKey{}; ///< 私钥标量。
        std::array<std::uint8_t, X25519Klen> PublicKey{}; ///< 对应公钥。
    };

    /** @brief 调用者拥有的 Ed25519 完整私钥与公钥。 */
    struct Ed25519Keypair final
    {
        std::array<std::uint8_t, Ed25519Plen> PrivateKey{}; ///< 种子与公钥。
        std::array<std::uint8_t, Ed25519Klen> PublicKey{}; ///< 公钥。
    };

    /**
     * @brief 从同步借用的 32 字节私钥推导公钥；成功结果拥有输出。
     * @return 非法输入长度返回 InvalidArgument，不返回全零哨兵。
     * @note 原生 public_from_private 对合法长度不提供失败返回值。
     */
    [[nodiscard]] inline auto DerivePubkey(const std::span<const std::uint8_t> PrivateKey)
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

    /**
     * @brief 使用统一 CSPRNG 生成密钥对；失败立即返回且局部私钥可靠擦除。
     * @return 成功 expected 拥有密钥对；随机源和推导错误原样返回。
     */
    [[nodiscard]] inline auto GenerateKeypair() -> std::expected<X25519Keypair, Fault::Failure>
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

    /**
     * @brief 对同步借用的本方私钥与对端公钥执行 X25519；结果拥有共享秘密。
     * @return 长度非法返回 InvalidArgument；低阶点或原生失败返回 Kexfail。
     * @details 拒绝全零共享秘密并擦除局部副本，调用者无需用全零哨兵判断错误。
     */
    [[nodiscard]] inline auto X25519(const std::span<const std::uint8_t> PrivateKey,
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
}
