/**
 * @file X25519.hpp
 * @brief X25519 椭圆曲线 Diffie-Hellman 密钥交换
 * @details 提供 X25519 密钥对生成、公钥推导和共享密钥计算功能。
 * 基于 BoringSSL 的 EVP_PKEY API 实现，用于 Reality 协议的密钥交换。
 * X25519 使用 Curve25519 椭圆曲线，提供 128 位安全强度，
 * 是 TLS 1.3 中 ECDHE 的首选曲线之一。
 * @note 所有密钥和共享密钥长度固定为 32 字节。
 * @note 已分叉，各自演进（与主库 foundation 无镜像同步约束）
 */
#pragma once

#include <cstring>

#include <openssl/rand.h>

#include <openssl/curve25519.h>

#include <preview/Foundation/Fault/Code.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>

namespace Preview::Crypto
{

    /**
     * @brief X25519 密钥长度（字节）
     */
    constexpr std::size_t X25519Klen = 32;

    /**
     * @brief X25519 共享密钥长度（字节）
     */
    constexpr std::size_t X25519Slen = 32;

    /**
     * @brief Ed25519 公钥长度（字节）
     */
    constexpr std::size_t Ed25519Klen = 32;

    /**
     * @brief Ed25519 私钥长度（字节，含种子+公钥的完整格式）
     */
    constexpr std::size_t Ed25519Plen = 64;

    /**
     * @struct X25519Keypair
     * @brief X25519 密钥对
     * @details 包含 X25519 的私钥和对应的公钥，各 32 字节。
     * 私钥是随机生成的 32 字节标量，公钥是 Curve25519 上的点。
     */
    struct X25519Keypair
    {
        std::array<std::uint8_t, X25519Klen> private_key{}; // X25519 私钥（32 字节标量）
        std::array<std::uint8_t, X25519Klen> PublicKey{};  // X25519 公钥（Curve25519 上的点，32 字节）
    };

    /**
     * @brief 生成 X25519 密钥对
     * @details 使用 BoringSSL 的随机数生成器生成私钥，
     * 然后从私钥推导对应的公钥。
     * @return 随机生成的 X25519 密钥对
     */
    [[nodiscard]] auto GenerateKeypair() -> X25519Keypair;

    /**
     * @brief 从私钥推导公钥
     * @details 执行 X25519 标量乘法，将私钥映射为 Curve25519 上的公钥点。
     * 如果私钥无效则返回全零。
     * @param private_key 32 字节 X25519 私钥
     * @return 推导出的 32 字节公钥，失败时返回全零
     */
    [[nodiscard]] auto DerivePubkey(std::span<const std::uint8_t> private_key)
        -> std::array<std::uint8_t, X25519Klen>;

    /**
     * @brief X25519 密钥交换
     * @details 计算 SharedSecret = X25519(private_key, PeerPubkey)。
     * 成功时返回 Fault::Code::Success 和共享密钥。
     * 失败可能原因：无效的公钥（低阶点）或 EVP API 错误。
     * @param private_key 本方 32 字节 X25519 私钥
     * @param PeerPubkey 对方 32 字节 X25519 公钥
     * @return 错误码和 32 字节共享密钥的配对
     * @note 即使对方公钥是低阶点，X25519 也会成功计算（输出全零），
     * 调用者应检查共享密钥是否为全零以检测此类攻击。
     */
    [[nodiscard]] auto X25519(std::span<const std::uint8_t> private_key,
                              std::span<const std::uint8_t> PeerPubkey)
        -> std::pair<Fault::Code, std::array<std::uint8_t, X25519Slen>>;

    /**
     * @struct Ed25519Keypair
     * @brief Ed25519 密钥对
     * @details 包含 Ed25519 的完整私钥（64字节：种子+公钥）和公钥（32字节）。
     * 用于 Reality 协议的服务端自签名证书生成和 CertificateVerify 签名。
     */
    struct Ed25519Keypair
    {
        std::array<std::uint8_t, Ed25519Plen> private_key{}; // Ed25519 完整私钥（64 字节：种子+公钥）
        std::array<std::uint8_t, Ed25519Klen> PublicKey{};  // Ed25519 公钥（32 字节）
    };



    inline auto GenerateKeypair() -> X25519Keypair
    {
        X25519Keypair keypair;

        if (RAND_bytes(keypair.private_key.data(), static_cast<int>(X25519Klen)) != 1)
        {
            return keypair;
        }

        keypair.PublicKey = DerivePubkey(keypair.private_key);
        return keypair;
    }

    inline auto DerivePubkey(std::span<const std::uint8_t> private_key)
        -> std::array<std::uint8_t, X25519Klen>
    {
        std::array<std::uint8_t, X25519Klen> PublicKey{};

        if (private_key.size() != X25519Klen)
        {
            return PublicKey;
        }

        X25519_public_from_private(PublicKey.data(), private_key.data());

        return PublicKey;
    }

    inline auto X25519(std::span<const std::uint8_t> private_key,
                       const std::span<const std::uint8_t> PeerPubkey)
        -> std::pair<Fault::Code, std::array<std::uint8_t, X25519Slen>>
    {
        std::array<std::uint8_t, X25519Slen> SharedSecret{};

        if (private_key.size() != X25519Klen)
        {
            return {Fault::Code::InvalidArgument, SharedSecret};
        }

        if (PeerPubkey.size() != X25519Klen)
        {
            return {Fault::Code::InvalidArgument, SharedSecret};
        }

        if (::X25519(SharedSecret.data(), private_key.data(), PeerPubkey.data()) != 1)
        {
            SharedSecret.fill(0);
            return {Fault::Code::Kexfail, SharedSecret};
        }

        // 检查全零共享密钥（低阶点攻击）
        bool AllZero = true;
        for (const auto b : SharedSecret)
        {
            if (b != 0)
            {
                AllZero = false;
                break;
            }
        }
        if (AllZero)
        {
            SharedSecret.fill(0);
            return {Fault::Code::Kexfail, SharedSecret};
        }

        return {Fault::Code::Success, SharedSecret};
    }


} // namespace Preview::Crypto
