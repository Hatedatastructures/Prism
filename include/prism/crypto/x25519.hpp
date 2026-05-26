/**
 * @file x25519.hpp
 * @brief X25519 椭圆曲线 Diffie-Hellman 密钥交换
 * @details 提供 X25519 密钥对生成、公钥推导和共享密钥计算功能。
 * 基于 BoringSSL 的 EVP_PKEY API 实现，用于 Reality 协议的密钥交换。
 * X25519 使用 Curve25519 椭圆曲线，提供 128 位安全强度，
 * 是 TLS 1.3 中 ECDHE 的首选曲线之一。
 * @note 所有密钥和共享密钥长度固定为 32 字节。
 */
#pragma once

#include <prism/fault/code.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>


namespace psm::crypto
{

    /**
     * @brief X25519 密钥长度（字节）
     */
    constexpr std::size_t x25519_klen = 32;

    /**
     * @brief X25519 共享密钥长度（字节）
     */
    constexpr std::size_t x25519_slen = 32;

    /**
     * @brief Ed25519 公钥长度（字节）
     */
    constexpr std::size_t ed25519_klen = 32;

    /**
     * @brief Ed25519 私钥长度（字节，含种子+公钥的完整格式）
     */
    constexpr std::size_t ed25519_plen = 64;

    /**
     * @struct x25519_keypair
     * @brief X25519 密钥对
     * @details 包含 X25519 的私钥和对应的公钥，各 32 字节。
     * 私钥是随机生成的 32 字节标量，公钥是 Curve25519 上的点。
     */
    struct x25519_keypair
    {
        std::array<std::uint8_t, x25519_klen> private_key{}; // X25519 私钥（32 字节标量）
        std::array<std::uint8_t, x25519_klen> public_key{};  // X25519 公钥（Curve25519 上的点，32 字节）
    };

    /**
     * @brief 生成 X25519 密钥对
     * @details 使用 BoringSSL 的随机数生成器生成私钥，
     * 然后从私钥推导对应的公钥。
     * @return 随机生成的 X25519 密钥对
     */
    [[nodiscard]] auto generate_keypair()
        -> x25519_keypair;

    /**
     * @brief 从私钥推导公钥
     * @details 执行 X25519 标量乘法，将私钥映射为 Curve25519 上的公钥点。
     * 如果私钥无效则返回全零。
     * @param private_key 32 字节 X25519 私钥
     * @return 推导出的 32 字节公钥，失败时返回全零
     */
    [[nodiscard]] auto derive_pubkey(std::span<const std::uint8_t> private_key)
        -> std::array<std::uint8_t, x25519_klen>;

    /**
     * @brief X25519 密钥交换
     * @details 计算 shared_secret = X25519(private_key, peer_pubkey)。
     * 成功时返回 fault::code::success 和共享密钥。
     * 失败可能原因：无效的公钥（低阶点）或 EVP API 错误。
     * @param private_key 本方 32 字节 X25519 私钥
     * @param peer_pubkey 对方 32 字节 X25519 公钥
     * @return 错误码和 32 字节共享密钥的配对
     * @note 即使对方公钥是低阶点，X25519 也会成功计算（输出全零），
     * 调用者应检查共享密钥是否为全零以检测此类攻击。
     */
    [[nodiscard]] auto x25519(std::span<const std::uint8_t> private_key, std::span<const std::uint8_t> peer_pubkey)
        -> std::pair<fault::code, std::array<std::uint8_t, x25519_slen>>;

    /**
     * @struct ed25519_keypair
     * @brief Ed25519 密钥对
     * @details 包含 Ed25519 的完整私钥（64字节：种子+公钥）和公钥（32字节）。
     * 用于 Reality 协议的服务端自签名证书生成和 CertificateVerify 签名。
     */
    struct ed25519_keypair
    {
        std::array<std::uint8_t, ed25519_plen> private_key{}; // Ed25519 完整私钥（64 字节：种子+公钥）
        std::array<std::uint8_t, ed25519_klen> public_key{};          // Ed25519 公钥（32 字节）
    };
} // namespace psm::crypto
