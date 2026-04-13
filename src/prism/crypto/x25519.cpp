/**
 * @file x25519.cpp
 * @brief X25519 椭圆曲线密钥交换实现
 * @details 使用 BoringSSL 的 EVP_PKEY API 实现 X25519 密钥交换。
 * EVP_PKEY_new_raw_private_key 从原始字节创建 EVP_PKEY，
 * EVP_PKEY_derive 计算共享密钥。
 */

#include <prism/crypto/x25519.hpp>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <cstring>
#include <prism/trace.hpp>

namespace psm::crypto
{
    constexpr std::string_view X25519_TAG = "[Crypto.X25519]";

    auto generate_x25519_keypair() -> x25519_keypair
    {
        x25519_keypair keypair;

        // 生成 32 字节随机私钥
        RAND_bytes(keypair.private_key.data(), static_cast<int>(X25519_KEY_LEN));

        // 从私钥推导公钥
        keypair.public_key = derive_x25519_public_key(keypair.private_key);
        return keypair;
    }

    auto derive_x25519_public_key(const std::span<const std::uint8_t> private_key)
        -> std::array<std::uint8_t, X25519_KEY_LEN>
    {
        std::array<std::uint8_t, X25519_KEY_LEN> public_key{};

        if (private_key.size() != X25519_KEY_LEN)
        {
            trace::error("{} invalid private key length: {}", X25519_TAG, private_key.size());
            return public_key;
        }

        // 从原始私钥字节创建 EVP_PKEY
        auto *pkey = EVP_PKEY_new_raw_private_key(
            EVP_PKEY_X25519, nullptr, private_key.data(), private_key.size());
        if (!pkey)
        {
            trace::error("{} EVP_PKEY_new_raw_private_key failed", X25519_TAG);
            return public_key;
        }

        // 提取公钥
        std::size_t pub_len = X25519_KEY_LEN;
        if (EVP_PKEY_get_raw_public_key(pkey, public_key.data(), &pub_len) != 1)
        {
            trace::error("{} EVP_PKEY_get_raw_public_key failed", X25519_TAG);
            public_key.fill(0);
        }

        EVP_PKEY_free(pkey);
        return public_key;
    }

    auto x25519(const std::span<const std::uint8_t> private_key, const std::span<const std::uint8_t> peer_public_key)
        -> std::pair<fault::code, std::array<std::uint8_t, X25519_SHARED_LEN>>
    {
        std::array<std::uint8_t, X25519_SHARED_LEN> shared_secret{};

        if (private_key.size() != X25519_KEY_LEN)
        {
            trace::error("{} invalid private key length: {}", X25519_TAG, private_key.size());
            return {fault::code::invalid_argument, shared_secret};
        }

        if (peer_public_key.size() != X25519_KEY_LEN)
        {
            trace::error("{} invalid peer public key length: {}", X25519_TAG, peer_public_key.size());
            return {fault::code::invalid_argument, shared_secret};
        }

        // 从原始私钥创建本地 EVP_PKEY
        auto *pkey = EVP_PKEY_new_raw_private_key(
            EVP_PKEY_X25519, nullptr, private_key.data(), private_key.size());
        if (!pkey)
        {
            trace::error("{} failed to create local private key", X25519_TAG);
            return {fault::code::reality_key_exchange_failed, shared_secret};
        }

        // 从原始公钥创建对方 EVP_PKEY
        auto *peer_pkey = EVP_PKEY_new_raw_public_key(
            EVP_PKEY_X25519, nullptr, peer_public_key.data(), peer_public_key.size());
        if (!peer_pkey)
        {
            trace::error("{} failed to create peer public key", X25519_TAG);
            EVP_PKEY_free(pkey);
            return {fault::code::reality_key_exchange_failed, shared_secret};
        }

        // 创建推导上下文
        auto *ctx = EVP_PKEY_CTX_new(pkey, nullptr);
        if (!ctx)
        {
            trace::error("{} EVP_PKEY_CTX_new failed", X25519_TAG);
            EVP_PKEY_free(peer_pkey);
            EVP_PKEY_free(pkey);
            return {fault::code::reality_key_exchange_failed, shared_secret};
        }

        // 初始化密钥推导
        if (EVP_PKEY_derive_init(ctx) != 1)
        {
            trace::error("{} EVP_PKEY_derive_init failed", X25519_TAG);
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(peer_pkey);
            EVP_PKEY_free(pkey);
            return {fault::code::reality_key_exchange_failed, shared_secret};
        }

        // 设置对方公钥
        if (EVP_PKEY_derive_set_peer(ctx, peer_pkey) != 1)
        {
            trace::error("{} EVP_PKEY_derive_set_peer failed", X25519_TAG);
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(peer_pkey);
            EVP_PKEY_free(pkey);
            return {fault::code::reality_key_exchange_failed, shared_secret};
        }

        // 计算共享密钥
        std::size_t secret_len = X25519_SHARED_LEN;
        if (EVP_PKEY_derive(ctx, shared_secret.data(), &secret_len) != 1)
        {
            trace::error("{} EVP_PKEY_derive failed", X25519_TAG);
            shared_secret.fill(0);
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(peer_pkey);
            EVP_PKEY_free(pkey);
            return {fault::code::reality_key_exchange_failed, shared_secret};
        }

        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(peer_pkey);
        EVP_PKEY_free(pkey);

        return {fault::code::success, shared_secret};
    }
} // namespace psm::crypto
