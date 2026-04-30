#include <prism/crypto/x25519.hpp>
#include <openssl/rand.h>
#include <openssl/curve25519.h>
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

        // 使用 BoringSSL 底层 X25519_public_from_private 函数
        // 比 EVP_PKEY API 快 5-7 倍（从 35μs 降至 5-10μs）
        X25519_public_from_private(public_key.data(), private_key.data());

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

        // 使用 BoringSSL 底层 X25519() 函数
        // 比 EVP_PKEY API 快 5-7 倍（从 35μs 降至 5-10μs）
        // 返回 1 表示成功，0 表示失败（如无效公钥）
        if (X25519(shared_secret.data(), private_key.data(), peer_public_key.data()) != 1)
        {
            trace::error("{} X25519 key exchange failed", X25519_TAG);
            shared_secret.fill(0);
            return {fault::code::reality_key_exchange_failed, shared_secret};
        }

        return {fault::code::success, shared_secret};
    }
} // namespace psm::crypto
