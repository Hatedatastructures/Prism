#include <prism/crypto/x25519.hpp>
#include <prism/trace/trace.hpp>
#include <prism/trace/context.hpp>

#include <openssl/curve25519.h>
#include <openssl/rand.h>

#include <cstring>

using namespace psm::trace;

namespace psm::crypto
{

    auto generate_keypair()
        -> x25519_keypair
    {
        x25519_keypair keypair;

        if (RAND_bytes(keypair.private_key.data(), static_cast<int>(x25519_klen)) != 1)
        {
            trace::error("RAND_bytes failed");
            return keypair;
        }

        keypair.public_key = derive_pubkey(keypair.private_key);
        return keypair;
    }


    auto derive_pubkey(const std::span<const std::uint8_t> private_key)
        -> std::array<std::uint8_t, x25519_klen>
    {
        std::array<std::uint8_t, x25519_klen> public_key{};

        if (private_key.size() != x25519_klen)
        {
            trace::error("invalid private key length: {}", private_key.size());
            return public_key;
        }

        X25519_public_from_private(public_key.data(), private_key.data());

        return public_key;
    }


    auto x25519(const std::span<const std::uint8_t> private_key, const std::span<const std::uint8_t> peer_pubkey)
        -> std::pair<fault::code, std::array<std::uint8_t, x25519_slen>>
    {
        std::array<std::uint8_t, x25519_slen> shared_secret{};

        if (private_key.size() != x25519_klen)
        {
            trace::error("invalid private key length: {}", private_key.size());
            return {fault::code::invalid_argument, shared_secret};
        }

        if (peer_pubkey.size() != x25519_klen)
        {
            trace::error("invalid peer pubkey length: {}", peer_pubkey.size());
            return {fault::code::invalid_argument, shared_secret};
        }

        if (X25519(shared_secret.data(), private_key.data(), peer_pubkey.data()) != 1)
        {
            trace::error("X25519 key exchange failed");
            shared_secret.fill(0);
            return {fault::code::kexfail, shared_secret};
        }

        // 检查全零共享密钥（低阶点攻击）
        bool all_zero = true;
        for (const auto b : shared_secret)
        {
            if (b != 0)
            {
                all_zero = false;
                break;
            }
        }
        if (all_zero)
        {
            trace::error("X25519 shared secret all-zero (possible low-order point attack)");
            shared_secret.fill(0);
            return {fault::code::kexfail, shared_secret};
        }

        return {fault::code::success, shared_secret};
    }


} // namespace psm::crypto
