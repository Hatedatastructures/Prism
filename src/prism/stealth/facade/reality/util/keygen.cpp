#include <prism/stealth/facade/reality/util/keygen.hpp>

#include <prism/trace.hpp>

#include <cstring>

using namespace psm::trace;

namespace psm::stealth::reality
{

    namespace tls = psm::protocol::tls;

    namespace
    {
        void copy_key(std::span<const std::uint8_t> src, auto &dst)
        {
            std::memcpy(dst.data(), src.data(), std::min(src.size(), dst.size()));
        }
    } // namespace


    auto derive_hs_keys(constspan shared_secret, constspan chello_msg, constspan shello_msg)
        -> std::pair<fault::code, key_material>
    {
        key_material keys{};

        std::array<std::uint8_t, crypto::sha256_len> zero_salt{};
        std::array<std::uint8_t, crypto::sha256_len> zero_ikm{};
        const auto early_secret = crypto::hkdf_extract(zero_salt, zero_ikm);

        const auto empty_hash = crypto::sha256(std::span<const std::uint8_t>{});
        auto [ec1, derived_secret] = crypto::expand_label({early_secret, "derived", empty_hash, crypto::sha256_len});
        if (fault::failed(ec1))
        {
            trace::error("failed to derive 'derived' secret");
            return {fault::code::kdferr, keys};
        }

        const auto handshake_secret = crypto::hkdf_extract(derived_secret, shared_secret);

        const auto hello_hash = crypto::sha256(chello_msg, shello_msg);

        auto [ec2, c_hs_traffic] = crypto::expand_label(
            {handshake_secret, "c hs traffic", hello_hash, crypto::sha256_len});
        if (fault::failed(ec2))
        {
            trace::error("failed to derive 'c hs traffic'");
            return {fault::code::kdferr, keys};
        }

        auto [ec3, s_hs_traffic] = crypto::expand_label(
            {handshake_secret, "s hs traffic", hello_hash, crypto::sha256_len});
        if (fault::failed(ec3))
        {
            trace::error("failed to derive 's hs traffic'");
            return {fault::code::kdferr, keys};
        }

        auto [ec4, s_hs_key] = crypto::expand_label({s_hs_traffic, "key", {}, tls::AES_128_KEY_LEN});
        if (fault::failed(ec4))
        {
            trace::error("failed to derive server handshake key");
            return {fault::code::kdferr, keys};
        }
        auto [ec5, s_hs_iv] = crypto::expand_label({s_hs_traffic, "iv", {}, tls::AEAD_NONCE_LEN});
        if (fault::failed(ec5))
        {
            trace::error("failed to derive server handshake iv");
            return {fault::code::kdferr, keys};
        }

        auto [ec6, c_hs_key] = crypto::expand_label({c_hs_traffic, "key", {}, tls::AES_128_KEY_LEN});
        if (fault::failed(ec6))
        {
            trace::error("failed to derive client handshake key");
            return {fault::code::kdferr, keys};
        }
        auto [ec7, c_hs_iv] = crypto::expand_label({c_hs_traffic, "iv", {}, tls::AEAD_NONCE_LEN});
        if (fault::failed(ec7))
        {
            trace::error("failed to derive client handshake iv");
            return {fault::code::kdferr, keys};
        }

        auto [ec8, derived_master] = crypto::expand_label(
            {handshake_secret, "derived", empty_hash, crypto::sha256_len});
        if (fault::failed(ec8))
        {
            trace::error("failed to derive master 'derived' secret");
            return {fault::code::kdferr, keys};
        }
        keys.master_secret = crypto::hkdf_extract(derived_master, zero_ikm);

        copy_key(s_hs_key, keys.server_hskey);
        copy_key(s_hs_iv, keys.server_hsiv);
        copy_key(c_hs_key, keys.client_hskey);
        copy_key(c_hs_iv, keys.client_hsiv);

        // 服务端 Finished 密钥
        auto [ec9, finished_key] = crypto::expand_label(
            {s_hs_traffic, "finished", {}, crypto::sha256_len});
        if (fault::failed(ec9))
        {
            trace::error("failed to derive server finished key");
            return {fault::code::kdferr, keys};
        }
        std::memcpy(keys.server_finkey.data(), finished_key.data(), crypto::sha256_len);

        return {fault::code::success, std::move(keys)};
    }


    auto derive_app_keys(const std::span<const std::uint8_t> master_secret, const std::span<const std::uint8_t> server_finhash, key_material &keys)
        -> fault::code
    {
        auto [ec1, s_ap_traffic] = crypto::expand_label(
            {master_secret, "s ap traffic", server_finhash, crypto::sha256_len});
        if (fault::failed(ec1))
        {
            trace::error("failed to derive 's ap traffic'");
            return fault::code::kdferr;
        }

        auto [ec2, c_ap_traffic] = crypto::expand_label(
            {master_secret, "c ap traffic", server_finhash, crypto::sha256_len});
        if (fault::failed(ec2))
        {
            trace::error("failed to derive 'c ap traffic'");
            return fault::code::kdferr;
        }

        auto [ec3, s_app_key] = crypto::expand_label({s_ap_traffic, "key", {}, tls::AES_128_KEY_LEN});
        if (fault::failed(ec3))
        {
            trace::error("failed to derive server app key");
            return fault::code::kdferr;
        }
        auto [ec4, s_app_iv] = crypto::expand_label({s_ap_traffic, "iv", {}, tls::AEAD_NONCE_LEN});
        if (fault::failed(ec4))
        {
            trace::error("failed to derive server app iv");
            return fault::code::kdferr;
        }

        auto [ec5, c_app_key] = crypto::expand_label({c_ap_traffic, "key", {}, tls::AES_128_KEY_LEN});
        if (fault::failed(ec5))
        {
            trace::error("failed to derive client app key");
            return fault::code::kdferr;
        }
        auto [ec6, c_app_iv] = crypto::expand_label({c_ap_traffic, "iv", {}, tls::AEAD_NONCE_LEN});
        if (fault::failed(ec6))
        {
            trace::error("failed to derive client app iv");
            return fault::code::kdferr;
        }

        copy_key(s_app_key, keys.server_appkey);
        copy_key(s_app_iv, keys.server_appiv);
        copy_key(c_app_key, keys.client_appkey);
        copy_key(c_app_iv, keys.client_appiv);

        return fault::code::success;
    }


    auto compute_verify(const std::span<const std::uint8_t> finished_key, const std::span<const std::uint8_t> transcript_hash)
        -> std::array<std::uint8_t, crypto::sha256_len>
    {
        return crypto::hmac_sha256(finished_key, transcript_hash);
    }
} // namespace psm::stealth::reality
