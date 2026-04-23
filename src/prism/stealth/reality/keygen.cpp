#include <prism/stealth/reality/keygen.hpp>
#include <prism/trace.hpp>
#include <cstring>

namespace psm::stealth::reality
{
    constexpr std::string_view KsTag = "[Stealth.KeySchedule]";

    static auto copy_key(std::span<const std::uint8_t> src, auto &dst) -> void
    {
        std::memcpy(dst.data(), src.data(), std::min(src.size(), dst.size()));
    }

    auto derive_handshake_keys(constspan shared_secret, constspan client_hello_msg, constspan server_hello_msg)
        -> std::pair<fault::code, key_material>
    {
        key_material keys{};

        // Step 1: early_secret = HKDF-Extract(salt=0^32, IKM=0^32)
        std::array<std::uint8_t, crypto::SHA256_LEN> zero_salt{};
        std::array<std::uint8_t, crypto::SHA256_LEN> zero_ikm{};
        const auto early_secret = crypto::hkdf_extract(zero_salt, zero_ikm);

        // Step 2: derived_secret
        const auto empty_hash = crypto::sha256(std::span<const std::uint8_t>{});
        auto [ec1, derived_secret] = crypto::hkdf_expand_label(early_secret, "derived", empty_hash, crypto::SHA256_LEN);
        if (fault::failed(ec1))
        {
            trace::error("{} failed to derive 'derived' secret", KsTag);
            return {fault::code::reality_key_schedule_error, keys};
        }

        // Step 3: handshake_secret
        const auto handshake_secret = crypto::hkdf_extract(derived_secret, shared_secret);

        // Step 4: hello_hash
        const auto hello_hash = crypto::sha256(client_hello_msg, server_hello_msg);

        // Step 5-6: client/server handshake traffic secrets
        auto [ec2, c_hs_traffic] = crypto::hkdf_expand_label(
            handshake_secret, "c hs traffic", hello_hash, crypto::SHA256_LEN);
        if (fault::failed(ec2))
        {
            trace::error("{} failed to derive 'c hs traffic'", KsTag);
            return {fault::code::reality_key_schedule_error, keys};
        }

        auto [ec3, s_hs_traffic] = crypto::hkdf_expand_label(
            handshake_secret, "s hs traffic", hello_hash, crypto::SHA256_LEN);
        if (fault::failed(ec3))
        {
            trace::error("{} failed to derive 's hs traffic'", KsTag);
            return {fault::code::reality_key_schedule_error, keys};
        }

        // Step 7-10: server/client handshake key + iv
        auto [ec4, s_hs_key] = crypto::hkdf_expand_label(s_hs_traffic, "key", {}, tls::AES_128_KEY_LEN);
        if (fault::failed(ec4))
        {
            trace::error("{} failed to derive server handshake key", KsTag);
            return {fault::code::reality_key_schedule_error, keys};
        }
        auto [ec5, s_hs_iv] = crypto::hkdf_expand_label(s_hs_traffic, "iv", {}, tls::AEAD_NONCE_LEN);
        if (fault::failed(ec5))
        {
            trace::error("{} failed to derive server handshake iv", KsTag);
            return {fault::code::reality_key_schedule_error, keys};
        }

        auto [ec6, c_hs_key] = crypto::hkdf_expand_label(c_hs_traffic, "key", {}, tls::AES_128_KEY_LEN);
        if (fault::failed(ec6))
        {
            trace::error("{} failed to derive client handshake key", KsTag);
            return {fault::code::reality_key_schedule_error, keys};
        }
        auto [ec7, c_hs_iv] = crypto::hkdf_expand_label(c_hs_traffic, "iv", {}, tls::AEAD_NONCE_LEN);
        if (fault::failed(ec7))
        {
            trace::error("{} failed to derive client handshake iv", KsTag);
            return {fault::code::reality_key_schedule_error, keys};
        }

        // Step 11-12: master secret
        auto [ec8, derived_master] = crypto::hkdf_expand_label(
            handshake_secret, "derived", empty_hash, crypto::SHA256_LEN);
        if (fault::failed(ec8))
        {
            trace::error("{} failed to derive master 'derived' secret", KsTag);
            return {fault::code::reality_key_schedule_error, keys};
        }
        keys.master_secret = crypto::hkdf_extract(derived_master, zero_ikm);

        copy_key(s_hs_key, keys.server_handshake_key);
        copy_key(s_hs_iv, keys.server_handshake_iv);
        copy_key(c_hs_key, keys.client_handshake_key);
        copy_key(c_hs_iv, keys.client_handshake_iv);

        // server finished_key
        auto [ec9, finished_key] = crypto::hkdf_expand_label(
            s_hs_traffic, "finished", {}, crypto::SHA256_LEN);
        if (fault::failed(ec9))
        {
            trace::error("{} failed to derive server finished key", KsTag);
            return {fault::code::reality_key_schedule_error, keys};
        }
        std::memcpy(keys.server_finished_key.data(), finished_key.data(), crypto::SHA256_LEN);

        return {fault::code::success, std::move(keys)};
    }

    auto derive_application_keys(const std::span<const std::uint8_t> master_secret,
                                 const std::span<const std::uint8_t> server_finished_hash,
                                 key_material &keys) -> fault::code
    {
        auto [ec1, s_ap_traffic] = crypto::hkdf_expand_label(
            master_secret, "s ap traffic", server_finished_hash, crypto::SHA256_LEN);
        if (fault::failed(ec1))
        {
            trace::error("{} failed to derive 's ap traffic'", KsTag);
            return fault::code::reality_key_schedule_error;
        }

        auto [ec2, c_ap_traffic] = crypto::hkdf_expand_label(
            master_secret, "c ap traffic", server_finished_hash, crypto::SHA256_LEN);
        if (fault::failed(ec2))
        {
            trace::error("{} failed to derive 'c ap traffic'", KsTag);
            return fault::code::reality_key_schedule_error;
        }

        auto [ec3, s_app_key] = crypto::hkdf_expand_label(s_ap_traffic, "key", {}, tls::AES_128_KEY_LEN);
        if (fault::failed(ec3))
        {
            trace::error("{} failed to derive server app key", KsTag);
            return fault::code::reality_key_schedule_error;
        }
        auto [ec4, s_app_iv] = crypto::hkdf_expand_label(s_ap_traffic, "iv", {}, tls::AEAD_NONCE_LEN);
        if (fault::failed(ec4))
        {
            trace::error("{} failed to derive server app iv", KsTag);
            return fault::code::reality_key_schedule_error;
        }

        auto [ec5, c_app_key] = crypto::hkdf_expand_label(c_ap_traffic, "key", {}, tls::AES_128_KEY_LEN);
        if (fault::failed(ec5))
        {
            trace::error("{} failed to derive client app key", KsTag);
            return fault::code::reality_key_schedule_error;
        }
        auto [ec6, c_app_iv] = crypto::hkdf_expand_label(c_ap_traffic, "iv", {}, tls::AEAD_NONCE_LEN);
        if (fault::failed(ec6))
        {
            trace::error("{} failed to derive client app iv", KsTag);
            return fault::code::reality_key_schedule_error;
        }

        copy_key(s_app_key, keys.server_app_key);
        copy_key(s_app_iv, keys.server_app_iv);
        copy_key(c_app_key, keys.client_app_key);
        copy_key(c_app_iv, keys.client_app_iv);

        return fault::code::success;
    }

    auto compute_finished_verify_data(const std::span<const std::uint8_t> finished_key,
                                      const std::span<const std::uint8_t> transcript_hash)
        -> std::array<std::uint8_t, crypto::SHA256_LEN>
    {
        return crypto::hmac_sha256(finished_key, transcript_hash);
    }
} // namespace psm::stealth::reality
