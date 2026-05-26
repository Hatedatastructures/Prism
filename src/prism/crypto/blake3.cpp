#include <prism/crypto/blake3.hpp>

#include <blake3.h>

namespace psm::crypto
{

    void derive_key(const std::string_view context, const std::span<const std::uint8_t> material,
                    const std::span<std::uint8_t> out)
    {
        blake3_hasher hasher;
        blake3_hasher_init_derive_key_raw(&hasher, context.data(), context.size());
        blake3_hasher_update(&hasher, material.data(), material.size());
        blake3_hasher_finalize(&hasher, out.data(), out.size());
    }


    auto derive_key(const std::string_view context, const std::span<const std::uint8_t> material, const std::size_t out_len)
        -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> out(out_len);
        derive_key(context, material, out);
        return out;
    }


    auto keyed_hasher(const std::span<const std::uint8_t> key)
        -> blake3_hasher
    {
        blake3_hasher hasher;
        blake3_hasher_init_keyed(&hasher, key.data());
        return hasher;
    }


    auto keyed_hash(const std::span<const std::uint8_t> key, const std::span<const std::uint8_t> data)
        -> std::array<std::uint8_t, 32>
    {
        blake3_hasher hasher;
        blake3_hasher_init_keyed(&hasher, key.data());
        blake3_hasher_update(&hasher, data.data(), data.size());
        std::array<std::uint8_t, 32> out;
        blake3_hasher_finalize(&hasher, out.data(), out.size());
        return out;
    }


    auto hash(const std::span<const std::uint8_t> data)
        -> std::array<std::uint8_t, 32>
    {
        blake3_hasher hasher;
        blake3_hasher_init(&hasher);
        blake3_hasher_update(&hasher, data.data(), data.size());
        std::array<std::uint8_t, 32> out;
        blake3_hasher_finalize(&hasher, out.data(), out.size());
        return out;
    }

} // namespace psm::crypto
