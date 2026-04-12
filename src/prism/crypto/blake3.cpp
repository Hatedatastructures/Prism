/**
 * @file blake3.cpp
 * @brief BLAKE3 密钥派生实现
 * @details 使用 BLAKE3 C API 的流式接口实现 derive_key。
 * BLAKE3 C API 提供 blake3_hasher_init_derive_key + update + finalize，
 * 本文件将其包装为便捷的 derive_key 函数。
 */

#include <blake3.h>
#include <prism/crypto/blake3.hpp>

namespace psm::crypto
{
    auto derive_key(const std::string_view context, const std::span<const std::uint8_t> material,
                    const std::size_t out_len, const std::span<std::uint8_t> out)
        -> void
    {
        blake3_hasher hasher;
        blake3_hasher_init_derive_key_raw(&hasher, context.data(), context.size());
        blake3_hasher_update(&hasher, material.data(), material.size());
        blake3_hasher_finalize(&hasher, out.data(), out_len);
    }

    auto derive_key(const std::string_view context, const std::span<const std::uint8_t> material,
                    const std::size_t out_len)
        -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> out(out_len);
        derive_key(context, material, out_len, out);
        return out;
    }
} // namespace psm::crypto
