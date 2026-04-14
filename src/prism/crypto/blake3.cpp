#include <blake3.h>
#include <prism/crypto/blake3.hpp>

namespace psm::crypto
{
    // BLAKE3 密钥派生：基于上下文字符串和输入材料派生指定长度的密钥。
    //
    // BLAKE3 的 derive_key 模式比 HKDF 更快（BLAKE3 本身就比 SHA-256 快很多），
    // 且不需要"提取"和"扩展"两步。适合用于 Shadowsocks 2022 的子密钥派生。
    //
    // context：上下文字符串，用于域分离（不同用途用不同的 context，派生出的密钥就不一样）
    // material：输入密钥材料（如主密钥）
    // out_len：输出长度（BLAKE3 支持任意长度的输出）
    // out：输出缓冲区
    auto derive_key(const std::string_view context, const std::span<const std::uint8_t> material,
                    const std::size_t out_len, const std::span<std::uint8_t> out)
        -> void
    {
        blake3_hasher hasher;
        blake3_hasher_init_derive_key_raw(&hasher, context.data(), context.size());
        blake3_hasher_update(&hasher, material.data(), material.size());
        blake3_hasher_finalize(&hasher, out.data(), out_len);
    }

    // 便捷版本：自动分配输出缓冲区并返回。
    auto derive_key(const std::string_view context, const std::span<const std::uint8_t> material,
                    const std::size_t out_len)
        -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> out(out_len);
        derive_key(context, material, out_len, out);
        return out;
    }
} // namespace psm::crypto
