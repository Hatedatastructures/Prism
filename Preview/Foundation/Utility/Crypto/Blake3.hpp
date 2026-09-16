/**
 * @file Blake3.hpp
 * @brief BLAKE3 哈希与密钥派生工具
 * @details 提供 BLAKE3 的三种工作模式：
 * 1. DeriveKey：基于上下文字符串的密钥派生，用于 SS2022 会话子密钥
 * 2. keyed mode：密钥化哈希（等效 MAC），用于 Restls 认证
 * 3. Hash：普通哈希，用于数据完整性校验
 * 包装 BLAKE3 C API，提供类型安全的 C++ 接口。
 * 函数命名为 DeriveKey（非 blake3_derive_key）以避免与 C API 冲突。
 * @note 所有密钥和输出长度均为字节数。BLAKE3_KEY_LEN = 32。
 * @note 已分叉，各自演进（与主库 foundation 无镜像同步约束）
 */
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string_view>
#include <vector>

#include <blake3.h>

#include <Preview/Foundation/Error.hpp>

namespace Preview::Crypto
{

    /**
     * @brief BLAKE3 密钥派生
     * @details 使用 BLAKE3 的 DeriveKey 模式，从上下文字符串和密钥材料
     * 派生指定长度的密钥。上下文字符串用于域分离，确保不同用途
     * 派生出不同的密钥。输出长度由 out 的大小决定。
     * @param Context 上下文字符串（如 "shadowsocks 2022 session subkey"）
     * @param material 输入密钥材料
     * @param out 输出缓冲区，其大小决定派生密钥长度
     */
    void DeriveKey(std::string_view Context, std::span<const std::uint8_t> Material,
                   std::span<std::uint8_t> Output);

    /**
     * @brief BLAKE3 密钥派生（返回 vector 版本）
     * @details 使用 BLAKE3 的 DeriveKey 模式，从上下文字符串和密钥材料
     * 派生指定长度的密钥。返回包含派生密钥的 vector。
     * @param Context 上下文字符串
     * @param material 输入密钥材料
     * @param OutLen 输出密钥长度
     * @return 派生出的密钥字节
     */
    [[nodiscard]] auto DeriveKey(std::string_view Context, std::span<const std::uint8_t> Material,
                                  std::size_t OutLen) -> std::vector<std::uint8_t>;

    /**
     * @brief 初始化 BLAKE3 keyed hasher
     * @details 使用 BLAKE3 的 keyed mode（blake3_hasher_init_keyed），
     * 等效于 Go 的 blake3.New(32, key)。返回的 hasher 已初始化为密钥化状态，
     * 调用方通过 hasher_update + hasher_finalize 完成计算。
     * @note 调用方负责 hasher 的生命周期。hasher 大小约 1912 字节，适合栈分配。
     * @param key 密钥，必须恰好 32 字节（BLAKE3_KEY_LEN）
     * @return 已初始化的 blake3_hasher（值类型，可直接使用）
     */
    [[nodiscard]] auto KeyedHasher(std::span<const std::uint8_t> Key)
        -> std::expected<blake3_hasher, Preview::Error>;

    /**
     * @brief BLAKE3 密钥化哈希（便捷函数）
     * @details 计算 BLAKE3 keyed Hash，等效于一次性完成
     * init_keyed + Update + finalize。输出固定 32 字节。
     * @param key 密钥（32 字节）
     * @param Data 待哈希数据
     * @return 32 字节哈希值
     */
    [[nodiscard]] auto KeyedHash(std::span<const std::uint8_t> Key, std::span<const std::uint8_t> Data)
        -> std::expected<std::array<std::uint8_t, 32>, Preview::Error>;

    /**
     * @brief BLAKE3 普通哈希
     * @details 计算 BLAKE3 标准哈希，输出固定 32 字节。
     * @param Data 待哈希数据
     * @return 32 字节哈希值
     */
    [[nodiscard]] auto Hash(std::span<const std::uint8_t> Data) -> std::array<std::uint8_t, 32>;



    inline void DeriveKey(std::string_view Context, std::span<const std::uint8_t> Material,
                          const std::span<std::uint8_t> Output)
    {
        blake3_hasher Hasher;
        blake3_hasher_init_derive_key_raw(&Hasher, Context.data(), Context.size());
        blake3_hasher_update(&Hasher, Material.data(), Material.size());
        blake3_hasher_finalize(&Hasher, Output.data(), Output.size());
    }

    inline auto DeriveKey(std::string_view Context, std::span<const std::uint8_t> Material,
                            const std::size_t OutLen) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Output(OutLen);
        DeriveKey(Context, Material, Output);
        return Output;
    }

    inline auto KeyedHasher(std::span<const std::uint8_t> Key)
        -> std::expected<blake3_hasher, Preview::Error>
    {
        if (Key.size() != BLAKE3_KEY_LEN)
        {
            return std::unexpected(Preview::Error::BadLength);
        }
        blake3_hasher Hasher{};
        blake3_hasher_init_keyed(&Hasher, Key.data());
        return Hasher;
    }

    inline auto KeyedHash(std::span<const std::uint8_t> Key, std::span<const std::uint8_t> Data)
        -> std::expected<std::array<std::uint8_t, 32>, Preview::Error>
    {
        auto Hasher = KeyedHasher(Key);
        if (!Hasher)
        {
            return std::unexpected(Hasher.error());
        }
        auto &HasherContext = *Hasher;
        blake3_hasher_update(&HasherContext, Data.data(), Data.size());
        std::array<std::uint8_t, 32> Output{};
        blake3_hasher_finalize(&HasherContext, Output.data(), Output.size());
        return Output;
    }

    inline auto Hash(std::span<const std::uint8_t> Data) -> std::array<std::uint8_t, 32>
    {
        blake3_hasher Hasher;
        blake3_hasher_init(&Hasher);
        blake3_hasher_update(&Hasher, Data.data(), Data.size());
        std::array<std::uint8_t, 32> Output;
        blake3_hasher_finalize(&Hasher, Output.data(), Output.size());
        return Output;
    }


} // namespace Preview::Crypto
