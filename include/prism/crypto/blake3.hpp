/**
 * @file blake3.hpp
 * @brief BLAKE3 哈希与密钥派生工具
 * @details 提供 BLAKE3 的三种工作模式：
 * 1. derive_key：基于上下文字符串的密钥派生，用于 SS2022 会话子密钥
 * 2. keyed mode：密钥化哈希（等效 MAC），用于 Restls 认证
 * 3. hash：普通哈希，用于数据完整性校验
 * 包装 BLAKE3 C API，提供类型安全的 C++ 接口。
 * 函数命名为 derive_key（非 blake3_derive_key）以避免与 C API 冲突。
 * @note 所有密钥和输出长度均为字节数。BLAKE3_KEY_LEN = 32。
 */
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

#include <blake3.h>

namespace psm::crypto
{
    // ── derive_key 模式 ──

    /**
     * @brief BLAKE3 密钥派生
     * @details 使用 BLAKE3 的 derive_key 模式，从上下文字符串和密钥材料
     * 派生指定长度的密钥。上下文字符串用于域分离，确保不同用途
     * 派生出不同的密钥。输出长度由 out 的大小决定。
     * @param context 上下文字符串（如 "shadowsocks 2022 session subkey"）
     * @param material 输入密钥材料
     * @param out 输出缓冲区，其大小决定派生密钥长度
     */
    void derive_key(std::string_view context, std::span<const std::uint8_t> material, std::span<std::uint8_t> out);

    /**
     * @brief BLAKE3 密钥派生（返回 vector 版本）
     * @details 使用 BLAKE3 的 derive_key 模式，从上下文字符串和密钥材料
     * 派生指定长度的密钥。返回包含派生密钥的 vector。
     * @param context 上下文字符串
     * @param material 输入密钥材料
     * @param out_len 输出密钥长度
     * @return 派生出的密钥字节
     */
    [[nodiscard]] auto derive_key(std::string_view context, std::span<const std::uint8_t> material, std::size_t out_len)
        -> std::vector<std::uint8_t>;

    // ── keyed mode（密钥化哈希 / MAC） ──

    /**
     * @brief 初始化 BLAKE3 keyed hasher
     * @details 使用 BLAKE3 的 keyed mode（blake3_hasher_init_keyed），
     * 等效于 Go 的 blake3.New(32, key)。返回的 hasher 已初始化为密钥化状态，
     * 调用方通过 hasher_update + hasher_finalize 完成计算。
     * @note 调用方负责 hasher 的生命周期。hasher 大小约 1912 字节，适合栈分配。
     * @param key 密钥，必须恰好 32 字节（BLAKE3_KEY_LEN）
     * @return 已初始化的 blake3_hasher（值类型，可直接使用）
     */
    [[nodiscard]] auto keyed_hasher(std::span<const std::uint8_t> key)
        -> blake3_hasher;

    /**
     * @brief BLAKE3 密钥化哈希（便捷函数）
     * @details 计算 BLAKE3 keyed hash，等效于一次性完成
     * init_keyed + update + finalize。输出固定 32 字节。
     * @param key 密钥（32 字节）
     * @param data 待哈希数据
     * @return 32 字节哈希值
     */
    [[nodiscard]] auto keyed_hash(std::span<const std::uint8_t> key, std::span<const std::uint8_t> data)
        -> std::array<std::uint8_t, 32>;

    // ── hash 模式（普通哈希） ──

    /**
     * @brief BLAKE3 普通哈希
     * @details 计算 BLAKE3 标准哈希，输出固定 32 字节。
     * @param data 待哈希数据
     * @return 32 字节哈希值
     */
    [[nodiscard]] auto hash(std::span<const std::uint8_t> data)
        -> std::array<std::uint8_t, 32>;
} // namespace psm::crypto
