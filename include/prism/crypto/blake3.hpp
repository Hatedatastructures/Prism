/**
 * @file blake3.hpp
 * @brief BLAKE3 密钥派生工具
 * @details 提供 BLAKE3 derive_key 功能，用于 SS2022 (SIP022) 会话密钥派生。
 * 包装 BLAKE3 C API，提供类型安全的 C++ 接口。
 * 函数命名为 derive_key（非 blake3_derive_key）以避免与 C API 冲突。
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace psm::crypto
{
    /**
     * @brief BLAKE3 密钥派生
     * @param context 上下文字符串（如 "shadowsocks 2022 session subkey"）
     * @param material 输入密钥材料
     * @param out_len 输出密钥长度
     * @param out 输出缓冲区，必须至少 out_len 字节
     */
    auto derive_key(std::string_view context, std::span<const std::uint8_t> material, std::size_t out_len,
                    std::span<std::uint8_t> out)
        -> void;

    /**
     * @brief BLAKE3 密钥派生（返回 vector 版本）
     * @param context 上下文字符串
     * @param material 输入密钥材料
     * @param out_len 输出密钥长度
     * @return 派生出的密钥字节
     */
    [[nodiscard]] auto derive_key(std::string_view context, std::span<const std::uint8_t> material,
                                  std::size_t out_len)
        -> std::vector<std::uint8_t>;
} // namespace psm::crypto
