/**
 * @file kdf.hpp
 * @brief VMess 密钥派生（KDF）
 * @details 实现 VMess AEAD KDF 链式哈希（对齐 mihomo/sing-vmess 嵌套
 *          HMAC 结构）与 UUID → cmdKey 派生：
 *          - kdf(key, paths...)：嵌套 HMAC-SHA256 链
 *          - cmd_key_from_uuid()：MD5(uuid || uuid_salt)
 *          - parse_uuid()：36 字符 UUID → 16 字节
 * @note 纯逻辑零 I/O，无状态。
 */

#pragma once

#include <common/vmess/types.hpp>

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <array>
#include <cstdint>
#include <functional>
#include <span>
#include <string_view>
#include <type_traits>
#include <vector>

namespace psmtest::vmess
{

    namespace detail
    {

        /// HMAC-SHA256 单次
        [[nodiscard]] inline auto hmac_sha256(std::span<const std::uint8_t> key,
                                              std::span<const std::uint8_t> data)
            -> std::array<std::uint8_t, 32>
        {
            std::array<std::uint8_t, 32> out{};
            unsigned int len = 0;
            HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
                 data.data(), data.size(), out.data(), &len);
            return out;
        }

        /// MD5 摘要（16 字节）
        [[nodiscard]] inline auto md5(std::span<const std::uint8_t> data)
            -> std::array<std::uint8_t, 16>
        {
            std::array<std::uint8_t, 16> out{};
            unsigned int len = 0;
            EVP_Digest(data.data(), data.size(), out.data(), &len, EVP_md5(), nullptr);
            return out;
        }

        /// SHA-256 摘要（32 字节）
        [[nodiscard]] inline auto sha256(std::span<const std::uint8_t> data)
            -> std::array<std::uint8_t, 32>
        {
            std::array<std::uint8_t, 32> out{};
            unsigned int len = 0;
            EVP_Digest(data.data(), data.size(), out.data(), &len, EVP_sha256(), nullptr);
            return out;
        }

        /// 路径转字节视图（支持 string_view / span / array）
        template <typename Path>
        [[nodiscard]] inline auto as_bytes(const Path &path) -> std::span<const std::uint8_t>
        {
            if constexpr (std::is_convertible_v<Path, std::string_view>)
            {
                const std::string_view sv(path);
                return {reinterpret_cast<const std::uint8_t *>(sv.data()), sv.size()};
            }
            else
            {
                return std::span<const std::uint8_t>(path);
            }
        }

        /// 路径填充到 64 字节块（对齐 Go hmac copyPad）
        [[nodiscard]] inline auto xor_pad(std::span<const std::uint8_t> path,
                                          std::uint8_t mask) -> std::array<std::uint8_t, 64>
        {
            std::array<std::uint8_t, 64> out{};
            const auto n = std::min(path.size(), out.size());
            std::copy(path.begin(), path.begin() + static_cast<std::ptrdiff_t>(n), out.begin());
            for (auto &b : out)
                b ^= mask;
            return out;
        }

    } // namespace detail

    /// @brief 执行 VMess AEAD KDF 链式哈希（对齐 Go 嵌套 HMAC 结构）
    /// @tparam Path 路径类型（string_view / span / array）
    /// @param key 初始密钥
    /// @param paths KDF 路径列表
    /// @return 32 字节派生密钥
    template <typename... Path>
    [[nodiscard]] auto kdf(std::span<const std::uint8_t> key, const Path &...paths)
        -> std::array<std::uint8_t, 32>
    {
        std::function<std::array<std::uint8_t, 32>(std::span<const std::uint8_t>)> h =
            [](std::span<const std::uint8_t> msg) -> std::array<std::uint8_t, 32>
        {
            return detail::hmac_sha256(detail::as_bytes(kdf_inner_marker), msg);
        };

        auto wrap = [&h](std::span<const std::uint8_t> path)
        {
            const auto prev = h;
            const auto ipad = detail::xor_pad(path, 0x36);
            const auto opad = detail::xor_pad(path, 0x5C);
            h = [prev, ipad, opad](std::span<const std::uint8_t> msg)
                -> std::array<std::uint8_t, 32>
            {
                std::vector<std::uint8_t> inner_in(64 + msg.size());
                std::copy(ipad.begin(), ipad.end(), inner_in.begin());
                std::copy(msg.begin(), msg.end(), inner_in.begin() + 64);
                const auto inner = prev(inner_in);

                std::array<std::uint8_t, 64 + 32> outer_in{};
                std::copy(opad.begin(), opad.end(), outer_in.begin());
                std::copy(inner.begin(), inner.end(), outer_in.begin() + 64);
                return prev(outer_in);
            };
        };

        (wrap(detail::as_bytes(paths)), ...);
        return h(key);
    }

    /// @brief 由 UUID 16 字节派生 cmdKey
    /// @param uuid 16 字节 UUID 原始字节
    /// @return 16 字节 cmdKey = MD5(uuid || uuid_salt)
    [[nodiscard]] inline auto cmd_key_from_uuid(std::span<const std::uint8_t, 16> uuid)
        -> std::array<std::uint8_t, 16>
    {
        std::array<std::uint8_t, 16 + 36> input{};
        std::copy(uuid.begin(), uuid.end(), input.begin());
        const auto salt = detail::as_bytes(uuid_salt);
        std::copy(salt.begin(), salt.end(), input.begin() + 16);
        return detail::md5(input);
    }

    /// @brief 解析 36 字符 UUID 字符串为 16 字节
    /// @param uuid UUID 字符串
    /// @param out 输出 16 字节
    /// @return 成功返回 true
    [[nodiscard]] inline auto parse_uuid(std::string_view uuid, std::span<std::uint8_t, 16> out) -> bool
    {
        if (uuid.size() != 36)
            return false;
        auto nibble = [](char c) -> int
        {
            if (c >= '0' && c <= '9')
                return c - '0';
            if (c >= 'a' && c <= 'f')
                return c - 'a' + 10;
            if (c >= 'A' && c <= 'F')
                return c - 'A' + 10;
            return -1;
        };
        std::size_t pos = 0;
        for (std::size_t i = 0; i < uuid.size();)
        {
            if (uuid[i] == '-')
            {
                ++i;
                continue;
            }
            if (i + 1 >= uuid.size())
                return false;
            const int hi = nibble(uuid[i]);
            const int lo = nibble(uuid[i + 1]);
            if (hi < 0 || lo < 0)
                return false;
            out[pos++] = static_cast<std::uint8_t>((hi << 4) | lo);
            i += 2;
        }
        return pos == 16;
    }

} // namespace psmtest::vmess
