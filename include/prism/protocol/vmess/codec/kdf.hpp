/**
 * @file kdf.hpp
 * @brief VMess 密钥派生函数
 * @details 实现 VMess AEAD 嵌套 HMAC-SHA256 KDF 与 cmdKey 派生。
 *          对齐 mihomo/sing-vmess 的 hMacCreator 嵌套哈希结构：
 *          H0 = HMAC-SHA256(key="VMess AEAD KDF")
 *          Hn = HMAC(哈希=Hn-1, key=pathN)
 *             = Hn-1( (pathN⊕opad) || Hn-1( (pathN⊕ipad) || msg ) )
 */

#pragma once

#include <prism/protocol/vmess/constants.hpp>

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <functional>
#include <span>
#include <string_view>
#include <type_traits>
#include <vector>

namespace psm::protocol::vmess::codec
{

    /// KDF 最内层固定盐
    inline constexpr std::string_view kdf_inner_marker = "VMess AEAD KDF";

    /**
     * @brief 将路径参数归一化为字节视图
     * @tparam Path 路径类型（string_view / span / array）
     * @param path 路径参数
     * @return 字节视图
     */
    template <typename Path>
    [[nodiscard]] inline auto as_span(const Path &path) -> std::span<const std::uint8_t>
    {
        if constexpr (std::is_convertible_v<Path, std::string_view>)
        {
            const std::string_view sv(path);
            return std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(sv.data()),
                                                 sv.size());
        }
        else
        {
            return std::span<const std::uint8_t>(path);
        }
    }

    namespace detail
    {

        /**
         * 标准 HMAC-SHA256
         */
        [[nodiscard]] inline auto hmac_sha256(const std::span<const std::uint8_t> key,
                                              const std::span<const std::uint8_t> msg)
            -> std::array<std::uint8_t, 32>
        {
            std::array<std::uint8_t, 32> out{};
            unsigned int len = 0;
            HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), msg.data(), msg.size(), out.data(),
                 &len);
            return out;
        }

        /**
         * @brief 路径段填充到 64 字节并与掩码异或（对齐 Go hmac copyPad）
         * @details copy 一次 key，剩余字节按 0 填充后再异或掩码
         */
        [[nodiscard]] inline auto xor_pad(const std::span<const std::uint8_t> path, const std::uint8_t mask)
            -> std::array<std::uint8_t, 64>
        {
            std::array<std::uint8_t, 64> out{};
            const auto n = std::min(path.size(), out.size());
            std::ranges::copy(path.first(n), out.begin());
            for (auto &b : out)
            {
                b ^= mask;
            }
            return out;
        }

    } // namespace detail

    /**
     * @brief 执行 VMess AEAD KDF 链式派生（mihomo/sing-vmess 嵌套哈希结构）
     * @param key 输入密钥
     * @param paths KDF 路径段列表（string_view / span / array）
     * @return 32 字节派生结果
     * @details 哈希函数链逐层包裹：H0 = HMAC-SHA256("VMess AEAD KDF")，
     *          每段路径作为一层 HMAC 的 key 包裹前一层哈希。
     */
    template <typename... Path>
    [[nodiscard]] auto kdf(const std::span<const std::uint8_t> key, const Path &...paths)
        -> std::array<std::uint8_t, 32>
    {
        // H0 = HMAC-SHA256(key="VMess AEAD KDF")
        std::function<std::array<std::uint8_t, 32>(std::span<const std::uint8_t>)> h =
            [](const std::span<const std::uint8_t> msg) -> std::array<std::uint8_t, 32>
        {
            const auto marker = as_span(kdf_inner_marker);
            return detail::hmac_sha256(marker, msg);
        };

        // 每段路径包裹一层：Hn(msg) = Hn-1(path⊕opad || Hn-1(path⊕ipad || msg))
        auto wrap = [&h](const std::span<const std::uint8_t> path)
        {
            const auto prev = h;
            const auto ipad = detail::xor_pad(path, 0x36);
            const auto opad = detail::xor_pad(path, 0x5C);
            h = [prev, ipad, opad](const std::span<const std::uint8_t> msg) -> std::array<std::uint8_t, 32>
            {
                std::vector<std::uint8_t> inner_in(64 + msg.size());
                std::ranges::copy(ipad, inner_in.begin());
                std::ranges::copy(msg, inner_in.begin() + 64);
                const auto inner = prev(inner_in);

                std::array<std::uint8_t, 64 + 32> outer_in{};
                std::ranges::copy(opad, outer_in.begin());
                std::ranges::copy(inner, outer_in.begin() + 64);
                return prev(outer_in);
            };
        };

        (wrap(as_span(paths)), ...);
        return h(key);
    }

    /**
     * @brief 从 UUID 派生连接密钥 cmdKey
     * @param uuid 16 字节 UUID 原始字节
     * @return 16 字节 cmdKey = MD5(uuid || uuid_salt)
     */
    [[nodiscard]] inline auto cmd_key_from_uuid(const std::span<const std::uint8_t, 16> uuid)
        -> std::array<std::uint8_t, 16>
    {
        std::array<std::uint8_t, 16> result{};
        std::array<std::uint8_t, 52> input{};
        std::ranges::copy(uuid, input.begin());
        std::ranges::copy(uuid_salt, input.begin() + 16);
        unsigned int len = 0;
        EVP_Digest(input.data(), input.size(), result.data(), &len, EVP_md5(), nullptr);
        return result;
    }

    /**
     * @brief 解析 36 字符 UUID 字符串为 16 字节
     * @param uuid UUID 字符串（含连字符）
     * @param out 输出 16 字节
     * @return 解析成功返回 true
     */
    [[nodiscard]] inline auto parse_uuid(const std::string_view uuid, std::span<std::uint8_t, 16> out) -> bool
    {
        if (uuid.size() != 36)
        {
            return false;
        }
        auto nibble = [](const char c) -> int
        {
            if (c >= '0' && c <= '9')
            {
                return c - '0';
            }
            if (c >= 'a' && c <= 'f')
            {
                return c - 'a' + 10;
            }
            if (c >= 'A' && c <= 'F')
            {
                return c - 'A' + 10;
            }
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
            {
                return false;
            }
            const int hi = nibble(uuid[i]);
            const int lo = nibble(uuid[i + 1]);
            if (hi < 0 || lo < 0)
            {
                return false;
            }
            out[pos++] = static_cast<std::uint8_t>((hi << 4) | lo);
            i += 2;
        }
        return pos == 16;
    }

} // namespace psm::protocol::vmess::codec
