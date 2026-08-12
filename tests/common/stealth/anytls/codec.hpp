/**
 * @file codec.hpp
 * @brief AnyTLS 认证帧编解码（纯函数）
 * @details 对齐 mihomo transport/anytls/client.go 与
 * C++ src/prism/handshake/anytls/scheme.cpp：
 *          认证帧 = [SHA-256(password) 32B][PadLen 2B BE][Padding]
 * @note 参考 AnyTLS 协议规范。
 */

#pragma once

#include <common/core/error.hpp>
#include <common/stealth/anytls/types.hpp>

#include <openssl/evp.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace psmtest::anytls
{

    /**
     * @brief 计算密码哈希
     * @param password 密码
     * @return SHA-256(password) 32 字节
     */
    [[nodiscard]] inline auto password_hash(std::string_view password)
    -> std::array<std::uint8_t, password_hash_len>
    {
        std::array<std::uint8_t, password_hash_len> out{};
        unsigned int len = 0;
        EVP_Digest(password.data(), password.size(), out.data(), &len, EVP_sha256(), nullptr);
        return out;
    }

    /**
     * @brief 构造认证帧
     * @param password 密码
     * @param pad_len Padding 长度
     * @param out 输出帧 [hash 32][padlen 2 BE][padding]
     * @return 错误码
     */
    [[nodiscard]] inline auto build_auth_frame(std::string_view password, std::uint16_t pad_len,
                                               std::string &out) -> error
    {
        const auto hash = password_hash(password);
        out.clear();
        out.reserve(auth_frame_hdrlen + pad_len);
        out.append(reinterpret_cast<const char *>(hash.data()), hash.size());
        out.push_back(static_cast<char>((pad_len >> 8) & 0xFF));
        out.push_back(static_cast<char>(pad_len & 0xFF));
        for (std::uint16_t i = 0; i < pad_len; ++i)
            out.push_back(static_cast<char>(i * 13 + 7));
        return error::none;
    }

    /**
     * @brief 解析认证帧
     * @param data 帧数据
     * @param hash 输出密码哈希（32 字节）
     * @param pad_len 输出 Padding 长度
     * @return 错误码；bad_length = 帧过短
     */
    [[nodiscard]] inline auto parse_auth_frame(std::span<const std::uint8_t> data,
                                               std::array<std::uint8_t, password_hash_len> &hash,
                                               std::uint16_t &pad_len) -> error
    {
        if (data.size() < auth_frame_hdrlen)
            return error::bad_length;
        std::memcpy(hash.data(), data.data(), password_hash_len);
        pad_len = static_cast<std::uint16_t>(data[password_hash_len]) << 8 |
                  data[password_hash_len + 1];
        if (data.size() < auth_frame_hdrlen + pad_len)
            return error::bad_length;
        return error::none;
    }

    /**
     * @brief 校验认证帧密码
     * @param password 期望密码
     * @param hash 帧内密码哈希
     * @return true = 匹配
     */
    [[nodiscard]] inline auto verify_auth(std::string_view password,
                                          const std::array<std::uint8_t, password_hash_len> &hash)
        -> bool
    {
        const auto expected = password_hash(password);
        return std::equal(expected.begin(), expected.end(), hash.begin());
    }

} // namespace psmtest::anytls
