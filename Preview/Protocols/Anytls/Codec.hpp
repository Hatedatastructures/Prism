/**
 * @file Codec.hpp
 * @brief AnyTLS 认证帧编解码（纯函数）
 * @details 对齐 mihomo transport/anytls/Client.go 与
 * C++ src/prism/handshake/anytls/scheme.cpp：
 *          认证帧 = [SHA-256(password) 32B][PadLen 2B BE][Padding]
 * @note 参考 AnyTLS 协议规范。
 */

#pragma once

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <string_view>

#include <Preview/Foundation/Error.hpp>
#include <Preview/Protocols/Anytls/Types.hpp>

namespace Preview::Anytls
{

    /**
     * @brief 计算密码哈希
     * @param Password 密码
     * @return SHA-256(password) 32 字节
     */
    [[nodiscard]] inline auto PasswordHash(std::string_view Password)
        -> std::array<std::uint8_t, PasswordHashLen>
    {
        std::array<std::uint8_t, PasswordHashLen> Output{};
        unsigned int Len = 0;
        EVP_Digest(Password.data(), Password.size(), Output.data(), &Len, EVP_sha256(), nullptr);
        return Output;
    }

    /**
     * @brief 构造认证帧
     * @param Password 密码
     * @param PadLen Padding 长度
     * @param Output 输出帧 [Hash 32][PadLen 2 BE][Padding]
     * @return 错误码
     */
    [[nodiscard]] inline auto BuildAuthFrame(
        std::string_view Password,
        std::uint16_t PadLen,
        std::string &Output) -> Error
    {
        const auto Hash = PasswordHash(Password);
        Output.clear();
        Output.reserve(AuthFrameHdrlen + PadLen);
        Output.append(reinterpret_cast<const char *>(Hash.data()), Hash.size());
        Output.push_back(static_cast<char>((PadLen >> 8) & 0xFF));
        Output.push_back(static_cast<char>(PadLen & 0xFF));
        for (std::uint16_t I = 0; I < PadLen; ++I)
        {
            Output.push_back(static_cast<char>(I * 13 + 7));
        }
        return Error::None;
    }

    /**
     * @brief 解析认证帧
     * @param Data 帧数据
     * @param Hash 输出密码哈希（32 字节）
     * @param PadLen 输出 Padding 长度
     * @return 错误码；bad_length = 帧过短
     */
    [[nodiscard]] inline auto ParseAuthFrame(
        std::span<const std::uint8_t> Data,
        std::array<std::uint8_t, PasswordHashLen> &Hash,
        std::uint16_t &PadLen) -> Error
    {
        if (Data.size() < AuthFrameHdrlen)
        {
            return Error::BadLength;
        }
        std::memcpy(Hash.data(), Data.data(), PasswordHashLen);
        PadLen = static_cast<std::uint16_t>(Data[PasswordHashLen]) << 8 | Data[PasswordHashLen + 1];
        if (Data.size() < AuthFrameHdrlen + PadLen)
        {
            return Error::BadLength;
        }
        return Error::None;
    }

    /**
     * @brief 校验认证帧密码
     * @param Password 期望密码
     * @param Hash 帧内密码哈希
     * @return true = 匹配
     */
    [[nodiscard]] inline auto VerifyAuth(
        std::string_view Password,
        const std::array<std::uint8_t, PasswordHashLen> &Hash) -> bool
    {
        const auto Expected = PasswordHash(Password);
        // 常量时间比较，避免哈希逐字节 timing 泄漏（与 Shadowtls 一致）
        return CRYPTO_memcmp(Expected.data(), Hash.data(), Hash.size()) == 0;
    }

} // namespace Preview::Anytls
