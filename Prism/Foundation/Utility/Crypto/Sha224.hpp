/**
 * @file Sha224.hpp
 * @brief 固定输出 SHA224 凭据编码。
 */
#pragma once

#include <Prism/Foundation/Utility/Crypto/Operation.hpp>
#include <openssl/sha.h>
#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <expected>
#include <string_view>

namespace Prism::Crypto
{
    /**
     * @brief 计算字符串的 SHA224 十六进制凭据；输入同步借用，结果拥有 56 个字符。
     * @details 不分配字符串；逐步检查摘要操作，临时原始摘要和上下文在返回时擦除。
     *          无取消、半关闭、最终关闭或 executor 行为；失败不提供伪造凭据。
     */
    [[nodiscard]] inline auto Sha224(const std::string_view Input)
        -> std::expected<std::array<char, 56>, Fault::Failure>
    {
        SHA256_CTX Context{};
        const SecretScope ContextCleanup{
            {reinterpret_cast<std::uint8_t *>(&Context), sizeof(Context)}};
        std::array<std::uint8_t, SHA224_DIGEST_LENGTH> Hash{};
        const SecretScope HashCleanup{Hash};
        ERR_clear_error();
        if (SHA224_Init(&Context) != 1 || SHA224_Update(&Context, Input.data(), Input.size()) != 1 ||
            SHA224_Final(Hash.data(), &Context) != 1)
        {
            return std::unexpected(Detail::NativeFailure(Fault::Code::CryptoError));
        }
        std::array<char, 56> Result{};
        const SecretScope ResultCleanup{
            {reinterpret_cast<std::uint8_t *>(Result.data()), Result.size()}};
        constexpr char HexChars[] = "0123456789abcdef";
        for (std::size_t Index = 0; Index < Hash.size(); ++Index)
        {
            Result[Index * 2] = HexChars[(Hash[Index] >> 4) & 0x0F];
            Result[Index * 2 + 1] = HexChars[Hash[Index] & 0x0F];
        }
        return Result;
    }

    /** @brief 同步检查借用文本是否全部为十六进制字符，不分配或拥有资源。 */
    [[nodiscard]] inline auto IsHex(const std::string_view Text) noexcept -> bool
    {
        for (const auto Character : Text)
        {
            if (!std::isxdigit(static_cast<std::uint8_t>(Character)))
            {
                return false;
            }
        }
        return true;
    }

    /**
     * @brief 将借用凭据规范为调用者拥有的 56 字符值；已编码内容保持原字节。
     * @return 明文转换的 SHA224 失败原样返回；无取消、关闭和 executor 行为。
     */
    [[nodiscard]] inline auto NormalizeCredential(const std::string_view Credential)
        -> std::expected<std::array<char, 56>, Fault::Failure>
    {
        if (Credential.size() == 56 && IsHex(Credential))
        {
            std::array<char, 56> Result{};
            const SecretScope Cleanup{
                {reinterpret_cast<std::uint8_t *>(Result.data()), Result.size()}};
            std::copy(Credential.begin(), Credential.end(), Result.begin());
            return Result;
        }
        return Sha224(Credential);
    }
}
