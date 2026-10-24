/**
 * @file Sha224.cpp
 * @brief 固定输出 SHA224 凭据编码实现。
 */
#include <Prism/Foundation/Utility/Crypto/Sha224.hpp>

#include <openssl/sha.h>
#include <openssl/err.h>

#include <algorithm>
#include <cctype>
#include <cstdint>

namespace Prism::Crypto
{
    auto Sha224(const std::string_view Input)
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

    auto IsHex(const std::string_view Text) noexcept -> bool
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

    auto NormalizeCredential(const std::string_view Credential)
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
} // namespace Prism::Crypto
