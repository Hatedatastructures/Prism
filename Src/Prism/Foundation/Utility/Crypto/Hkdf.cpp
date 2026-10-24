/**
 * @file Hkdf.cpp
 * @brief SHA-256/512、HMAC 与 TLS 1.3 HKDF 实现。
 */
#include <Prism/Foundation/Utility/Crypto/Hkdf.hpp>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/hkdf.h>
#include <openssl/hmac.h>
#include <openssl/mem.h>
#include <openssl/sha.h>

#include <cstring>

namespace Prism::Crypto
{
    auto HmacSha256(const std::span<const std::uint8_t> Key,
        const std::span<const std::uint8_t> Data)
        -> std::expected<std::array<std::uint8_t, Sha256Len>, Fault::Failure>
    {
        std::array<std::uint8_t, Sha256Len> Result{};
        const SecretScope Cleanup{Result};
        unsigned int Length = 0;
        ERR_clear_error();
        if (!HMAC(EVP_sha256(), Key.data(), Key.size(), Data.data(),
            Data.size(), Result.data(), &Length) || Length != Result.size())
        {
            return std::unexpected(Detail::NativeFailure(Fault::Code::CryptoError));
        }
        return Result;
    }

    auto HmacSha512(const std::span<const std::uint8_t> Key,
        const std::span<const std::uint8_t> Data)
        -> std::expected<std::array<std::uint8_t, Sha512Len>, Fault::Failure>
    {
        std::array<std::uint8_t, Sha512Len> Result{};
        const SecretScope Cleanup{Result};
        unsigned int Length = 0;
        ERR_clear_error();
        if (!HMAC(EVP_sha512(), Key.data(), Key.size(), Data.data(),
            Data.size(), Result.data(), &Length) || Length != Result.size())
        {
            return std::unexpected(Detail::NativeFailure(Fault::Code::CryptoError));
        }
        return Result;
    }

    auto HkdfExtract(const std::span<const std::uint8_t> Salt,
        const std::span<const std::uint8_t> IKM)
        -> std::expected<std::array<std::uint8_t, Sha256Len>, Fault::Failure>
    {
        if (Salt.empty())
        {
            const std::array<std::uint8_t, Sha256Len> ZeroSalt{};
            return HmacSha256(ZeroSalt, IKM);
        }
        return HmacSha256(Salt, IKM);
    }

    auto HkdfExpand(const HkdfExpandInput Input, const std::span<std::uint8_t> Output)
        -> Fault::Failure
    {
        if (Input.Prk.size() < Sha256Len || Input.Info.size() > 514 || Output.size() > 255 * Sha256Len)
        {
            return {Fault::Code::InvalidArgument, {}};
        }
        if (Output.empty())
        {
            return {};
        }
        ERR_clear_error();
        if (HKDF_expand(Output.data(), Output.size(), EVP_sha256(), Input.Prk.data(),
            Input.Prk.size(), Input.Info.data(), Input.Info.size()) != 1)
        {
            const auto Failure = Detail::NativeFailure(Fault::Code::CryptoError);
            OPENSSL_cleanse(Output.data(), Output.size());
            return Failure;
        }
        return {};
    }

    auto ExpandLabel(const ExpandParams Params, const std::span<std::uint8_t> Output)
        -> Fault::Failure
    {
        constexpr std::string_view Prefix = "tls13 ";
        if (Params.Label.size() > 255 - Prefix.size() || Params.Context.size() > 255 ||
            Output.size() > 255 * Sha256Len)
        {
            return {Fault::Code::InvalidArgument, {}};
        }
        std::array<std::uint8_t, 2 + 1 + 255 + 1 + 255> LabelBuffer{};
        const SecretScope Cleanup{LabelBuffer};
        std::size_t Position = 0;
        LabelBuffer[Position++] = static_cast<std::uint8_t>(Output.size() >> 8);
        LabelBuffer[Position++] = static_cast<std::uint8_t>(Output.size() & 0xFF);
        LabelBuffer[Position++] = static_cast<std::uint8_t>(Prefix.size() + Params.Label.size());
        std::memcpy(LabelBuffer.data() + Position, Prefix.data(), Prefix.size());
        Position += Prefix.size();
        if (!Params.Label.empty())
        {
            std::memcpy(LabelBuffer.data() + Position, Params.Label.data(), Params.Label.size());
            Position += Params.Label.size();
        }
        LabelBuffer[Position++] = static_cast<std::uint8_t>(Params.Context.size());
        if (!Params.Context.empty())
        {
            std::memcpy(LabelBuffer.data() + Position, Params.Context.data(), Params.Context.size());
            Position += Params.Context.size();
        }
        return HkdfExpand({Params.Secret, {LabelBuffer.data(), Position}}, Output);
    }

    auto Sha256(const HashInput Input)
        -> std::expected<std::array<std::uint8_t, Sha256Len>, Fault::Failure>
    {
        SHA256_CTX Context{};
        const SecretScope ContextCleanup{
            {reinterpret_cast<std::uint8_t *>(&Context), sizeof(Context)}};
        std::array<std::uint8_t, Sha256Len> Output{};
        const SecretScope OutputCleanup{Output};
        ERR_clear_error();
        if (SHA256_Init(&Context) != 1)
        {
            return std::unexpected(Detail::NativeFailure(Fault::Code::CryptoError));
        }
        for (const auto Segment : Input.Segments)
        {
            if (SHA256_Update(&Context, Segment.data(), Segment.size()) != 1)
            {
                return std::unexpected(Detail::NativeFailure(Fault::Code::CryptoError));
            }
        }
        if (SHA256_Final(Output.data(), &Context) != 1)
        {
            return std::unexpected(Detail::NativeFailure(Fault::Code::CryptoError));
        }
        return Output;
    }
} // namespace Prism::Crypto
