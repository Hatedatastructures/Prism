/**
 * @file AuthHeader.hpp
 * @brief VMess AEAD 认证头密封与打开
 * @details 负责认证头的随机 nonce、长度块和请求头载荷的 wire 编排。
 *          AuthID、UUID/cmdKey 和 KDF 分别由 AuthId.hpp、AuthKdf.hpp 提供。
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <functional>
#include <limits>
#include <span>
#include <vector>

#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Utility/Crypto/Random.hpp>
#include <Prism/Protocols/Vmess/AuthId.hpp>

namespace Prism::Vmess
{

    using RandomSource = std::function<int(std::uint8_t *, int)>;

    /**
     * @brief 认证头密封输入
     */
    struct AuthHeaderInput
    {
        std::span<const std::uint8_t> Body;
        std::int64_t TimeSec{0};
        std::span<const std::uint8_t, 4> random;
    };

    /**
     * @brief 密封 AEAD 认证头
     * @param CmdKey 16 字节 cmdKey
     * @param Input 输入（body + TimeSec + random）
     * @param Source 可选随机源
     * @return 认证头字节
     */
    [[nodiscard]] inline auto SealAuthHeader(
        std::span<const std::uint8_t, 16> CmdKey,
        const AuthHeaderInput &Input,
        const RandomSource &Source) -> std::vector<std::uint8_t>
    {
        if (Input.Body.size() > (std::numeric_limits<std::uint16_t>::max)())
        {
            return {};
        }
        const auto AuthId = CreateAuthId(CmdKey, Input.TimeSec, Input.random);
        std::array<std::uint8_t, 8> Nonce8{};
        bool Filled = false;
        if (Source)
        {
            Filled = Prism::Crypto::FillRandom(std::span<std::uint8_t>(Nonce8), Source).has_value();
        }
        else
        {
            Filled = Prism::Crypto::FillRandom(std::span<std::uint8_t>(Nonce8)).has_value();
        }
        if (!Filled)
        {
            return {};
        }

        std::array<std::uint8_t, 2> LenPlain{
            static_cast<std::uint8_t>(Input.Body.size() >> 8),
            static_cast<std::uint8_t>(Input.Body.size() & 0xFF)};
        const auto LenKey = Kdf(CmdKey, KdfHeaderLenKey, AuthId, Nonce8);
        const auto LenIv = Kdf(CmdKey, KdfHeaderLenIv, AuthId, Nonce8);
        const auto LenEnc = detail::AesGcmSeal(
            detail::SealInput{std::span<const std::uint8_t>(LenKey.data(), 16),
                               std::span<const std::uint8_t>(LenIv.data(), 12), LenPlain, AuthId});
        if (LenEnc.size() != 18)
        {
            return {};
        }

        const auto HdrKey = Kdf(CmdKey, KdfHeaderKey, AuthId, Nonce8);
        const auto HdrIv = Kdf(CmdKey, KdfHeaderIv, AuthId, Nonce8);
        const auto HdrEnc = detail::AesGcmSeal(
            detail::SealInput{std::span<const std::uint8_t>(HdrKey.data(), 16),
                               std::span<const std::uint8_t>(HdrIv.data(), 12), Input.Body, AuthId});
        if (HdrEnc.size() != Input.Body.size() + 16)
        {
            return {};
        }

        std::vector<std::uint8_t> Output;
        Output.reserve(16 + LenEnc.size() + 8 + HdrEnc.size());
        Output.insert(Output.end(), AuthId.begin(), AuthId.end());
        Output.insert(Output.end(), LenEnc.begin(), LenEnc.end());
        Output.insert(Output.end(), Nonce8.begin(), Nonce8.end());
        Output.insert(Output.end(), HdrEnc.begin(), HdrEnc.end());
        return Output;
    }

    [[nodiscard]] inline auto SealAuthHeader(
        std::span<const std::uint8_t, 16> CmdKey,
        const AuthHeaderInput &Input) -> std::vector<std::uint8_t>
    {
        return SealAuthHeader(CmdKey, Input, {});
    }

    /**
     * @brief 打开 AEAD 认证头
     * @param CmdKey 16 字节 cmdKey
     * @param Header 认证头
     * @param Output 输出明文载荷
     * @return 错误码
     */
    [[nodiscard]] inline auto OpenAuthHeader(
        std::span<const std::uint8_t, 16> CmdKey,
        std::span<const std::uint8_t> Header,
        std::vector<std::uint8_t> &Output) -> Error
    {
        constexpr std::size_t AuthIdLength = 16;
        constexpr std::size_t LengthCipherLength = 18;
        constexpr std::size_t NonceLength = 8;
        constexpr std::size_t AeadTagLength = 16;
        constexpr std::size_t MinimumBodyLength = 2;
        constexpr std::size_t BodyOffset = AuthIdLength + LengthCipherLength + NonceLength;
        if (Header.size() < BodyOffset + MinimumBodyLength + AeadTagLength)
        {
            return Error::NeedMore;
        }
        const auto AuthId = Header.first(AuthIdLength);
        const auto AuthKey = Kdf(CmdKey, KdfAuthId);
        const auto AuthPlain = detail::AesEcbDecrypt(
            std::span<const std::uint8_t, 16>(AuthKey.data(), 16),
            std::span<const std::uint8_t, 16>(AuthId.data(), 16));
        const auto ExpectedCrc = detail::Crc32(
            std::span<const std::uint8_t>(AuthPlain.data(), TimestampLen + AuthRandomLen));
        std::uint32_t CrcDifference = 0;
        for (std::size_t I = 0; I < sizeof(ExpectedCrc); ++I)
        {
            const auto ExpectedByte = static_cast<std::uint8_t>(
                ExpectedCrc >> (8 * (sizeof(ExpectedCrc) - 1 - I)));
            CrcDifference |= static_cast<std::uint32_t>(
                AuthPlain[TimestampLen + AuthRandomLen + I] ^ ExpectedByte);
        }
        if (CrcDifference != 0)
        {
            return Error::BadAuth;
        }
        std::uint64_t AuthTimestamp = 0;
        for (std::size_t I = 0; I < TimestampLen; ++I)
        {
            AuthTimestamp = (AuthTimestamp << 8) | AuthPlain[I];
        }
        const auto CurrentTime = std::time(nullptr);
        if (CurrentTime < 0)
        {
            return Error::BadAuth;
        }
        const auto Now = static_cast<std::uint64_t>(CurrentTime);
        const auto Tolerance = static_cast<std::uint64_t>(TimeTolerance);
        std::uint64_t Difference = 0;
        if (Now >= AuthTimestamp)
        {
            Difference = Now - AuthTimestamp;
        }
        else
        {
            Difference = AuthTimestamp - Now;
        }
        if (Difference > Tolerance)
        {
            return Error::BadAuth;
        }
        const auto LenEnc = Header.subspan(AuthIdLength, LengthCipherLength);
        const auto Nonce8 = Header.subspan(BodyOffset - NonceLength, NonceLength);
        const auto LenKey = Kdf(CmdKey, KdfHeaderLenKey, AuthId, Nonce8);
        const auto LenIv = Kdf(CmdKey, KdfHeaderLenIv, AuthId, Nonce8);
        const auto LenPlain = detail::AesGcmOpen(
            detail::OpenInput{std::span<const std::uint8_t>(LenKey.data(), 16),
                               std::span<const std::uint8_t>(LenIv.data(), 12), LenEnc, AuthId});
        if (LenPlain.size() != 2)
        {
            return Error::BadAuth;
        }
        const auto Length = static_cast<std::size_t>(LenPlain[0]) << 8 | LenPlain[1];
        if (Header.size() < BodyOffset + Length + AeadTagLength)
        {
            return Error::NeedMore;
        }

        const auto HdrKey = Kdf(CmdKey, KdfHeaderKey, AuthId, Nonce8);
        const auto HdrIv = Kdf(CmdKey, KdfHeaderIv, AuthId, Nonce8);
        const auto Body = detail::AesGcmOpen(
            detail::OpenInput{std::span<const std::uint8_t>(HdrKey.data(), 16),
                               std::span<const std::uint8_t>(HdrIv.data(), 12),
                               Header.subspan(BodyOffset, Length + AeadTagLength), AuthId});
        if (Body.empty())
        {
            return Error::BadAuth;
        }
        Output = Body;
        return Error::None;
    }

} // namespace Prism::Vmess
