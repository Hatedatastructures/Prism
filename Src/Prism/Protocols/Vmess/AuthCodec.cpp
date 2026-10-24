/**
 * @file AuthCodec.cpp
 * @brief VMess 认证与加密编解码实现。
 */

#include <Prism/Foundation/Utility/Crypto/Random.hpp>
#include <Prism/Protocols/Vmess/AuthCrypto.hpp>
#include <Prism/Protocols/Vmess/AuthHeader.hpp>
#include <Prism/Protocols/Vmess/AuthId.hpp>
#include <Prism/Protocols/Vmess/AuthKdf.hpp>

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <limits>
#include <vector>

namespace Prism::Vmess
{
    namespace Detail
    {
        [[nodiscard]] auto KdfStage::operator()(std::span<const std::uint8_t> Message) const
            -> std::array<std::uint8_t, 32>
        {
            std::vector<std::uint8_t> InnerIn(64 + Message.size());
            std::copy(Ipad.begin(), Ipad.end(), InnerIn.begin());
            std::copy(Message.begin(), Message.end(), InnerIn.begin() + 64);
            const auto Inner = Previous(InnerIn);

            std::array<std::uint8_t, 64 + 32> OuterIn{};
            std::copy(Opad.begin(), Opad.end(), OuterIn.begin());
            std::copy(Inner.begin(), Inner.end(), OuterIn.begin() + 64);
            return Previous(OuterIn);
        }

        [[nodiscard]] auto BaseKdf(std::span<const std::uint8_t> Message) -> std::array<std::uint8_t, 32>
        {
            return detail::HmacSha256(detail::AsBytes(KdfInnerMarker), Message);
        }

        auto AppendKdfStage(KdfFunction& Chain, std::span<const std::uint8_t> Path) -> void
        {
            Chain = KdfStage{Chain, detail::XorPad(Path, 0x36), detail::XorPad(Path, 0x5C)};
        }
    } // namespace Detail

    namespace detail
    {
        [[nodiscard]] auto HmacSha256(std::span<const std::uint8_t> Key, std::span<const std::uint8_t> Data)
            -> std::array<std::uint8_t, 32>
        {
            std::array<std::uint8_t, 32> Output{};
            constexpr auto MaxInt = static_cast<std::size_t>((std::numeric_limits<int>::max)());
            if (Key.size() > MaxInt)
            {
                return {};
            }
            unsigned int Len = 0;
            const auto* Result = HMAC(EVP_sha256(), Key.data(), static_cast<int>(Key.size()), Data.data(),
                Data.size(), Output.data(), &Len);
            if (Result == nullptr || Len != Output.size())
            {
                return {};
            }
            return Output;
        }

        [[nodiscard]] auto Md5(std::span<const std::uint8_t> Data) -> std::array<std::uint8_t, 16>
        {
            std::array<std::uint8_t, 16> Output{};
            unsigned int Len = 0;
            EVP_Digest(Data.data(), Data.size(), Output.data(), &Len, EVP_md5(), nullptr);
            return Output;
        }

        [[nodiscard]] auto Sha256(std::span<const std::uint8_t> Data) -> std::array<std::uint8_t, 32>
        {
            std::array<std::uint8_t, 32> Output{};
            unsigned int Len = 0;
            EVP_Digest(Data.data(), Data.size(), Output.data(), &Len, EVP_sha256(), nullptr);
            return Output;
        }

        [[nodiscard]] auto XorPad(std::span<const std::uint8_t> Path, std::uint8_t Mask)
            -> std::array<std::uint8_t, 64>
        {
            std::array<std::uint8_t, 64> Output{};
            const auto Count = std::min(Path.size(), Output.size());
            std::copy(Path.begin(), Path.begin() + static_cast<std::ptrdiff_t>(Count), Output.begin());
            for (auto& Byte : Output)
            {
                Byte ^= Mask;
            }
            return Output;
        }

        [[nodiscard]] auto ValidAesGcmInput(const SealInput& Input) noexcept -> bool
        {
            constexpr auto MaxInt = static_cast<std::size_t>((std::numeric_limits<int>::max)());
            return Input.Key.size() == 16 && Input.Nonce.size() == 12 && Input.Plain.size() <= MaxInt &&
                Input.Aad.size() <= MaxInt;
        }

        [[nodiscard]] auto ValidAesGcmInput(const OpenInput& Input) noexcept -> bool
        {
            constexpr auto MaxInt = static_cast<std::size_t>((std::numeric_limits<int>::max)());
            return Input.Key.size() == 16 && Input.Nonce.size() == 12 && Input.Cipher.size() <= MaxInt &&
                Input.Aad.size() <= MaxInt;
        }

        [[nodiscard]] auto AesGcmSeal(const SealInput& Input) -> std::vector<std::uint8_t>
        {
            if (!ValidAesGcmInput(Input))
            {
                return {};
            }
            std::vector<std::uint8_t> Output(Input.Plain.size() + 16);
            EVP_CIPHER_CTX* Context = EVP_CIPHER_CTX_new();
            if (!Context)
            {
                return {};
            }
            int Len = 0;
            bool Ok = EVP_EncryptInit_ex(Context, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) == 1;
            Ok = Ok && EVP_CIPHER_CTX_ctrl(Context, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr) == 1;
            Ok = Ok &&
                EVP_EncryptInit_ex(Context, nullptr, nullptr, Input.Key.data(), Input.Nonce.data()) == 1;
            if (Ok && !Input.Aad.empty())
            {
                Ok = EVP_EncryptUpdate(Context, nullptr, &Len, Input.Aad.data(),
                         static_cast<int>(Input.Aad.size())) == 1;
            }
            int OutLen = 0;
            if (Ok)
            {
                Ok = EVP_EncryptUpdate(Context, Output.data(), &Len, Input.Plain.data(),
                         static_cast<int>(Input.Plain.size())) == 1;
                OutLen = Len;
            }
            if (Ok)
            {
                Ok = EVP_EncryptFinal_ex(Context, Output.data() + OutLen, &Len) == 1;
                OutLen += Len;
            }
            if (Ok)
            {
                Ok = EVP_CIPHER_CTX_ctrl(Context, EVP_CTRL_GCM_GET_TAG, 16, Output.data() + OutLen) == 1;
            }
            if (!Ok || OutLen != static_cast<int>(Input.Plain.size()))
            {
                EVP_CIPHER_CTX_free(Context);
                return {};
            }
            Output.resize(static_cast<std::size_t>(OutLen) + 16);
            EVP_CIPHER_CTX_free(Context);
            return Output;
        }

        [[nodiscard]] auto AesGcmOpen(const OpenInput& Input) -> std::vector<std::uint8_t>
        {
            if (Input.Cipher.size() < 16)
            {
                return {};
            }
            const auto CipherLen = Input.Cipher.size() - 16;
            const OpenInput ValidInput{Input.Key, Input.Nonce,
                std::span<const std::uint8_t>(Input.Cipher).subspan(0, CipherLen), Input.Aad};
            if (!ValidAesGcmInput(ValidInput))
            {
                return {};
            }
            std::vector<std::uint8_t> Output(CipherLen);
            EVP_CIPHER_CTX* Context = EVP_CIPHER_CTX_new();
            if (!Context)
            {
                return {};
            }
            int Len = 0;
            bool Ok = EVP_DecryptInit_ex(Context, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) == 1;
            Ok = Ok && EVP_CIPHER_CTX_ctrl(Context, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr) == 1;
            Ok = Ok &&
                EVP_DecryptInit_ex(Context, nullptr, nullptr, Input.Key.data(), Input.Nonce.data()) == 1;
            if (Ok && !Input.Aad.empty())
            {
                Ok = EVP_DecryptUpdate(Context, nullptr, &Len, Input.Aad.data(),
                         static_cast<int>(Input.Aad.size())) == 1;
            }
            int OutLen = 0;
            if (Ok && CipherLen > 0)
            {
                Ok = EVP_DecryptUpdate(Context, Output.data(), &Len, Input.Cipher.data(),
                         static_cast<int>(CipherLen)) == 1;
                OutLen = Len;
            }
            if (Ok)
            {
                Ok = EVP_CIPHER_CTX_ctrl(Context, EVP_CTRL_GCM_SET_TAG, 16,
                         const_cast<std::uint8_t*>(Input.Cipher.data()) + CipherLen) == 1;
            }
            if (Ok)
            {
                std::array<std::uint8_t, 16> FinalOutput{};
                std::uint8_t* FinalData = nullptr;
                if (Output.empty())
                {
                    FinalData = FinalOutput.data();
                }
                else
                {
                    FinalData = Output.data() + OutLen;
                }
                Ok = EVP_DecryptFinal_ex(Context, FinalData, &Len) == 1;
                OutLen += Len;
            }
            EVP_CIPHER_CTX_free(Context);
            if (!Ok || OutLen != static_cast<int>(CipherLen))
            {
                return {};
            }
            Output.resize(static_cast<std::size_t>(OutLen));
            return Output;
        }

        [[nodiscard]] auto Fnv1a32(std::span<const std::uint8_t> Data) -> std::uint32_t
        {
            std::uint32_t H = 0x811C9DC5;
            for (const auto Byte : Data)
            {
                H ^= Byte;
                H *= 0x01000193;
            }
            return H;
        }

        [[nodiscard]] auto AesEcbEncrypt(std::span<const std::uint8_t, 16> Key,
            std::span<const std::uint8_t, 16> Plain) -> std::array<std::uint8_t, 16>
        {
            std::array<std::uint8_t, 16> Out{};
            EVP_CIPHER_CTX* Ctx = EVP_CIPHER_CTX_new();
            if (!Ctx)
            {
                return {};
            }
            int Len = 0;
            int Total = 0;
            const bool Ok = EVP_EncryptInit_ex(Ctx, EVP_aes_128_ecb(), nullptr, Key.data(), nullptr) == 1 &&
                EVP_CIPHER_CTX_set_padding(Ctx, 0) == 1 &&
                EVP_EncryptUpdate(Ctx, Out.data(), &Len, Plain.data(), Plain.size()) == 1;
            if (Ok)
            {
                Total = Len;
                const bool FinalOk = EVP_EncryptFinal_ex(Ctx, Out.data() + Total, &Len) == 1;
                Total += Len;
                EVP_CIPHER_CTX_free(Ctx);
                if (!FinalOk || Total != static_cast<int>(Out.size()))
                {
                    return {};
                }
                return Out;
            }
            EVP_CIPHER_CTX_free(Ctx);
            return {};
        }

        [[nodiscard]] auto AesEcbDecrypt(std::span<const std::uint8_t, 16> Key,
            std::span<const std::uint8_t, 16> Cipher) -> std::array<std::uint8_t, 16>
        {
            std::array<std::uint8_t, 16> Out{};
            EVP_CIPHER_CTX* Ctx = EVP_CIPHER_CTX_new();
            if (!Ctx)
            {
                return {};
            }
            int Len = 0;
            int Total = 0;
            const bool Ok = EVP_DecryptInit_ex(Ctx, EVP_aes_128_ecb(), nullptr, Key.data(), nullptr) == 1 &&
                EVP_CIPHER_CTX_set_padding(Ctx, 0) == 1 &&
                EVP_DecryptUpdate(Ctx, Out.data(), &Len, Cipher.data(), Cipher.size()) == 1;
            if (Ok)
            {
                Total = Len;
                const bool FinalOk = EVP_DecryptFinal_ex(Ctx, Out.data() + Total, &Len) == 1;
                Total += Len;
                EVP_CIPHER_CTX_free(Ctx);
                if (!FinalOk || Total != static_cast<int>(Out.size()))
                {
                    return {};
                }
                return Out;
            }
            EVP_CIPHER_CTX_free(Ctx);
            return {};
        }

        [[nodiscard]] auto HexNibble(const char Character) noexcept -> int
        {
            if (Character >= '0' && Character <= '9')
            {
                return Character - '0';
            }
            if (Character >= 'a' && Character <= 'f')
            {
                return Character - 'a' + 10;
            }
            if (Character >= 'A' && Character <= 'F')
            {
                return Character - 'A' + 10;
            }
            return -1;
        }

        [[nodiscard]] auto Crc32(std::span<const std::uint8_t> Data) -> std::uint32_t
        {
            std::uint32_t Crc = 0xFFFFFFFFU;
            for (const auto Byte : Data)
            {
                Crc ^= Byte;
                for (int I = 0; I < 8; ++I)
                {
                    if ((Crc & 1U) != 0U)
                    {
                        Crc = (Crc >> 1) ^ 0xEDB88320U;
                    }
                    else
                    {
                        Crc >>= 1;
                    }
                }
            }
            return Crc ^ 0xFFFFFFFFU;
        }

        [[nodiscard]] auto EncodeTimestamp(std::int64_t Ts) -> std::array<std::uint8_t, 8>
        {
            std::array<std::uint8_t, 8> Output{};
            const auto U = static_cast<std::uint64_t>(Ts);
            for (std::size_t I = 0; I < 8; ++I)
            {
                Output[7 - I] = static_cast<std::uint8_t>((U >> (I * 8)) & 0xFF);
            }
            return Output;
        }

    } // namespace detail

    [[nodiscard]] auto CmdKeyFromUuid(std::span<const std::uint8_t, 16> Uuid) -> std::array<std::uint8_t, 16>
    {
        std::array<std::uint8_t, 16 + 36> Input{};
        std::copy(Uuid.begin(), Uuid.end(), Input.begin());
        const auto Salt = detail::AsBytes(UuidSalt);
        std::copy(Salt.begin(), Salt.end(), Input.begin() + 16);
        return detail::Md5(Input);
    }

    [[nodiscard]] auto ParseUuid(std::string_view Uuid, std::span<std::uint8_t, 16> Output) -> bool
    {
        if (Uuid.size() != 36)
        {
            return false;
        }
        constexpr std::array<std::size_t, 5> GroupLengths{8, 4, 4, 4, 12};
        std::size_t InputPos = 0;
        std::size_t OutputPos = 0;
        for (std::size_t Group = 0; Group < GroupLengths.size(); ++Group)
        {
            for (std::size_t Byte = 0; Byte < GroupLengths[Group] / 2; ++Byte)
            {
                const int Hi = detail::HexNibble(Uuid[InputPos]);
                const int Lo = detail::HexNibble(Uuid[InputPos + 1]);
                if (Hi < 0 || Lo < 0)
                {
                    return false;
                }
                Output[OutputPos++] = static_cast<std::uint8_t>((Hi << 4) | Lo);
                InputPos += 2;
            }
            if (Group + 1 < GroupLengths.size())
            {
                if (Uuid[InputPos] != '-')
                {
                    return false;
                }
                ++InputPos;
            }
        }
        return InputPos == Uuid.size() && OutputPos == Output.size();
    }

    [[nodiscard]] auto CreateAuthId(std::span<const std::uint8_t, 16> CmdKey, std::int64_t TimeSec,
        std::span<const std::uint8_t, 4> RandomBytes) -> std::array<std::uint8_t, 16>
    {
        std::array<std::uint8_t, 16> Plain{};
        const auto Ts = detail::EncodeTimestamp(TimeSec);
        std::copy(Ts.begin(), Ts.end(), Plain.begin());
        std::copy(RandomBytes.begin(), RandomBytes.end(), Plain.begin() + TimestampLen);
        const auto Crc =
            detail::Crc32(std::span<const std::uint8_t>(Plain.data(), TimestampLen + AuthRandomLen));
        for (std::size_t I = 0; I < sizeof(Crc); ++I)
        {
            Plain[TimestampLen + AuthRandomLen + I] =
                static_cast<std::uint8_t>(Crc >> (8 * (sizeof(Crc) - 1 - I)));
        }
        const auto AuthKey = Kdf(CmdKey, KdfAuthId);
        return detail::AesEcbEncrypt(std::span<const std::uint8_t, 16>(AuthKey.data(), 16), Plain);
    }

    [[nodiscard]] auto SealAuthHeader(std::span<const std::uint8_t, 16> CmdKey, const AuthHeaderInput& Input,
        const RandomSource& Source) -> std::vector<std::uint8_t>
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

        std::array<std::uint8_t, 2> LenPlain{static_cast<std::uint8_t>(Input.Body.size() >> 8),
            static_cast<std::uint8_t>(Input.Body.size() & 0xFF)};
        const auto LenKey = Kdf(CmdKey, KdfHeaderLenKey, AuthId, Nonce8);
        const auto LenIv = Kdf(CmdKey, KdfHeaderLenIv, AuthId, Nonce8);
        const auto LenEnc =
            detail::AesGcmSeal(detail::SealInput{std::span<const std::uint8_t>(LenKey.data(), 16),
                std::span<const std::uint8_t>(LenIv.data(), 12), LenPlain, AuthId});
        if (LenEnc.size() != 18)
        {
            return {};
        }

        const auto HdrKey = Kdf(CmdKey, KdfHeaderKey, AuthId, Nonce8);
        const auto HdrIv = Kdf(CmdKey, KdfHeaderIv, AuthId, Nonce8);
        const auto HdrEnc =
            detail::AesGcmSeal(detail::SealInput{std::span<const std::uint8_t>(HdrKey.data(), 16),
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

    [[nodiscard]] auto SealAuthHeader(std::span<const std::uint8_t, 16> CmdKey, const AuthHeaderInput& Input)
        -> std::vector<std::uint8_t>
    {
        return SealAuthHeader(CmdKey, Input, {});
    }

    [[nodiscard]] auto OpenAuthHeader(std::span<const std::uint8_t, 16> CmdKey,
        std::span<const std::uint8_t> Header, std::vector<std::uint8_t>& Output) -> Error
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
        const auto AuthPlain = detail::AesEcbDecrypt(std::span<const std::uint8_t, 16>(AuthKey.data(), 16),
            std::span<const std::uint8_t, 16>(AuthId.data(), 16));
        const auto ExpectedCrc =
            detail::Crc32(std::span<const std::uint8_t>(AuthPlain.data(), TimestampLen + AuthRandomLen));
        std::uint32_t CrcDifference = 0;
        for (std::size_t I = 0; I < sizeof(ExpectedCrc); ++I)
        {
            const auto ExpectedByte =
                static_cast<std::uint8_t>(ExpectedCrc >> (8 * (sizeof(ExpectedCrc) - 1 - I)));
            CrcDifference |=
                static_cast<std::uint32_t>(AuthPlain[TimestampLen + AuthRandomLen + I] ^ ExpectedByte);
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
        const auto LenPlain =
            detail::AesGcmOpen(detail::OpenInput{std::span<const std::uint8_t>(LenKey.data(), 16),
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
        const auto Body = detail::AesGcmOpen(detail::OpenInput{
            std::span<const std::uint8_t>(HdrKey.data(), 16), std::span<const std::uint8_t>(HdrIv.data(), 12),
            Header.subspan(BodyOffset, Length + AeadTagLength), AuthId});
        if (Body.empty())
        {
            return Error::BadAuth;
        }
        Output = Body;
        return Error::None;
    }

} // namespace Prism::Vmess
