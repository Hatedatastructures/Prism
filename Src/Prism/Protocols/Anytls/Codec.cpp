/** @file Codec.cpp @brief AnyTLS 认证帧密码学实现。 */
#include <Prism/Protocols/Anytls/Codec.hpp>
#include <Prism/Protocols/Anytls/Frame.hpp>

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <cstring>
#include <system_error>
#include <utility>

namespace Prism::Anytls
{

    auto PasswordHash(std::string_view Password)
        -> std::array<std::uint8_t, PasswordHashLen>
    {
        std::array<std::uint8_t, PasswordHashLen> Output{};
        unsigned int Length = 0;
        (void)EVP_Digest(Password.data(), Password.size(), Output.data(), &Length,
            EVP_sha256(), nullptr);
        return Output;
    }

    auto BuildAuthFrame(std::string_view Password, std::uint16_t PadLen,
        std::string& Output) -> Error
    {
        const auto Hash = PasswordHash(Password);
        Output.clear();
        Output.reserve(AuthFrameHdrlen + PadLen);
        Output.append(reinterpret_cast<const char*>(Hash.data()), Hash.size());
        Output.push_back(static_cast<char>((PadLen >> 8) & 0xFF));
        Output.push_back(static_cast<char>(PadLen & 0xFF));
        for (std::uint16_t Index = 0; Index < PadLen; ++Index)
        {
            Output.push_back(static_cast<char>(Index * 13 + 7));
        }
        return Error::None;
    }

    auto ParseAuthFrame(std::span<const std::uint8_t> Data,
        std::array<std::uint8_t, PasswordHashLen>& Hash,
        std::uint16_t& PadLen) -> Error
    {
        if (Data.size() < AuthFrameHdrlen)
        {
            return Error::BadLength;
        }
        std::memcpy(Hash.data(), Data.data(), PasswordHashLen);
        PadLen = static_cast<std::uint16_t>(Data[PasswordHashLen]) << 8 |
            Data[PasswordHashLen + 1];
        return Data.size() < AuthFrameHdrlen + PadLen ? Error::BadLength : Error::None;
    }

    auto VerifyAuth(std::string_view Password,
        const std::array<std::uint8_t, PasswordHashLen>& Hash) -> bool
    {
        const auto Expected = PasswordHash(Password);
        return CRYPTO_memcmp(Expected.data(), Hash.data(), Hash.size()) == 0;
    }


    namespace
    {
        [[nodiscard]] auto FrameReadFailure(Prism::Fault::Failure Failure)
            -> std::expected<Frame, Error>
        {
            if (Failure.Code == Prism::Fault::Code::Eof)
            {
                return std::unexpected(Error::UnexpectedEof);
            }
            throw std::system_error(Prism::Fault::ToNative(Failure));
        }
    } // namespace

    FrameReader::FrameReader(Prism::SharedTransmission Stream)
        : Stream_(std::move(Stream))
    {
    }

    auto FrameReader::ReadExact(std::span<std::byte> Bytes)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        if (Bytes.empty())
        {
            co_return std::expected<void, Prism::Fault::Failure>{};
        }
        if (Terminal_)
        {
            co_return std::unexpected(*Terminal_);
        }
        std::size_t Offset = 0;
        while (Offset < Bytes.size())
        {
            if (!Stream_)
            {
                Terminal_ = Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument};
                co_return std::unexpected(*Terminal_);
            }
            const auto Part = co_await Stream_->ReadSome(Bytes.subspan(Offset));
            const auto Count = Part.Bytes;
            if (Count > Bytes.size() - Offset)
            {
                Terminal_ = Prism::Fault::Failure{
                    Prism::Fault::Code::InvalidArgument, Part.Failure.Native};
                co_return std::unexpected(*Terminal_);
            }
            Offset += Count;
            if (Part.Failure.Failed())
            {
                if (Offset == Bytes.size())
                {
                    Terminal_ = Part.Failure;
                    co_return std::expected<void, Prism::Fault::Failure>{};
                }
                auto Failure = Part.Failure;
                if (Failure.Code == Prism::Fault::Code::Eof && Offset != 0U)
                {
                    Failure = Prism::Fault::Failure{
                        Prism::Fault::Code::ProtocolError, Failure.Native};
                }
                Terminal_ = Failure;
                co_return std::unexpected(Failure);
            }
            if (Count == 0U)
            {
                Terminal_ = Prism::Fault::Failure{Offset == 0U
                    ? Prism::Fault::Code::Eof
                    : Prism::Fault::Code::ProtocolError};
                co_return std::unexpected(*Terminal_);
            }
        }
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    auto FrameReader::Read() -> Net::awaitable<std::expected<Frame, Error>>
    {
        if (Terminal_)
        {
            co_return FrameReadFailure(*Terminal_);
        }
        std::array<std::byte, 7> Header{};
        const auto HeaderRead = co_await ReadExact(Header);
        if (!HeaderRead)
        {
            co_return FrameReadFailure(HeaderRead.error());
        }
        Frame Result;
        Result.Kind = static_cast<Command>(std::to_integer<std::uint8_t>(Header[0]));
        if (Result.Kind > Command::ServerSettings)
        {
            if (Terminal_)
            {
                co_return FrameReadFailure(*Terminal_);
            }
            co_return std::unexpected(Error::BadMessage);
        }
        for (std::size_t Index = 1; Index != 5; ++Index)
            Result.StreamId = (Result.StreamId << 8) | std::to_integer<std::uint8_t>(Header[Index]);
        const auto Size = (std::to_integer<std::size_t>(Header[5]) << 8) |
                           std::to_integer<std::size_t>(Header[6]);
        Result.Payload.resize(Size);
        const auto PayloadRead = co_await ReadExact(Result.Payload);
        if (!PayloadRead)
        {
            co_return FrameReadFailure(PayloadRead.error());
        }
        co_return std::move(Result);
    }

    auto Encode(Frame Value) -> std::vector<std::byte>
    {
        if (Value.Payload.size() > 65535) return {};
        std::vector<std::byte> Wire{std::byte{static_cast<std::uint8_t>(Value.Kind)},
            std::byte{static_cast<std::uint8_t>(Value.StreamId >> 24)},
            std::byte{static_cast<std::uint8_t>(Value.StreamId >> 16)},
            std::byte{static_cast<std::uint8_t>(Value.StreamId >> 8)},
            std::byte{static_cast<std::uint8_t>(Value.StreamId)},
            std::byte{static_cast<std::uint8_t>(Value.Payload.size() >> 8)},
            std::byte{static_cast<std::uint8_t>(Value.Payload.size())}};
        Wire.insert(Wire.end(), Value.Payload.begin(), Value.Payload.end());
        return Wire;
    }

} // namespace Prism::Anytls
