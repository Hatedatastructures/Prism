/**
 * @file Codec.cpp
 * @brief Trojan 地址、凭据、请求和数据报编解码实现。
 */

#include <Prism/Foundation/ByteSpan.hpp>
#include <Prism/Protocols/Trojan/AddressCodec.hpp>
#include <Prism/Protocols/Trojan/BeastCodec.hpp>
#include <Prism/Protocols/Trojan/CredentialCodec.hpp>
#include <Prism/Protocols/Trojan/RequestCodec.hpp>
#include <Prism/Protocols/Trojan/Types.hpp>
#include <Prism/Protocols/Trojan/UdpCodec.hpp>

#include <openssl/evp.h>

#include <algorithm>
#include <cstdio>
#include <cstring>

namespace Prism::Trojan
{
    Serializer::Serializer(std::string_view Password) : Cred_(Credential(Password))
    {
    }

    auto Serializer::Reset(const Message& MessageValue) -> void
    {
        const auto CommandValue = MessageValue.Udp ? Command::UdpAssociate : MessageValue.Cmd;
        Wire_ = BuildRequest(Cred_, CommandValue, MessageValue.Target);
        Offset_ = 0;
    }

    auto Serializer::Get(boost::asio::mutable_buffer Buffer, std::error_code& ErrorCode) -> std::size_t
    {
        ErrorCode.clear();
        const auto Count = std::min(Buffer.size(), Wire_.size() - Offset_);
        std::memcpy(Buffer.data(), Wire_.data() + Offset_, Count);
        Offset_ += Count;
        return Count;
    }

    Parser::Parser(std::string_view Password, const bool ValidateCredential)
        : Cred_(Credential(Password)), ValidateCredential_(ValidateCredential)
    {
    }

    auto Parser::SetCredential(std::string_view CredentialValue, const bool ValidateCredential) -> void
    {
        Cred_ = std::string(CredentialValue);
        ValidateCredential_ = ValidateCredential;
        Reset();
    }

    [[nodiscard]] auto Parser::CredentialValue() const noexcept -> std::string_view
    {
        if (!Done_ || Buf_.size() < CredentialLen)
        {
            return {};
        }
        return {reinterpret_cast<const char*>(Buf_.data()), CredentialLen};
    }

    auto Parser::Put(boost::asio::const_buffer Buffer, std::error_code& ErrorCode) -> std::size_t
    {
        ErrorCode.clear();
        if (Done_)
        {
            return 0;
        }
        const auto Data =
            std::span<const std::uint8_t>(static_cast<const std::uint8_t*>(Buffer.data()), Buffer.size());
        const auto PreviousBufferSize = Buf_.size();
        Buf_.insert(Buf_.end(), Data.begin(), Data.end());
        std::size_t Consumed = 0;
        RequestHeader RequestValue;
        const auto ParseError = ParseRequest(Buf_, RequestValue, Consumed);
        if (ParseError == Error::NeedMore)
        {
            ErrorCode = make_error_code(Error::NeedMore);
            return 0;
        }
        if (ParseError != Error::None)
        {
            ErrorCode = make_error_code(ParseError);
            return 0;
        }
        if (ValidateCredential_ &&
            (Buf_.size() < CredentialLen ||
                !Prism::ConstantTimeEqual(
                    std::string_view(reinterpret_cast<const char*>(Buf_.data()), CredentialLen), Cred_)))
        {
            ErrorCode = make_error_code(Error::BadAuth);
            return 0;
        }
        Msg_.Cmd = RequestValue.Cmd;
        Msg_.Target = RequestValue.Target;
        Msg_.Udp = RequestValue.Cmd == Command::UdpAssociate;
        Msg_.Valid = true;
        Valid_ = true;
        Done_ = true;
        return std::min(Consumed, Buf_.size()) - PreviousBufferSize;
    }

    auto Parser::Reset() -> void
    {
        Buf_.clear();
        Msg_ = Message{};
        Valid_ = false;
        Done_ = false;
    }

    namespace Detail
    {
        [[nodiscard]] auto Sha224(std::span<const std::uint8_t> Data) -> std::array<std::uint8_t, 28>
        {
            std::array<std::uint8_t, 28> Output{};
            unsigned int Length = 0;
            EVP_Digest(Data.data(), Data.size(), Output.data(), &Length, EVP_sha224(), nullptr);
            return Output;
        }
    } // namespace Detail
    [[nodiscard]] auto Credential(std::string_view Password) -> std::string
    {
        const auto Hash = Detail::Sha224(AsU8Span(Password));
        std::string Output;
        Output.reserve(CredentialLen);
        static constexpr char Hex[] = "0123456789abcdef";
        for (const auto Byte : Hash)
        {
            Output.push_back(Hex[(Byte >> 4) & 0x0F]);
            Output.push_back(Hex[Byte & 0x0F]);
        }
        return Output;
    }

    namespace Detail
    {
        [[nodiscard]] auto FormatIpv4(const std::uint8_t* Bytes, std::string& Host) -> bool
        {
            std::array<char, 16> Buffer{};
            const auto Length = std::snprintf(Buffer.data(), Buffer.size(), "%u.%u.%u.%u",
                static_cast<unsigned int>(Bytes[0]), static_cast<unsigned int>(Bytes[1]),
                static_cast<unsigned int>(Bytes[2]), static_cast<unsigned int>(Bytes[3]));
            if (Length < 0 || static_cast<std::size_t>(Length) >= Buffer.size())
            {
                return false;
            }
            Host.assign(Buffer.data(), static_cast<std::size_t>(Length));
            return true;
        }

    } // namespace Detail

    [[nodiscard]] auto EncodeAddress(const Address& AddressValue) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Output;
        if (!EncodeAddress(AddressValue, Output))
        {
            return {};
        }
        return Output;
    }

    [[nodiscard]] auto ParseAddress(std::span<const std::uint8_t> Data, Address& Output,
        std::size_t& Consumed) -> Error
    {
        if (Data.empty())
        {
            return Error::NeedMore;
        }
        Output.Type = static_cast<AddressType>(Data[0]);
        std::size_t Offset = 1;
        switch (Output.Type)
        {
        case AddressType::Ipv4: {
            if (Data.size() - Offset < 4 + 2)
            {
                return Error::NeedMore;
            }
            if (!Detail::FormatIpv4(Data.data() + Offset, Output.Host))
            {
                return Error::BadMessage;
            }
            Offset += 4;
            break;
        }
        case AddressType::Ipv6: {
            if (Data.size() - Offset < 16 + 2)
            {
                return Error::NeedMore;
            }
            Output.Host.assign(reinterpret_cast<const char*>(Data.data() + Offset), 16);
            Offset += 16;
            break;
        }
        case AddressType::Domain: {
            if (Data.size() - Offset < 1)
            {
                return Error::NeedMore;
            }
            const auto Length = Data[Offset++];
            if (Length == 0)
            {
                return Error::BadMessage;
            }
            if (Data.size() - Offset < Length + 2)
            {
                return Error::NeedMore;
            }
            Output.Host.assign(reinterpret_cast<const char*>(Data.data() + Offset), Length);
            Offset += Length;
            break;
        }
        default:
            return Error::BadMessage;
        }
        Output.Port = static_cast<std::uint16_t>(Data[Offset]) << 8 | Data[Offset + 1];
        Offset += 2;
        Consumed = Offset;
        return Error::None;
    }

    [[nodiscard]] auto BuildRequest(std::string_view CredentialValue, Command Cmd, const Address& Target)
        -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Output;
        BuildRequest(RequestParameters{CredentialValue, Cmd, Target}, Output);
        return Output;
    }

    [[nodiscard]] auto ParseRequest(std::span<const std::uint8_t> Data, RequestHeader& Output,
        std::size_t& Consumed) -> Error
    {
        if (Data.size() < CredentialLen + 2)
        {
            return Error::NeedMore;
        }
        if (Data[CredentialLen] != '\r' || Data[CredentialLen + 1] != '\n')
        {
            return Error::BadMagic;
        }
        std::size_t Offset = CredentialLen + 2;
        if (Data.size() - Offset < 2)
        {
            return Error::NeedMore;
        }
        Output.Cmd = static_cast<Command>(Data[Offset++]);
        if (Output.Cmd != Command::Connect && Output.Cmd != Command::UdpAssociate &&
            Output.Cmd != Command::Mux)
        {
            return Error::BadMessage;
        }

        std::size_t AddressConsumed = 0;
        const auto AddressError = ParseAddress(Data.subspan(Offset), Output.Target, AddressConsumed);
        if (AddressError != Error::None)
        {
            return AddressError;
        }
        Offset += AddressConsumed;
        if (Data.size() - Offset < 2)
        {
            return Error::NeedMore;
        }
        if (Data[Offset] != '\r' || Data[Offset + 1] != '\n')
        {
            return Error::BadMagic;
        }
        Consumed = Offset + 2;
        return Error::None;
    }

    [[nodiscard]] auto BuildUdpPkt(const Address& Target, std::span<const std::uint8_t> Payload)
        -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Output;
        BuildUdpPkt(Target, Payload, Output);
        return Output;
    }

    [[nodiscard]] auto ParseUdpPkt(std::span<const std::uint8_t> Data, Address& Target,
        std::span<const std::uint8_t>& Payload) -> Error
    {
        std::size_t AddressConsumed = 0;
        const auto AddressError = ParseAddress(Data, Target, AddressConsumed);
        if (AddressError != Error::None)
        {
            return AddressError;
        }
        if (Data.size() - AddressConsumed < 4)
        {
            return Error::NeedMore;
        }
        const auto Length = static_cast<std::size_t>(Data[AddressConsumed]) << 8 | Data[AddressConsumed + 1];
        if (Data[AddressConsumed + 2] != '\r' || Data[AddressConsumed + 3] != '\n')
        {
            return Error::BadMagic;
        }
        const auto PayloadStart = AddressConsumed + 4;
        if (Data.size() - PayloadStart < Length)
        {
            return Error::NeedMore;
        }
        Payload = Data.subspan(PayloadStart, Length);
        return Error::None;
    }

} // namespace Prism::Trojan
