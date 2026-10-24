/**
 * @file Codec.cpp
 * @brief VLESS 地址、请求和 UDP 编解码实现。
 */

#include <Prism/Protocols/Vless/AddressCodec.hpp>
#include <Prism/Protocols/Vless/BeastCodec.hpp>
#include <Prism/Protocols/Vless/RequestCodec.hpp>
#include <Prism/Protocols/Vless/UdpCodec.hpp>

#include <algorithm>
#include <cstdio>
#include <cstring>

namespace Prism::Vless
{
    Serializer::Serializer(const std::array<std::uint8_t, UuidLen>& Uuid) : Uuid_(Uuid)
    {
    }

    auto Serializer::Reset(const Message& MessageValue) -> void
    {
        RequestHeader RequestValue;
        RequestValue.Version = ProtocolVersion;
        RequestValue.Uuid = Uuid_;
        RequestValue.Cmd = static_cast<Command>(MessageValue.cmd);
        RequestValue.Target = MessageValue.dst;
        Wire_ = BuildRequest(RequestValue);
        Offset_ = 0;
    }

    auto Serializer::Get(Net::mutable_buffer Buffer, std::error_code& ErrorCode) -> std::size_t
    {
        ErrorCode.clear();
        const auto Count = std::min(Buffer.size(), Wire_.size() - Offset_);
        std::memcpy(Buffer.data(), Wire_.data() + Offset_, Count);
        Offset_ += Count;
        return Count;
    }

    Parser::Parser(const std::array<std::uint8_t, UuidLen>& Uuid, const bool ValidateUuid)
        : Uuid_(Uuid), ValidateUuid_(ValidateUuid)
    {
    }

    auto Parser::Put(Net::const_buffer Buffer, std::error_code& ErrorCode) -> std::size_t
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
        // UUID 校验
        const std::string_view GotUuid(reinterpret_cast<const char*>(RequestValue.Uuid.data()),
            RequestValue.Uuid.size());
        const std::string_view ExpectedUuid(reinterpret_cast<const char*>(Uuid_.data()), Uuid_.size());
        if (ValidateUuid_ && !Prism::ConstantTimeEqual(GotUuid, ExpectedUuid))
        {
            ErrorCode = make_error_code(Error::BadAuth);
            return 0;
        }
        Msg_.uuid = RequestValue.Uuid;
        Msg_.cmd = static_cast<std::uint8_t>(RequestValue.Cmd);
        Msg_.dst = RequestValue.Target;
        Msg_.valid = true;
        Done_ = true;
        return std::min(Consumed, Buf_.size()) - PreviousBufferSize;
    }

    auto Parser::Reset() -> void
    {
        Buf_.clear();
        Msg_ = Message{};
        Done_ = false;
    }

    namespace Detail
    {
        [[nodiscard]] auto ParseAddressBody(std::span<const std::uint8_t> Data, Address& Output,
            std::size_t& Offset) -> Error
        {
            if (Offset >= Data.size())
            {
                return Error::NeedMore;
            }
            Output.Type = static_cast<AddressType>(Data[Offset++]);
            switch (Output.Type)
            {
            case AddressType::Ipv4: {
                if (Data.size() - Offset < 4)
                {
                    return Error::NeedMore;
                }
                std::array<char, 16> Buffer{};
                std::snprintf(Buffer.data(), Buffer.size(), "%u.%u.%u.%u",
                    static_cast<unsigned int>(Data[Offset]), static_cast<unsigned int>(Data[Offset + 1]),
                    static_cast<unsigned int>(Data[Offset + 2]), static_cast<unsigned int>(Data[Offset + 3]));
                Output.Host = Buffer.data();
                Offset += 4;
                break;
            }
            case AddressType::Ipv6:
                if (Data.size() - Offset < 16)
                {
                    return Error::NeedMore;
                }
                Output.Host.assign(reinterpret_cast<const char*>(Data.data() + Offset), 16);
                Offset += 16;
                break;
            case AddressType::Domain: {
                if (Offset >= Data.size())
                {
                    return Error::NeedMore;
                }
                const auto Length = Data[Offset++];
                if (Data.size() - Offset < Length)
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
            return Error::None;
        }

    } // namespace Detail

    [[nodiscard]] auto EncodeAddress(const Address& AddressValue) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Output;
        EncodeAddress(AddressValue, Output);
        return Output;
    }

    [[nodiscard]] auto ParseAddress(std::span<const std::uint8_t> Data, Address& Output, std::size_t& Offset)
        -> Error
    {
        const auto AddressError = Detail::ParseAddressBody(Data, Output, Offset);
        if (AddressError != Error::None)
        {
            return AddressError;
        }
        if (Data.size() - Offset < 2)
        {
            return Error::NeedMore;
        }
        Output.Port = static_cast<std::uint16_t>(Data[Offset]) << 8 | Data[Offset + 1];
        Offset += 2;
        return Error::None;
    }

    [[nodiscard]] auto BuildRequest(const RequestHeader& RequestValue) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Output;
        BuildRequest(RequestValue, Output);
        return Output;
    }

    [[nodiscard]] auto ParseRequest(std::span<const std::uint8_t> Data, RequestHeader& Output,
        std::size_t& Consumed) -> Error
    {
        if (Data.size() < 18)
        {
            return Error::NeedMore;
        }
        Output.Version = Data[0];
        if (Output.Version != ProtocolVersion)
        {
            return Error::BadMagic;
        }
        std::copy_n(Data.begin() + 1, UuidLen, Output.Uuid.begin());
        const auto AddnlLen = Data[17];
        const auto CommandOffset = 18U + static_cast<std::size_t>(AddnlLen);
        if (Data.size() <= CommandOffset)
        {
            return Error::NeedMore;
        }
        Output.Addons.assign(Data.begin() + 18, Data.begin() + 18 + AddnlLen);
        std::size_t Offset = CommandOffset;
        Output.Cmd = static_cast<Command>(Data[Offset++]);
        if (Output.Cmd != Command::Tcp && Output.Cmd != Command::Udp && Output.Cmd != Command::Mux)
        {
            return Error::BadMessage;
        }
        if (Output.Cmd == Command::Mux)
        {
            Output.Target.Type = AddressType::Domain;
            Output.Target.Host = "v1.mux.cool";
            Output.Target.Port = 0;
            Consumed = Offset;
            return Error::None;
        }
        if (Data.size() - Offset < 3U)
        {
            return Error::NeedMore;
        }
        Output.Target.Port = static_cast<std::uint16_t>(Data[Offset]) << 8 | Data[Offset + 1];
        Offset += 2;
        const auto AddressError = Detail::ParseAddressBody(Data, Output.Target, Offset);
        if (AddressError != Error::None)
        {
            return AddressError;
        }
        if (Output.Target.Type == AddressType::Domain && Output.Target.Host.empty())
        {
            return Error::BadMessage;
        }
        Consumed = Offset;
        return Error::None;
    }

    [[nodiscard]] auto ParseUdpPkt(const std::span<const std::uint8_t> Frame,
        std::span<const std::uint8_t>& Payload) -> UdpResult
    {
        if (Frame.size() < 2U)
        {
            return std::unexpected(UdpFailure{{Prism::Fault::Code::BadMessage}, Frame.size()});
        }

        const auto Length = (static_cast<std::size_t>(Frame[0]) << 8U) | Frame[1];
        if (Frame.size() != Length + 2U)
        {
            return std::unexpected(UdpFailure{{Prism::Fault::Code::BadMessage}, Frame.size()});
        }
        Payload = Frame.subspan(2U);
        return {};
    }

} // namespace Prism::Vless
