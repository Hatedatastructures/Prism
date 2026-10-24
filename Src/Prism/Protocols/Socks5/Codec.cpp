/**
 * @file Codec.cpp
 * @brief SOCKS5 地址、消息和认证编解码实现。
 */

#include <Prism/Protocols/Socks5/AddressCodec.hpp>
#include <Prism/Protocols/Socks5/AuthCodec.hpp>
#include <Prism/Protocols/Socks5/BeastCodec.hpp>
#include <Prism/Protocols/Socks5/MessageCodec.hpp>
#include <Prism/Protocols/Socks5/TransportCodec.hpp>

#include <algorithm>
#include <charconv>
#include <cstring>
#include <system_error>

namespace Prism::Socks5
{
    auto Serializer::Reset(const Message& MessageValue) -> void
    {
        Wire_.clear();
        Offset_ = 0;
        switch (MessageValue.Type)
        {
        case Message::Kind::Greeting: {
            Greeting GreetingValue;
            GreetingValue.Ver = Version;
            GreetingValue.Methods = MessageValue.Methods;
            Wire_ = BuildGreeting(GreetingValue);
            break;
        }
        case Message::Kind::MethodReply: {
            MethodReply MethodReplyValue;
            MethodReplyValue.Ver = Version;
            MethodReplyValue.Method = static_cast<AuthMethod>(MessageValue.Method);
            const auto Wire = BuildMethodReply(MethodReplyValue);
            Wire_.assign(Wire.begin(), Wire.end());
            break;
        }
        case Message::Kind::Userpass:
            Wire_ = BuildUserpass(MessageValue.Username, MessageValue.Password);
            break;
        case Message::Kind::Request: {
            Request RequestValue;
            RequestValue.Ver = Version;
            RequestValue.Cmd = MessageValue.Cmd;
            RequestValue.Target = MessageValue.AddressValue;
            Wire_ = BuildRequest(RequestValue);
            break;
        }
        case Message::Kind::Reply: {
            Reply ReplyValue;
            ReplyValue.Ver = Version;
            ReplyValue.Code = MessageValue.Code;
            ReplyValue.Bind = MessageValue.AddressValue;
            Wire_ = BuildReply(ReplyValue);
            break;
        }
        }
    }

    auto Serializer::Get(Net::mutable_buffer Buffer, std::error_code& ErrorCode) -> std::size_t
    {
        ErrorCode.clear();
        const auto N = std::min(Buffer.size(), Wire_.size() - Offset_);
        std::memcpy(Buffer.data(), Wire_.data() + Offset_, N);
        Offset_ += N;
        return N;
    }

    auto Parser::Expect(Message::Kind Kind) -> void
    {
        Expect_ = Kind;
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
        PrevBufSize_ = Buf_.size();
        Buf_.insert(Buf_.end(), Data.begin(), Data.end());
        std::size_t Consumed = 0;
        Error ParseResult = Error::None;

        switch (Expect_)
        {
        case Message::Kind::Greeting: {
            Greeting GreetingValue;
            ParseResult = ParseGreeting(Buf_, GreetingValue, Consumed);
            if (ParseResult == Error::None)
            {
                Msg_.Type = Message::Kind::Greeting;
                Msg_.Methods = std::move(GreetingValue.Methods);
            }
            break;
        }
        case Message::Kind::MethodReply: {
            MethodReply MethodReplyValue;
            ParseResult = ParseMethodReply(Buf_, MethodReplyValue);
            if (ParseResult == Error::None)
            {
                Msg_.Type = Message::Kind::MethodReply;
                Msg_.Method = static_cast<std::uint8_t>(MethodReplyValue.Method);
                Consumed = 2;
            }
            break;
        }
        case Message::Kind::Userpass: {
            std::size_t Off = 0;
            if (Buf_.size() < Off + 2)
            {
                ParseResult = Error::NeedMore;
                break;
            }
            if (Buf_[0] != 0x01)
            {
                ParseResult = Error::BadMagic;
                break;
            }
            const auto ULength = Buf_[1];
            Off = 2;
            if (Buf_.size() < Off + ULength + 1)
            {
                ParseResult = Error::NeedMore;
                break;
            }
            Msg_.Username.assign(reinterpret_cast<const char*>(Buf_.data() + Off), ULength);
            Off += ULength;
            const auto PLength = Buf_[Off++];
            if (Buf_.size() < Off + PLength)
            {
                ParseResult = Error::NeedMore;
                break;
            }
            Msg_.Password.assign(reinterpret_cast<const char*>(Buf_.data() + Off), PLength);
            Off += PLength;
            Consumed = Off;
            Msg_.Type = Message::Kind::Userpass;
            break;
        }
        case Message::Kind::Request: {
            Request RequestValue;
            ParseResult = ParseRequest(Buf_, RequestValue, Consumed);
            if (ParseResult == Error::None)
            {
                Msg_.Type = Message::Kind::Request;
                Msg_.Cmd = RequestValue.Cmd;
                Msg_.AddressValue = RequestValue.Target;
            }
            break;
        }
        case Message::Kind::Reply: {
            Reply ReplyValue;
            ParseResult = ParseReply(Buf_, ReplyValue, Consumed);
            if (ParseResult == Error::None)
            {
                Msg_.Type = Message::Kind::Reply;
                Msg_.Code = ReplyValue.Code;
                Msg_.AddressValue = ReplyValue.Bind;
            }
            break;
        }
        }

        if (ParseResult == Error::NeedMore)
        {
            return 0;
        }
        if (ParseResult != Error::None)
        {
            ErrorCode = make_error_code(ParseResult);
            return 0;
        }
        Done_ = true;
        Consumed_ = Consumed;
        const auto NewBufSize = Buf_.size();
        const auto Incremental = std::min(Consumed, NewBufSize) - PrevBufSize_;
        return Incremental;
    }

    [[nodiscard]] auto Parser::Remaining() const -> std::span<const std::uint8_t>
    {
        if (Buf_.empty() || !Done_)
        {
            return {};
        }
        return std::span<const std::uint8_t>(Buf_.data() + Consumed_, Buf_.size() - Consumed_);
    }

    [[nodiscard]] auto Parser::TakeRemaining() -> std::vector<std::uint8_t>
    {
        if (!Done_ || Consumed_ >= Buf_.size())
        {
            return {};
        }
        std::vector<std::uint8_t> Output(Buf_.begin() + static_cast<std::ptrdiff_t>(Consumed_), Buf_.end());
        Buf_.clear();
        Consumed_ = 0;
        PrevBufSize_ = 0;
        return Output;
    }

    auto Parser::Reset() -> void
    {
        Buf_.clear();
        Msg_ = Message{};
        Done_ = false;
        Consumed_ = 0;
        PrevBufSize_ = 0;
    }

    [[nodiscard]] auto AsyncRead(SharedTransmission Transport, Parser& ParserValue) -> Net::awaitable<Error>
    {
        std::array<std::uint8_t, 512> Buffer{};
        while (!ParserValue.IsDone())
        {
            auto ByteBuffer = AsBytes(std::span<std::uint8_t>(Buffer));
            const auto Part = co_await Transport->ReadSome(ByteBuffer);
            if (Part.Bytes > Buffer.size())
            {
                co_return Error::IoError;
            }
            std::error_code ParseError;
            if (Part.Bytes != 0)
            {
                ParserValue.Put(Net::buffer(Buffer.data(), Part.Bytes), ParseError);
            }
            if (Part.Failure.Failed())
            {
                co_return Error::IoError;
            }
            if (Part.Bytes == 0)
            {
                co_return Error::UnexpectedEof;
            }
            if (ParseError)
            {
                co_return static_cast<Error>(ParseError.value());
            }
        }
        co_return Error::None;
    }

    [[nodiscard]] auto AsyncWrite(SharedTransmission Transport, Serializer& SerializerValue)
        -> Net::awaitable<Error>
    {
        std::array<std::uint8_t, 512> Buffer{};
        while (!SerializerValue.IsDone())
        {
            std::error_code ErrorCode;
            const auto N = SerializerValue.Get(Net::buffer(Buffer.data(), Buffer.size()), ErrorCode);
            if (ErrorCode)
            {
                co_return Error::IoError;
            }
            if (N == 0)
            {
                co_return Error::BadLength;
            }
            std::size_t Done = 0;
            while (Done < N)
            {
                auto View = AsBytes(std::span<const std::uint8_t>(Buffer.data() + Done, N - Done));
                const auto Part = co_await Transport->WriteSome(View);
                if (Part.Failure.Failed())
                {
                    co_return Error::IoError;
                }
                if (Part.Bytes == 0 || Part.Bytes > N - Done)
                {
                    co_return Error::BrokenPipe;
                }
                Done += Part.Bytes;
            }
        }
        co_return Error::None;
    }

    namespace Detail
    {
        [[nodiscard]] auto FormatIpv4(const std::uint8_t* Bytes, std::string& Host) -> bool
        {
            std::array<char, 16> Buffer{};
            auto* Cursor = Buffer.data();
            for (std::size_t Index = 0; Index < 4; ++Index)
            {
                if (Index != 0)
                {
                    *Cursor++ = '.';
                }
                const auto [End, ErrorCode] = std::to_chars(Cursor, Buffer.data() + Buffer.size(),
                    static_cast<unsigned int>(Bytes[Index]));
                if (ErrorCode != std::errc{})
                {
                    return false;
                }
                Cursor = End;
            }
            Host.assign(Buffer.data(), Cursor);
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
        std::size_t Off = 1;
        switch (Output.Type)
        {
        case AddressType::Ipv4: {
            if (Data.size() < Off + 4 + 2)
            {
                return Error::NeedMore;
            }
            if (!Detail::FormatIpv4(Data.data() + Off, Output.Host))
            {
                return Error::BadMessage;
            }
            Off += 4;
            break;
        }
        case AddressType::Ipv6: {
            if (Data.size() < Off + 16 + 2)
            {
                return Error::NeedMore;
            }
            Output.Host.assign(reinterpret_cast<const char*>(Data.data() + Off), 16);
            Off += 16;
            break;
        }
        case AddressType::Domain: {
            if (Off >= Data.size())
            {
                return Error::NeedMore;
            }
            const auto Len = Data[Off++];
            if (Len == 0)
            {
                return Error::BadMessage;
            }
            if (Data.size() < Off + Len + 2)
            {
                return Error::NeedMore;
            }
            Output.Host.assign(reinterpret_cast<const char*>(Data.data() + Off), Len);
            Off += Len;
            break;
        }
        default:
            return Error::BadMessage;
        }
        Output.Port = static_cast<std::uint16_t>(Data[Off]) << 8 | Data[Off + 1];
        Consumed = Off + 2;
        return Error::None;
    }

    [[nodiscard]] auto BuildGreeting(const Greeting& GreetingValue) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Output;
        BuildGreeting(GreetingValue, Output);
        return Output;
    }

    [[nodiscard]] auto ParseGreeting(std::span<const std::uint8_t> Data, Greeting& Output,
        std::size_t& Consumed) -> Error
    {
        if (Data.size() < 2)
        {
            return Error::NeedMore;
        }
        Output.Ver = Data[0];
        if (Output.Ver != Version)
        {
            return Error::BadMagic;
        }
        const auto NMethods = Data[1];
        if (Data.size() < 2 + NMethods)
        {
            return Error::NeedMore;
        }
        Output.Methods.assign(Data.begin() + 2, Data.begin() + 2 + NMethods);
        Consumed = 2 + NMethods;
        return Error::None;
    }

    [[nodiscard]] auto BuildMethodReply(const MethodReply& MethodReplyValue) -> std::array<std::uint8_t, 2>
    {
        return {MethodReplyValue.Ver, static_cast<std::uint8_t>(MethodReplyValue.Method)};
    }

    [[nodiscard]] auto ParseMethodReply(std::span<const std::uint8_t> Data, MethodReply& Output) -> Error
    {
        if (Data.size() < 2)
        {
            return Error::NeedMore;
        }
        Output.Ver = Data[0];
        if (Output.Ver != Version)
        {
            return Error::BadMagic;
        }
        Output.Method = static_cast<AuthMethod>(Data[1]);
        return Error::None;
    }

    [[nodiscard]] auto BuildRequest(const Request& RequestValue) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Output;
        BuildRequest(RequestValue, Output);
        return Output;
    }

    [[nodiscard]] auto ParseRequest(std::span<const std::uint8_t> Data, Request& Output,
        std::size_t& Consumed) -> Error
    {
        if (Data.size() < 4)
        {
            return Error::NeedMore;
        }
        Output.Ver = Data[0];
        if (Output.Ver != Version)
        {
            return Error::BadMagic;
        }
        Output.Cmd = static_cast<Command>(Data[1]);
        if (Output.Cmd != Command::Connect && Output.Cmd != Command::UdpAssociate)
        {
            return Error::Unsupported;
        }
        Output.Rsv = Data[2];
        if (Output.Rsv != 0)
        {
            return Error::BadMessage;
        }
        std::size_t AddressConsumed = 0;
        const auto ErrorCode = ParseAddress(Data.subspan(3), Output.Target, AddressConsumed);
        if (ErrorCode != Error::None)
        {
            return ErrorCode;
        }
        Consumed = 3 + AddressConsumed;
        return Error::None;
    }

    [[nodiscard]] auto BuildReply(const Reply& ReplyValue) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Output;
        BuildReply(ReplyValue, Output);
        return Output;
    }

    [[nodiscard]] auto ParseReply(std::span<const std::uint8_t> Data, Reply& Output, std::size_t& Consumed)
        -> Error
    {
        if (Data.size() < 4)
        {
            return Error::NeedMore;
        }
        Output.Ver = Data[0];
        if (Output.Ver != Version)
        {
            return Error::BadMagic;
        }
        Output.Code = static_cast<ReplyCode>(Data[1]);
        Output.Rsv = Data[2];
        if (Output.Rsv != 0)
        {
            return Error::BadMessage;
        }
        std::size_t AddressConsumed = 0;
        const auto ErrorCode = ParseAddress(Data.subspan(3), Output.Bind, AddressConsumed);
        if (ErrorCode != Error::None)
        {
            return ErrorCode;
        }
        Consumed = 3 + AddressConsumed;
        return Error::None;
    }

    [[nodiscard]] auto BuildUdpDatagram(const Address& Target, std::span<const std::uint8_t> Payload)
        -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Output;
        BuildUdpDatagram(Target, Payload, Output);
        return Output;
    }

    [[nodiscard]] auto ParseUdpDatagram(std::span<const std::uint8_t> Data, Address& Target,
        std::span<const std::uint8_t>& Payload) -> Error
    {
        if (Data.size() < 3)
        {
            return Error::NeedMore;
        }
        if (Data[0] != 0x00 || Data[1] != 0x00)
        {
            return Error::BadMagic;
        }
        if (Data[2] != 0x00)
        {
            return Error::Unsupported;
        }
        std::size_t AddressConsumed = 0;
        const auto ErrorCode = ParseAddress(Data.subspan(3), Target, AddressConsumed);
        if (ErrorCode != Error::None)
        {
            return ErrorCode;
        }
        Payload = Data.subspan(3 + AddressConsumed);
        return Error::None;
    }

    [[nodiscard]] auto BuildUserpass(std::string_view User, std::string_view Password)
        -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Output;
        BuildUserpass(User, Password, Output);
        return Output;
    }

    [[nodiscard]] auto ParseUserpassReply(std::span<const std::uint8_t> Data) -> Error
    {
        if (Data.size() < 2)
        {
            return Error::NeedMore;
        }
        if (Data[0] != 0x01)
        {
            return Error::BadMagic;
        }
        if (Data[1] == 0x00)
        {
            return Error::None;
        }
        return Error::BadAuth;
    }

} // namespace Prism::Socks5
