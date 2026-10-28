/**
 * @file Handshake.hpp
 * @brief WebSocket HTTP Upgrade 握手 owner。
 * @details ConnHandshake 负责 GET/101 报文、Sec-WebSocket-Key/Accept 校验、
 *          path/host 约束和握手读取中的后续帧回注。
 * @note 实例非线程安全，应在同一协程或线程内使用。
 */
#pragma once

#include <boost/asio/awaitable.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <string_view>

#include <Prism/Foundation/ByteSpan.hpp>
#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Protocols/Ws/Detail/Codec.hpp>
#include <Prism/Protocols/Ws/Detail/Connection/Session.hpp>
#include <Prism/Protocols/Ws/Detail/Connection/Transport.hpp>

namespace Prism::Ws::Detail
{

    namespace Net = boost::asio;

    /**
     * @class ConnHandshake
     * @brief WebSocket HTTP Upgrade 握手 owner。
     * @tparam Memory 会话内存策略。
     */
    template <Prism::Memory::Restrict Memory>
    class ConnHandshake final
    {
    public:
        ConnHandshake(
            ConnSession<Memory> &Session,
            ConnTransport<Memory> &Transport)
            : Session_(Session), Transport_(Transport)
        {
        }

        ConnHandshake(const ConnHandshake &) = delete;
        auto operator=(const ConnHandshake &) -> ConnHandshake & = delete;

        [[nodiscard]] auto Accept() const noexcept -> const std::string &
        {
            return Session_.Accept();
        }

        /**
         * @brief 客户端发送 Upgrade 请求并等待 101 响应。
         */
        [[nodiscard]] auto WriteHandshake(
            std::string_view Key,
            std::string_view Host)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            if (!Session_.HasUpstream())
            {
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::IoError});
            }
            Prepare();
            const auto KeyValue = std::string(Key);
            const auto HostValue = std::string(Host);
            std::string Header;
            Header.reserve(128 + HostValue.size() + KeyValue.size());
            Header += "GET / HTTP/1.1\r\n";
            Header += "Host: " + HostValue + "\r\n";
            Header += "Upgrade: websocket\r\n";
            Header += "Connection: Upgrade\r\n";
            Header += "Sec-WebSocket-Key: " + KeyValue + "\r\n";
            Header += "Sec-WebSocket-Version: 13\r\n";
            Header += "\r\n";

            const auto Sent = co_await Transport_.SendBytes(AsU8Span(Header));
            if (Sent.Failure.Failed())
            {
                co_return std::unexpected(Sent.Failure);
            }

            std::array<std::uint8_t, 256> ResponseChunk{};
            std::string Response;
            for (int I = 0; I < 16; ++I)
            {
                const auto Part = co_await Transport_.ReadHandshakeChunk(
                    std::span<std::uint8_t>(ResponseChunk));
                const auto Count = Part.Bytes;
                if (Count > ResponseChunk.size())
                {
                    auto Failure = Part.Failure;
                    if (!Failure.Failed())
                    {
                        co_return ProtocolFailure(Error::BadLength);
                    }
                    co_return std::unexpected(Failure);
                }
                Response.append(
                    reinterpret_cast<const char *>(ResponseChunk.data()), Count);
                if (Part.Failure.Failed())
                {
                    co_return std::unexpected(Part.Failure);
                }
                if (Count == 0)
                {
                    co_return std::unexpected(
                        Prism::Fault::Failure{Prism::Fault::Code::WouldBlock});
                }
                if (Response.find("\r\n\r\n") != std::string::npos)
                {
                    break;
                }
            }

            const auto HeaderEnd = Response.find("\r\n\r\n");
            const auto StatusEnd = Response.find("\r\n");
            if (HeaderEnd == std::string::npos ||
                StatusEnd == std::string::npos ||
                !IsStatus101(std::string_view(Response).substr(0, StatusEnd)))
            {
                co_return ProtocolFailure(Error::BadMagic);
            }
            const auto Expected = ComputeAccept(KeyValue);
            const auto AcceptValue = HeaderValue(
                Response, "Sec-WebSocket-Accept");
            if (!AcceptValue || *AcceptValue != Expected)
            {
                co_return ProtocolFailure(Error::BadAuth);
            }
            Transport_.PreserveTail(Response, HeaderEnd + 4);
            Session_.MarkHandshaken(Expected);
            co_return std::expected<void, Prism::Fault::Failure>{};
        }

        /**
         * @brief 服务端读取 Upgrade 请求并回复 101。
         */
        [[nodiscard]] auto ReadHandshake(
            std::string &Key,
            std::string_view ExpectedPath = {},
            std::string_view ExpectedHost = {})
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            if (!Session_.HasUpstream())
            {
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::IoError});
            }
            Prepare();
            std::array<std::uint8_t, 256> Chunk{};
            std::string Header;
            for (int I = 0; I < 16; ++I)
            {
                const auto Part = co_await Transport_.ReadHandshakeChunk(
                    std::span<std::uint8_t>(Chunk));
                const auto Count = Part.Bytes;
                if (Count > Chunk.size())
                {
                    auto Failure = Part.Failure;
                    if (!Failure.Failed())
                    {
                        co_return ProtocolFailure(Error::BadLength);
                    }
                    co_return std::unexpected(Failure);
                }
                Header.append(
                    reinterpret_cast<const char *>(Chunk.data()), Count);
                if (Part.Failure.Failed())
                {
                    co_return std::unexpected(Part.Failure);
                }
                if (Count == 0)
                {
                    co_return std::unexpected(
                        Prism::Fault::Failure{Prism::Fault::Code::WouldBlock});
                }
                if (Header.find("\r\n\r\n") != std::string::npos)
                {
                    break;
                }
            }

            const auto HeaderEnd = Header.find("\r\n\r\n");
            const auto RequestEnd = Header.find("\r\n");
            if (HeaderEnd == std::string::npos ||
                RequestEnd == std::string::npos ||
                !IsGetRequest(std::string_view(Header).substr(0, RequestEnd)))
            {
                co_return ProtocolFailure(Error::BadMagic);
            }

            const auto RequestLine = std::string_view(Header).substr(
                0, RequestEnd);
            const auto TargetEnd = RequestLine.find(' ', 4);
            if (TargetEnd == std::string_view::npos || TargetEnd <= 4)
            {
                co_return ProtocolFailure(Error::BadMagic);
            }
            if (!ExpectedPath.empty() &&
                RequestLine.substr(4, TargetEnd - 4) != ExpectedPath)
            {
                co_return ProtocolFailure(Error::BadMagic);
            }

            const auto Upgrade = HeaderValue(Header, "Upgrade");
            const auto Connection = HeaderValue(Header, "Connection");
            const auto Host = HeaderValue(Header, "Host");
            const auto KeyHeader = HeaderValue(Header, "Sec-WebSocket-Key");
            const auto Version = HeaderValue(Header, "Sec-WebSocket-Version");
            if (!Upgrade || !ContainsToken(*Upgrade, "websocket") ||
                !Connection || !ContainsToken(*Connection, "upgrade") ||
                !KeyHeader || KeyHeader->empty() || !Version ||
                *Version != "13" ||
                (!ExpectedHost.empty() &&
                 (!Host || !EqualInsensitive(Trim(*Host), ExpectedHost))))
            {
                co_return ProtocolFailure(Error::BadMagic);
            }
            Key = std::string(*KeyHeader);

            const auto AcceptValue = ComputeAccept(Key);
            std::string Response = "HTTP/1.1 101 Switching Protocols\r\n";
            Response += "Upgrade: websocket\r\n";
            Response += "Connection: Upgrade\r\n";
            Response += "Sec-WebSocket-Accept: " + AcceptValue + "\r\n";
            Response += "\r\n";
            const auto Sent = co_await Transport_.SendBytes(AsU8Span(Response));
            if (Sent.Failure.Failed())
            {
                co_return std::unexpected(Sent.Failure);
            }
            Transport_.PreserveTail(Header, HeaderEnd + 4);
            Session_.MarkHandshaken(AcceptValue);
            co_return std::expected<void, Prism::Fault::Failure>{};
        }

    private:
        [[nodiscard]] static auto ProtocolFailure(Error Value)
            -> std::unexpected<Prism::Fault::Failure>
        {
            return std::unexpected(Prism::Fault::Failure{
                Prism::Fault::ToCode(Prism::make_error_code(Value))});
        }

        auto Prepare() -> void
        {
            Session_.BeginHandshake();
            Transport_.Reset();
        }

        [[nodiscard]] static auto Trim(
            std::string_view Value) noexcept -> std::string_view
        {
            while (!Value.empty() &&
                   (Value.front() == ' ' || Value.front() == '\t'))
            {
                Value.remove_prefix(1);
            }
            while (!Value.empty() &&
                   (Value.back() == ' ' || Value.back() == '\t'))
            {
                Value.remove_suffix(1);
            }
            return Value;
        }

        [[nodiscard]] static auto EqualInsensitive(
            std::string_view Left,
            std::string_view Right) noexcept -> bool
        {
            if (Left.size() != Right.size())
            {
                return false;
            }
            for (std::size_t Index = 0; Index < Left.size(); ++Index)
            {
                const auto Lower = [](char Character) noexcept -> char
                {
                    if (Character >= 'A' && Character <= 'Z')
                    {
                        return static_cast<char>(Character + ('a' - 'A'));
                    }
                    return Character;
                };
                if (Lower(Left[Index]) != Lower(Right[Index]))
                {
                    return false;
                }
            }
            return true;
        }

        [[nodiscard]] static auto HeaderValue(
            std::string_view Header,
            std::string_view Name) noexcept
            -> std::optional<std::string_view>
        {
            std::size_t Begin = 0;
            while (Begin < Header.size())
            {
                const auto End = Header.find("\r\n", Begin);
                if (End == std::string_view::npos)
                {
                    return std::nullopt;
                }
                const auto Line = Header.substr(Begin, End - Begin);
                if (Line.empty())
                {
                    return std::nullopt;
                }
                const auto Colon = Line.find(':');
                if (Colon != std::string_view::npos &&
                    EqualInsensitive(Trim(Line.substr(0, Colon)), Name))
                {
                    return Trim(Line.substr(Colon + 1));
                }
                Begin = End + 2;
            }
            return std::nullopt;
        }

        [[nodiscard]] static auto ContainsToken(
            std::string_view Value,
            std::string_view Token) noexcept -> bool
        {
            std::size_t Begin = 0;
            while (Begin <= Value.size())
            {
                const auto End = Value.find(',', Begin);
                std::string_view Part;
                if (End == std::string_view::npos)
                {
                    Part = Trim(Value.substr(Begin));
                }
                else
                {
                    Part = Trim(Value.substr(Begin, End - Begin));
                }
                if (EqualInsensitive(Part, Token))
                {
                    return true;
                }
                if (End == std::string_view::npos)
                {
                    break;
                }
                Begin = End + 1;
            }
            return false;
        }

        [[nodiscard]] static auto IsGetRequest(
            std::string_view RequestLine) noexcept -> bool
        {
            return RequestLine.starts_with("GET ") &&
                   RequestLine.ends_with(" HTTP/1.1");
        }

        [[nodiscard]] static auto IsStatus101(
            std::string_view StatusLine) noexcept -> bool
        {
            return StatusLine.starts_with("HTTP/1.1 ") &&
                   StatusLine.size() >= 12 &&
                   StatusLine.substr(9, 3) == "101" &&
                   (StatusLine.size() == 12 || StatusLine[12] == ' ');
        }

        ConnSession<Memory> &Session_;
        ConnTransport<Memory> &Transport_;
    };

} // namespace Prism::Ws::Detail
