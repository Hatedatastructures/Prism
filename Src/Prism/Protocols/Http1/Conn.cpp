/**
 * @file Conn.cpp
 * @brief HTTP/1.1 入站连接与客户端握手 I/O 实现
 */

#include <Prism/Protocols/Http1/Conn.hpp>
#include <Prism/Protocols/Http1/Forward/Request.hpp>
#include <Prism/Protocols/Http1/Forward/Request/Transport.hpp>
#include <Prism/Foundation/ByteSpan.hpp>
#include <Prism/Transport/Preview.hpp>

#include <charconv>
#include <cstdint>
#include <span>
#include <string_view>
#include <system_error>
#include <utility>

namespace Prism::Http11
{
    ServerConn::ServerConn(
        SharedTransmission Transport,
        std::shared_ptr<Prism::Memory::BytePool> Bytes)
        : Transport_(std::move(Transport)), Bytes_(std::move(Bytes))
    {
        Buffer_.resize(4096);
    }

    namespace
    {
        [[nodiscard]] auto IsCompleteChunkedBody(std::span<const std::byte> Data) noexcept -> bool
        {
            if (Data.empty())
            {
                return false;
            }
            const std::string_view Wire(
                reinterpret_cast<const char *>(Data.data()), Data.size());
            std::size_t Offset = 0;
            while (true)
            {
                const auto LineEnd = Wire.find("\r\n", Offset);
                if (LineEnd == std::string_view::npos)
                {
                    return false;
                }
                const auto Line = Wire.substr(Offset, LineEnd - Offset);
                const auto Extension = Line.find(';');
                const auto SizeText = Line.substr(0, Extension);
                std::uint64_t ChunkSize = 0;
                const auto Parsed = std::from_chars(
                    SizeText.data(), SizeText.data() + SizeText.size(), ChunkSize, 16);
                if (SizeText.empty() || Parsed.ec != std::errc{} ||
                    Parsed.ptr != SizeText.data() + SizeText.size())
                {
                    return false;
                }
                Offset = LineEnd + 2U;
                if (ChunkSize == 0U)
                {
                    while (true)
                    {
                        const auto TrailerEnd = Wire.find("\r\n", Offset);
                        if (TrailerEnd == std::string_view::npos)
                        {
                            return false;
                        }
                        if (TrailerEnd == Offset)
                        {
                            return true;
                        }
                        if (Wire.substr(Offset, TrailerEnd - Offset).find(':') ==
                            std::string_view::npos)
                        {
                            return false;
                        }
                        Offset = TrailerEnd + 2U;
                    }
                }
                const auto Remaining = Wire.size() - Offset;
                if (Remaining < 2U || ChunkSize > Remaining - 2U)
                {
                    return false;
                }
                Offset += static_cast<std::size_t>(ChunkSize);
                if (Wire.substr(Offset, 2U) != "\r\n")
                {
                    return false;
                }
                Offset += 2U;
            }
        }

        [[nodiscard]] auto IsCompleteRequestBody(
            const HttpRequest &Request,
            std::span<const std::byte> Preread) noexcept -> bool
        {
            if (Request.Headers.HasTransferEncoding)
            {
                return Request.Headers.FinalTransferCodingChunked &&
                       IsCompleteChunkedBody(Preread);
            }
            if (!Request.Headers.HasContentLength)
            {
                return true;
            }
            return Request.Headers.ContentLength <= Preread.size();
        }
    }

    auto SendResponse(SharedTransmission Transport,
                                        std::string_view Body)
    -> Net::awaitable<Fault::Failure>
    {
    if (!Transport)
    {
        co_return Fault::Failure{Fault::Code::IoError};
    }
    const auto Result = co_await Transport->WriteExact(AsBytesSpan(Body));
    if (Result.Failure.Failed())
    {
        co_return Result.Failure;
    }
    if (Result.Bytes != Body.size())
    {
        co_return Fault::Failure{Fault::Code::IoError};
    }
    co_return Fault::Failure{Fault::Code::Success};
    }

    auto ServerConn::ReadRequest(HttpRequest &Request)
        -> Net::awaitable<Fault::Failure>
    {
        ReadFailure_ = {};
        std::size_t Used = 0;
        while (true)
        {
            const auto Sv = std::string_view(Buffer_.data(), Used);
            const auto HeadersEnd = Sv.find("\r\n\r\n");
            if (HeadersEnd != std::string_view::npos)
            {
                const auto Result = ParseRequest(Sv, Request);
                if (Result == Fault::Code::Success)
                {
                    Request_ = Request;
                    Used_ = Used;
                    const auto BodyOffset = HeadersEnd + 4;
                    if (BodyOffset < Used)
                    {
                        const auto Tail = AsBytesSpan(
                            std::string_view(Buffer_.data() + BodyOffset, Used - BodyOffset));
                        Preread_.assign(Tail.begin(), Tail.end());
                    }
                    if (ReadFailure_.Failed() &&
                        !IsCompleteRequestBody(
                            Request_, std::span<const std::byte>(Preread_)))
                    {
                        co_return ReadFailure_;
                    }
                    co_return Fault::Failure{Fault::Code::Success};
                }
                co_return Fault::Failure{Fault::Code::ParseError};
            }
            if (ReadFailure_.Failed())
            {
                co_return ReadFailure_;
            }
            if (Used >= Buffer_.size())
            {
                if (Buffer_.size() >= MaxHdrSize)
                {
                    co_return Fault::Failure{Fault::Code::ParseError};
                }
                Buffer_.resize(Buffer_.size() * 2);
            }
            const auto Part = co_await Transport_->ReadSome(
                AsBytesSpan(std::span(Buffer_.data() + Used, Buffer_.size() - Used)));
            const auto Count = Part.Bytes;
            if (Count > Buffer_.size() - Used)
            {
                co_return Fault::Failure{Fault::Code::IoError};
            }
            if (Count == 0U && Part.Failure.Succeeded())
            {
                co_return Fault::Failure{Fault::Code::IoError};
            }
            Used += Count;
            if (Part.Failure.Failed())
            {
                ReadFailure_ = Part.Failure;
            }
        }
    }

    auto ServerConn::SendResponse(std::string_view Body)
        -> Net::awaitable<Fault::Failure>
    {
        co_return co_await Prism::Http11::SendResponse(Transport_, Body);
    }

    auto ServerConn::Release() -> SharedTransmission
    {
        if (Preread_.empty() && ReadFailure_.Succeeded())
        {
            return std::move(Transport_);
        }
        const auto Created = Prism::Transport::PreviewTransport::Create(
            Transport_, Prism::Transport::PrefixInput{
                std::span<const std::byte>(Preread_.data(), Preread_.size()), Bytes_, ReadFailure_});
        if (!Created)
        {
            return {};
        }
        Transport_.reset();
        return *Created;
    }

    auto ServerConn::ReleaseForward() -> SharedTransmission
    {
        if (!Transport_)
        {
            return {};
        }
        const auto Raw = std::string_view(Buffer_.data(), Used_);
        const auto HeaderRaw = Raw.substr(0, Request_.HdrEnd);
        const auto Forwarded = BuildForwardRequest(HeaderRaw, Request_);
        if (Forwarded.empty())
        {
            return {};
        }
        ForwardRequestOptions Options;
        Options.Inner = std::move(Transport_);
        Options.Header = Forwarded;
        Options.Preread = std::move(Preread_);
        Options.PrereadFailure = std::move(ReadFailure_);
        const auto UpgradeRequested = Request_.Headers.HasUpgrade &&
                                      Request_.Headers.ConnectionContains("upgrade");
        Options.AwaitUpgrade = UpgradeRequested;
        if (Request_.Headers.HasTransferEncoding)
        {
            Options.BodyMode = ForwardBodyMode::Chunked;
        }
        else if (Request_.Headers.HasContentLength)
        {
            Options.BodyMode = ForwardBodyMode::ContentLength;
            Options.ContentLength = Request_.Headers.ContentLength;
        }
        return MakeForwardRequestTransport(std::move(Options));
    }

    auto SendConnect(ConnectParameters Params)
    -> Net::awaitable<Fault::Code>
    {
    const auto Req = MakeConnectRequest(Params.Host, Params.Port, Params.Authorization);
    const auto Bytes = AsBytesSpan(Req);
    const auto Result = co_await Params.Transport->WriteExact(Bytes);
    if (Result.Failure.Failed() || Result.Bytes != Bytes.size())
    {
        co_return Fault::Code::IoError;
    }
    co_return Fault::Code::Success;
    }

    auto SendConnect(
    SharedTransmission Transport,
    std::string_view Host,
    std::uint16_t Port) -> Net::awaitable<Fault::Code>
    {
    auto Result = co_await SendConnect(ConnectParameters{std::move(Transport), Host, Port, {}});
    co_return Result;
    }

    auto ReadResponse(
    SharedTransmission &Transport,
    std::error_code &ErrorCode,
    std::shared_ptr<Prism::Memory::BytePool> Bytes) -> Net::awaitable<int>
    {
    ErrorCode.clear();
    std::string Buffer;
    Buffer.resize(1024);
    std::size_t Used = 0;
    Fault::Failure ReadFailure;
    while (true)
    {
        const auto DataView = std::string_view(Buffer.data(), Used);
        const auto HeadersEnd = DataView.find("\r\n\r\n");
        if (HeadersEnd != std::string_view::npos)
        {
            const auto BodyOffset = HeadersEnd + 4;
            if (BodyOffset < Used)
            {
                const auto Created = Prism::Transport::PreviewTransport::Create(
                    Transport, Prism::Transport::PrefixInput{
                        AsBytesSpan(std::string_view(Buffer.data() + BodyOffset, Used - BodyOffset)),
                        Bytes, ReadFailure});
                if (!Created)
                {
                    ErrorCode = Prism::Fault::ToNative(Created.error());
                    co_return 0;
                }
                Transport = *Created;
            }
            else if (ReadFailure.Failed())
            {
                ErrorCode = Prism::Fault::ToNative(ReadFailure);
            }
            co_return ParseStatusCode(DataView);
        }
        if (ReadFailure.Failed())
        {
            ErrorCode = Prism::Fault::ToNative(ReadFailure);
            co_return 0;
        }
        if (Used >= Buffer.size())
        {
            if (Buffer.size() >= MaxHdrSize)
            {
                ErrorCode = std::make_error_code(std::errc::message_size);
                co_return 0; // 响应头超限（防恶意响应 OOM，与 Server 端一致）
            }
            Buffer.resize(Buffer.size() * 2);
        }
        const auto Part = co_await Transport->ReadSome(
            AsBytesSpan(std::span(Buffer.data() + Used, Buffer.size() - Used)));
        const auto Count = Part.Bytes;
        if (Count > Buffer.size() - Used)
        {
            ErrorCode = std::make_error_code(std::errc::value_too_large);
            co_return 0;
        }
        if (Count == 0U && Part.Failure.Succeeded())
        {
            co_return 0;
        }
        Used += Count;
        if (Part.Failure.Failed())
        {
            ReadFailure = Part.Failure;
        }
    }
    }
} // namespace Prism::Http11
