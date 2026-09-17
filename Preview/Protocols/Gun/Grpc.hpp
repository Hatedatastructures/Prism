/**
 * @file Grpc.hpp
 * @brief Gun 标准 gRPC/HTTP2 endpoint。
 * @details 保留 gun-lite CONNECT 兼容路径，同时提供标准 HTTP/2 gRPC
 *          metadata、5-byte message envelope、response headers 和 trailers。
 */
#pragma once

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <utility>
#include <vector>

#include <Preview/Foundation/Error.hpp>
#include <Preview/Foundation/Fault/Code.hpp>
#include <Preview/Protocols/Http2/Impl.hpp>
#include <Preview/Protocols/Http2/Session.hpp>
#include <Preview/Transport/Transmission.hpp>

namespace Preview::Gun::Grpc
{

    namespace Net = boost::asio;
    namespace H2 = Preview::Http2;

    inline constexpr std::size_t DefaultMaxMessageBytes = 16U * 1024U * 1024U;

    struct Config final
    {
        std::string Path{"/GunService/Tun"};
        std::string Authority{"gun"};
        std::size_t MaxMessageBytes{DefaultMaxMessageBytes};
    };

    struct RequestHeaders final
    {
        std::string Path;
        std::string Authority;
        std::string ContentType;
        std::string Te;
    };

    [[nodiscard]] inline auto MakeRequestHeaders(
        std::string_view Path,
        std::string_view Authority) -> H2::HeaderList
    {
        return {{":method", "POST"},
                {":scheme", "http"},
                {":path", std::string(Path)},
                {":authority", std::string(Authority)},
                {"content-type", "application/grpc"},
                {"te", "trailers"}};
    }

    [[nodiscard]] inline auto ParseRequestHeaders(
        const H2::HeaderList &Headers) -> std::optional<RequestHeaders>
    {
        RequestHeaders Result;
        bool MethodOk = false;
        bool SchemeOk = false;
        for (const auto &Header : Headers)
        {
            if (Header.Name == ":method")
            {
                MethodOk = Header.value == "POST";
            }
            else if (Header.Name == ":scheme")
            {
                SchemeOk = Header.value == "http" || Header.value == "https";
            }
            else if (Header.Name == ":path")
            {
                Result.Path = Header.value;
            }
            else if (Header.Name == ":authority")
            {
                Result.Authority = Header.value;
            }
            else if (Header.Name == "content-type")
            {
                Result.ContentType = Header.value;
            }
            else if (Header.Name == "te")
            {
                Result.Te = Header.value;
            }
        }
        if (!MethodOk || !SchemeOk || Result.Path.empty() || Result.Authority.empty() ||
            !std::string_view(Result.ContentType).starts_with("application/grpc") ||
            Result.Te != "trailers")
        {
            return std::nullopt;
        }
        return Result;
    }

    [[nodiscard]] inline auto MakeResponseHeaders() -> H2::HeaderList
    {
        return {{":status", "200"},
                {"content-type", "application/grpc"},
                {"grpc-encoding", "identity"},
                {"grpc-accept-encoding", "identity"}};
    }

    [[nodiscard]] inline auto MakeResponseTrailers(const std::uint32_t Status)
        -> H2::HeaderList
    {
        return {{"grpc-status", std::to_string(Status)}, {"grpc-message", {}}};
    }

    [[nodiscard]] inline auto EncodeMessage(
        std::span<const std::byte> Payload) -> std::vector<std::byte>
    {
        if (Payload.size() > static_cast<std::size_t>((std::numeric_limits<std::uint32_t>::max)()))
        {
            return {};
        }
        std::vector<std::byte> Output(5U + Payload.size());
        Output[0] = std::byte{0};
        const auto Length = static_cast<std::uint32_t>(Payload.size());
        Output[1] = static_cast<std::byte>((Length >> 24U) & 0xFFU);
        Output[2] = static_cast<std::byte>((Length >> 16U) & 0xFFU);
        Output[3] = static_cast<std::byte>((Length >> 8U) & 0xFFU);
        Output[4] = static_cast<std::byte>(Length & 0xFFU);
        std::copy(Payload.begin(), Payload.end(), Output.begin() + 5);
        return Output;
    }

    class MessageDecoder final
    {
    public:
        explicit MessageDecoder(const std::size_t MaxMessageBytes = DefaultMaxMessageBytes)
            : MaxMessageBytes_(MaxMessageBytes)
        {
        }

        [[nodiscard]] auto Feed(
            std::span<const std::byte> Data,
            std::vector<std::vector<std::byte>> &Messages) -> bool
        {
            Buffer_.insert(Buffer_.end(), Data.begin(), Data.end());
            while (Buffer_.size() >= 5U)
            {
                if (Buffer_[0] != std::byte{0})
                {
                    return false;
                }
                const auto Length = (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(Buffer_[1])) << 24U) |
                                    (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(Buffer_[2])) << 16U) |
                                    (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(Buffer_[3])) << 8U) |
                                    static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(Buffer_[4]));
                if (Length > MaxMessageBytes_)
                {
                    return false;
                }
                const auto Total = 5U + static_cast<std::size_t>(Length);
                if (Buffer_.size() < Total)
                {
                    break;
                }
                Messages.emplace_back(Buffer_.begin() + 5,
                                      Buffer_.begin() + static_cast<std::ptrdiff_t>(Total));
                Buffer_.erase(Buffer_.begin(), Buffer_.begin() + static_cast<std::ptrdiff_t>(Total));
            }
            return true;
        }

        [[nodiscard]] auto Empty() const noexcept -> bool
        {
            return Buffer_.empty();
        }

    private:
        std::size_t MaxMessageBytes_;
        std::vector<std::byte> Buffer_;
    };

    using MessageHandler = std::function<std::vector<std::byte>(std::span<const std::byte>)>;

    struct ClientResult final
    {
        std::uint32_t GrpcStatus{1};
        H2::HeaderList ResponseHeaders;
        H2::HeaderList Trailers;
        std::vector<std::byte> Payload;
        Preview::Fault::Code Code{Preview::Fault::Code::ProtocolError};
    };

    class ServerSession final : public std::enable_shared_from_this<ServerSession>
    {
    public:
        ServerSession(Preview::SharedTransmission Transport, Config ConfigValue = {},
                      MessageHandler Handler = {})
            : Transport_(std::move(Transport)), Config_(std::move(ConfigValue)),
              Handler_(std::move(Handler)),
              Session_(std::make_shared<H2::SessionImpl>(Transport_->Executor(), true))
        {
            Session_->OnHeaders = [this](const std::int32_t StreamId,
                                         const H2::HeaderList &Headers, const bool EndStream)
            { OnHeaders(StreamId, Headers, EndStream); };
            Session_->OnData = [this](const std::int32_t StreamId, const std::span<const std::byte> Data)
            { OnData(StreamId, Data); };
            Session_->OnStreamClose = [this](const std::int32_t StreamId, const std::uint32_t ErrorCode)
            { OnStreamClose(StreamId, ErrorCode); };
        }

        [[nodiscard]] auto Run() -> Net::awaitable<Preview::Fault::Code>
        {
            Session_->SendSettings();
            if (!co_await Flush())
            {
                co_return Preview::Fault::Code::IoError;
            }
            std::array<std::byte, 16384> Buffer{};
            while (Transport_ && Transport_->IsOpen())
            {
                std::error_code Error;
                const auto Count = co_await Transport_->async_read_some(Buffer, Error);
                if (Error)
                {
                    co_return Completed_ ? Preview::Fault::Code::Success
                                         : Preview::Fault::Code::IoError;
                }
                if (Count == 0U)
                {
                    co_return Preview::Fault::Code::Success;
                }
                if (!Session_->Feed(std::span<const std::byte>(Buffer).first(Count), Error) || Error)
                {
                    co_return Completed_ ? Preview::Fault::Code::Success
                                         : Preview::Fault::Code::ProtocolError;
                }
                if (!co_await Flush())
                {
                    co_return Preview::Fault::Code::IoError;
                }
            }
            co_return Preview::Fault::Code::Success;
        }

    private:
        struct StreamState final
        {
            bool Accepted{false};
            bool ResponseStarted{false};
            MessageDecoder Decoder;

            explicit StreamState(const std::size_t MaxMessageBytes)
                : Decoder(MaxMessageBytes)
            {
            }
        };

        [[nodiscard]] auto Flush() -> Net::awaitable<bool>
        {
            std::vector<std::byte> Output;
            if (!Session_->Collect(Output) || Output.empty())
            {
                co_return true;
            }
            std::size_t Offset = 0;
            while (Offset < Output.size())
            {
                std::error_code Error;
                const auto Written = co_await Transport_->async_write_some(
                    std::span<const std::byte>(Output).subspan(Offset), Error);
                if (Error || Written == 0U || Written > Output.size() - Offset)
                {
                    co_return false;
                }
                Offset += Written;
            }
            co_return true;
        }

        auto OnHeaders(const std::int32_t StreamId, const H2::HeaderList &Headers,
                       const bool EndStream) -> void
        {
            auto [Iterator, Inserted] = Streams_.try_emplace(
                StreamId, Config_.MaxMessageBytes);
            if (!Inserted || Iterator->second.ResponseStarted)
            {
                (void)Session_->ResetStream(StreamId, H2::ErrorProtocol);
                return;
            }
            const auto Request = ParseRequestHeaders(Headers);
            if (!Request || Request->Path != Config_.Path || EndStream)
            {
                Iterator->second.ResponseStarted = true;
                (void)Session_->SubmitHeaders(
                    StreamId, {{":status", "415"}, {"content-type", "application/grpc"}}, false);
                (void)Session_->SubmitHeaders(StreamId, MakeResponseTrailers(12), true);
                return;
            }
            Iterator->second.Accepted = true;
            Iterator->second.ResponseStarted = true;
            (void)Session_->SubmitHeaders(StreamId, MakeResponseHeaders(), false);
        }

        auto OnData(const std::int32_t StreamId, const std::span<const std::byte> Data) -> void
        {
            const auto Iterator = Streams_.find(StreamId);
            if (Iterator == Streams_.end() || !Iterator->second.Accepted)
            {
                return;
            }
            std::vector<std::vector<std::byte>> Messages;
            if (!Iterator->second.Decoder.Feed(Data, Messages))
            {
                (void)Session_->ResetStream(StreamId, H2::ErrorProtocol);
                return;
            }
            for (const auto &Message : Messages)
            {
                const auto Response = Handler_
                                          ? Handler_(std::span<const std::byte>(Message))
                                          : std::vector<std::byte>(Message.begin(), Message.end());
                const auto Wire = EncodeMessage(Response);
                (void)Session_->SubmitData(StreamId, Wire, false);
            }
        }

        auto OnStreamClose(const std::int32_t StreamId, const std::uint32_t ErrorCode) -> void
        {
            const auto Iterator = Streams_.find(StreamId);
            if (Iterator == Streams_.end())
            {
                return;
            }
            if (Iterator->second.Accepted && ErrorCode == H2::ErrorNoError &&
                Iterator->second.Decoder.Empty())
            {
                (void)Session_->SubmitHeaders(StreamId, MakeResponseTrailers(0), true);
                Completed_ = true;
            }
            Streams_.erase(Iterator);
        }

        Preview::SharedTransmission Transport_;
        Config Config_;
        MessageHandler Handler_;
        std::shared_ptr<H2::SessionImpl> Session_;
        std::unordered_map<std::int32_t, StreamState> Streams_;
        bool Completed_{false};
    };

    class ClientSession final : public std::enable_shared_from_this<ClientSession>
    {
    public:
        ClientSession(Preview::SharedTransmission Transport, Config ConfigValue = {})
            : Transport_(std::move(Transport)), Config_(std::move(ConfigValue)),
              Session_(std::make_shared<H2::SessionImpl>(Transport_->Executor(), false)),
              Decoder_(Config_.MaxMessageBytes)
        {
            Session_->OnHeaders = [this](const std::int32_t StreamId,
                                         const H2::HeaderList &Headers, const bool EndStream)
            {
                if (StreamId != StreamId_)
                {
                    return;
                }
                if (ResponseHeaders_.empty())
                {
                    ResponseHeaders_ = Headers;
                }
                else
                {
                    Trailers_ = Headers;
                }
                if (EndStream)
                {
                    Done_ = true;
                }
            };
            Session_->OnData = [this](const std::int32_t StreamId,
                                      const std::span<const std::byte> Data)
            {
                if (StreamId != StreamId_)
                {
                    return;
                }
                std::vector<std::vector<std::byte>> Messages;
                if (!Decoder_.Feed(Data, Messages))
                {
                    Failed_ = true;
                    return;
                }
                for (const auto &Message : Messages)
                {
                    Payload_.insert(Payload_.end(), Message.begin(), Message.end());
                }
            };
            Session_->OnStreamClose = [this](const std::int32_t StreamId, const std::uint32_t ErrorCode)
            {
                if (StreamId == StreamId_)
                {
                    Done_ = ErrorCode == H2::ErrorNoError;
                }
            };
        }

        [[nodiscard]] auto Run(std::span<const std::byte> Payload)
            -> Net::awaitable<ClientResult>
        {
            if (!PrepareRequest(Payload) || !co_await Flush())
            {
                Transport_->Close();
                co_return ClientResult{};
            }
            co_return co_await ReadResponse();
        }

    private:
        [[nodiscard]] auto PrepareRequest(std::span<const std::byte> Payload) -> bool
        {
            Session_->SendSettings();
            StreamId_ = Session_->OpenStream(
                MakeRequestHeaders(Config_.Path, Config_.Authority), false);
            return StreamId_ >= 0 && Session_->SubmitData(StreamId_, EncodeMessage(Payload), true) == 0;
        }

        [[nodiscard]] auto ReadResponse() -> Net::awaitable<ClientResult>
        {
            std::array<std::byte, 16384> Buffer{};
            while (!Done_ && !Failed_ && Transport_->IsOpen())
            {
                std::error_code Error;
                const auto Count = co_await Transport_->async_read_some(Buffer, Error);
                if (Error || Count == 0U ||
                    !Session_->Feed(std::span<const std::byte>(Buffer).first(Count), Error) || Error)
                {
                    break;
                }
                // The trailers carry END_STREAM. Do not flush WINDOW_UPDATE
                // frames generated while consuming the final response DATA
                // after the peer has already closed the stream.
                if (!Done_ && !co_await Flush())
                {
                    break;
                }
            }
            ClientResult Result;
            Result.ResponseHeaders = ResponseHeaders_;
            Result.Trailers = Trailers_;
            Result.Payload = Payload_;
            Result.Code = Failed_ ? Preview::Fault::Code::ProtocolError
                                  : (Done_ ? Preview::Fault::Code::Success
                                           : Preview::Fault::Code::IoError);
            for (const auto &Header : Trailers_)
            {
                if (Header.Name == "grpc-status")
                {
                    std::uint32_t Status = 1;
                    const auto Parsed = std::from_chars(
                        Header.value.data(), Header.value.data() + Header.value.size(), Status);
                    if (Parsed.ec == std::errc{})
                    {
                        Result.GrpcStatus = Status;
                    }
                }
            }
            Transport_->Close();
            co_return Result;
        }

        [[nodiscard]] auto Flush() -> Net::awaitable<bool>
        {
            std::vector<std::byte> Output;
            if (!Session_->Collect(Output) || Output.empty())
            {
                co_return true;
            }
            std::size_t Offset = 0;
            while (Offset < Output.size())
            {
                std::error_code Error;
                const auto Written = co_await Transport_->async_write_some(
                    std::span<const std::byte>(Output).subspan(Offset), Error);
                if (Error || Written == 0U || Written > Output.size() - Offset)
                {
                    co_return false;
                }
                Offset += Written;
            }
            co_return true;
        }

        Preview::SharedTransmission Transport_;
        Config Config_;
        std::shared_ptr<H2::SessionImpl> Session_;
        MessageDecoder Decoder_;
        std::int32_t StreamId_{-1};
        bool Done_{false};
        bool Failed_{false};
        H2::HeaderList ResponseHeaders_;
        H2::HeaderList Trailers_;
        std::vector<std::byte> Payload_;
    };

    /**
     * @class StreamTransport
     * @brief 将标准 gRPC message stream 映射为 Preview Transmission。
     * @details HTTP/2 解析、DATA 分帧和 trailers 由 owner-held coroutines 驱动；
     *          上层协议只看到连续的 message payload，不接触 HTTP/2 状态。
     */
    class StreamTransport final : public Preview::Transmission,
                                  public std::enable_shared_from_this<StreamTransport>
    {
    public:
        [[nodiscard]] static auto Accept(
            Preview::SharedTransmission Lower,
            Config ConfigValue = {}) -> Net::awaitable<std::shared_ptr<StreamTransport>>
        {
            if (!Lower)
            {
                co_return nullptr;
            }
            auto Self = std::shared_ptr<StreamTransport>(
                new StreamTransport(std::move(Lower), std::move(ConfigValue)));
            Net::co_spawn(
                Self->Executor(),
                [Self]() -> Net::awaitable<void> { co_await Self->ReadLoop(); },
                Net::detached);
            Net::co_spawn(
                Self->Executor(),
                [Self]() -> Net::awaitable<void> { co_await Self->WriteLoop(); },
                Net::detached);
            boost::system::error_code Error;
            co_await Self->Ready_.async_receive(
                Net::redirect_error(Net::use_awaitable, Error));
            if (Error || !Self->ReadyOk_)
            {
                Self->Close();
                co_return nullptr;
            }
            co_return Self;
        }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            return Lower_->Executor();
        }

        [[nodiscard]] auto async_read_some(
            std::span<std::byte> Buffer,
            std::error_code &Error) -> Net::awaitable<std::size_t> override
        {
            Error.clear();
            co_await Net::dispatch(Executor(), Net::use_awaitable);
            while (!Closed_ && RxQueue_.empty())
            {
                RxNotify_.reset();
                boost::system::error_code NotifyError;
                co_await RxNotify_.async_receive(
                    Net::redirect_error(Net::use_awaitable, NotifyError));
                if (NotifyError && Closed_)
                {
                    co_return 0;
                }
            }
            if (RxQueue_.empty())
            {
                co_return 0;
            }
            auto &Front = RxQueue_.front();
            const auto Count = (std::min)(Buffer.size(), Front.size() - RxOffset_);
            std::memcpy(Buffer.data(), Front.data() + RxOffset_, Count);
            RxOffset_ += Count;
            if (RxOffset_ == Front.size())
            {
                RxQueue_.pop_front();
                RxOffset_ = 0;
            }
            co_return Count;
        }

        [[nodiscard]] auto async_write_some(
            std::span<const std::byte> Buffer,
            std::error_code &Error) -> Net::awaitable<std::size_t> override
        {
            Error.clear();
            co_await Net::dispatch(Executor(), Net::use_awaitable);
            if (Closed_ || !ReadyOk_ || StreamId_ <= 0)
            {
                Error = std::make_error_code(std::errc::broken_pipe);
                co_return 0;
            }
            const auto Message = EncodeMessage(Buffer);
            if (Message.empty() && !Buffer.empty() ||
                Session_->SubmitData(StreamId_, Message, false) != 0)
            {
                Error = std::make_error_code(std::errc::io_error);
                co_return 0;
            }
            (void)WriteNotify_.try_send(boost::system::error_code{});
            co_return Buffer.size();
        }

        auto Close() -> void override
        {
            if (Closed_)
            {
                return;
            }
            Closed_ = true;
            Lower_->Close();
            Ready_.close();
            RxNotify_.close();
            WriteNotify_.close();
        }

        auto Cancel() -> void override
        {
            Lower_->Cancel();
            (void)RxNotify_.try_send(boost::system::error_code{});
            (void)WriteNotify_.try_send(boost::system::error_code{});
        }

        auto Shutdown() -> void override
        {
            if (!Closed_ && StreamId_ > 0 && !LocalEnded_)
            {
                LocalEnded_ = true;
                (void)Session_->SubmitHeaders(StreamId_, MakeResponseTrailers(0), true);
                (void)WriteNotify_.try_send(boost::system::error_code{});
            }
        }

        auto SetTimeout(std::chrono::milliseconds Timeout) -> void override
        {
            Lower_->SetTimeout(Timeout);
        }

        [[nodiscard]] auto IsOpen() const -> bool override
        {
            return !Closed_ && Lower_->IsOpen();
        }

        [[nodiscard]] auto NextLayer() noexcept -> Preview::Transmission * override
        {
            return Lower_.get();
        }

    private:
        StreamTransport(Preview::SharedTransmission Lower, Config ConfigValue)
            : Lower_(std::move(Lower)), Config_(std::move(ConfigValue)),
              Session_(std::make_shared<H2::SessionImpl>(Lower_->Executor(), true)),
              Ready_(Lower_->Executor(), 1), RxNotify_(Lower_->Executor(), 1),
              WriteNotify_(Lower_->Executor(), 8), Decoder_(Config_.MaxMessageBytes)
        {
            Session_->OnHeaders = [this](const std::int32_t StreamId,
                                         const H2::HeaderList &Headers, const bool EndStream)
            {
                if (StreamId_ > 0 || EndStream)
                {
                    (void)Session_->ResetStream(StreamId, H2::ErrorProtocol);
                    return;
                }
                const auto Request = ParseRequestHeaders(Headers);
                if (!Request || Request->Path != Config_.Path)
                {
                    (void)Session_->SubmitHeaders(
                        StreamId, {{":status", "415"}, {"content-type", "application/grpc"}}, false);
                    (void)Session_->SubmitHeaders(StreamId, MakeResponseTrailers(12), true);
                    ReadyOk_ = false;
                    (void)Ready_.try_send(boost::system::error_code{});
                    return;
                }
                StreamId_ = StreamId;
                ReadyOk_ = Session_->SubmitHeaders(StreamId, MakeResponseHeaders(), false) == 0;
                (void)Ready_.try_send(boost::system::error_code{});
                (void)WriteNotify_.try_send(boost::system::error_code{});
            };
            Session_->OnData = [this](const std::int32_t StreamId,
                                      const std::span<const std::byte> Data)
            {
                if (StreamId != StreamId_)
                {
                    return;
                }
                std::vector<std::vector<std::byte>> Messages;
                if (!Decoder_.Feed(Data, Messages))
                {
                    (void)Session_->ResetStream(StreamId, H2::ErrorProtocol);
                    return;
                }
                for (auto &Message : Messages)
                {
                    RxQueue_.push_back(std::move(Message));
                }
                if (!Messages.empty())
                {
                    (void)RxNotify_.try_send(boost::system::error_code{});
                }
            };
            Session_->OnStreamClose = [this](const std::int32_t StreamId,
                                             const std::uint32_t ErrorCode)
            {
                if (StreamId == StreamId_ && ErrorCode == H2::ErrorNoError && !LocalEnded_)
                {
                    LocalEnded_ = true;
                    (void)Session_->SubmitHeaders(StreamId, MakeResponseTrailers(0), true);
                    (void)WriteNotify_.try_send(boost::system::error_code{});
                    (void)RxNotify_.try_send(boost::system::error_code{});
                }
            };
        }

        [[nodiscard]] auto Flush() -> Net::awaitable<bool>
        {
            std::vector<std::byte> Output;
            if (!Session_->Collect(Output) || Output.empty())
            {
                co_return true;
            }
            std::size_t Offset = 0;
            while (Offset < Output.size())
            {
                std::error_code Error;
                const auto Written = co_await Lower_->async_write_some(
                    std::span<const std::byte>(Output).subspan(Offset), Error);
                if (Error || Written == 0U || Written > Output.size() - Offset)
                {
                    co_return false;
                }
                Offset += Written;
            }
            co_return true;
        }

        [[nodiscard]] auto ReadLoop() -> Net::awaitable<void>
        {
            Session_->SendSettings();
            (void)WriteNotify_.try_send(boost::system::error_code{});
            std::array<std::byte, 16384> Buffer{};
            while (!Closed_ && Lower_->IsOpen())
            {
                std::error_code Error;
                const auto Count = co_await Lower_->async_read_some(Buffer, Error);
                if (Error || Count == 0U)
                {
                    Close();
                    co_return;
                }
                if (!Session_->Feed(std::span<const std::byte>(Buffer).first(Count), Error) || Error)
                {
                    Close();
                    co_return;
                }
                (void)WriteNotify_.try_send(boost::system::error_code{});
            }
        }

        [[nodiscard]] auto WriteLoop() -> Net::awaitable<void>
        {
            while (!Closed_)
            {
                boost::system::error_code Error;
                co_await WriteNotify_.async_receive(
                    Net::redirect_error(Net::use_awaitable, Error));
                if (Error || Closed_)
                {
                    co_return;
                }
                if (!co_await Flush())
                {
                    Close();
                    co_return;
                }
            }
        }

        Preview::SharedTransmission Lower_;
        Config Config_;
        std::shared_ptr<H2::SessionImpl> Session_;
        Net::experimental::channel<void(boost::system::error_code)> Ready_;
        Net::experimental::channel<void(boost::system::error_code)> RxNotify_;
        Net::experimental::channel<void(boost::system::error_code)> WriteNotify_;
        MessageDecoder Decoder_;
        std::deque<std::vector<std::byte>> RxQueue_;
        std::size_t RxOffset_{0};
        std::int32_t StreamId_{-1};
        bool ReadyOk_{false};
        bool LocalEnded_{false};
        bool Closed_{false};
    };

} // namespace Preview::Gun::Grpc
