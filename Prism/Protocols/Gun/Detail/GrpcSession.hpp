/**
 * @file GrpcSession.hpp
 * @brief gRPC HTTP/2 客户端和服务端会话 owner。
 * @details 会话 owner 负责 HTTP/2 输入输出、流回调和 unary message 生命周期；
 *          纯 framing 与 metadata 由 GrpcFraming/GrpcMetadata 提供。
 */
#pragma once

#include <Prism/Protocols/Gun/GrpcFraming.hpp>
#include <Prism/Protocols/Gun/GrpcMetadata.hpp>
#include <Prism/Protocols/Gun/GrpcTypes.hpp>
#include <Prism/Protocols/Http2/Session.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/asio/awaitable.hpp>

#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <span>
#include <system_error>
#include <unordered_map>
#include <utility>
#include <vector>

namespace Prism::Gun::Grpc::Detail
{

    class ServerSession final : public std::enable_shared_from_this<ServerSession>
    {
    public:
        ServerSession(Prism::SharedTransmission Transport, Config ConfigValue = {},
            MessageHandler Handler = {})
            : Transport_(std::move(Transport)), Config_(std::move(ConfigValue)), Handler_(std::move(Handler)),
              Session_(std::make_shared<H2::Session>(Transport_->Executor(), true))
        {
            Session_->OnHeaders = [this](const std::int32_t StreamId, const H2::HeaderList& Headers,
                                      const bool EndStream) { OnHeaders(StreamId, Headers, EndStream); };
            Session_->OnData = [this](const std::int32_t StreamId, const std::span<const std::byte> Data)
            { OnData(StreamId, Data); };
            Session_->OnStreamClose = [this](const H2::StreamReceiveClosure &Closure)
            { OnStreamClose(Closure); };
        }

        [[nodiscard]] auto Run() -> Net::awaitable<Prism::Fault::Code>
        {
            Session_->SendSettings();
            if (!co_await Flush())
            {
                co_return Prism::Fault::Code::IoError;
            }
            std::array<std::byte, 16384> Buffer{};
            while (Transport_ && Transport_->IsOpen())
            {
                const auto Part = co_await Transport_->ReadSome(Buffer);
                std::error_code Error = Prism::Fault::ToNative(Part.Failure);
                const auto Count = Part.Bytes;
                if (Error)
                {
                    if (Completed_)
                    {
                        co_return Prism::Fault::Code::Success;
                    }
                    co_return Prism::Fault::Code::IoError;
                }
                if (Count == 0U)
                {
                    co_return Prism::Fault::Code::Success;
                }
                if (!Session_->Feed(std::span<const std::byte>(Buffer).first(Count), Error) || Error)
                {
                    if (Completed_)
                    {
                        co_return Prism::Fault::Code::Success;
                    }
                    co_return Prism::Fault::Code::ProtocolError;
                }
                if (ControlFailure_.Failed())
                {
                    co_return ControlFailure_.Code;
                }
                const auto PendingStatus = RetryPendingResponses();
                if (PendingStatus != Prism::Fault::Code::Success)
                {
                    co_return PendingStatus;
                }
                if (!co_await Flush())
                {
                    co_return Prism::Fault::Code::IoError;
                }
            }
            co_return Prism::Fault::Code::Success;
        }

    private:
        struct StreamState final
        {
            bool Accepted{false};
            bool ResponseStarted{false};
            bool TrailersPending{false};
            std::deque<std::vector<std::byte>> PendingResponses;
            std::size_t PendingOffset{0};
            MessageDecoder Decoder;

            explicit StreamState(const std::size_t MaxMessageBytes) : Decoder(MaxMessageBytes)
            {
            }
        };

        [[nodiscard]] auto RetryPendingResponses() -> Prism::Fault::Code
        {
            auto Iterator = Streams_.begin();
            while (Iterator != Streams_.end())
            {
                auto &State = Iterator->second;
                bool Blocked = false;
                bool Erased = false;
                while (!State.PendingResponses.empty())
                {
                    auto &Wire = State.PendingResponses.front();
                    const auto Count = (std::min)(std::size_t{16U * 1024U}, Wire.size() - State.PendingOffset);
                    const auto Chunk = std::span<const std::byte>(Wire).subspan(State.PendingOffset, Count);
                    const auto Status = Session_->SubmitData(Iterator->first, Chunk, false);
                    if (Status == H2::SubmitDataStatus::Blocked)
                    {
                        Blocked = true;
                        break;
                    }
                    if (Status == H2::SubmitDataStatus::Closed)
                    {
                        Iterator = Streams_.erase(Iterator);
                        Erased = true;
                        break;
                    }
                    if (Status == H2::SubmitDataStatus::Invalid)
                    {
                        return Prism::Fault::Code::ProtocolError;
                    }
                    State.PendingOffset += Count;
                    if (State.PendingOffset == Wire.size())
                    {
                        State.PendingResponses.pop_front();
                        State.PendingOffset = 0;
                    }
                }
                if (Erased)
                {
                    continue;
                }
                if (!Blocked && State.TrailersPending && State.PendingResponses.empty())
                {
                    if (const auto Headers = Session_->SubmitHeaders(
                            Iterator->first, MakeResponseTrailers(0), true); !Headers)
                    {
                        return Headers.error().Code;
                    }
                    Completed_ = true;
                    Iterator = Streams_.erase(Iterator);
                    continue;
                }
                ++Iterator;
            }
            return Prism::Fault::Code::Success;
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
                const auto Part = co_await Transport_->WriteSome(
                    std::span<const std::byte>(Output).subspan(Offset));
                const auto Error = Prism::Fault::ToNative(Part.Failure);
                const auto Written = Part.Bytes;
                if (Error || Written == 0U || Written > Output.size() - Offset)
                {
                    co_return false;
                }
                Offset += Written;
            }
            co_return true;
        }

        auto OnHeaders(const std::int32_t StreamId, const H2::HeaderList& Headers, const bool EndStream)
            -> void
        {
            auto [Iterator, Inserted] = Streams_.try_emplace(StreamId, Config_.MaxMessageBytes);
            if (!Inserted || Iterator->second.ResponseStarted)
            {
                const auto Reset = Session_->ResetStream(StreamId, H2::ErrorProtocol);
                if (!Reset) RecordControlFailure(Reset.error());
                return;
            }
            const auto Request = ParseRequestHeaders(Headers);
            if (!Request || Request->Path != Config_.Path || EndStream)
            {
                Iterator->second.ResponseStarted = true;
                const auto Response = Session_->SubmitHeaders(StreamId,
                    {{":status", "415"}, {"content-type", "application/grpc"}}, false);
                const auto Trailers = Session_->SubmitHeaders(
                    StreamId, MakeResponseTrailers(12), true);
                if (!Response) RecordControlFailure(Response.error());
                if (!Trailers) RecordControlFailure(Trailers.error());
                return;
            }
            Iterator->second.Accepted = true;
            Iterator->second.ResponseStarted = true;
            const auto ResponseHeaders = Session_->SubmitHeaders(
                StreamId, MakeResponseHeaders(), false);
            if (!ResponseHeaders) RecordControlFailure(ResponseHeaders.error());
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
                const auto Reset = Session_->ResetStream(StreamId, H2::ErrorProtocol);
                if (!Reset) RecordControlFailure(Reset.error());
                return;
            }
            for (const auto& Message : Messages)
            {
                std::vector<std::byte> Response;
                if (Handler_)
                {
                    Response = Handler_(std::span<const std::byte>(Message));
                }
                else
                {
                    Response.assign(Message.begin(), Message.end());
                }
                Iterator->second.PendingResponses.emplace_back(EncodeMessage(Response));
            }
        }

        auto OnStreamClose(const H2::StreamReceiveClosure &Closure) -> void
        {
            const auto Iterator = Streams_.find(Closure.StreamId);
            if (Iterator == Streams_.end())
            {
                return;
            }
            if (Closure.Kind == H2::StreamReceiveClosureKind::Reset)
            {
                Streams_.erase(Iterator);
                return;
            }
            if (Iterator->second.Accepted && Iterator->second.Decoder.Empty())
            {
                Iterator->second.TrailersPending = true;
                return;
            }
            Streams_.erase(Iterator);
        }

        auto RecordControlFailure(const Prism::Fault::Failure Failure) -> void
        {
            if (ControlFailure_.Succeeded()) ControlFailure_ = Failure;
        }

        Prism::SharedTransmission Transport_;
        Config Config_;
        MessageHandler Handler_;
        std::shared_ptr<H2::Session> Session_;
        std::unordered_map<std::int32_t, StreamState> Streams_;
        Prism::Fault::Failure ControlFailure_{};
        bool Completed_{false};
    };

    class ClientSession final : public std::enable_shared_from_this<ClientSession>
    {
    public:
        ClientSession(Prism::SharedTransmission Transport, Config ConfigValue = {})
            : Transport_(std::move(Transport)), Config_(std::move(ConfigValue)),
              Session_(std::make_shared<H2::Session>(Transport_->Executor(), false)),
              Decoder_(Config_.MaxMessageBytes)
        {
            Session_->OnHeaders = [this](const std::int32_t StreamId,
                                          const H2::HeaderList &Headers, const bool EndStream)
            { HandleHeaders(StreamId, Headers, EndStream); };
            Session_->OnData = [this](const std::int32_t StreamId,
                                       const std::span<const std::byte> Data)
            { HandleData(StreamId, Data); };
            Session_->OnStreamClose = [this](const H2::StreamReceiveClosure &Closure)
            { HandleStreamClose(Closure); };
        }

        /**
         * @brief 发送 unary 请求并返回唯一 typed 响应或完整传输失败。
         * @param Payload 借用到请求编码完成；响应、headers 与 trailers 按值返回。
         * @return 远端 gRPC status 留在成功响应中；I/O Code/Native 在失败值中原样保留。
         * @details 所有读写使用 Transport executor；请求以 END_STREAM 结束，Run 完成时关闭本 client transport。
         */
        [[nodiscard]] auto Run(std::span<const std::byte> Payload) -> Net::awaitable<ClientResult>
        {
            ClientResult Result{std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::ProtocolError})};
            const auto Prepared = PrepareRequest();
            if (!Prepared)
            {
                Result = std::unexpected(Prepared.error());
            }
            else
            {
                const auto Submitted = co_await SubmitRequest(Payload);
                if (!Submitted)
                {
                    Result = std::unexpected(Submitted.error());
                }
                else
                {
                    Result = co_await ReadResponse();
                }
            }

            const auto Closed = Transport_->Close();
            if (!Closed && Result)
            {
                co_return std::unexpected(Closed.error());
            }
            co_return Result;
        }
    private:
        auto HandleHeaders(const std::int32_t StreamId, const H2::HeaderList &Headers,
                           const bool EndStream) -> void
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
        }

        auto HandleData(const std::int32_t StreamId, const std::span<const std::byte> Data) -> void
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
        }

        auto HandleStreamClose(const H2::StreamReceiveClosure &Closure) -> void
        {
            if (Closure.StreamId == StreamId_)
            {
                Done_ = Closure.Kind == H2::StreamReceiveClosureKind::EndStream;
                Failed_ = Closure.Kind == H2::StreamReceiveClosureKind::Reset;
            }
        }

        /**
         * @brief 同步排入 unary 请求的设置与初始头。
         * @return 成功表示请求 stream 和头帧已入会话队列；失败保留完整 HTTP/2 Failure。
         * @details Session 与 Transport 由 ClientSession 强持有；须在 Transport executor 上
         *          串行调用。本操作没有取消点，POST 的初始头不结束发送半边；Run 负责后续
         *          I/O 并在结束时关闭该 client transport。
         */
        [[nodiscard]] auto PrepareRequest()
            -> std::expected<void, Prism::Fault::Failure>
        {
            Session_->SendSettings();
            const auto Opened = Session_->OpenStream(
                MakeRequestHeaders(Config_.Path, Config_.Authority), false);
            if (!Opened)
            {
                return std::unexpected(Opened.error());
            }
            StreamId_ = *Opened;
            return {};
        }

        [[nodiscard]] auto SubmitRequest(std::span<const std::byte> Payload)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            const auto Wire = EncodeMessage(Payload);
            if (Wire.empty() && !Payload.empty())
            {
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::OversizedMsg});
            }
            std::size_t Offset = 0;
            while (Offset < Wire.size())
            {
                const auto Count = (std::min)(std::size_t{16U * 1024U}, Wire.size() - Offset);
                const auto Last = Offset + Count == Wire.size();
                const auto Chunk = std::span<const std::byte>(Wire).subspan(Offset, Count);
                auto Status = Session_->SubmitData(StreamId_, Chunk, Last);
                while (Status == H2::SubmitDataStatus::Blocked)
                {
                    const auto Pumped = co_await PumpResponseFrame();
                    if (!Pumped)
                    {
                        co_return std::unexpected(Pumped.error());
                    }
                    Status = Session_->SubmitData(StreamId_, Chunk, Last);
                }
                if (Status == H2::SubmitDataStatus::Closed)
                {
                    co_return std::unexpected(
                        Prism::Fault::Failure{Prism::Fault::Code::ConnectionAborted});
                }
                if (Status == H2::SubmitDataStatus::Invalid)
                {
                    co_return std::unexpected(
                        Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
                }
                Offset += Count;
                const auto Flushed = co_await Flush();
                if (!Flushed)
                {
                    co_return std::unexpected(Flushed.error());
                }
            }
            co_return std::expected<void, Prism::Fault::Failure>{};
        }

        [[nodiscard]] auto PumpResponseFrame()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            std::array<std::byte, 16384> Buffer{};
            const auto Part = co_await Transport_->ReadSome(Buffer);
            if (Part.Failure.Failed())
            {
                co_return std::unexpected(Part.Failure);
            }
            if (Part.Bytes == 0U)
            {
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::IoError});
            }
            std::error_code Error;
            const auto Fed = Session_->Feed(
                std::span<const std::byte>(Buffer).first(Part.Bytes), Error);
            if (!Fed || Error)
            {
                if (Error)
                {
                    co_return std::unexpected(Prism::Fault::FromNative(Error));
                }
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::ProtocolError});
            }
            if (!Done_)
            {
                const auto Flushed = co_await Flush();
                if (!Flushed)
                {
                    co_return std::unexpected(Flushed.error());
                }
            }
            co_return std::expected<void, Prism::Fault::Failure>{};
        }

        [[nodiscard]] auto ReadResponse() -> Net::awaitable<ClientResult>
        {
            while (!Done_ && !Failed_ && Transport_->IsOpen())
            {
                const auto Pumped = co_await PumpResponseFrame();
                if (!Pumped)
                {
                    co_return std::unexpected(Pumped.error());
                }
            }
            if (Failed_)
            {
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::ProtocolError});
            }
            if (!Done_)
            {
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::IoError});
            }

            ClientResponse Result;
            Result.ResponseHeaders = ResponseHeaders_;
            Result.Trailers = Trailers_;
            Result.Payload = Payload_;
            for (const auto &Header : Trailers_)
            {
                if (Header.Name == "grpc-status")
                {
                    std::uint32_t Status = 1;
                    const auto Parsed = std::from_chars(Header.Value.data(),
                        Header.Value.data() + Header.Value.size(), Status);
                    if (Parsed.ec == std::errc{})
                    {
                        Result.GrpcStatus = Status;
                    }
                }
            }
            co_return Result;
        }

        [[nodiscard]] auto Flush()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            std::vector<std::byte> Output;
            if (!Session_->Collect(Output) || Output.empty())
            {
                co_return std::expected<void, Prism::Fault::Failure>{};
            }
            std::size_t Offset = 0;
            while (Offset < Output.size())
            {
                const auto Part = co_await Transport_->WriteSome(
                    std::span<const std::byte>(Output).subspan(Offset));
                if (Part.Failure.Failed())
                {
                    co_return std::unexpected(Part.Failure);
                }
                const auto Written = Part.Bytes;
                if (Written == 0U)
                {
                    co_return std::unexpected(Prism::Fault::FromNative(
                        std::make_error_code(std::errc::broken_pipe)));
                }
                if (Written > Output.size() - Offset)
                {
                    co_return std::unexpected(
                        Prism::Fault::Failure{Prism::Fault::Code::IoError});
                }
                Offset += Written;
            }
            co_return std::expected<void, Prism::Fault::Failure>{};
        }

        Prism::SharedTransmission Transport_;
        Config Config_;
        std::shared_ptr<H2::Session> Session_;
        MessageDecoder Decoder_;
        std::int32_t StreamId_{-1};
        bool Done_{false};
        bool Failed_{false};
        H2::HeaderList ResponseHeaders_;
        H2::HeaderList Trailers_;
        std::vector<std::byte> Payload_;
    };

} // namespace Prism::Gun::Grpc::Detail
