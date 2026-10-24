/**
 * @file GrpcSession.hpp
 * @brief gRPC HTTP/2 客户端和服务端会话 owner。
 * @details 会话 owner 负责 HTTP/2 输入输出、流回调和 unary message 生命周期；
 *          纯 framing 与 metadata 由 GrpcFraming/GrpcEndpoint 提供。
 */
#pragma once

#include <Prism/Protocols/Gun/GrpcFraming.hpp>
#include <Prism/Protocols/Gun/GrpcEndpoint.hpp>
#include <Prism/Protocols/Http2/Session.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/asio/awaitable.hpp>

#include <algorithm>
#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <span>
#include <system_error>
#include <unordered_map>
#include <vector>

namespace Prism::Gun::Grpc::Detail
{

    class ServerSession final : public std::enable_shared_from_this<ServerSession>
    {
    public:
        ServerSession(Prism::SharedTransmission Transport, Config ConfigValue = {},
            MessageHandler Handler = {});

        [[nodiscard]] auto Run() -> Net::awaitable<Prism::Fault::Failure>;

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

        [[nodiscard]] auto RetryPendingResponses() -> Prism::Fault::Code;
        [[nodiscard]] auto Flush() -> Net::awaitable<bool>;

        auto OnHeaders(const std::int32_t StreamId, const H2::HeaderList& Headers, const bool EndStream)
            -> void;

        auto OnData(const std::int32_t StreamId, const std::span<const std::byte> Data) -> void;

        auto OnStreamClose(const H2::StreamReceiveClosure &Closure) -> void;

        auto RecordControlFailure(const Prism::Fault::Failure Failure) -> void;

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
        ClientSession(Prism::SharedTransmission Transport, Config ConfigValue = {});

        /**
         * @brief 发送 unary 请求并返回唯一 typed 响应或完整传输失败。
         * @param Payload 借用到请求编码完成；完整响应、读写终态及关闭收尾按值返回。
         * @return 已完整解析的响应与请求/读取终态分开表达；Close 和 Drain 失败各自保留。
         * @details 所有读写使用 Transport executor；请求以 END_STREAM 结束，Run 完成时先关闭再排空本 client transport。
         */
        [[nodiscard]] auto Run(std::span<const std::byte> Payload)
            -> Net::awaitable<ClientOutcome>;
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
            -> std::expected<void, Prism::Fault::Failure>;

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
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;

        [[nodiscard]] auto ReadResponse() -> Net::awaitable<ClientOutcome>;

        [[nodiscard]] auto BuildResponse() const -> std::optional<ClientResponse>;

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
        Prism::Fault::Failure ProcessingFailure_{};
        Prism::Fault::Failure ReadTerminal_{};
        H2::HeaderList ResponseHeaders_;
        H2::HeaderList Trailers_;
        std::vector<std::byte> Payload_;
    };

} // namespace Prism::Gun::Grpc::Detail
