/**
 * @file GrpcStreamOwner.hpp
 * @brief 标准 gRPC message stream 到 Preview Transmission 的 owner。
 * @details 该 owner 独占 HTTP/2 读写协程、接收队列和关闭状态；上层只看到连续
 *          的 payload，不直接操作 HTTP/2 状态机。
 */
#pragma once
#include <Preview/Protocols/Gun/GrpcFraming.hpp>
#include <Preview/Protocols/Gun/GrpcMetadata.hpp>
#include <Preview/Protocols/Gun/Detail/GrpcStreamActivity.hpp>
#include <Preview/Protocols/Http2/Session.hpp>
#include <Preview/Contract/Ingress/InboundAdmission.hpp>
#include <Preview/Foundation/Fault/FailureState.hpp>
#include <Preview/Transport/Transmission.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/deferred.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <exception>
#include <memory>
#include <span>
#include <system_error>
#include <utility>
#include <vector>

namespace Preview::Gun::Grpc::Detail
{
    class StreamFactory;
    struct GrpcStreamDriver;

    /**
     * @class StreamTransport
     * @brief 将标准 gRPC message stream 映射为 Preview Transmission。
     * @details HTTP/2 解析、DATA 分帧和 trailers 由 owner-held coroutines 驱动；
     *          上层协议只看到连续的 message payload，不接触 HTTP/2 状态。
     */
    class StreamTransport final : public Preview::Transmission
    {
    public:
        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            return Lower_->Executor();
        }

        [[nodiscard]] auto Activity() const noexcept
            -> std::shared_ptr<Preview::Contract::CarrierActivity> override
        {
            return Activity_;
        }

        [[nodiscard]] auto RequiresExternalCloseReceipt() const noexcept -> bool override
        {
            return true;
        }

        /** @brief 读取一部分已解码 message payload；结果与借用沿正式前门交付一次。 */
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            Initiate<ReadWork>(GrpcRead{std::static_pointer_cast<StreamTransport>(Transmission::shared_from_this()), Buffer},
                     std::move(Handler));
        }

        /** @brief 写入一部分 message payload；编码与 HTTP/2 提交语义不变。 */
        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            Initiate<WriteWork>(GrpcWrite{std::static_pointer_cast<StreamTransport>(Transmission::shared_from_this()), Buffer},
                     std::move(Handler));
        }

        /**
         * @brief 真实写半关闭：提交本地 trailers 并结束本地流；读取方向仍然可用。
         */
        auto StartWriteShutdown(Completion Handler) -> void override
        {
            Preview::Fault::Failure Failure;
            if (Closed_)
            {
                Failure = Activity_->Failure();
                if (Failure.Succeeded()) Failure = {Preview::Fault::Code::Canceled};
            }
            else if (StreamId_ <= 0)
            {
                Failure = {Preview::Fault::Code::ProtocolError};
            }
            else if (!LocalEnded_)
            {
                const auto Trailers = Session_->SubmitHeaders(
                    StreamId_, MakeResponseTrailers(0), true);
                if (!Trailers)
                {
                    Failure = Trailers.error();
                }
                else
                {
                    LocalEnded_ = true;
                    // 满队列时已有通知足以唤醒 writer；本端结束仍由 Flush completion 退栈。
                    (void)WriteNotify_.try_send(boost::system::error_code{});
                }
            }
            if (Failure.Failed()) RecordFailure(Failure);
            Preview::Transport::Detail::PostResult(
                Executor(), std::move(Handler), Preview::IoResult{0, Failure});
        }

        /**
         * @brief 封止本地状态并交付底层关闭
         * @return 底层命令接管结果；实际退出由 Activity()->Drain() 另行等待。
         */
        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            if (Closed_)
            {
                return {};
            }
            Closed_ = true;
            Activity_->Seal();
            const auto Result = Lower_->Close();
            if (!Result)
            {
                RecordFailure(Result.error());
            }
            Ready_.close();
            RxNotify_.close();
            WriteNotify_.close();
            return Result;
        }

        /**
         * @brief 可重复取消底层挂起操作并唤醒本层等待者
         * @return 底层命令接管结果；不宣称已经关闭。
         */
        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            const auto Result = Lower_->Cancel();
            if (!Result)
            {
                RecordFailure(Result.error());
            }
            (void)RxNotify_.try_send(boost::system::error_code{});
            (void)WriteNotify_.try_send(boost::system::error_code{});
            return Result;
        }

        auto SetTimeout(std::chrono::milliseconds Timeout) -> void override
        {
            Lower_->SetTimeout(Timeout);
        }

        [[nodiscard]] auto IsOpen() const -> bool override
        {
            return !Closed_ && Lower_->IsOpen();
        }

        [[nodiscard]] auto NextLayer() noexcept -> Preview::Transmission* override
        {
            return Lower_.get();
        }

    private:
        friend class StreamFactory;
        friend struct GrpcStreamDriver;

        auto SignalReady(Preview::Fault::Failure Failure) -> void
        {
            if (Failure.Failed())
            {
                RecordFailure(Failure);
                ReadyOk_ = false;
            }
            else
            {
                ReadyOk_ = true;
            }
            if (ReadySignaled_)
            {
                return;
            }
            ReadySignaled_ = true;
            (void)Ready_.try_send(boost::system::error_code{});
        }

        [[nodiscard]] auto RetireFailure(
            Preview::Contract::InboundAdmission Admission,
            Preview::Fault::Failure Cause)
            -> Net::awaitable<Preview::Fault::Failure>
        {
            co_await Net::this_coro::throw_if_cancelled(false);
            co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
            RecordFailure(Cause);
            const auto Canceled = Cancel();
            if (!Canceled) RecordFailure(Canceled.error());
            const auto Closed = Close();
            if (!Closed) RecordFailure(Closed.error());
            const auto Drained = co_await Activity_->Drain();
            if (!Drained) RecordFailure(Drained.error());
            co_return co_await Admission.Retire(Activity_->Failure());
        }

        /** @brief 原协程体：等待并取出一段已解码 payload，保留 dispatch 与通知语义。 */
        [[nodiscard]] auto ReadPartial(std::span<std::byte> Buffer, std::error_code& Error)
            -> Net::awaitable<std::size_t>
        {
            Error.clear();
            co_await Net::dispatch(Executor(), Net::use_awaitable);
            while (!Closed_ && !RemoteEnded_ && RxQueue_.empty())
            {
                RxNotify_.reset();
                boost::system::error_code NotifyError;
                co_await RxNotify_.async_receive(Net::redirect_error(Net::use_awaitable, NotifyError));
                if (NotifyError && Closed_)
                {
                    co_return 0;
                }
            }
            if (RxQueue_.empty())
            {
                const auto Failure = Activity_->Failure();
                if (Failure.Failed())
                {
                    Error = Preview::Fault::ToNative(Failure);
                }
                co_return 0;
            }
            auto& Front = RxQueue_.front();
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

        /** @brief 原协程体：编码并提交一段 payload，保留 dispatch 与失败判定。 */
        [[nodiscard]] auto WritePartial(std::span<const std::byte> Buffer, std::error_code& Error)
            -> Net::awaitable<std::size_t>
        {
            Error.clear();
            co_await Net::dispatch(Executor(), Net::use_awaitable);
            if (Closed_ || !ReadyOk_ || StreamId_ <= 0)
            {
                const auto Failure = Activity_->Failure();
                if (Failure.Failed())
                {
                    Error = Preview::Fault::ToNative(Failure);
                }
                else
                {
                    Error = std::make_error_code(std::errc::broken_pipe);
                }
                co_return 0;
            }
            std::vector<std::byte> Payload;
            if (TunEnvelope_)
                Payload = EncodeTunMessage(Buffer);
            else
                Payload.assign(Buffer.begin(), Buffer.end());
            const auto Message = EncodeMessage(Payload);
            if (Message.empty() && !Buffer.empty())
            {
                Error = Preview::Fault::ToNative(
                    Preview::Fault::Failure{Preview::Fault::Code::OversizedMsg});
                co_return 0;
            }
            std::size_t Offset = 0;
            while (Offset < Message.size())
            {
                const auto Count = (std::min)(std::size_t{16U * 1024U}, Message.size() - Offset);
                const auto Chunk = std::span<const std::byte>(Message).subspan(Offset, Count);
                auto Status = Session_->SubmitData(StreamId_, Chunk, false);
                while (Status == H2::SubmitDataStatus::Blocked)
                {
                    (void)WriteNotify_.try_send(boost::system::error_code{});
                    const auto Writable = co_await Session_->AwaitWritable(StreamId_, Count);
                    if (!Writable)
                    {
                        Error = Preview::Fault::ToNative(Writable.error());
                        RecordFailure(Writable.error());
                        RecordControlFailure(Close());
                        co_return 0;
                    }
                    Status = Session_->SubmitData(StreamId_, Chunk, false);
                }
                if (Status != H2::SubmitDataStatus::Accepted)
                {
                    auto Failure = Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument};
                    if (Status == H2::SubmitDataStatus::Closed)
                    {
                        Failure = {Preview::Fault::Code::ConnectionAborted};
                    }
                    Error = Preview::Fault::ToNative(Failure);
                    RecordFailure(Failure);
                    RecordControlFailure(Close());
                    co_return 0;
                }
                Offset += Count;
                (void)WriteNotify_.try_send(boost::system::error_code{});
            }
            co_return Buffer.size();
        }

        struct GrpcRead final { std::shared_ptr<StreamTransport> Owner; std::span<std::byte> Buffer; };
        struct GrpcWrite final { std::shared_ptr<StreamTransport> Owner; std::span<const std::byte> Buffer; };
        struct ReadWork final
        {
            template<class State>
            auto operator()(State Operation, GrpcRead Input) const -> void
            {
                Preview::Transport::Detail::ConfigureIo(Operation);
                if (!Input.Owner) co_return std::tuple{Preview::IoResult{0, {Preview::Fault::Code::InvalidArgument}}};
                std::error_code Error;
                const auto Count = co_await Net::co_spawn(
                    Input.Owner->Executor(), Input.Owner->ReadPartial(Input.Buffer, Error), Net::deferred);
                co_return std::tuple{Preview::IoResult{Count, Preview::Fault::FromNative(Error)}};
            }
        };
        struct WriteWork final
        {
            template<class State>
            auto operator()(State Operation, GrpcWrite Input) const -> void
            {
                Preview::Transport::Detail::ConfigureIo(Operation);
                if (!Input.Owner) co_return std::tuple{Preview::IoResult{0, {Preview::Fault::Code::InvalidArgument}}};
                std::error_code Error;
                const auto Count = co_await Net::co_spawn(
                    Input.Owner->Executor(), Input.Owner->WritePartial(Input.Buffer, Error), Net::deferred);
                co_return std::tuple{Preview::IoResult{Count, Preview::Fault::FromNative(Error)}};
            }
        };
        template<class Work, class Input>
        auto Initiate(Input Value, Completion Handler) -> void
        {
            Net::async_initiate<Completion, void(Preview::IoResult)>(
                Net::co_composed<void(Preview::IoResult)>(Work{}, Executor()), Handler, std::move(Value));
        }

        StreamTransport(Preview::SharedTransmission Lower, Config ConfigValue)
            : Preview::Transmission(Lower->Executor()),
              Lower_(std::move(Lower)), Config_(std::move(ConfigValue)),
              Session_(std::make_shared<H2::Session>(Lower_->Executor(), true)),
              Ready_(Lower_->Executor(), 1),
              RxNotify_(Lower_->Executor(), 1),
              WriteNotify_(Lower_->Executor(), 8), Decoder_(Config_.MaxMessageBytes)
        {
            Activity_ = std::make_shared<GrpcStreamActivity>(
                Lower_->Executor(), GrpcStreamActivityLayers{
                    Preview::Transmission::Activity(), Lower_->Activity(), CloseReceipt()});
            Session_->OnHeaders = [this](const std::int32_t StreamId,
                                          const H2::HeaderList &Headers, const bool EndStream)
            { HandleHeaders(StreamId, Headers, EndStream); };
            Session_->OnData = [this](const std::int32_t StreamId,
                                       const std::span<const std::byte> Data)
            { HandleData(StreamId, Data); };
            Session_->OnStreamClose = [this](const H2::StreamReceiveClosure &Closure)
            { HandleStreamClose(Closure); };
        }

        auto HandleHeaders(const std::int32_t StreamId, const H2::HeaderList &Headers,
                           const bool EndStream) -> void
        {
            const auto Request = ParseRequestHeaders(Headers);
            if (StreamId_ > 0 || EndStream)
            {
                const auto Reset = Session_->ResetStream(StreamId, H2::ErrorProtocol);
                if (!Reset)
                {
                    RecordFailure(Reset.error());
                    RecordControlFailure(Close());
                }
                return;
            }
            if (!Request || Request->Path != Config_.Path)
            {
                const auto Response = Session_->SubmitHeaders(
                    StreamId, {{":status", "415"}, {"content-type", "application/grpc"}}, false);
                const auto Trailers = Session_->SubmitHeaders(
                    StreamId, MakeResponseTrailers(12), true);
                if (!Response || !Trailers)
                {
                    auto Failure = Preview::Fault::Failure{};
                    if (!Response) Failure = Response.error();
                    else Failure = Trailers.error();
                    RecordFailure(Failure);
                    RecordControlFailure(Close());
                    SignalReady(Failure);
                    return;
                }
                SignalReady({Preview::Fault::Code::ProtocolError});
                return;
            }
            StreamId_ = StreamId;
            const auto SubmitResult = Session_->SubmitHeaders(StreamId, MakeResponseHeaders(), false);
            if (!SubmitResult)
                SignalReady(SubmitResult.error());
            else
                SignalReady({});
            (void)WriteNotify_.try_send(boost::system::error_code{});
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
                const Preview::Fault::Failure Failure{
                    Preview::Fault::Code::ProtocolError};
                RecordFailure(Failure);
                if (Session_->ResetStream(StreamId, H2::ErrorProtocol))
                {
                    RemoteEnded_ = true;
                }
                else
                {
                    RecordControlFailure(Close());
                }
                (void)RxNotify_.try_send(boost::system::error_code{});
                return;
            }
            for (auto &Message : Messages)
            {
                if (auto TunMessage = DecodeTunMessage(Message))
                {
                    TunEnvelope_ = true;
                    RxQueue_.push_back(std::move(*TunMessage));
                }
                else
                {
                    RxQueue_.push_back(std::move(Message));
                }
            }
            if (!Messages.empty())
            {
                (void)RxNotify_.try_send(boost::system::error_code{});
            }
        }

        auto HandleStreamClose(const H2::StreamReceiveClosure &Closure) -> void
        {
            if (Closure.StreamId != StreamId_)
            {
                return;
            }
            if (Closure.Kind == H2::StreamReceiveClosureKind::EndStream)
            {
                RemoteEnded_ = true;
                (void)RxNotify_.try_send(boost::system::error_code{});
                return;
            }
            auto Code = Preview::Fault::Code::ProtocolError;
            if (Closure.ErrorCode == H2::ErrorNoError)
                Code = Preview::Fault::Code::ConnectionReset;
            RecordFailure({Code});
            RecordControlFailure(Close());
        }

        [[nodiscard]] auto Flush() -> Net::awaitable<Preview::Fault::Failure>
        {
            std::vector<std::byte> Output;
            if (!Session_->Collect(Output) || Output.empty())
            {
                co_return Preview::Fault::Failure{};
            }
            std::size_t Offset = 0;
            while (Offset < Output.size())
            {
                const auto Part = co_await Lower_->WriteSome(
                    std::span<const std::byte>(Output).subspan(Offset));
                const auto Written = Part.Bytes;
                if (Part.Failure.Failed())
                {
                    co_return Part.Failure;
                }
                if (Written > Output.size() - Offset)
                {
                    co_return Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument};
                }
                if (Written == 0U)
                {
                    co_return Preview::Fault::Failure{Preview::Fault::Code::WouldBlock};
                }
                Offset += Written;
            }
            co_return Preview::Fault::Failure{};
        }

        [[nodiscard]] auto ReadLoop() -> Net::awaitable<void>
        {
            Session_->SendSettings();
            (void)WriteNotify_.try_send(boost::system::error_code{});
            std::array<std::byte, 16384> Buffer{};
            while (!Closed_ && Lower_->IsOpen())
            {
                const auto Part = co_await Lower_->ReadSome(Buffer);
                const auto Count = Part.Bytes;
                if (Part.Failure.Failed() || Count == 0U)
                {
                    auto Failure = Part.Failure;
                    if (!Failure.Failed())
                    {
                        Failure = {Preview::Fault::Code::Eof};
                    }
                    SignalReady(Failure);
                    RecordControlFailure(Close());
                    co_return;
                }
                std::error_code Error;
                if (!Session_->Feed(std::span<const std::byte>(Buffer).first(Count), Error) || Error)
                {
                    auto Failure = Preview::Fault::Failure{Preview::Fault::Code::ProtocolError};
                    if (Error)
                    {
                        Failure = Preview::Fault::FromNative(Error);
                    }
                    SignalReady(Failure);
                    RecordControlFailure(Close());
                    co_return;
                }
                (void)WriteNotify_.try_send(boost::system::error_code{});
            }
            if (!Closed_)
            {
                SignalReady({Preview::Fault::Code::Eof});
                RecordControlFailure(Close());
            }
        }

        [[nodiscard]] auto WriteLoop() -> Net::awaitable<void>
        {
            while (!Closed_)
            {
                boost::system::error_code Error;
                co_await WriteNotify_.async_receive(Net::redirect_error(Net::use_awaitable, Error));
                if (Error || Closed_)
                {
                    co_return;
                }
                const auto Failure = co_await Flush();
                if (Failure.Failed())
                {
                    SignalReady(Failure);
                    RecordControlFailure(Close());
                    co_return;
                }
            }
        }

        Preview::SharedTransmission Lower_;
        std::shared_ptr<GrpcStreamActivity> Activity_;
        Config Config_;
        std::shared_ptr<H2::Session> Session_;
        Net::experimental::channel<void(boost::system::error_code)> Ready_;

        Net::experimental::channel<void(boost::system::error_code)> RxNotify_;
        Net::experimental::channel<void(boost::system::error_code)> WriteNotify_;
        MessageDecoder Decoder_;
        std::deque<std::vector<std::byte>> RxQueue_;
        std::size_t RxOffset_{0};
        std::int32_t StreamId_{-1};
        bool ReadyOk_{false};
        bool ReadySignaled_{false};
        bool TunEnvelope_{false};
        bool LocalEnded_{false};
        bool RemoteEnded_{false};
        bool Closed_{false};
        auto RecordFailure(const Preview::Fault::Failure Failure) noexcept -> void
        {
            if (Failure.Failed())
            {
                // 同一首因由 accepted activity owner 统一保存。
                if (Activity_) Activity_->RecordFailure(Failure);
            }
        }

        auto RecordControlFailure(const Preview::Transmission::ControlResult &Result) noexcept -> void
        {
            if (!Result) RecordFailure(Result.error());
        }
    };

} // namespace Preview::Gun::Grpc::Detail
