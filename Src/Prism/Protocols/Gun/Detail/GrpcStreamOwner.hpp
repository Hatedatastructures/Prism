/**
 * @file GrpcStreamOwner.hpp
 * @brief 标准 gRPC message stream 到 Prism Transmission 的 owner。
 * @details 该 owner 独占 HTTP/2 读写协程、接收队列和关闭状态；上层只看到连续
 *          的 payload，不直接操作 HTTP/2 状态机。
 */
#pragma once
#include <Prism/Protocols/Gun/GrpcFraming.hpp>
#include <Prism/Protocols/Gun/GrpcEndpoint.hpp>
#include <Prism/Protocols/Gun/Detail/GrpcStreamActivity.hpp>
#include <Prism/Protocols/Http2/Session.hpp>
#include <Prism/Contract/Ingress/InboundAdmission.hpp>
#include <Prism/Foundation/Fault/FailureState.hpp>
#include <Prism/Transport/Transmission.hpp>

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
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <exception>
#include <memory>
#include <optional>
#include <span>
#include <system_error>
#include <tuple>
#include <utility>
#include <vector>

namespace Prism::Gun::Grpc::Detail
{
    class StreamFactory;
    struct GrpcStreamDriver;

    /**
     * @class StreamTransport
     * @brief 将标准 gRPC message stream 映射为 Prism Transmission。
     * @details HTTP/2 解析、DATA 分帧和 trailers 由 owner-held coroutines 驱动；
     *          上层协议只看到连续的 message payload，不接触 HTTP/2 状态。
     */
    class StreamTransport final : public Prism::Transmission
    {
    public:
        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            return Prism::Transmission::Executor();
        }

        [[nodiscard]] auto Activity() const noexcept
            -> std::shared_ptr<Prism::Contract::CarrierActivity> override
        {
            return Activity_;
        }

        [[nodiscard]] auto RequiresExternalCloseReceipt() const noexcept -> bool override
        {
            return true;
        }

        /** @brief 读取一部分已解码 message payload；结果与借用沿正式前门交付一次。 */
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override;

        /** @brief 写入一部分 message payload；编码与 HTTP/2 提交语义不变。 */
        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override;

        /**
         * @brief 真实写半关闭：提交本地 trailers 并结束本地流；读取方向仍然可用。
         */
        auto StartWriteShutdown(Completion Handler) -> void override;

        /**
         * @brief 封止本地状态并交付底层关闭
         * @return 底层命令接管结果；实际退出由 Activity()->Drain() 另行等待。
         */
        [[nodiscard]] auto OnClose() -> ControlResult override;

        /**
         * @brief 可重复取消底层挂起操作并唤醒本层等待者
         * @return 底层命令接管结果；不宣称已经关闭。
         */
        [[nodiscard]] auto OnCancel() -> ControlResult override;

        auto SetTimeout(std::chrono::milliseconds Timeout) -> void override
        {
            Lower_->SetTimeout(Timeout);
        }

        [[nodiscard]] auto IsOpen() const -> bool override
        {
            return !Closed_ && Lower_->IsOpen();
        }

        [[nodiscard]] auto NextLayer() noexcept -> Prism::Transmission* override
        {
            return Lower_.get();
        }

    private:
        enum class PublicReadState : std::uint8_t
        {
            Idle,
            Active,
            Canceled,
        };

        friend class StreamFactory;
        friend struct GrpcStreamDriver;

        auto SignalReady(Prism::Fault::Failure Failure) -> void;

        [[nodiscard]] auto RetireFailure(
            Prism::Contract::InboundAdmission Admission,
            Prism::Fault::Failure Cause)
            -> Net::awaitable<Prism::Fault::Failure>;

        /** @brief 原协程体：等待并取出一段已解码 payload，保留 dispatch 与通知语义。 */
        [[nodiscard]] auto ReadPartial(std::span<std::byte> Buffer, std::error_code& Error)
            -> Net::awaitable<std::size_t>;

        /** @brief 原协程体：编码并提交一段 payload，保留 dispatch 与失败判定。 */
        [[nodiscard]] auto WritePartial(std::span<const std::byte> Buffer, std::error_code& Error)
            -> Net::awaitable<std::size_t>;

        struct GrpcRead final { std::shared_ptr<StreamTransport> Owner; std::span<std::byte> Buffer; };
        struct GrpcWrite final { std::shared_ptr<StreamTransport> Owner; std::span<const std::byte> Buffer; };
        struct ReadWork final
        {
            template<class State>
            auto operator()(State Operation, GrpcRead Input) const -> void
            {
                Prism::Transmission::ConfigureIo(Operation);
                if (!Input.Owner) co_return std::tuple{Prism::IoResult{0, {Prism::Fault::Code::InvalidArgument}}};
                std::error_code Error;
                const auto Count = co_await Net::co_spawn(
                    Input.Owner->Executor(), Input.Owner->ReadPartial(Input.Buffer, Error), Net::deferred);
                co_return std::tuple{Prism::IoResult{Count, Prism::Fault::FromNative(Error)}};
            }
        };
        struct WriteWork final
        {
            template<class State>
            auto operator()(State Operation, GrpcWrite Input) const -> void
            {
                Prism::Transmission::ConfigureIo(Operation);
                if (!Input.Owner) co_return std::tuple{Prism::IoResult{0, {Prism::Fault::Code::InvalidArgument}}};
                std::error_code Error;
                const auto Count = co_await Net::co_spawn(
                    Input.Owner->Executor(), Input.Owner->WritePartial(Input.Buffer, Error), Net::deferred);
                co_return std::tuple{Prism::IoResult{Count, Prism::Fault::FromNative(Error)}};
            }
        };
        template<class Work, class Input>
        auto Initiate(Input Value, Completion Handler) -> void
        {
            Net::async_initiate<Completion, void(Prism::IoResult)>(
                Net::co_composed<void(Prism::IoResult)>(Work{}, Executor()), Handler, std::move(Value));
        }

        StreamTransport(Prism::SharedTransmission Lower, Config ConfigValue);

        auto HandleHeaders(const std::int32_t StreamId, const H2::HeaderList &Headers,
                           const bool EndStream) -> void;

        auto HandleData(const std::int32_t StreamId, const std::span<const std::byte> Data) -> void;

        auto HandleStreamClose(const H2::StreamReceiveClosure &Closure) -> void;

        /** @brief 等待本地 END_STREAM 帧真实写出后完成写半关闭操作。 */
        auto CompleteWriteShutdowns(Prism::Fault::Failure Failure) -> void;

        [[nodiscard]] auto Flush() -> Net::awaitable<Prism::Fault::Failure>;

        [[nodiscard]] auto ReadLoop() -> Net::awaitable<void>;

        [[nodiscard]] auto WriteLoop() -> Net::awaitable<void>;

        Prism::SharedTransmission Lower_;
        std::shared_ptr<GrpcStreamActivity> Activity_;
        Config Config_;
        std::shared_ptr<H2::Session> Session_;
        Net::experimental::channel<void(boost::system::error_code)> Ready_;

        Net::experimental::channel<void(boost::system::error_code)> RxNotify_;
        Net::experimental::channel<void(boost::system::error_code)> WriteNotify_;
        MessageDecoder Decoder_;
        std::deque<std::vector<std::byte>> RxQueue_;
        std::size_t RxOffset_{0};
        /** @brief 已握手流的读向终态；队列耗尽前不封止 wrapper。 */
        std::optional<Prism::Fault::Failure> ReadTerminal_;
        /** @brief 同次 Feed 中的 gRPC 解码错误，始终优先于下层终态。 */
        Prism::Fault::Failure ProcessingFailure_{};
        /** @brief response writer 失败；只在 read terminal 后延迟 wrapper 关闭。 */
        Prism::Fault::Failure WriterFailure_{};
        std::vector<Completion> PendingWriteShutdowns_;
        /** @brief 一次性绑定单个公共读操作的取消状态；Transmission 要求读向串行发起。 */
        std::atomic<PublicReadState> PublicReadState_{PublicReadState::Idle};
        std::int32_t StreamId_{-1};
        bool ReadyOk_{false};
        bool ReadySignaled_{false};
        bool ReadInFlight_{false};
        bool CancelPendingRead_{false};
        bool WriterFailed_{false};
        bool TunEnvelope_{false};
        bool LocalEnded_{false};
        bool LocalEndFlushPending_{false};
        bool LocalEndFlushed_{false};
        bool RemoteEnded_{false};
        bool ResetReceived_{false};
        bool Closed_{false};
        auto RecordFailure(const Prism::Fault::Failure Failure) noexcept -> void;

        auto RecordControlFailure(const Prism::Transmission::ControlResult &Result) noexcept -> void;
    };

} // namespace Prism::Gun::Grpc::Detail
