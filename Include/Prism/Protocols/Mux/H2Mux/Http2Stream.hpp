/** @file Http2Stream.hpp @brief 标准 HTTP/2 虚拟流的流控、双向终态和 tracked retirement。 */
#pragma once
#include <Prism/Protocols/Mux/H2Mux/Http2State.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <boost/asio/async_result.hpp>
#include <boost/asio/co_composed.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/deferred.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <system_error>
#include <tuple>
#include <utility>
#include <vector>
namespace Prism::Mux::H2Mux
{
    class Http2Stream final : public Prism::Transmission
    {
    public:
        Http2Stream(std::shared_ptr<Http2State> StateValue, std::int32_t StreamIdValue);

        [[nodiscard]] auto StreamId() const noexcept -> std::int32_t { return StreamId_; }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            return Executor_;
        }

        /** @brief 读取一部分虚拟流数据；结果与借用经正式前门恰好交付一次。 */
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            Initiate<ReadWork>(StreamRead{
                std::static_pointer_cast<Http2Stream>(Transmission::shared_from_this()), Buffer},
                std::move(Handler));
        }

        /** @brief 写入一部分虚拟流数据；保留 DATA 提交与 Flush 的完整写入语义。 */
        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            Initiate<WriteWork>(StreamWrite{
                std::static_pointer_cast<Http2Stream>(Transmission::shared_from_this()), Buffer},
                std::move(Handler));
        }

        /** @brief 关闭当前虚拟流；本地 END_STREAM 实际 Flush 前保持 admission slot。 */
        [[nodiscard]] auto OnClose() -> ControlResult override;
        /** @brief 本地半关闭只发送当前流 END_STREAM；共享 Raw 与兄弟流保持开启。 */
        auto StartWriteShutdown(Completion Handler) -> void override;

        /** @brief 取消只重置当前流；排队或 Flush 失败保留 typed cause 与 slot。 */
        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            return StartReset(Prism::Http2::ErrorCancel);
        }
        /** @brief 接管本 stream 的 RESET；不向共享连接传播 sibling cancellation。 */
        [[nodiscard]] auto StartReset(std::uint32_t ErrorCode) -> ControlResult;

        auto SetTimeout(const std::chrono::milliseconds Timeout) -> void override
        {
            if (State_ && State_->Raw) State_->Raw->SetTimeout(Timeout);
        }

        [[nodiscard]] auto IsOpen() const -> bool override
        {
            return !Closed_ && State_ && !State_->Closed && State_->Raw && State_->Raw->IsOpen();
        }

        [[nodiscard]] auto NextLayer() noexcept -> Prism::Transmission * override
        {
            // Raw 是 H2 根与所有虚拟流共享的 carrier，不归当前 child 所有。
            return nullptr;
        }

        [[nodiscard]] auto NextLayer() const noexcept -> const Prism::Transmission * override
        {
            // Raw 是 H2 根与所有虚拟流共享的 carrier，不归当前 child 所有。
            return nullptr;
        }

        auto Push(std::span<const std::byte> Data) -> void;

        auto MarkIncomingPending(bool Pending) -> void;

        /** @brief 由 root 在 catalog 登记后提交唯一 :status 200 并释放入向待定状态。 */
        [[nodiscard]] auto AcceptRequest()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;

        /** @brief 远端 END_STREAM 只封止接收；仍须完成本地终态及在途读写。 */
        auto SetRemoteClosed() -> void;

        /** @brief RST_STREAM 终止双向协议流；accepted child 可重复读取 ConnectionAborted。 */
        auto SetRemoteReset(std::uint32_t ErrorCode) -> void;
        /** @brief 根连接结束保留已接收 DATA 和准确终态，等 child 消费或显式关闭。 */
        auto SetConnectionClosed(Prism::Fault::Failure Terminal) -> void;

    private:
        auto FinalizeTerminalClose() -> void;
        [[nodiscard]] auto CloseBase() -> ControlResult;
        [[nodiscard]] auto PeerResetFailure() const noexcept -> Prism::Fault::Failure
        {
            if (LocalReset_) return {Prism::Fault::Code::Canceled};
            // HTTP/2 会话对关闭或重置的流统一返回 ConnectionAborted；wire 错误码由会话闭包保留。
            // typed 结果不得携带底层 close/cancel 的 native cause。
            return {Prism::Fault::Code::ConnectionAborted};
        }

    public:
        [[nodiscard]] auto CanRetire() const noexcept -> bool
        {
            return Retired_ || (CanAttemptRetirement() && !RetirementFailed_);
        }

        /** @brief 根关闭已发布而 child 尚未确认终态消费时阻止 Drain 提前封止读取。 */
        [[nodiscard]] auto AwaitsTerminalClose() const noexcept -> bool
        {
            return StreamTerminalPending_ && !TerminalCloseFinalized_;
        }

        [[nodiscard]] auto CanAttemptRetirement() const noexcept -> bool;

        /** @brief 仍占用本端并发流配额的流：双向终态尚未同时成立。 */
        [[nodiscard]] auto OccupiesQuota() const noexcept -> bool
        {
            // 只有本地终态与远端终态都已成立才释放并发 slot。
            return !Retired_ && !(LocalTerminal_ && RemoteClosed_);
        }

        [[nodiscard]] auto HasPendingControl() const noexcept -> bool
        {
            return LocalEndPending_ || ResetPending_;
        }

        auto MarkRetirementFailed(Prism::Fault::Failure Failure) -> void;

        auto MarkRetirementRecovered() noexcept -> void { RetirementFailed_ = false; }

        /** @brief 真实读写与控制屏障排空后分离已退休句柄和共享连接 owner。 */
        auto MarkRetired() noexcept -> void;

        /** @brief 等待本流所有 FIN/RESET/Flush 协程退栈并返回完整首个 typed failure。 */
        [[nodiscard]] auto DrainTerminations()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;

    private:
        enum class ControlKind : std::uint8_t { Fin, Reset };

        struct StreamRead final
        {
            std::shared_ptr<Http2Stream> Owner;
            std::span<std::byte> Buffer;
        };

        struct StreamWrite final
        {
            std::shared_ptr<Http2Stream> Owner;
            std::span<const std::byte> Buffer;
        };

        struct ControlRequest final
        {
            std::shared_ptr<Http2State> State;
            std::shared_ptr<Http2Stream> Stream;
            std::shared_ptr<Prism::Lifecycle::DrainBarrier> Barrier;
            std::int32_t Id{0};
            ControlKind Kind{ControlKind::Fin};
            std::uint32_t ErrorCode{Prism::Http2::ErrorNoError};
        };

        struct ReadWork final
        {
            template<class StateValue>
            auto operator()(StateValue Operation, StreamRead Input) const -> void
            {
                Prism::Transmission::ConfigureIo(Operation);
                if (!Input.Owner)
                    co_return std::tuple{Prism::IoResult{0, {Prism::Fault::Code::InvalidArgument}}};
                std::error_code ErrorCode;
                std::size_t Count = 0;
                try
                {
                    Count = co_await Net::co_spawn(
                        Input.Owner->Executor(),
                        Input.Owner->ReadPartial(Input.Buffer, ErrorCode),
                        Net::deferred);
                }
                catch (const boost::system::system_error &Exception)
                {
                    ErrorCode = static_cast<std::error_code>(Exception.code());
                }
                catch (const std::system_error &Exception)
                {
                    ErrorCode = Exception.code();
                }
                catch (...)
                {
                    ErrorCode = std::make_error_code(std::errc::io_error);
                }
                auto Failure = Prism::Fault::FromNative(ErrorCode);
                // ConnectionAborted 是 H2 流级 typed 终态，不携带根连接 native cause。
                if (Failure.Code == Prism::Fault::Code::ConnectionAborted)
                    Failure.Native.clear();
                co_return std::tuple{Prism::IoResult{Count, Failure}};
            }
        };

        struct WriteWork final
        {
            template<class StateValue>
            auto operator()(StateValue Operation, StreamWrite Input) const -> void
            {
                Prism::Transmission::ConfigureIo(Operation);
                if (!Input.Owner)
                    co_return std::tuple{Prism::IoResult{0, {Prism::Fault::Code::InvalidArgument}}};
                std::error_code ErrorCode;
                std::size_t Count = 0;
                try
                {
                    Count = co_await Net::co_spawn(
                        Input.Owner->Executor(),
                        Input.Owner->WritePartial(Input.Buffer, ErrorCode),
                        Net::deferred);
                }
                catch (const boost::system::system_error &Exception)
                {
                    ErrorCode = static_cast<std::error_code>(Exception.code());
                }
                catch (const std::system_error &Exception)
                {
                    ErrorCode = Exception.code();
                }
                catch (...)
                {
                    ErrorCode = std::make_error_code(std::errc::io_error);
                }
                auto Failure = Prism::Fault::FromNative(ErrorCode);
                if (Failure.Code == Prism::Fault::Code::ConnectionAborted)
                    Failure.Native.clear();
                co_return std::tuple{Prism::IoResult{Count, Failure}};
            }
        };

        /** @brief 部分读取先排空已收 DATA，再交付 peer reset、连接终态或远端 EOF。 */
        [[nodiscard]] auto ReadPartial(std::span<std::byte> Buffer, std::error_code &ErrorCode)
            -> Net::awaitable<std::size_t>;

        /** @brief 原协程体：部分写入，保留 DATA 提交与 Flush 的完整写入语义。 */
        [[nodiscard]] auto WritePartial(
            std::span<const std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t>;

        [[nodiscard]] auto MakeControlRequest(
            const ControlKind Kind,
            const std::uint32_t ErrorCode) -> ControlRequest;

        [[nodiscard]] static auto SubmitControl(ControlRequest Value) -> ControlResult;
        [[nodiscard]] static auto ProcessControl(ControlRequest Request) -> Net::awaitable<void>;
        auto OnControlFailed(ControlKind Kind, Prism::Fault::Failure Failure) -> void;
        auto CompletePendingWriteShutdowns(Prism::Fault::Failure Failure) -> void;
        auto OnControlCompleted(
            ControlKind Kind,
            const std::expected<void, Prism::Fault::Failure> &Outcome) -> void;

        auto TryQueueRetirement() -> void;

        /** @brief 在唯一 stream executor 上发起一次受跟踪的部分 I/O。 */
        template<class Work, class Input>
        auto Initiate(Input Value, Completion Handler) -> void
        {
            Net::async_initiate<Completion, void(Prism::IoResult)>(
                Net::co_composed<void(Prism::IoResult)>(Work{}, Executor()),
                Handler, std::move(Value));
        }

        Net::any_io_executor Executor_;
        std::shared_ptr<Http2State> State_;
        std::int32_t StreamId_{0};
        /**
         * @brief 唤醒通道必须在所属 io_context 存活期间释放。
         * @details Stream 可能被调用方保留到连接退休之后；退休时显式释放通道，
         *          避免对象析构晚于 channel service 导致的 use-after-free。
         */
        std::unique_ptr<Net::experimental::channel<void(
            boost::system::error_code)>> Notify_;
        std::deque<std::vector<std::byte>> Rx_;
        bool RemoteClosed_{false};
        bool Closed_{false};
        bool ConnectionClosed_{false};
        bool StreamTerminalPending_{false};
        bool TerminalCloseFinalized_{false};
        bool CloseReceiptAvailable_{false};
        bool FinSent_{false};
        bool LocalEndPending_{false};
        bool ResetPending_{false};
        bool ResetByPeer_{false};
        /** @brief 本端发起的 RST/Cancel 与对端 RST 区分；本地取消按 Canceled 交付。 */
        bool LocalReset_{false};
        /** @brief 本端正常 Close 已封止读取；与远端 EOF 区分。 */
        bool LocalClose_{false};
        std::uint32_t RemoteResetCode_{Prism::Http2::ErrorNoError};
        bool LocalTerminal_{false};
        bool LocalEndFlushed_{false};
        bool IncomingPending_{true};
        bool RetirementQueued_{false};
        bool RetirementFailed_{false};
        bool Retired_{false};
        std::optional<Prism::Fault::Failure> ConnectionTerminal_;
        std::optional<Prism::Fault::Failure> LocalEndFailure_;
        std::vector<Completion> PendingWriteShutdowns_;
        std::shared_ptr<Prism::Lifecycle::DrainBarrier> Terminations_;
    };
}
