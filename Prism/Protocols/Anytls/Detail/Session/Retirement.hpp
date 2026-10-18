/**
 * @file Retirement.hpp
 * @brief AnyTLS 传输链的控制结果、真实 Activity drain 与失败实物回收。
 * @details retirement owner 在 admission/握手前预构造；接管 transport 与 child lease 后，
 *          任一关闭、调度或 drain 失败都由 ClosingStorage 保留同一实物并允许重试。
 */
#pragma once

#include <Prism/Foundation/Executor/ClosingStorage.hpp>
#include <Prism/Foundation/Executor/ContextOwner.hpp>
#include <Prism/Foundation/Executor/ExecutorReclaimer.hpp>
#include <Prism/Foundation/Fault/FailureState.hpp>
#include <Prism/Protocols/Anytls/Detail/Session/RetirementFailure.hpp>
#include <Prism/Protocols/Anytls/Detail/Session/RetirementExecutor.hpp>
#include <Prism/Account/Lease.hpp>
#include <Prism/Contract/Ingress/MuxRootCreateRequest.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/bind_executor.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <atomic>
#include <cstddef>
#include <exception>
#include <expected>
#include <memory>
#include <optional>
#include <utility>

namespace Prism::Anytls::Detail
{
    namespace Net = boost::asio;

    /**
     * @brief AnyTLS 传输链与 child quota 的预构造最终关闭 owner。
     * @details owner 在握手或 child admission 开始前分配；Attach 只移动 SharedTransmission 与
     *          StreamLease，不分配。owner 本身先持有备用 ProcessStorage；接管实物后优先切换
     *          到对应 executor 的 ClosingStorage。只有原 executor 上 Cancel、Close 和每层真实
     *          Activity Drain 全成功才释放 lease。reclaimer/ticket 分配或 dispatch 失败时，
     *          已预构造 owner 保留整条实物与 lease，后续 Retry 可重新准备 reclaimer。
     */
    class TransportRetirement final : public Prism::Executor::ClosingResource,
                                      public Prism::Contract::MuxRootCreateOwner,
                                      public std::enable_shared_from_this<TransportRetirement>
    {
        struct OperationTicket final
        {
            explicit OperationTicket(std::shared_ptr<TransportRetirement> Value)
                : Owner(std::move(Value)) {}
            ~OperationTicket()
            {
                if (!Owner || Completed.load(std::memory_order_acquire)) return;
                if (!Started.load(std::memory_order_acquire))
                    Owner->Scheduled_.store(false, std::memory_order_release);
                else Owner->Record({Prism::Fault::Code::Blocked});
            }
            auto MarkStarted() noexcept -> void { Started.store(true, std::memory_order_release); }
            auto MarkCompleted() noexcept -> void
            {
                Completed.store(true, std::memory_order_release);
                Owner->Scheduled_.store(false, std::memory_order_release);
            }
            std::shared_ptr<TransportRetirement> Owner;
            std::atomic<bool> Started{false};
            std::atomic<bool> Completed{false};
        };

        struct Delivery final
        {
            std::shared_ptr<OperationTicket> Ticket;
            bool Invoked{false};

            explicit Delivery(std::shared_ptr<OperationTicket> Value)
                : Ticket(std::move(Value)) {}
            Delivery(Delivery &&Other) noexcept
                : Ticket(std::move(Other.Ticket)), Invoked(Other.Invoked) {}
            ~Delivery()
            {
                if (Ticket && !Invoked) Ticket->Owner->Record({Prism::Fault::Code::Blocked});
            }

            auto operator()() -> void
            {
                Invoked = true;
                Ticket->Owner->StartRetry(Ticket);
            }
        };

        struct Completion final
        {
            std::shared_ptr<OperationTicket> Ticket;
            bool Invoked{false};

            explicit Completion(std::shared_ptr<OperationTicket> Value)
                : Ticket(std::move(Value)) {}
            Completion(Completion &&Other) noexcept
                : Ticket(std::move(Other.Ticket)), Invoked(Other.Invoked) {}
            ~Completion()
            {
                if (Ticket && !Invoked) Ticket->Owner->Record({Prism::Fault::Code::Blocked});
            }

            auto operator()(
                std::exception_ptr Exception,
                std::expected<void, Prism::Fault::Failure> Result) -> void
            {
                Invoked = true;
                const auto Owner = Ticket->Owner;
                if (Exception)
                    Result = std::unexpected(FailureFromExecutorException(
                        Owner->Reclaimer_->Executor(), Exception));
                Owner->FinishAttempt(Ticket, Result);
            }
        };

    public:
        /**
         * @brief 在 admission/握手前预留真实退休 owner。
         * @return 可接管 transport/lease 的 owning 节点；预留失败时调用者尚未启动业务 I/O。
         */
        [[nodiscard]] static auto Prepare() noexcept
            -> std::expected<std::shared_ptr<TransportRetirement>, Prism::Fault::Failure>
        {
            try
            {
                return std::shared_ptr<TransportRetirement>(new TransportRetirement());
            }
            catch (...)
            {
                return std::unexpected(FailureFromRetirementException(std::current_exception()));
            }
        }

        /** @brief 无分配移交整条传输链与其最终退栈后归还的 child lease。 */
        [[nodiscard]] auto Attach(
            SharedTransmission &&Transport,
            Prism::Account::StreamLease &&ChildLease) noexcept
            -> std::expected<void, Prism::Fault::Failure>
        {
            if (!Transport || Transport_ || Attached_)
            {
                return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
            }
            Transport_ = std::move(Transport);
            ChildLease_ = std::move(ChildLease);
            Attached_ = true;
            try
            {
                Storage_ = Prism::Executor::ContextOwner::Storage(Transport_->Executor());
            }
            catch (...)
            {
                // 预构造 ProcessStorage 仍持有该节点；Attach 不因 executor owner 查询失败丢实物。
            }
            return {};
        }

        [[nodiscard]] auto ClaimMuxRootCreate() noexcept -> bool override
        {
            if (Retired_.load(std::memory_order_acquire) || RootPlane_) return false;
            bool Available = false;
            return MuxRootClaimed_.compare_exchange_strong(
                Available, true, std::memory_order_acq_rel, std::memory_order_acquire);
        }
        [[nodiscard]] auto CanAttachMuxRootParentStreamLease() const noexcept
            -> bool override
        {
            return !Retired_.load(std::memory_order_acquire) &&
                !MuxRootClaimed_.load(std::memory_order_acquire) && !RootPlane_ && !Attached_;
        }
        auto AttachMuxRootPlane(Prism::Contract::ProtocolDataPlane &&Plane) noexcept -> void override
        {
            if (!Attached_)
            {
                Transport_ = Plane.Transport();
                Attached_ = static_cast<bool>(Transport_);
                try
                {
                    if (Transport_)
                        Storage_ = Prism::Executor::ContextOwner::Storage(Transport_->Executor());
                }
                catch (...)
                {
                    // ProcessStorage is already reserved and retains this same owner.
                }
            }
            if (!RootPlane_) RootPlane_.emplace(std::move(Plane));
        }

        auto AttachMuxRootGenerationLease(
            Prism::Foundation::GenerationUseLease &&Lease) noexcept -> void override
        {
            RootGenerationLease_ = std::move(Lease);
        }
        [[nodiscard]] auto MuxRootTransport() const noexcept
            -> Prism::SharedTransmission override
        {
            if (RootPlane_) return RootPlane_->Transport();
            return Transport_;
        }
        auto AttachMuxRootSession(std::shared_ptr<Prism::Contract::MuxSession> Session) noexcept
            -> void override
        {
            if (RootPlane_)
                if (auto *Mux = RootPlane_->Mux()) Mux->Session = std::move(Session);
        }
        [[nodiscard]] auto TakeMuxRootPlane() noexcept
            -> Prism::Contract::ProtocolDataPlane override
        {
            Prism::Contract::ProtocolDataPlane Result;
            if (RootPlane_)
            {
                Result = std::move(*RootPlane_);
                RootPlane_.reset();
            }
            return Result;
        }

        [[nodiscard]] auto TakeMuxRootGenerationLease() noexcept
            -> Prism::Foundation::GenerationUseLease override
        {
            return std::move(RootGenerationLease_);
        }

        auto TransferMuxRoot() noexcept -> void override
        {
            RootPlane_.reset();
            RootGenerationLease_ = {};
            Transport_.reset();
            Attached_ = false;
            Retired_.store(true, std::memory_order_release);
            Storage_->Collect();
        }

        auto RetainMuxRoot() noexcept -> void override
        {
            RetainForRetry();
            RequestRetirement();
        }

        /** @brief 在创建协程帧前把已持实物的 owner 登记到无分配 ClosingStorage。 */
        auto RetainForRetry() noexcept -> void
        {
            if (Transport_) Storage_->Retain(shared_from_this());
        }

        /** @brief 在传输原 executor 关闭整条链并等待真实 Activity 退栈。 */
        [[nodiscard]] auto RetireAndDrain()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            if (!Transport_)
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});

            const auto Owner = shared_from_this();
            RetainForRetry();
            co_await Net::this_coro::throw_if_cancelled(false);
            co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
            bool Expected = false;
            if (!Scheduled_.compare_exchange_strong(
                    Expected, true, std::memory_order_acq_rel, std::memory_order_acquire))
                co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            const auto ReclaimerReady = PrepareRetirementExecutor(Transport_, Reclaimer_);
            if (!ReclaimerReady)
            {
                Scheduled_.store(false, std::memory_order_release);
                Record(ReclaimerReady.error());
                co_return std::unexpected(ReclaimerReady.error());
            }
            std::shared_ptr<OperationTicket> Ticket;
            try { Ticket = std::make_shared<OperationTicket>(Owner); }
            catch (...)
            {
                Scheduled_.store(false, std::memory_order_release);
                const auto Failure = FailureFromRetirementException(std::current_exception());
                Record(Failure);
                co_return std::unexpected(Failure);
            }
            std::expected<void, Prism::Fault::Failure> Result;
            std::optional<Prism::Fault::Failure> SpawnFailure;
            try
            {
                Result = co_await Net::co_spawn(
                    Owner->Reclaimer_->Executor(), Owner->RetireOnExecutor(Ticket),
                    Net::use_awaitable);
            }
            catch (...)
            {
                const auto Failure = FailureFromExecutorException(
                    Reclaimer_->Executor(), std::current_exception());
                Record(Failure);
                if (!Ticket->Started.load(std::memory_order_acquire)) Ticket->MarkCompleted();
                SpawnFailure = Failure;
            }
            if (SpawnFailure)
            {
                if (Ticket->Started.load(std::memory_order_acquire))
                {
                    try
                    {
                        co_await Net::post(Reclaimer_->Executor(), Net::use_awaitable);
                        FinishAttempt(Ticket, std::unexpected(*SpawnFailure));
                    }
                    catch (...) { Record(FailureFromRetirementException(std::current_exception())); }
                }
                co_return std::unexpected(*SpawnFailure);
            }
            try
            {
                co_await Net::post(Reclaimer_->Executor(), Net::use_awaitable);
                FinishAttempt(Ticket, Result);
            }
            catch (...)
            {
                const auto Failure = FailureFromExecutorException(
                    Reclaimer_->Executor(), std::current_exception());
                Record(Failure);
                Ticket->MarkCompleted();
                co_return std::unexpected(Failure);
            }
            co_return Result;
        }

        /** @brief 进程级回收重试入口；只投递到本传输链原 executor。 */
        auto RequestRetirement() -> void override
        {
            if (Retired_.load(std::memory_order_acquire) || !Transport_)
                return;
            bool Expected = false;
            if (!Scheduled_.compare_exchange_strong(
                    Expected, true, std::memory_order_acq_rel, std::memory_order_acquire)) return;

            Storage_->Retain(shared_from_this());
            const auto ReclaimerReady = PrepareRetirementExecutor(Transport_, Reclaimer_);
            if (!ReclaimerReady)
            {
                Scheduled_.store(false, std::memory_order_release);
                Record(ReclaimerReady.error());
                return;
            }
            if (!Reclaimer_->CanDispatch())
            {
                Scheduled_.store(false, std::memory_order_release);
                Record({Prism::Fault::Code::Blocked});
                return;
            }

            try
            {
                auto Ticket = std::make_shared<OperationTicket>(shared_from_this());
                Storage_->Retain(shared_from_this());
                auto Result = Reclaimer_->Post(Delivery(std::move(Ticket)));
                if (!Result)
                {
                    Record(Result.error());
                }
            }
            catch (...)
            {
                Scheduled_.store(false, std::memory_order_release);
                Record(FailureFromExecutorException(
                    Reclaimer_->Executor(), std::current_exception()));
            }
        }

        /** @brief 只在 Close 成功且全部真实 Activity 退栈后报告退休。 */
        [[nodiscard]] auto IsRetired() const noexcept -> bool override
        {
            return Retired_.load(std::memory_order_acquire);
        }

        /** @brief 原 executor 不可投递或回收命令无法交付时保留失败事实。 */
        [[nodiscard]] auto IsDispatchUnavailable() const noexcept -> bool override
        {
            return Reclaimer_ && !Reclaimer_->CanDispatch();
        }

    private:
        TransportRetirement() : Storage_(Prism::Executor::ClosingStorage::ProcessStorage()) {}

        /** @brief 同步请求方和回收 owner 共用一次串行关闭/Drain 实现。 */
        [[nodiscard]] auto RetireOnExecutor(std::shared_ptr<OperationTicket> Ticket)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            Ticket->MarkStarted();
            co_await Net::this_coro::throw_if_cancelled(false);
            co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
            AttemptPhysicallyComplete_ = false;
            std::expected<void, Prism::Fault::Failure> FirstFailure;
            std::exception_ptr FirstException;
            bool AllDrained = true;
            if (RootPlane_)
            {
                if (auto *Mux = RootPlane_->Mux(); Mux && Mux->Session)
                {
                    MuxRetirementAttempt Attempt{
                        Mux->Session, MuxCancelAttempted_, MuxCloseAttempted_, AllDrained,
                        FirstFailure, FirstException};
                    co_await RetireMuxSession(Attempt);
                }
            }
            if (!CancelAttempted_)
            {
                CancelAttempted_ = true;
                try
                {
                    const auto Cancel = Transport_->Cancel();
                    CancelAccepted_ = static_cast<bool>(Cancel);
                    if (!Cancel) KeepFirstRetirementFailure(FirstFailure, Cancel.error());
                }
                catch (...)
                {
                    FirstException = std::current_exception();
                    FirstFailure = std::unexpected(
                        FailureFromRetirementException(FirstException));
                }
            }
            if (!CloseAttempted_)
            {
                CloseAttempted_ = true;
                try
                {
                    const auto Close = Transport_->Close();
                    CloseAccepted_ = static_cast<bool>(Close);
                    if (!Close) KeepFirstRetirementFailure(FirstFailure, Close.error());
                }
                catch (...)
                {
                    const auto Exception = std::current_exception();
                    if (!FirstException) FirstException = Exception;
                    KeepFirstRetirementFailure(
                        FirstFailure, FailureFromRetirementException(Exception));
                }
            }

            for (std::size_t Index = 0;; ++Index)
            {
                bool Found = false;
                const auto Activity = RetirementActivityAt(Transport_, Index, Found);
                if (!Found) break;
                if (!Activity)
                {
                    AllDrained = false;
                    KeepFirstRetirementFailure(FirstFailure,
                        Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
                    continue;
                }
                std::expected<void, Prism::Fault::Failure> Drained;
                try
                {
                    Drained = co_await Activity->Drain();
                }
                catch (...)
                {
                    const auto Exception = std::current_exception();
                    if (!FirstException) FirstException = Exception;
                    Drained = std::unexpected(
                        FailureFromRetirementException(Exception));
                }
                if (!Drained)
                {
                    KeepFirstRetirementFailure(FirstFailure, Drained.error());
                }
                if (!Activity->IsRetired()) AllDrained = false;
            }

            if (FirstException)
                PublishRetirementFatal(Reclaimer_->Executor(), FirstException);
            if (AllDrained)
            {
                AttemptPhysicallyComplete_ = true;
                if (!FirstFailure) co_return std::unexpected(FirstFailure.error());
                co_return std::expected<void, Prism::Fault::Failure>{};
            }
            if (!FirstFailure) co_return std::unexpected(FirstFailure.error());
            co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        }

        /** @brief 原 executor 上启动失败资源的异步重试，并让完成通知持有本 owner。 */
        auto StartRetry(std::shared_ptr<OperationTicket> Ticket) -> void
        {
            try
            {
                const auto Executor = Reclaimer_->Executor();
                Net::co_spawn(Executor, RetireOnExecutor(Ticket),
                    Net::bind_executor(Executor, Completion(Ticket)));
            }
            catch (...)
            {
                Record(FailureFromExecutorException(
                    Reclaimer_->Executor(), std::current_exception()));
                if (!Ticket->Started.load(std::memory_order_acquire)) Ticket->MarkCompleted();
            }
        }

        /** @brief 只在真实完成回执后释放载体并归还操作预约。 */
        auto FinishAttempt(
            const std::shared_ptr<OperationTicket> &Ticket,
            const std::expected<void, Prism::Fault::Failure> &Result) noexcept -> void
        {
            if (AttemptPhysicallyComplete_)
            {
                if (!Result)
                {
                    const auto Stored = Failure_.TrySet(Result.error());
                    (void)Stored;
                }
                RootPlane_.reset();
                RootGenerationLease_ = {};
                Transport_.reset();
                ChildLease_.Release();
                ReleaseMuxRootParentStreamLease();
                Retired_.store(true, std::memory_order_release);
            }
            else if (!Result) Record(Result.error());
            AttemptPhysicallyComplete_ = false;
            Ticket->MarkCompleted();
            if (Retired_.load(std::memory_order_acquire)) Storage_->Collect();
        }

        /** @brief 保留首个关闭或 Drain cause，不覆盖更早的 I/O 失败。 */
        auto Record(const Prism::Fault::Failure Failure) noexcept -> void
        {
            const auto Stored = Failure_.TrySet(Failure);
            (void)Stored;
            Storage_->Retain(shared_from_this());
        }

        Prism::Account::StreamLease ChildLease_;
        SharedTransmission Transport_;
        std::optional<Prism::Contract::ProtocolDataPlane> RootPlane_;
        Prism::Foundation::GenerationUseLease RootGenerationLease_;
        std::shared_ptr<Prism::Executor::ClosingStorage> Storage_;
        std::shared_ptr<Prism::Executor::ExecutorReclaimer> Reclaimer_;
        Prism::Fault::FailureState Failure_;
        /** @brief 仅记录同步提交接收；原生 handler 回执由全部 Activity Drain 证明。 */
        bool CancelAccepted_{false};
        bool CloseAccepted_{false};
        bool CancelAttempted_{false};
        bool CloseAttempted_{false};
        bool MuxCancelAttempted_{false};
        bool MuxCloseAttempted_{false};
        bool AttemptPhysicallyComplete_{false};
        bool Attached_{false};
        std::atomic<bool> MuxRootClaimed_{false};
        std::atomic<bool> Scheduled_{false};
        std::atomic<bool> Retired_{false};
    };
}
