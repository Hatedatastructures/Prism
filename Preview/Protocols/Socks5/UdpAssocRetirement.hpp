/**
 * @file UdpAssocRetirement.hpp
 * @brief SOCKS5 UDP 关联的唯一关闭、失败保留与真实退栈 owner。
 * @details Run/Bind 操作、UDP socket、TCP Conn 全层 Activity 和 retry 实物共用此生命周期。
 */
#pragma once

#include <Preview/Contract/Io/CarrierActivity.hpp>
#include <Preview/Foundation/Executor/ClosingStorage.hpp>
#include <Preview/Foundation/Executor/ContextOwner.hpp>
#include <Preview/Foundation/Executor/ExecutorReclaimer.hpp>
#include <Preview/Foundation/Fault/FailureState.hpp>
#include <Preview/Protocols/Common/ProtocolActivity.hpp>
#include <Preview/Protocols/Socks5/Conn.hpp>
#include <Preview/Transport/Reliable.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/cancellation_signal.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/system_error.hpp>

#include <atomic>
#include <exception>
#include <expected>
#include <functional>
#include <memory>
#include <optional>
#include <system_error>
#include <utility>
#include <vector>

namespace Preview::Socks5
{
    namespace Net = boost::asio;

    /**
     * @brief 管理一个 UDP_ASSOCIATE 的 Run、控制 TCP、原生 UDP socket 与失败退休。
     * @details Close/Cancel 只投递原 executor 请求；Drain 才观察 close 与所有层 I/O 的真实结果。
     */
    class UdpAssocRetirement final : public Preview::Contract::CarrierActivity,
                                     public Preview::Executor::ClosingResource,
                                     public std::enable_shared_from_this<UdpAssocRetirement>
    {
        friend class UdpAssoc;
        friend class UdpAssocBindGate;

    private:
        struct DrainWaiter final
        {
            explicit DrainWaiter(std::atomic<std::size_t> &Count) : Count_(Count)
            { Count_.fetch_add(1, std::memory_order_acq_rel); }
            ~DrainWaiter() { Count_.fetch_sub(1, std::memory_order_acq_rel); }
            std::atomic<std::size_t> &Count_;
        };

    public:
        using Failure = Preview::Fault::Failure;
        using Result = std::expected<void, Failure>;
        using Completion = std::function<void()>;
        using Socket = Net::ip::udp::socket;

        struct ControlEndpointSnapshot final
        {
            Net::ip::tcp::endpoint Local;
            Net::ip::tcp::endpoint Peer;
        };

        /**
         * @brief 固定 TCP/UDP 管理 executor，并快照 TCP 所有层的真实 Activity owner。
         * @param Executor UDP 关联的原 executor；所有 UDP socket 与最终关闭都在此域执行。
         * @param Tcp 已接管的控制连接；本 owner 保留每层 Activity 直到 Drain 完成。
         */
        UdpAssocRetirement(Net::any_io_executor Executor,
                           std::shared_ptr<Conn<>> Tcp)
            : Executor_(std::move(Executor)),
              Context_(Preview::Executor::ContextOwner::Find(Executor_)),
              Storage_(Preview::Executor::ContextOwner::Storage(Executor_)),
              Reclaimer_(std::make_shared<Preview::Executor::ExecutorReclaimer>(Executor_)),
              Operations_(Executor_),
              Changes_(Executor_, 1),
              Ingress_(Executor_),
              Egress_(Executor_),
              Tcp_(std::move(Tcp))
        {
            if (Tcp_)
            {
                for (Preview::Transmission *Layer = Tcp_.get(); Layer; Layer = Layer->NextLayer())
                {
                    auto Activity = Layer->Activity();
                    if (!Activity)
                    {
                        Failure_.TrySet({Preview::Fault::Code::InvalidArgument});
                        continue;
                    }
                    TcpActivities_.push_back(std::move(Activity));
                }
            }
        }

    private:
        class Operation final
        {
        public:
            Operation(Operation &&Other) noexcept
                : Owner_(std::move(Other.Owner_)), Reservation_(std::move(Other.Reservation_)) {}
            Operation(const Operation &) = delete;
            auto operator=(const Operation &) -> Operation & = delete;
            ~Operation() { Complete(); }

            /** @brief 所有嵌套协程与 native completion 已退出，归还一次操作预约。 */
            auto Complete() noexcept -> void
            {
                if (!Reservation_) return;
                Reservation_->Complete();
                Reservation_.reset();
                Owner_.reset();
            }

        private:
            friend class UdpAssocRetirement;
            Operation(std::shared_ptr<UdpAssocRetirement> Owner,
                      Preview::Protocols::ProtocolActivity::Reservation Reservation)
                : Owner_(std::move(Owner)), Reservation_(std::move(Reservation)) {}

            std::shared_ptr<UdpAssocRetirement> Owner_;
            std::optional<Preview::Protocols::ProtocolActivity::Reservation> Reservation_;
        };

        [[nodiscard]] auto BeginOperation() -> std::expected<Operation, Failure>
        {
            if (CloseRequested_.load(std::memory_order_acquire))
                return std::unexpected(Failure{Preview::Fault::Code::Canceled});
            auto Reservation = Operations_.TryBegin();
            if (!Reservation) return std::unexpected(Reservation.error());
            if (CloseRequested_.load(std::memory_order_acquire))
            {
                Reservation->Complete();
                return std::unexpected(Failure{Preview::Fault::Code::Canceled});
            }
            return Operation(shared_from_this(), std::move(*Reservation));
        }

        [[nodiscard]] auto BeginRun() -> std::expected<Operation, Failure>
        {
            if (RunStarted_.exchange(true, std::memory_order_acq_rel))
                return std::unexpected(Failure{Preview::Fault::Code::InvalidArgument});
            return BeginOperation();
        }

    public:
        /** @brief 返回唯一 UDP 管理执行域；TCP 各层通过独立 Activity 保留其真实 executor。 */
        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            return Executor_;
        }

        /** @brief 封止新 Run/Bind 准入，不提前归还当前协程的操作预约。 */
        auto Seal() noexcept -> void override
        {
            Operations_.Seal();
        }

        /** @brief 请求关闭并等待 TCP 全层与关联操作退栈；保留并交付 Native 失败。 */
        [[nodiscard]] auto Drain()
            -> Net::awaitable<Result> override
        {
            return AwaitRetirement(true);
        }

    private:
        /** @brief Run 等待真实关闭，但将原生失败留给公开 Activity::Drain 观察。 */
        [[nodiscard]] auto RunDrain() -> Net::awaitable<Result>
        {
            return AwaitRetirement(false);
        }

        [[nodiscard]] auto Ingress() noexcept -> Socket & { return Ingress_; }
        [[nodiscard]] auto Egress() noexcept -> Socket & { return Egress_; }
        [[nodiscard]] auto Tcp() const noexcept -> std::shared_ptr<Conn<>> { return Tcp_; }
        [[nodiscard]] auto ReadControlEndpoints() const
            -> std::expected<ControlEndpointSnapshot, Failure>
        {
            if (!Tcp_) return std::unexpected(Failure{Preview::Fault::Code::IoError});
            const auto Underlying = Tcp_->Underlying();
            if (!Underlying) return std::unexpected(Failure{Preview::Fault::Code::IoError});
            auto *Reliable = Underlying->lowest_layer<Preview::Transport::Reliable>();
            if (!Reliable || !Reliable->IsOpen())
                return std::unexpected(Failure{Preview::Fault::Code::IoError});
            boost::system::error_code LocalError;
            boost::system::error_code PeerError;
            const auto Local = Reliable->NativeSocket().local_endpoint(LocalError);
            if (LocalError)
                return std::unexpected(Preview::Fault::FromNative(
                    static_cast<std::error_code>(LocalError)));
            const auto Peer = Reliable->NativeSocket().remote_endpoint(PeerError);
            if (PeerError)
                return std::unexpected(Preview::Fault::FromNative(
                    static_cast<std::error_code>(PeerError)));
            return ControlEndpointSnapshot{Local, Peer};
        }
        auto CloseEgress() noexcept -> Failure
        {
            const auto Result = CloseSocket(Egress_);
            if (Result.Failed()) RecordFailure(Result);
            return Result;
        }
        [[nodiscard]] auto CancellationSlot() noexcept -> Net::cancellation_slot
        { return Cancellation_.slot(); }
        [[nodiscard]] auto IsCancelled() const noexcept -> bool
        { return Cancelled_.load(std::memory_order_acquire); }
        [[nodiscard]] auto IsCloseRequested() const noexcept -> bool
        { return CloseRequested_.load(std::memory_order_acquire); }

        /** @brief 保留报告状态 owner；不封止操作、不发起关闭。 */
        auto PinOwner(std::shared_ptr<void> OwnerPin, Completion Callback) noexcept -> void
        {
            if (Retired_.load(std::memory_order_acquire)) return;
            if (OwnerPin) OwnerPin_.store(std::move(OwnerPin), std::memory_order_release);
            if (Callback)
            {
                try
                {
                    Callback_.store(std::make_shared<Completion>(std::move(Callback)),
                                    std::memory_order_release);
                }
                catch (...)
                {
                    RecordFailure({Preview::Fault::Code::Blocked});
                }
            }
            if (Retired_.load(std::memory_order_acquire))
            {
                OwnerPin_.store({}, std::memory_order_release);
                Callback_.store({}, std::memory_order_release);
            }
        }

        /** @brief 可跨线程调用；只登记 owner 并经原 executor 请求真实关闭。 */
        auto RequestClose(std::shared_ptr<void> OwnerPin = {}, Completion Callback = {}) noexcept -> void
        {
            if (Retired_.load(std::memory_order_acquire)) return;
            PinOwner(std::move(OwnerPin), std::move(Callback));
            if (Retired_.load(std::memory_order_acquire)) return;
            CloseRequested_.store(true, std::memory_order_release);
            Operations_.Seal();
            Storage_->Retain(shared_from_this());
            ScheduleRetirement();
        }

        /** @brief 可跨线程标记取消，并走同一个原 executor 幂等关闭路径。 */
        auto RequestCancel(std::shared_ptr<void> OwnerPin = {}, Completion Callback = {}) noexcept -> void
        {
            if (Retired_.load(std::memory_order_acquire)) return;
            Cancelled_.store(true, std::memory_order_release);
            RequestClose(std::move(OwnerPin), std::move(Callback));
        }

        /** @brief 记录首个无法退休的真实错误并保留完整 association owner。 */
        auto RecordFailure(const Failure Value) noexcept -> void
        {
            if (Value.Succeeded()) return;
            Failure_.TrySet(Value);
            if (Value.Native && !NativeFailure_.load(std::memory_order_acquire))
            {
                try
                {
                    auto Native = std::make_shared<const std::error_code>(Value.Native);
                    std::shared_ptr<const std::error_code> Empty;
                    (void)NativeFailure_.compare_exchange_strong(
                        Empty, std::move(Native), std::memory_order_acq_rel);
                }
                catch (...)
                {
                }
            }
            Storage_->Retain(shared_from_this());
            Notify();
        }

        auto RecordNative(const boost::system::error_code Native) noexcept -> void
        {
            if (!Native) return;
            RecordFailure(Preview::Fault::FromNative(static_cast<std::error_code>(Native)));
        }

        /** @brief 保留异常的首次 owner failure，并返回该次精确 Code/Native 投影。 */
        [[nodiscard]] auto RecordException(const std::exception_ptr Exception) noexcept -> Failure
        {
            const auto FailureValue = FailureFromException(Exception);
            RecordFailure(FailureValue);
            return FailureValue;
        }

        [[nodiscard]] auto LoadFailure() const noexcept -> Failure
        {
            auto Value = Failure_.Load();
            if (!Value.Native)
            {
                if (const auto Native = NativeFailure_.load(std::memory_order_acquire))
                    Value.Native = *Native;
            }
            return Value;
        }

        auto RequestRetirement() -> void override
        {
            if (Retired_.load(std::memory_order_acquire)) return;
            if (!CloseRequested_.load(std::memory_order_acquire))
            {
                RequestClose(OwnerPin_.load(std::memory_order_acquire), LoadCompletion());
                return;
            }
            ScheduleRetirement();
        }

        [[nodiscard]] auto IsRetired() const noexcept -> bool override
        {
            return Retired_.load(std::memory_order_acquire);
        }

        [[nodiscard]] auto IsDispatchUnavailable() const noexcept -> bool override
        {
            if (Retired_.load(std::memory_order_acquire)) return false;
            if (Context_ && !Context_->CanDispatch()) return true;
            return !Reclaimer_->CanDispatch();
        }

    private:
        struct Delivery final
        {
            std::shared_ptr<UdpAssocRetirement> Owner;
            bool Invoked{false};

            explicit Delivery(std::shared_ptr<UdpAssocRetirement> Value)
                : Owner(std::move(Value)) {}
            Delivery(Delivery &&Other) noexcept
                : Owner(std::move(Other.Owner)), Invoked(Other.Invoked) {}
            ~Delivery()
            {
                if (Owner && !Invoked)
                {
                    Owner->Scheduled_.store(false, std::memory_order_release);
                    Owner->RecordFailure({Preview::Fault::Code::Blocked});
                }
            }
            auto operator()() -> void
            {
                Invoked = true;
                Owner->StartRetirement();
            }
        };

        [[nodiscard]] static auto FailureFromException(const std::exception_ptr Exception) noexcept
            -> Failure
        {
            try
            {
                if (Exception) std::rethrow_exception(Exception);
            }
            catch (const boost::system::system_error &ErrorValue)
            {
                const auto Native = static_cast<std::error_code>(ErrorValue.code());
                return {Preview::Fault::ToCode(Native), Native};
            }
            catch (const std::system_error &ErrorValue)
            {
                return {Preview::Fault::ToCode(ErrorValue.code()), ErrorValue.code()};
            }
            catch (...)
            {
                return {Preview::Fault::Code::IoError};
            }
            return {Preview::Fault::Code::IoError};
        }

        auto ScheduleRetirement() noexcept -> void
        {
            if (Retired_.load(std::memory_order_acquire) ||
                Scheduled_.exchange(true, std::memory_order_acq_rel))
                return;
            try
            {
                auto Result = Reclaimer_->Post(Delivery(shared_from_this()));
                if (!Result)
                {
                    Scheduled_.store(false, std::memory_order_release);
                    RecordFailure(Result.error());
                }
            }
            catch (...)
            {
                Scheduled_.store(false, std::memory_order_release);
                RecordFailure(FailureFromException(std::current_exception()));
            }
        }

        auto StartRetirement() noexcept -> void
        {
            const auto Self = shared_from_this();
            try
            {
                Net::co_spawn(
                    Executor_, RetireOnExecutor(),
                    [Self](std::exception_ptr Exception, Result RetiredResult)
                    {
                        Self->CompleteRetirement(std::move(Exception), std::move(RetiredResult));
                    });
            }
            catch (...)
            {
                Scheduled_.store(false, std::memory_order_release);
                RecordFailure(FailureFromException(std::current_exception()));
            }
        }

        [[nodiscard]] auto RetireOnExecutor() -> Net::awaitable<Result>
        {
            co_await Net::this_coro::throw_if_cancelled(false);
            co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
            Cancellation_.emit(Net::cancellation_type::all);

            auto FirstFailure = CloseSocket(Ingress_);
            PreserveFailure(FirstFailure, CloseSocket(Egress_));
            if (Tcp_)
            {
                const auto Cancel = Tcp_->Cancel();
                if (!Cancel) PreserveFailure(FirstFailure, Cancel.error());
                const auto Close = Tcp_->Close();
                if (!Close) PreserveFailure(FirstFailure, Close.error());
            }

            if (FirstFailure.Failed())
            {
                RecordFailure(FirstFailure);
                co_return std::unexpected(LoadFailure());
            }

            for (const auto &Activity : TcpActivities_)
            {
                Activity->Seal();
                const auto Drained = co_await Activity->Drain();
                // 只有同一层的物理退休回执已成立时，才接受取消结果并继续收尾。
                if (!Drained &&
                    (Drained.error().Code != Preview::Fault::Code::Canceled ||
                     !Activity->IsRetired()))
                {
                    RecordFailure(Drained.error());
                    co_return std::unexpected(LoadFailure());
                }
            }

            const auto OperationsDrained = co_await Operations_.Drain();
            // Run 操作的取消结果也必须与其独立退休回执同时成立。
            if (!OperationsDrained &&
                (OperationsDrained.error().Code != Preview::Fault::Code::Canceled ||
                 !Operations_.IsRetired()))
            {
                RecordFailure(OperationsDrained.error());
                co_return std::unexpected(LoadFailure());
            }

            TcpActivities_.clear();
            Tcp_.reset();
            if (const auto Callback = Callback_.load(std::memory_order_acquire))
            {
                try { (*Callback)(); }
                catch (...) { RecordFailure({Preview::Fault::Code::IoError}); }
            }
            OwnerPin_.store({}, std::memory_order_release);
            Retired_.store(true, std::memory_order_release);
            Notify();
            Storage_->Collect();
            co_return Result{};
        }

        auto CompleteRetirement(std::exception_ptr Exception, Result RetiredResult) noexcept -> void
        {
            if (Exception) RecordFailure(FailureFromException(Exception));
            else if (!RetiredResult) RecordFailure(RetiredResult.error());
            Scheduled_.store(false, std::memory_order_release);
            if (Retired_.load(std::memory_order_acquire)) Storage_->Collect();
            Notify();
        }

        [[nodiscard]] static auto CloseSocket(Socket &Value) noexcept -> Failure
        {
            boost::system::error_code ErrorCode;
            if (!Value.is_open()) return {};
            Value.cancel(ErrorCode);
            Failure Result;
            if (ErrorCode)
                Result = Preview::Fault::FromNative(static_cast<std::error_code>(ErrorCode));
            ErrorCode.clear();
            Value.close(ErrorCode);
            if (ErrorCode)
                PreserveFailure(Result, Preview::Fault::FromNative(
                    static_cast<std::error_code>(ErrorCode)));
            return Result;
        }

        static auto PreserveFailure(Failure &Primary, const Failure &Next) noexcept -> void
        {
            if (!Primary.Failed()) Primary = Next;
            else if (!Primary.Native && Next.Native) Primary.Native = Next.Native;
        }

        auto Notify() noexcept -> void
        {
            (void)Changes_.try_send(boost::system::error_code{});
        }

        [[nodiscard]] auto LoadCompletion() const noexcept -> Completion
        {
            const auto Value = Callback_.load(std::memory_order_acquire);
            return Value ? *Value : Completion{};
        }

        Net::any_io_executor Executor_;
        std::shared_ptr<Preview::Executor::ContextOwner> Context_;
        std::shared_ptr<Preview::Executor::ClosingStorage> Storage_;
        std::shared_ptr<Preview::Executor::ExecutorReclaimer> Reclaimer_;
        Preview::Protocols::ProtocolActivity Operations_;
        Net::experimental::concurrent_channel<void(boost::system::error_code)> Changes_;
        Net::ip::udp::socket Ingress_;
        Net::ip::udp::socket Egress_;
        std::shared_ptr<Conn<>> Tcp_;
        std::vector<std::shared_ptr<Preview::Contract::CarrierActivity>> TcpActivities_;
        Net::cancellation_signal Cancellation_;
        Preview::Fault::FailureState Failure_;
        std::atomic<std::shared_ptr<const std::error_code>> NativeFailure_;
        std::atomic<std::shared_ptr<void>> OwnerPin_;
        std::atomic<std::shared_ptr<Completion>> Callback_;
        std::atomic<bool> RunStarted_{false};
        std::atomic<bool> CloseRequested_{false};
        std::atomic<bool> Cancelled_{false};
        std::atomic<bool> Scheduled_{false};
        std::atomic<bool> Retired_{false};
        std::atomic<bool> FailureObserved_{false};
        std::atomic<std::size_t> DrainWaiters_{0};

        [[nodiscard]] auto AwaitRetirement(const bool ConsumeFailure)
            -> Net::awaitable<Result>
        {
            co_await Net::this_coro::throw_if_cancelled(false);
            if (Retired_.load(std::memory_order_acquire))
                co_return CompletedResult(ConsumeFailure);
            RequestClose(OwnerPin_.load(std::memory_order_acquire), LoadCompletion());
            for (;;)
            {
                if (Retired_.load(std::memory_order_acquire))
                    co_return CompletedResult(ConsumeFailure);
                const auto FailureValue = LoadFailure();
                if (FailureValue.Failed())
                {
                    if (ConsumeFailure) FailureObserved_.store(true, std::memory_order_release);
                    WakeWaiter();
                    co_return std::unexpected(FailureValue);
                }
                if (!Reclaimer_->CanDispatch())
                {
                    RecordFailure({Preview::Fault::Code::Blocked});
                    if (ConsumeFailure) FailureObserved_.store(true, std::memory_order_release);
                    WakeWaiter();
                    co_return std::unexpected(LoadFailure());
                }
                boost::system::error_code ErrorCode;
                {
                    DrainWaiter Waiter(DrainWaiters_);
                    co_await Changes_.async_receive(
                        Net::redirect_error(Net::use_awaitable, ErrorCode));
                }
                if (ErrorCode)
                {
                    RecordFailure(Preview::Fault::FromNative(
                        static_cast<std::error_code>(ErrorCode)));
                    if (ConsumeFailure) FailureObserved_.store(true, std::memory_order_release);
                    WakeWaiter();
                    co_return std::unexpected(LoadFailure());
                }
            }
        }

        [[nodiscard]] auto CompletedResult(const bool ConsumeFailure) noexcept -> Result
        {
            const auto FailureValue = LoadFailure();
            WakeWaiter();
            if (FailureValue.Failed() &&
                (!ConsumeFailure || !FailureObserved_.exchange(true, std::memory_order_acq_rel)))
                return std::unexpected(FailureValue);
            return {};
        }

        auto WakeWaiter() noexcept -> void
        {
            if (DrainWaiters_.load(std::memory_order_acquire) != 0) Notify();
        }
    };
}
