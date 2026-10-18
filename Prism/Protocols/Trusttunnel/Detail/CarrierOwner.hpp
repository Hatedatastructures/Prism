/**
 * @file CarrierOwner.hpp
 * @brief TrustTunnel HTTP/2 carrier 生命周期、关闭与真实物理排空。
 */
#pragma once

#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Fault/FailureState.hpp>
#include <Prism/Foundation/Executor/ClosingStorage.hpp>
#include <Prism/Foundation/Executor/ContextOwner.hpp>
#include <Prism/Foundation/Executor/ExecutorReclaimer.hpp>
#include <Prism/Contract/Ingress/InboundAdmission.hpp>
#include <Prism/Protocols/Trusttunnel/Detail/Http2Transport.hpp>
#include <Prism/Protocols/Trusttunnel/Detail/Http2WireWriter.hpp>
#include <Prism/Transport/Detail/IoCompletion.hpp>
#include <Prism/Transport/Encrypted.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/strand.hpp>

#include <atomic>
#include <chrono>
#include <expected>
#include <memory>
#include <system_error>
#include <utility>

namespace Prism::Trusttunnel
{
    struct WireAuthBinding;
    class AuthenticatedTransport;
}

namespace Prism::Trusttunnel::Detail
{
    namespace Net = boost::asio;

    struct Http2DriverParameters;
    using CarrierClosedChannel =
        Net::experimental::channel<void(boost::system::error_code)>;
    using CarrierDrainGate =
        Net::experimental::concurrent_channel<void(boost::system::error_code)>;

    /**
     * @struct CarrierLifecycle
     * @brief TrustTunnel carrier driver 的完成通知与弱观察句柄。
     * @details DriverState 由 HTTP/2 driver owning frame 持有；driver 清理 callback、
     *          取消 raw read 并由 co_spawn completion 释放后，Closed 才通知观察者。
     */
    struct CarrierLifecycle final
    {
        explicit CarrierLifecycle(Net::any_io_executor Executor)
            : Closed(std::make_shared<CarrierClosedChannel>(std::move(Executor), 1)),
              DrainGate(std::make_shared<CarrierDrainGate>(Closed->get_executor(), 1))
        {
            (void)DrainGate->try_send(boost::system::error_code{});
        }

        std::shared_ptr<CarrierClosedChannel> Closed;
        std::shared_ptr<CarrierDrainGate> DrainGate;
        std::weak_ptr<const Http2DriverParameters> DriverState;
        Prism::Fault::FailureState FirstFailure;
        std::atomic<bool> DriverStarted{false};
        std::atomic<bool> DriverCompleted{false};
        std::atomic<bool> LayersDrained{false};
        std::atomic<bool> Retired{false};

        auto RecordFailure(const Prism::Fault::Failure Value) noexcept -> void
        {
            if (Value.Failed())
            {
                // TrySet 的 bool 仅表示首因竞争胜者，不影响同一 lifecycle 的关闭回执。
                (void)FirstFailure.TrySet(Value);
            }
        }

        [[nodiscard]] auto Failure() const noexcept -> Prism::Fault::Failure
        {
            return FirstFailure.Load();
        }

        auto StartDriver() noexcept -> void
        {
            DriverStarted.store(true, std::memory_order_release);
        }

        auto CompleteDriver() noexcept -> void
        {
            DriverCompleted.store(true, std::memory_order_release);
            (void)Closed->try_send(boost::system::error_code{});
        }

        [[nodiscard]] auto WaitDriver()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            co_await Net::this_coro::throw_if_cancelled(false);
            while (DriverStarted.load(std::memory_order_acquire) &&
                   !DriverCompleted.load(std::memory_order_acquire))
            {
                boost::system::error_code Error;
                co_await Closed->async_receive(Net::redirect_error(Net::use_awaitable, Error));
                if (Error)
                {
                    RecordFailure(Prism::Fault::FromNative(static_cast<std::error_code>(Error)));
                    break;
                }
            }
            const auto First = Failure();
            if (First.Failed()) co_return std::unexpected(First);
            co_return std::expected<void, Prism::Fault::Failure>{};
        }
    };

    /**
     * @struct CarrierOwner
     * @brief 持有 HTTP/2 stream、wire writer 和 TLS raw read 的正式关闭 owner。
     * @details Close/Cancel 会取消并关闭底层 TLS，Shutdown 只提交 END_STREAM，
     *          保留反向读取能力。generation Binding pin 保留到 stream、writer、driver
     *          与 TLS 都确认物理退休后释放。
     */
    /** @brief TrustTunnel H2 最终关闭者的实际 stream、writer、TLS 与 driver 层。 */
    struct CarrierOwnerLayers final
    {
        std::shared_ptr<Http2Transport> Transport;
        std::shared_ptr<Http2WireWriter> Wire;
        std::shared_ptr<Prism::Transport::Encrypted> Encrypted;
        std::shared_ptr<CarrierLifecycle> Lifecycle;
        /** @brief accepted generation pin；仅 Retire 在完整物理退休后释放。 */
        std::shared_ptr<const Prism::Trusttunnel::WireAuthBinding> Binding;
    };

    struct CarrierOwner final : Prism::Executor::ClosingResource,
                                std::enable_shared_from_this<CarrierOwner>
    {
        explicit CarrierOwner(CarrierOwnerLayers Layers)
            : Transport(std::move(Layers.Transport)), Wire(std::move(Layers.Wire)),
              Encrypted(std::move(Layers.Encrypted)), Lifecycle(std::move(Layers.Lifecycle)),
              Binding(std::move(Layers.Binding)),
              Storage_(Prism::Executor::ContextOwner::Storage(Executor())),
              Reclaimer_(std::make_shared<Prism::Executor::ExecutorReclaimer>(
                  Net::make_strand(Executor())))
        {
        }

        std::shared_ptr<Http2Transport> Transport;
        std::shared_ptr<Http2WireWriter> Wire;
        std::shared_ptr<Prism::Transport::Encrypted> Encrypted;
        std::shared_ptr<CarrierLifecycle> Lifecycle;
        /** @brief generation pin；仅 Retire 在完整物理退休后释放。 */
        std::shared_ptr<const Prism::Trusttunnel::WireAuthBinding> Binding;

        struct RetryCommand final
        {
            std::shared_ptr<CarrierOwner> Owner;
            auto operator()() noexcept -> void { Owner->StartRetry(); }
        };

        struct RetryCompletion final
        {
            std::shared_ptr<CarrierOwner> Owner;

            auto operator()(
                std::exception_ptr Exception,
                std::expected<void, Prism::Fault::Failure> Result) const noexcept -> void
            {
                Owner->RetryScheduled_.store(false, std::memory_order_release);
                if (Exception)
                {
                    Owner->Lifecycle->RecordFailure(
                        Prism::Contract::InboundAdmission::ExceptionFailure(
                            std::move(Exception)));
                    Owner->Storage_->Retain(Owner);
                }
                else if (!Result)
                {
                    Owner->Storage_->Retain(Owner);
                }
                else
                {
                    Owner->Storage_->Collect();
                }
            }
        };

        /** @brief 返回冷构造时绑定的实际载体执行域；空载体由装配层拒绝。 */
        [[nodiscard]] auto Executor() const -> Net::any_io_executor
        {
            if (Transport) return Transport->Executor();
            if (Encrypted) return Encrypted->Executor();
            return Lifecycle->Closed->get_executor();
        }

        /** @brief 读取 driver、writer、TLS 与 H2 stream 全部物理退栈的事实。 */
        [[nodiscard]] auto IsRetired() const noexcept -> bool override
        {
            return Lifecycle && Lifecycle->Retired.load(std::memory_order_acquire);
        }

        /** @brief 关闭 HTTP/2 stream、wire writer 与底层加密载体；首个真实失败被保留。 */
        [[nodiscard]] auto Close() -> Prism::Transmission::ControlResult
        {
            if (!Lifecycle)
                return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
            if (IsRetired()) return {};
            Prism::Transmission::ControlResult Result{};
            if (Transport)
            {
                const auto Closed = Transport->Close();
                RecordControlFailure(Closed);
                if (!Closed) Result = std::unexpected(Closed.error());
            }
            if (Wire) Wire->Close();
            if (Encrypted)
            {
                const auto Canceled = Encrypted->Cancel();
                RecordControlFailure(Canceled);
                if (Result && !Canceled) Result = std::unexpected(Canceled.error());
                const auto Closed = Encrypted->Close();
                RecordControlFailure(Closed);
                if (Result && !Closed) Result = std::unexpected(Closed.error());
            }
            return Result;
        }

        /** @brief 可重复取消；成功只表示命令已接管，不宣称底层已经关闭。 */
        [[nodiscard]] auto Cancel() -> Prism::Transmission::ControlResult
        {
            if (!Lifecycle)
                return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
            if (IsRetired()) return {};
            Prism::Transmission::ControlResult Result{};
            if (Transport)
            {
                const auto Canceled = Transport->Cancel();
                RecordControlFailure(Canceled);
                if (!Canceled) Result = std::unexpected(Canceled.error());
            }
            if (Encrypted)
            {
                const auto Canceled = Encrypted->Cancel();
                RecordControlFailure(Canceled);
                if (Result && !Canceled) Result = std::unexpected(Canceled.error());
            }
            return Result;
        }

        /** @brief 重试关闭并等待 driver、frame writer 与加密载体的真实活动排空。 */
        [[nodiscard]] auto Drain()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            if (!Lifecycle)
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
            co_await Net::this_coro::throw_if_cancelled(false);
            co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
            co_await Net::dispatch(Executor(), Net::use_awaitable);
            boost::system::error_code GateError;
            co_await Lifecycle->DrainGate->async_receive(
                Net::redirect_error(Net::use_awaitable, GateError));
            if (GateError)
            {
                Lifecycle->RecordFailure(
                    Prism::Fault::FromNative(static_cast<std::error_code>(GateError)));
                RequestRetirement();
                co_return std::unexpected(Lifecycle->Failure());
            }
            struct DrainRelease final
            {
                std::shared_ptr<CarrierDrainGate> Gate;
                ~DrainRelease() noexcept
                {
                    if (Gate) (void)Gate->try_send(boost::system::error_code{});
                }
            } Release{Lifecycle->DrainGate};
            if (Lifecycle->Retired.load(std::memory_order_acquire))
            {
                const auto First = Lifecycle->Failure();
                if (First.Failed()) co_return std::unexpected(First);
                co_return std::expected<void, Prism::Fault::Failure>{};
            }
            bool Complete = true;
            const auto Closed = Close();
            if (!Closed) Lifecycle->RecordFailure(Closed.error());
            const auto Driver = co_await Lifecycle->WaitDriver();
            if (!Driver) Lifecycle->RecordFailure(Driver.error());
            if (Lifecycle->DriverStarted.load(std::memory_order_acquire) &&
                !Lifecycle->DriverCompleted.load(std::memory_order_acquire))
                Complete = false;
            Complete = (co_await DrainTransport()) && Complete;
            Complete = (co_await DrainWire()) && Complete;
            Complete = (co_await DrainEncrypted()) && Complete;
            Lifecycle->LayersDrained.store(Complete, std::memory_order_release);
            if (Complete) Retire();
            if (!Complete)
            {
                Lifecycle->RecordFailure(
                    Prism::Fault::Failure{Prism::Fault::Code::Blocked});
                RequestRetirement();
            }
            const auto First = Lifecycle->Failure();
            if (First.Failed()) co_return std::unexpected(First);
            co_return std::expected<void, Prism::Fault::Failure>{};
        }

        auto RequestRetirement() -> void override
        {
            if (IsRetired() || RetryScheduled_.exchange(true, std::memory_order_acq_rel))
                return;
            const auto Self = shared_from_this();
            Storage_->Retain(Self);
            const auto Posted = Reclaimer_->Post(RetryCommand{Self});
            if (!Posted)
            {
                RetryScheduled_.store(false, std::memory_order_release);
                Lifecycle->RecordFailure(Posted.error());
                Storage_->Retain(Self);
            }
        }

        [[nodiscard]] auto IsDispatchUnavailable() const noexcept -> bool override
        {
            return !Reclaimer_ || !Reclaimer_->CanDispatch();
        }

        /** @brief 真实写半关闭：只提交 END_STREAM，保留反向读取能力。 */
        auto WriteShutdown(Prism::Transmission::Completion Handler) -> void
        {
            if (!Transport)
            {
                Prism::Transport::Detail::PostResult(
                    Executor(),
                    std::move(Handler),
                    Prism::IoResult{0, {Prism::Fault::Code::IoError}});
                return;
            }
            Transport->WriteShutdown(std::move(Handler));
        }

    private:
        auto RecordControlFailure(const Prism::Transmission::ControlResult &Result) noexcept -> void
        {
            if (Lifecycle && !Result) Lifecycle->RecordFailure(Result.error());
        }

        [[nodiscard]] auto DrainTransport() -> Net::awaitable<bool>
        {
            if (!Transport) co_return true;
            const auto Activity = Transport->Activity();
            if (!Activity)
            {
                Lifecycle->RecordFailure(
                    Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
                co_return false;
            }
            const auto Drained = co_await Activity->Drain();
            if (!Drained) Lifecycle->RecordFailure(Drained.error());
            const bool Complete = Activity->IsRetired() && !Transport->IsOpen();
            if (!Complete)
                Lifecycle->RecordFailure(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            co_return Complete;
        }

        [[nodiscard]] auto DrainWire() -> Net::awaitable<bool>
        {
            if (!Wire) co_return true;
            const auto Drained = co_await Wire->Drain();
            if (!Drained) Lifecycle->RecordFailure(Drained.error());
            const bool Complete = Wire->IsRetired();
            if (!Complete)
                Lifecycle->RecordFailure(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            co_return Complete;
        }

        [[nodiscard]] auto DrainEncrypted() -> Net::awaitable<bool>
        {
            if (!Encrypted) co_return true;
            const auto Activity = Encrypted->Activity();
            if (!Activity)
            {
                Lifecycle->RecordFailure(
                    Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
                co_return false;
            }
            const auto Drained = co_await Activity->Drain();
            if (!Drained) Lifecycle->RecordFailure(Drained.error());
            const bool Complete = Activity->IsRetired() && !Encrypted->IsOpen();
            if (!Complete)
                Lifecycle->RecordFailure(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            co_return Complete;
        }

        friend class Prism::Trusttunnel::AuthenticatedTransport;

        /** @brief 释放物理层与 generation pin；仅在所有层都确认 IsRetired 后调用。 */
        auto Retire() noexcept -> void
        {
            Transport.reset();
            Wire.reset();
            Encrypted.reset();
            Lifecycle->DriverState.reset();
            Binding.reset();
            Lifecycle->Retired.store(true, std::memory_order_release);
            Storage_->Collect();
        }

        [[nodiscard]] auto RetryOnExecutor()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            const auto Drained = co_await Drain();
            if (IsRetired()) co_return std::expected<void, Prism::Fault::Failure>{};
            if (!Drained) co_return std::unexpected(Drained.error());
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        }

        auto StartRetry() noexcept -> void
        {
            if (IsRetired())
            {
                RetryScheduled_.store(false, std::memory_order_release);
                return;
            }
            const auto Self = shared_from_this();
            try
            {
                Net::co_spawn(
                    Reclaimer_->Executor(), RetryOnExecutor(), RetryCompletion{Self});
            }
            catch (...)
            {
                RetryScheduled_.store(false, std::memory_order_release);
                Lifecycle->RecordFailure(
                    Prism::Contract::InboundAdmission::ExceptionFailure(
                        std::current_exception()));
                Storage_->Retain(Self);
            }
        }

        std::shared_ptr<Prism::Executor::ClosingStorage> Storage_;
        std::shared_ptr<Prism::Executor::ExecutorReclaimer> Reclaimer_;
        std::atomic<bool> RetryScheduled_{false};
    };


} // namespace Prism::Trusttunnel::Detail
