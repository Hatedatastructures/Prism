/**
 * @file NativeStreamActivity.hpp
 * @brief 单条 QUIC stream 的真实操作、关闭命令与 native terminal 回执。
 * @details 不等待连接级长寿命收发循环；stream callback 负责在 map 移除与 credit 处理后发布终态。
 */
#pragma once

#include <Prism/Contract/Io/CarrierActivity.hpp>
#include <Prism/Foundation/Executor/ContextOwner.hpp>
#include <Prism/Foundation/Executor/ExecutorReclaimer.hpp>
#include <Prism/Foundation/Fault/FailureState.hpp>
#include <Prism/Lifecycle/DrainBarrier.hpp>
#include <Prism/Protocols/Quic/Detail/NativeConnectionState.hpp>

#include <atomic>
#include <expected>
#include <memory>
#include <stdexcept>
#include <utility>

namespace Prism::Quic::Detail
{
    class NativeStreamActivity final : public Prism::Contract::CarrierActivity,
        public std::enable_shared_from_this<NativeStreamActivity>
    {
    public:
        using Failure = Prism::Fault::Failure;

        class Operation final
        {
        public:
            Operation(const Operation&) = delete;
            auto operator=(const Operation&) -> Operation& = delete;
            Operation(Operation&& Other) noexcept
                : Owner_(std::move(Other.Owner_)), Carrier_(std::move(Other.Carrier_)),
                  Buffered_(std::exchange(Other.Buffered_, false)),
                  Entered_(std::exchange(Other.Entered_, false))
            {
            }
            ~Operation()
            {
                Carrier_.reset();
                if (Entered_ && Owner_)
                {
                    if (Buffered_) Owner_->BufferedReads_.Leave();
                    else Owner_->Operations_.Leave();
                }
            }
            [[nodiscard]] auto Carrier() const noexcept -> std::shared_ptr<void>
            {
                return Carrier_;
            }

        private:
            friend class NativeStreamActivity;
            Operation(std::shared_ptr<NativeStreamActivity> Owner,
                      std::shared_ptr<void> Carrier, const bool Buffered = false)
                : Owner_(std::move(Owner)), Carrier_(std::move(Carrier)),
                  Buffered_(Buffered), Entered_(true)
            {
            }
            std::shared_ptr<NativeStreamActivity> Owner_;
            std::shared_ptr<void> Carrier_;
            bool Buffered_{false};
            bool Entered_{false};
        };

        class CloseOperation final
        {
        public:
            CloseOperation() noexcept = default;
            CloseOperation(const CloseOperation&) = delete;
            auto operator=(const CloseOperation&) -> CloseOperation& = delete;
            CloseOperation(CloseOperation&& Other) noexcept
                : Owner_(std::move(Other.Owner_)), Carrier_(std::move(Other.Carrier_)),
                  Entered_(std::exchange(Other.Entered_, false))
            {
            }
            ~CloseOperation()
            {
                Carrier_.reset();
                if (Entered_ && Owner_)
                {
                    Owner_->CloseActions_.Leave();
                }
            }
            [[nodiscard]] explicit operator bool() const noexcept { return Entered_; }

        private:
            friend class NativeStreamActivity;
            CloseOperation(std::shared_ptr<NativeStreamActivity> Owner, std::shared_ptr<void> Carrier)
                : Owner_(std::move(Owner)), Carrier_(std::move(Carrier)), Entered_(true)
            {
            }
            std::shared_ptr<NativeStreamActivity> Owner_;
            std::shared_ptr<void> Carrier_;
            bool Entered_{false};
        };

        explicit NativeStreamActivity(std::shared_ptr<StreamState> State)
            : State_(RequireState(std::move(State))),
              Context_(Prism::Executor::ContextOwner::Find(State_->Executor)),
              Reclaimer_(std::make_shared<Prism::Executor::ExecutorReclaimer>(State_->Executor)),
              Operations_(Reclaimer_), BufferedReads_(Reclaimer_),
              CloseActions_(Reclaimer_), NativeTerminal_(Reclaimer_)
        {
            if (!NativeTerminal_.Enter())
            {
                NativeTerminal_.Block();
                return;
            }
            NativeTerminal_.Seal();
            if (State_->NativeTerminal.load(std::memory_order_acquire))
            {
                MarkNativeTerminal(State_->StreamCloseFailure);
            }
        }

        [[nodiscard]] auto BeginOperation(std::shared_ptr<void> Carrier)
            -> std::expected<Operation, Failure>
        {
            if (!Carrier)
            {
                return std::unexpected(Failure{Prism::Fault::Code::InvalidArgument});
            }
            if (!Operations_.Enter())
            {
                return std::unexpected(Failure{Prism::Fault::Code::Canceled});
            }
            return Operation(shared_from_this(), std::move(Carrier));
        }

        /** @brief native terminal 后只为已接收缓存数据创建读取回执。 */
        [[nodiscard]] auto BeginBufferedRead(std::shared_ptr<void> Carrier)
            -> std::expected<Operation, Failure>
        {
            if (!Carrier)
            {
                return std::unexpected(Failure{Prism::Fault::Code::InvalidArgument});
            }
            if ((!NativeTerminalSeen_.load(std::memory_order_acquire) &&
                    !State_->NativeTerminal.load(std::memory_order_acquire)) ||
                !BufferedReads_.Enter())
            {
                return std::unexpected(Failure{Prism::Fault::Code::Canceled});
            }
            return Operation(shared_from_this(), std::move(Carrier), true);
        }

        [[nodiscard]] auto BeginClose(std::shared_ptr<void> Carrier)
            -> std::expected<CloseOperation, Failure>
        {
            if (!Carrier)
            {
                return std::unexpected(Failure{Prism::Fault::Code::InvalidArgument});
            }
            if (CloseAccepted_.load(std::memory_order_acquire))
            {
                return CloseOperation{};
            }
            bool Open = false;
            if (!CloseClaimed_.compare_exchange_strong(Open, true, std::memory_order_acq_rel))
            {
                if (CloseAccepted_.load(std::memory_order_acquire))
                {
                    return CloseOperation{};
                }
                return std::unexpected(Failure{Prism::Fault::Code::Blocked});
            }
            if (!CloseActions_.Enter())
            {
                CloseClaimed_.store(false, std::memory_order_release);
                return std::unexpected(Failure{Prism::Fault::Code::Canceled});
            }
            return CloseOperation(shared_from_this(), std::move(Carrier));
        }

        auto Seal() noexcept -> void override
        {
            Operations_.Seal();
            BufferedReads_.Seal();
        }

        [[nodiscard]] auto Executor() const -> boost::asio::any_io_executor override
        {
            return Reclaimer_->Executor();
        }

        [[nodiscard]] auto IsRetired() const noexcept -> bool override
        {
            return CloseAccepted_.load(std::memory_order_acquire) &&
                   CloseDelivered_.load(std::memory_order_acquire) &&
                   NativeTerminalSeen_.load(std::memory_order_acquire) &&
                   Operations_.IsSealed() && Operations_.Active() == 0 && !Operations_.IsBlocked() &&
                   BufferedReads_.IsSealed() && BufferedReads_.Active() == 0 && !BufferedReads_.IsBlocked() &&
                   CloseActions_.IsSealed() && CloseActions_.Active() == 0 && !CloseActions_.IsBlocked() &&
                   NativeTerminal_.IsSealed() && NativeTerminal_.Active() == 0 && !NativeTerminal_.IsBlocked();
        }

        [[nodiscard]] auto Drain() -> boost::asio::awaitable<std::expected<void, Failure>> override
        {
            return DrainOwned(shared_from_this());
        }

        [[nodiscard]] auto CloseAccepted() const noexcept -> bool
        {
            return CloseAccepted_.load(std::memory_order_acquire);
        }

        auto CommitClose() noexcept -> void
        {
            Operations_.Seal();
            BufferedReads_.Seal();
            CloseAccepted_.store(true, std::memory_order_release);
            CloseActions_.Seal();
        }

        auto RollbackClose() noexcept -> void
        {
            if (!CloseAccepted_.load(std::memory_order_acquire))
            {
                CloseClaimed_.store(false, std::memory_order_release);
            }
        }

        auto CompleteClose(std::expected<void, Failure> Result) noexcept -> void
        {
            if (!Result)
            {
                Failure_.TrySet(Result.error());
            }
            BufferedReads_.Seal();
            CloseAccepted_.store(true, std::memory_order_release);
            CloseDelivered_.store(true, std::memory_order_release);
        }

        auto MarkNativeTerminal(Failure Reason) noexcept -> void
        {
            if (Reason.Failed())
            {
                Failure_.TrySet(Reason);
            }
            const auto FirstTerminal =
                !NativeTerminalSeen_.exchange(true, std::memory_order_acq_rel);
            Operations_.Seal();
            CloseActions_.Seal();
            CloseAccepted_.store(true, std::memory_order_release);
            CloseDelivered_.store(true, std::memory_order_release);
            if (FirstTerminal)
            {
                NativeTerminal_.Leave();
            }
        }

    private:
        [[nodiscard]] static auto DrainOwned(std::shared_ptr<NativeStreamActivity> Owner)
            -> boost::asio::awaitable<std::expected<void, Failure>>
        {
            co_await boost::asio::this_coro::throw_if_cancelled(false);
            if (Owner->State_->NativeTerminal.load(std::memory_order_acquire))
            {
                Owner->MarkNativeTerminal(Owner->State_->StreamCloseFailure);
            }
            if (!Owner->CloseAccepted_.load(std::memory_order_acquire) ||
                !Owner->CloseActions_.IsSealed())
            {
                co_return std::unexpected(Failure{Prism::Fault::Code::Blocked});
            }
            Owner->BufferedReads_.Seal();
            const auto Operations = co_await Owner->Operations_.Drain();
            if (!Operations)
            {
                co_return std::unexpected(Operations.error());
            }
            const auto Close = co_await Owner->CloseActions_.Drain();
            if (!Close)
            {
                co_return std::unexpected(Close.error());
            }
            const auto BufferedReads = co_await Owner->BufferedReads_.Drain();
            if (!BufferedReads)
            {
                co_return std::unexpected(BufferedReads.error());
            }
            const auto CloseFailure = Owner->Failure_.Load();
            if (CloseFailure.Failed() &&
                !Owner->NativeTerminalSeen_.load(std::memory_order_acquire))
            {
                co_return std::unexpected(CloseFailure);
            }
            const auto Terminal = co_await Owner->NativeTerminal_.Drain();
            if (!Terminal)
            {
                co_return std::unexpected(Terminal.error());
            }
            if (!Owner->IsRetired())
            {
                co_return std::unexpected(Failure{Prism::Fault::Code::Blocked});
            }
            const auto FailureValue = Owner->Failure_.Load();
            if (FailureValue.Failed())
            {
                co_return std::unexpected(FailureValue);
            }
            co_return std::expected<void, Failure>{};
        }

        [[nodiscard]] static auto RequireState(std::shared_ptr<StreamState> State)
            -> std::shared_ptr<StreamState>
        {
            if (!State)
            {
                throw std::invalid_argument("native stream activity requires a stream state");
            }
            return State;
        }

        std::shared_ptr<StreamState> State_;
        std::shared_ptr<Prism::Executor::ContextOwner> Context_;
        std::shared_ptr<Prism::Executor::ExecutorReclaimer> Reclaimer_;
        Prism::Lifecycle::DrainBarrier Operations_;
        Prism::Lifecycle::DrainBarrier BufferedReads_;
        Prism::Lifecycle::DrainBarrier CloseActions_;
        Prism::Lifecycle::DrainBarrier NativeTerminal_;
        Prism::Fault::FailureState Failure_;
        std::atomic<bool> CloseClaimed_{false};
        std::atomic<bool> CloseAccepted_{false};
        std::atomic<bool> CloseDelivered_{false};
        std::atomic<bool> NativeTerminalSeen_{false};
    };
}

