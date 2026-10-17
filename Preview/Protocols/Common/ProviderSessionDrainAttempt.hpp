/**
 * @file ProviderSessionDrainAttempt.hpp
 * @brief 一个 provider ticket drain attempt 的可并发完成回执。
 */
#pragma once

#include <Preview/Foundation/Fault/Failure.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/error_code.hpp>
#include <boost/system/system_error.hpp>

#include <atomic>
#include <cstdint>
#include <exception>
#include <expected>
#include <memory>
#include <system_error>
#include <utility>

namespace Preview::Protocols::Detail
{
    namespace Net = boost::asio;

    /** @brief provider root 与 carrier drain 的物理完成回执。 */
    struct ProviderSessionDrainResult final
    {
        bool Complete{true};
        Preview::Fault::Failure Error{};
    };

    /** @brief 可重试取消不能遮蔽同轮出现的真实 drain 故障。 */
    inline auto PreserveProviderDrainFailure(Preview::Fault::Failure& Primary,
        const Preview::Fault::Failure& Secondary) noexcept -> void
    {
        if (Secondary.Succeeded()) return;
        const bool PrimaryIsRetryableCancellation =
            Primary.Code == Preview::Fault::Code::Canceled;
        const bool SecondaryIsDurable =
            Secondary.Code != Preview::Fault::Code::Canceled;
        if (Primary.Succeeded() || (PrimaryIsRetryableCancellation && SecondaryIsDurable))
            Primary = Secondary;
    }

    [[nodiscard]] inline auto ProviderDrainAwaitFailure(const std::exception_ptr& Exception) noexcept
        -> Preview::Fault::Failure
    {
        try
        {
            if (Exception) std::rethrow_exception(Exception);
        }
        catch (const boost::system::system_error& Failure)
        {
            return Preview::Fault::FromNative(static_cast<std::error_code>(Failure.code()));
        }
        catch (const std::system_error& Failure)
        {
            return Preview::Fault::FromNative(Failure.code());
        }
        catch (...)
        {
            return Preview::Fault::Failure{Preview::Fault::Code::Blocked};
        }
        return Preview::Fault::Failure{Preview::Fault::Code::Blocked};
    }

    /** @brief 单个 ticket drain attempt 的一次性多 waiter 完成信号。 */
    class ProviderSessionDrainAttempt final
        : public std::enable_shared_from_this<ProviderSessionDrainAttempt>
    {
        using Signal = Net::experimental::concurrent_channel<void(boost::system::error_code)>;

        struct Waiter final
        {
            explicit Waiter(Net::any_io_executor Executor) : Events(std::move(Executor), 1U) {}
            Signal Events;
        };

        struct WaiterNode final
        {
            std::weak_ptr<Waiter> Value;
            std::shared_ptr<WaiterNode> Next;
        };

    public:
        using Result = std::expected<void, Preview::Fault::Failure>;

        ProviderSessionDrainAttempt()
            : ClosedSentinel_(std::make_shared<WaiterNode>()) {}

        [[nodiscard]] auto IsPublished() const noexcept -> bool
        {
            return Waiters_.load(std::memory_order_acquire) == ClosedSentinel_;
        }

        /** @brief 等待同一次 drain attempt 完成；每个 waiter 绑定自己的 executor。 */
        [[nodiscard]] auto Wait() -> Net::awaitable<Result>
        {
            return WaitPinned(shared_from_this());
        }

        /** @brief 原子封止新 waiter，再通知封口之前登记的 waiter。 */
        auto Publish(Result Value) noexcept -> void
        {
            bool Idle = false;
            if (!Publishing_.compare_exchange_strong(
                    Idle, true, std::memory_order_acq_rel, std::memory_order_acquire)) return;
            Result_ = std::move(Value);
            auto Current = Waiters_.exchange(ClosedSentinel_, std::memory_order_acq_rel);
            if (Current == ClosedSentinel_) return;
            while (Current)
            {
                if (const auto Value = Current->Value.lock()) Notify(Value);
                Current = std::move(Current->Next);
            }
        }

        [[nodiscard]] auto PublishedResult() const -> Result
        {
            if (!IsPublished())
            {
                return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::Blocked});
            }
            return Result_;
        }

    private:
        /** @brief 节点 CAS 与封口 exchange 在线性化顺序中不会丢失完成通知。 */
        auto RegisterWaiter(const std::shared_ptr<Waiter>& Value) -> bool
        {
            auto Current = Waiters_.load(std::memory_order_acquire);
            auto Node = std::make_shared<WaiterNode>();
            Node->Value = Value;
            while (Current != ClosedSentinel_)
            {
                Node->Next = Current;
                if (Waiters_.compare_exchange_weak(Current, Node,
                        std::memory_order_acq_rel, std::memory_order_acquire))
                {
                    return true;
                }
            }
            return false;
        }

        /** @brief waiter 先登记，再观察同一原子 registry 的封口状态。 */
        [[nodiscard]] static auto WaitPinned(
            std::shared_ptr<ProviderSessionDrainAttempt> Self) -> Net::awaitable<Result>
        {
            try
            {
                co_await Net::this_coro::throw_if_cancelled(false);
                co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
            }
            catch (...)
            {
                if (Self->IsPublished()) co_return Self->PublishedResult();
                co_return std::unexpected(ProviderDrainAwaitFailure(std::current_exception()));
            }
            std::shared_ptr<Waiter> Waiting;
            try
            {
                const auto Executor = co_await Net::this_coro::executor;
                Waiting = std::make_shared<Waiter>(Executor);
                if (!Self->RegisterWaiter(Waiting)) co_return Self->PublishedResult();
            }
            catch (...)
            {
                if (Self->IsPublished()) co_return Self->PublishedResult();
                co_return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::ResourceUnavailable});
            }

            boost::system::error_code Error;
            try
            {
                co_await Waiting->Events.async_receive(
                    Net::redirect_error(Net::use_awaitable, Error));
            }
            catch (const boost::system::system_error& Failure)
            {
                if (Self->IsPublished()) co_return Self->PublishedResult();
                co_return std::unexpected(Preview::Fault::FromNative(
                    static_cast<std::error_code>(Failure.code())));
            }
            catch (const std::system_error& Failure)
            {
                if (Self->IsPublished()) co_return Self->PublishedResult();
                co_return std::unexpected(Preview::Fault::FromNative(Failure.code()));
            }
            catch (...)
            {
                if (Self->IsPublished()) co_return Self->PublishedResult();
                co_return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::Blocked});
            }
            if (Error && !Self->IsPublished())
            {
                co_return std::unexpected(Preview::Fault::FromNative(
                    static_cast<std::error_code>(Error)));
            }
            co_return Self->PublishedResult();
        }

        static auto Notify(const std::shared_ptr<Waiter>& Value) noexcept -> void
        {
            try { (void)Value->Events.try_send(boost::system::error_code{}); }
            catch (...) { try { Value->Events.close(); } catch (...) {} }
        }

        std::shared_ptr<WaiterNode> ClosedSentinel_;
        std::atomic<std::shared_ptr<WaiterNode>> Waiters_;
        Result Result_{std::unexpected(
            Preview::Fault::Failure{Preview::Fault::Code::Blocked})};
        std::atomic<bool> Publishing_{false};
    };

    /** @brief Provider ticket 的请求握手与 drain 单飞 owner。 */
    class ProviderSessionDrainCoordinator final
    {
    public:
        class DrainTurn final
        {
        public:
            DrainTurn(std::shared_ptr<ProviderSessionDrainAttempt> Value,
                const bool Owner, ProviderSessionDrainAttempt::Result ResultValue) noexcept
                : Value_(std::move(Value)), Result_(std::move(ResultValue)), Owner_(Owner) {}
            DrainTurn(const DrainTurn&) = delete;
            auto operator=(const DrainTurn&) -> DrainTurn& = delete;
            DrainTurn(DrainTurn&& Other) noexcept
                : Value_(std::move(Other.Value_)), Result_(std::move(Other.Result_)),
                  Owner_(std::exchange(Other.Owner_, false)) {}
            auto operator=(DrainTurn&&) noexcept -> DrainTurn& = delete;
            ~DrainTurn() noexcept { Publish(); }

            [[nodiscard]] auto IsOwner() const noexcept -> bool { return Owner_; }
            [[nodiscard]] auto Outcome() const -> ProviderSessionDrainAttempt::Result
            { return Result_; }
            auto SetResult(ProviderSessionDrainAttempt::Result Value) noexcept -> void
            { Result_ = std::move(Value); }

        private:
            auto Publish() noexcept -> void
            {
                if (Owner_)
                {
                    Owner_ = false;
                    Value_->Publish(std::move(Result_));
                }
            }

            std::shared_ptr<ProviderSessionDrainAttempt> Value_;
            ProviderSessionDrainAttempt::Result Result_{std::unexpected(
                Preview::Fault::Failure{Preview::Fault::Code::Blocked})};
            bool Owner_{false};
        };

        /** @brief binding owner 与 accept 终态两信号均到达时请求一次票据退休。 */
        auto SignalOwnerClose() noexcept -> bool
        {
            return Signal(OwnerCloseBit, AcceptAttemptCompleteBit);
        }

        /** @brief Accept 事务退栈且拒绝 drain 结束后设置第二退休位。 */
        auto SignalAcceptAttemptComplete() noexcept -> bool
        {
            return Signal(AcceptAttemptCompleteBit,
                static_cast<std::uint8_t>(OwnerCloseBit | MuxRootRetirementBit));
        }

        auto SignalMuxRootRetirement() noexcept -> bool
        {
            return Signal(MuxRootRetirementBit, AcceptAttemptCompleteBit);
        }

        /** @brief drain 单飞；竞争者等待当前回执后再由调用者检查票据结果。 */
        [[nodiscard]] auto Acquire() -> Net::awaitable<
            std::expected<DrainTurn, Preview::Fault::Failure>>
        {
            try
            {
                co_await Net::this_coro::throw_if_cancelled(false);
                co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
                while (true)
                {
                    auto Current = Current_.load(std::memory_order_acquire);
                    if (Current && !Current->IsPublished())
                    {
                        const auto Waited = co_await Current->Wait();
                        if (!Waited) co_return std::unexpected(Waited.error());
                        co_return DrainTurn{std::move(Current), false, Waited};
                    }
                    std::shared_ptr<ProviderSessionDrainAttempt> Candidate;
                    try { Candidate = std::make_shared<ProviderSessionDrainAttempt>(); }
                    catch (...)
                    {
                        co_return std::unexpected(
                            Preview::Fault::Failure{Preview::Fault::Code::ResourceUnavailable});
                    }
                    if (Current_.compare_exchange_weak(Current, Candidate,
                            std::memory_order_acq_rel, std::memory_order_acquire))
                    {
                        co_return DrainTurn{std::move(Candidate), true,
                            std::unexpected(
                                Preview::Fault::Failure{Preview::Fault::Code::Blocked})};
                    }
                }
            }
            catch (...)
            {
                co_return std::unexpected(ProviderDrainAwaitFailure(std::current_exception()));
            }
        }

    private:
        inline static constexpr std::uint8_t OwnerCloseBit{0x01U};
        inline static constexpr std::uint8_t AcceptAttemptCompleteBit{0x02U};
        inline static constexpr std::uint8_t MuxRootRetirementBit{0x04U};

        auto Signal(const std::uint8_t Bit, const std::uint8_t TriggerMask) noexcept -> bool
        {
            const auto Previous = RetirementSignals_.fetch_or(Bit, std::memory_order_acq_rel);
            return (Previous & TriggerMask) != 0U;
        }

        std::atomic<std::uint8_t> RetirementSignals_{0U};
        std::atomic<std::shared_ptr<ProviderSessionDrainAttempt>> Current_;
    };
}
