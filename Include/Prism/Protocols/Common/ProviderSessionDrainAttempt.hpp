/**
 * @file ProviderSessionDrainAttempt.hpp
 * @brief 一个 provider ticket drain attempt 的可并发完成回执。
 */
#pragma once

#include <Prism/Foundation/Fault/Failure.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/system/error_code.hpp>

#include <atomic>
#include <cstdint>
#include <exception>
#include <expected>
#include <memory>
#include <system_error>
#include <utility>

namespace Prism::Protocols::Detail
{
    namespace Net = boost::asio;

    /** @brief provider root 与 carrier drain 的物理完成回执。 */
    struct ProviderSessionDrainResult final
    {
        bool Complete{true};
        Prism::Fault::Failure Error{};
    };

    /** @brief 可重试取消不能遮蔽同轮出现的真实 drain 故障。 */
    auto PreserveProviderDrainFailure(
        Prism::Fault::Failure& Primary,
        const Prism::Fault::Failure& Secondary) noexcept -> void;

    [[nodiscard]] auto ProviderDrainAwaitFailure(
        const std::exception_ptr& Exception) noexcept -> Prism::Fault::Failure;

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
        using Result = std::expected<void, Prism::Fault::Failure>;

        ProviderSessionDrainAttempt();

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
        auto Publish(Result Value) noexcept -> void;

        [[nodiscard]] auto PublishedResult() const -> Result;

    private:
        /** @brief 节点 CAS 与封口 exchange 在线性化顺序中不会丢失完成通知。 */
        auto RegisterWaiter(const std::shared_ptr<Waiter>& Value) -> bool;

        /** @brief waiter 先登记，再观察同一原子 registry 的封口状态。 */
        [[nodiscard]] static auto WaitPinned(
            std::shared_ptr<ProviderSessionDrainAttempt> Self) -> Net::awaitable<Result>;

        static auto Notify(const std::shared_ptr<Waiter>& Value) noexcept -> void;

        std::shared_ptr<WaiterNode> ClosedSentinel_;
        std::atomic<std::shared_ptr<WaiterNode>> Waiters_;
        Result Result_{std::unexpected(
            Prism::Fault::Failure{Prism::Fault::Code::Blocked})};
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
                const bool Owner, ProviderSessionDrainAttempt::Result ResultValue) noexcept;
            DrainTurn(const DrainTurn&) = delete;
            auto operator=(const DrainTurn&) -> DrainTurn& = delete;
            DrainTurn(DrainTurn&& Other) noexcept;
            auto operator=(DrainTurn&&) noexcept -> DrainTurn& = delete;
            ~DrainTurn() noexcept;

            [[nodiscard]] auto IsOwner() const noexcept -> bool { return Owner_; }
            [[nodiscard]] auto Outcome() const -> ProviderSessionDrainAttempt::Result
            { return Result_; }
            auto SetResult(ProviderSessionDrainAttempt::Result Value) noexcept -> void;

        private:
            auto Publish() noexcept -> void;

            std::shared_ptr<ProviderSessionDrainAttempt> Value_;
            ProviderSessionDrainAttempt::Result Result_{std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::Blocked})};
            bool Owner_{false};
        };

        /** @brief binding owner 与 accept 终态两信号均到达时请求一次票据退休。 */
        auto SignalOwnerClose() noexcept -> bool;

        /** @brief Accept 事务退栈且拒绝 drain 结束后设置第二退休位。 */
        auto SignalAcceptAttemptComplete() noexcept -> bool;

        auto SignalMuxRootRetirement() noexcept -> bool;

        /** @brief drain 单飞；竞争者等待当前回执后再由调用者检查票据结果。 */
        [[nodiscard]] auto Acquire() -> Net::awaitable<
            std::expected<DrainTurn, Prism::Fault::Failure>>;

    private:
        inline static constexpr std::uint8_t OwnerCloseBit{0x01U};
        inline static constexpr std::uint8_t AcceptAttemptCompleteBit{0x02U};
        inline static constexpr std::uint8_t MuxRootRetirementBit{0x04U};

        auto Signal(const std::uint8_t Bit, const std::uint8_t TriggerMask) noexcept -> bool;

        std::atomic<std::uint8_t> RetirementSignals_{0U};
        std::atomic<std::shared_ptr<ProviderSessionDrainAttempt>> Current_;
    };
}
