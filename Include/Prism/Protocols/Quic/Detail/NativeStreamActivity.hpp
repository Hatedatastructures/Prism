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
            Operation(Operation&& Other) noexcept;
            ~Operation();
            [[nodiscard]] auto Carrier() const noexcept -> std::shared_ptr<void>
            {
                return Carrier_;
            }

        private:
            friend class NativeStreamActivity;
            Operation(std::shared_ptr<NativeStreamActivity> Owner,
                      std::shared_ptr<void> Carrier, const bool Buffered = false);
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
            CloseOperation(CloseOperation&& Other) noexcept;
            ~CloseOperation();
            [[nodiscard]] explicit operator bool() const noexcept { return Entered_; }

        private:
            friend class NativeStreamActivity;
            CloseOperation(std::shared_ptr<NativeStreamActivity> Owner,
                           std::shared_ptr<void> Carrier);
            std::shared_ptr<NativeStreamActivity> Owner_;
            std::shared_ptr<void> Carrier_;
            bool Entered_{false};
        };

        explicit NativeStreamActivity(std::shared_ptr<StreamState> State);

        [[nodiscard]] auto BeginOperation(std::shared_ptr<void> Carrier)
            -> std::expected<Operation, Failure>;

        /** @brief native terminal 后只为已接收缓存数据创建读取回执。 */
        [[nodiscard]] auto BeginBufferedRead(std::shared_ptr<void> Carrier)
            -> std::expected<Operation, Failure>;

        [[nodiscard]] auto BeginClose(std::shared_ptr<void> Carrier)
            -> std::expected<CloseOperation, Failure>;

        auto Seal() noexcept -> void override;

        [[nodiscard]] auto Executor() const -> boost::asio::any_io_executor override
        {
            return Reclaimer_->Executor();
        }

        [[nodiscard]] auto IsRetired() const noexcept -> bool override;

        [[nodiscard]] auto Drain() -> boost::asio::awaitable<std::expected<void, Failure>> override
        {
            return DrainOwned(shared_from_this());
        }

        [[nodiscard]] auto CloseAccepted() const noexcept -> bool
        {
            return CloseAccepted_.load(std::memory_order_acquire);
        }

        auto CommitClose() noexcept -> void;

        auto RollbackClose() noexcept -> void;

        auto CompleteClose(std::expected<void, Failure> Result) noexcept -> void;

        auto MarkNativeTerminal(Failure Reason) noexcept -> void;

    private:
        [[nodiscard]] static auto DrainOwned(std::shared_ptr<NativeStreamActivity> Owner)
            -> boost::asio::awaitable<std::expected<void, Failure>>;

        [[nodiscard]] static auto RequireState(std::shared_ptr<StreamState> State)
            -> std::shared_ptr<StreamState>;

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
