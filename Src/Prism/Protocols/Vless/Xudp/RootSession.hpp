/** @file RootSession.hpp @brief XUDP 根会话的 typed Run、关联与 writer 退休边界。 */
#pragma once

#include <Prism/Protocols/Vless/Xudp/Association.hpp>
#include <Prism/Lifecycle/DrainBarrier.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/system_error.hpp>

#include <expected>
#include <chrono>
#include <memory>
#include <utility>
#include <atomic>
#include <system_error>

namespace Prism::Vless::Xudp
{
    using RunResult = std::expected<void, Prism::Fault::Failure>;

    /** @brief 登记 reader、执行域及子任务的首个完整失败。 */
    auto PreserveRunFailure(State& Root, Prism::Fault::Failure Failure) -> void;

    [[nodiscard]] auto CurrentRunResult(const State& Root) -> RunResult;

    class FrameCompletion final
    {
    public:
        explicit FrameCompletion(std::shared_ptr<State> Root);
        ~FrameCompletion();

    private:
        std::shared_ptr<State> Root_;
    };

    /** @brief reader 异常交给 TaskRegistry 的 typed failure owner，不在热循环捕获普通异常。 */
    auto RunFrames(std::shared_ptr<State> Root) -> Net::awaitable<void>;

    /** @brief 先退 reader、关联和 writer 的真实任务，再保存底层载体物理回执。 */
    auto DrainOwnedResources(const std::shared_ptr<State>& Root) -> Net::awaitable<void>;

    auto WaitForDrainCompletion(const std::shared_ptr<State>& Root) -> Net::awaitable<void>;

    auto SignalDrainCompletion(State& Root) noexcept -> void;

    [[nodiscard]] auto FinishPhysicalRetirement(const std::shared_ptr<State>& Root)
        -> Net::awaitable<RunResult>;

    auto DrainActivityResources(const std::shared_ptr<State>& Root)
        -> Net::awaitable<RunResult>;

    /** @brief 只凭任务计数、关联关闭、Run reservation 与 carrier receipt 释放资源。 */
    [[nodiscard]] auto FinishPhysicalRetirement(const std::shared_ptr<State>& Root)
        -> Net::awaitable<RunResult>;

    /** @brief Run 自己排空资源后归还 reservation，再确认 generation lease 可释放。 */
    auto DrainRunResources(
        const std::shared_ptr<State>& Root,
        Prism::Lifecycle::DrainReservation Reservation) -> Net::awaitable<RunResult>;

    class RootSession final : public Prism::Contract::MuxSession
    {
        class SessionActivity final : public Prism::Contract::CarrierActivity
        {
        public:
            explicit SessionActivity(std::shared_ptr<State> Value);

            /** @brief 封止 XUDP 的 frame、association、writer 与 Run reservation。 */
            auto Seal() noexcept -> void override;

            [[nodiscard]] auto Executor() const -> Net::any_io_executor override;

            [[nodiscard]] auto IsRetired() const noexcept -> bool override;

            /** @brief 活动 Run 退栈后再统一 drain；失败保留同一 owner 供重试。 */
            [[nodiscard]] auto Drain() -> Net::awaitable<RunResult> override;

        private:
            std::shared_ptr<State> State_;
        };

    public:
        RootSession(Prism::SharedTransmission Inbound,
                    Prism::Protocols::DatagramBinding Binding,
                    std::shared_ptr<Prism::Foundation::GenerationUseState> UseState);

        ~RootSession() override;

        /**
         * @brief 接管账户与代次租约，保留首个完整失败并等待 XUDP 实体资源退栈。
         * @details GenerationUseState 必须由请求携带；本根只获取一次，直到
         *          读帧循环、关联子任务、回包 writer 和底层载体都成功排空后才释放。
         */
        [[nodiscard]] auto Run(Prism::Contract::MuxRootRequest Request)
            -> Net::awaitable<RunResult> override;

        [[nodiscard]] auto Activity() const
            -> std::shared_ptr<Prism::Contract::CarrierActivity> override;

        /** @brief 独立回报 XUDP 全部实体活动与底层载体均已退栈。 */
        [[nodiscard]] auto IsRetired() const noexcept -> bool override;

        auto Cancel() noexcept -> void override;

        auto Close() noexcept -> void override;

    private:
        [[nodiscard]] auto FailAndDrain(Prism::Fault::Failure Failure)
            -> Net::awaitable<RunResult>;

        std::shared_ptr<State> State_;
        std::shared_ptr<SessionActivity> Activity_;
    };
}
