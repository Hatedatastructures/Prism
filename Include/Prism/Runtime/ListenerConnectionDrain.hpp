/**
 * @file ListenerConnectionDrain.hpp
 * @brief listener admission 的关闭交付、Activity 排空和 quota owner。
 * @details Reservation 中的 worker admission receipt 跟随该 owner；未启动 task 需排空入站
 *          Activity，已进入 Session 的 task 还必须确认 Session 完整 Control/Active 终态。
 */

#pragma once

#include <Prism/Foundation/Executor/PreparedAction.hpp>
#include <Prism/Foundation/Executor/ExecutorReclaimer.hpp>
#include <Prism/Foundation/Fault/FailureState.hpp>
#include <Prism/Runtime/ListenerConnectionGate.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/asio/awaitable.hpp>

#include <atomic>
#include <cstdint>
#include <exception>
#include <memory>
#include <utility>

namespace Prism::Runtime
{
    class Session;
}

namespace Prism::Runtime::Detail
{

    namespace Net = boost::asio;

    /** @brief admission task 的真实执行/排空状态，不由 TaskOutcome 猜测。 */
    struct SessionAdmissionState final
    {
        std::atomic<bool> Started{false};
        std::atomic<bool> Drained{false};
        std::atomic<bool> Terminal{false};
        std::atomic<std::shared_ptr<Prism::Runtime::Session>> SessionOwner{};
        Prism::Fault::FailureState TerminalFailure;

        auto RetainSession(std::shared_ptr<Prism::Runtime::Session> Owner) noexcept -> void;

        auto ReleaseSession() noexcept -> void;
    };

    /**
     * @brief 关闭交付后的 admission cleanup owner。
     * @details 未启动 Session、terminal failure 会先交付 listener CloseAction 并排空
     *          transport Activity；活动 Session 则等待其真实 Drained 回执后再执行 listener
     *          后置退休。失败实物继续保留于 storage。
     */
    class ListenerConnectionDrain final : public Prism::Executor::ClosingResource,
                                          public std::enable_shared_from_this<ListenerConnectionDrain>
    {
    public:
        struct Options final
        {
            Prism::SharedTransmission Transport;
            std::shared_ptr<ListenerConnectionGate::Reservation> Reservation;
            std::shared_ptr<Prism::Executor::PreparedAction> CloseAction;
            std::shared_ptr<SessionAdmissionState> SessionState;
        };

        explicit ListenerConnectionDrain(Options Input);

        /** @brief 在真实 transport executor 启动排空；失败 owner 交给 ClosingStorage。 */
        auto Start() noexcept -> void;

        auto RequestRetirement() noexcept -> void override;

        [[nodiscard]] auto IsRetired() const noexcept -> bool override;

        [[nodiscard]] auto IsDispatchUnavailable() const noexcept -> bool override;

        /** @brief 首次进入 Session::Run；未启动任务的 cleanup 不等待伪造 Session 终态。 */
        auto MarkSessionStarted() noexcept -> void;

        /** @brief 由实际 Run 协程保留 Session/Registration/Control/Active owner。 */
        auto RetainSession(std::shared_ptr<Prism::Runtime::Session> SessionOwner) noexcept -> void;

        /** @brief Session Control delivery 与 Active Finalize 全成功后的正式确认。 */
        auto MarkSessionDrained() noexcept -> void;

        /** @brief Session 协程已终态但未真实排空时发布失败并保留完整关闭 owner。 */
        auto MarkSessionTerminalFailure(Prism::Fault::Failure Error) noexcept -> void;

        /** @brief 在预构造 owner 上安装 Session 关闭交付与完整状态。 */
        auto ConfigureSession(std::shared_ptr<Prism::Executor::PreparedAction> CloseAction,
                              std::shared_ptr<SessionAdmissionState> SessionState) noexcept -> void;

        [[nodiscard]] static auto Make(Options Input)
            -> std::shared_ptr<ListenerConnectionDrain>
        {
            return std::make_shared<ListenerConnectionDrain>(std::move(Input));
        }

    private:
        struct DispatchCompletion final
        {
            std::shared_ptr<ListenerConnectionDrain> Owner;
            std::uint64_t Generation{0};
            std::exception_ptr Error;
            bool Invoked{false};

            DispatchCompletion(std::shared_ptr<ListenerConnectionDrain> Value,
                               const std::uint64_t ValueGeneration) noexcept;
            DispatchCompletion(DispatchCompletion &&Other) noexcept;
            ~DispatchCompletion() noexcept;
            auto operator()(std::exception_ptr Value) noexcept -> void;
        };

        [[nodiscard]] auto HasTerminalSessionFailure() const noexcept -> bool;

        auto StartOwner() noexcept -> void;

        static auto Run(std::shared_ptr<ListenerConnectionDrain> Owner) -> Net::awaitable<void>;

        auto Block(Prism::Fault::Failure Error) noexcept -> void;

        auto BlockDispatch(Prism::Fault::Failure Error) noexcept -> void;

        auto BlockTerminal(Prism::Fault::Failure Error) noexcept -> void;

        [[nodiscard]] auto CanDispatch() const noexcept -> bool
        {
            return Reclaimer_ && Reclaimer_->CanDispatch();
        }

        /** @brief Session 完整终态尚未发布时保留预约；这不是关闭失败。 */
        auto WaitForSessionDrain() noexcept -> void;

        auto OnDispatchDropped(const std::uint64_t Generation) noexcept -> void;

        auto OnDispatchCompleted(const std::uint64_t Generation,
                                 const std::exception_ptr &Error) noexcept -> void;

        Prism::SharedTransmission Transport_;
        std::shared_ptr<ListenerConnectionGate::Reservation> Reservation_;
        std::shared_ptr<Prism::Executor::PreparedAction> CloseAction_;
        std::shared_ptr<SessionAdmissionState> SessionState_;
        std::shared_ptr<Prism::Executor::ClosingStorage> Storage_;
        /** @brief 冷创建的原 Activity 执行域凭据，支持正式 io_context 与 strand 类型。 */
        std::shared_ptr<Prism::Executor::ExecutorReclaimer> Reclaimer_;
        std::atomic<bool> Started_{false};
        std::atomic<bool> Completed_{false};
        std::atomic<bool> Blocked_{false};
        std::atomic<bool> DispatchUnavailable_{false};
        std::atomic<bool> Retired_{false};
        std::atomic<bool> RetryRequested_{false};
        std::atomic<std::uint64_t> DispatchGeneration_{0};
        Prism::Fault::FailureState Failure_;
    };

} // namespace Prism::Runtime::Detail
