/** @file DrainBarrier.hpp @brief 真实计数与显式失败的可等待屏障。 */
#pragma once

#include <Prism/Foundation/Executor/ExecutorReclaimer.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <atomic>
#include <cstddef>
#include <expected>
#include <memory>

namespace Prism::Lifecycle
{
    namespace Net = boost::asio;

    /**
     * @brief 为已创建通知 channel 的 executor 绑定 drain 通知许可。
     * @details 返回的只读共享标记在 execution_context 开始 shutdown 时变为 false；它不持有或延长
     *          executor/context，也不表示操作已 drain、资源已关闭或任务已退休。调用方仅用它抑制
     *          shutdown 后的迟到通知。必须在相关 channel 构造后调用，以使本 service 先于 channel shutdown。
     * @param Executor 借用的通知 channel executor；在其 execution_context 上同步注册 service，context 须由调用方保活。
     * @return 初始为 true 的共享只读可用标记；context shutdown 时变为 false。标记不代替 Drain 回执。
     * @note 不投递任务、不提供取消或执行半关闭；最终资源关闭仍归实际 carrier/resource owner。
     *       服务绑定/分配异常向调用方传播。
     */
    [[nodiscard]] auto BindDrainNotification(const Net::any_io_executor& Executor)
        -> std::shared_ptr<const std::atomic<bool>>;

    /** @brief Enter/Leave 可跨线程；取消与 blocked 只返回失败，不清零 active。
     * @details 调用方保持 owner；实际资源关闭由其 executor owner 负责，无半关闭。
     */
    class DrainBarrier final
    {
        struct State;

    public:
        explicit DrainBarrier(std::shared_ptr<Prism::Executor::ExecutorReclaimer> Value);
        ~DrainBarrier();
        DrainBarrier(const DrainBarrier&) = delete;
        auto operator=(const DrainBarrier&) -> DrainBarrier& = delete;

        /** @brief 成功后调用者必须立即构造拥有型预约；拒绝不改变最终计数。 */
        [[nodiscard]] auto Enter() noexcept -> bool;
        /** @brief 真实 owner 退栈后归还一次，最后一个归还者唤醒全部 drain 链。 */
        auto Leave() noexcept -> void;
        auto Seal() noexcept -> void;
        auto Block() noexcept -> void;
        /** @brief 读取准入封止状态；已进入的预约仍必须真实归还。 */
        [[nodiscard]] auto IsSealed() const noexcept -> bool;
        /** @brief 读取仍由实际 owner 持有的 drain 预约数。 */
        [[nodiscard]] auto Active() const noexcept -> std::size_t;
        /** @brief 读取排空阻断状态；不改变真实 active 计数。 */
        [[nodiscard]] auto IsBlocked() const noexcept -> bool;
        /** @brief 原 executor 驱动等待，零 active 才成功；不把 Blocked 当成完成。 */
        [[nodiscard]] auto Drain() -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;

    private:
        [[nodiscard]] static auto DrainState(std::shared_ptr<State> Value)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;

        std::shared_ptr<State> State_;
    };

    /** @brief 接管一次成功 Enter 的计数，覆盖调度与构造异常。
     * @details move 后源为空；转交活动 owner 时 Transfer，一条路径只能归还一次。
     * 无 I/O/半关闭，析构仅 Leave，实际资源关闭由其 executor owner 负责。
     */
    class DrainReservation final
    {
    public:
        explicit DrainReservation(DrainBarrier& Barrier);
        DrainReservation(DrainReservation&& Other) noexcept;
        DrainReservation(const DrainReservation&)=delete;
        ~DrainReservation();
        auto Transfer() noexcept -> void;

    private:
        DrainBarrier* Barrier_;
    };
}
