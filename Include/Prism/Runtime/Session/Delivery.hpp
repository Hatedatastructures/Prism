/** @file Delivery.hpp @brief 单次前序命令水位确认，不等待共享 executor 静默。 */
#pragma once
#include <Prism/Foundation/Executor/ExecutorReclaimer.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <boost/asio/awaitable.hpp>
#include <expected>
#include <memory>
namespace Prism::Runtime
{
    namespace Net = boost::asio;
    /** @brief 绑定阶段创建 reclaimer state；Await 在调用 executor 上建立一次性 waiter。
     * @details 同一 control 的 finalizer 串行等待；只覆盖该次 post 之前的有限前缀。
     * 派生关闭动作由 SessionControl 捕获的有限动作集合逐层确认，不读取根 Pending。
     * waiter 与 Await 调用 executor 同寿命；shutdown 关闭通知权限后清理该 context 的接收操作。
     */
    class SessionDelivery final
    {
        struct ContextGate;
        class ContextLifetime;
        struct State;
        struct Waiter;
        struct Fence;
        struct WaitReservation;
    public:
        explicit SessionDelivery(std::shared_ptr<Prism::Executor::ExecutorReclaimer> Value);
        /** @brief 保活 caller-context waiter 等待原 executor fence；拒绝重复并发等待。 */
        [[nodiscard]] auto Await() -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        { return AwaitState(State_); }
    private:
        [[nodiscard]] static auto AwaitState(std::shared_ptr<State> Value)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;
        std::shared_ptr<State> State_;
    };
}
