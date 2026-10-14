/** @file Delivery.hpp @brief 单次前序命令水位确认，不等待共享 executor 静默。 */
#pragma once
#include <Preview/Foundation/Executor/ExecutorReclaimer.hpp>
#include <Preview/Foundation/Fault/Failure.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <expected>
namespace Preview::Runtime
{
    namespace Net = boost::asio;
    /** @brief 绑定阶段创建 signal/state；Await 不创建 shared 控制块。
     * @details 同一 control 的 finalizer 串行等待；只覆盖该次 post 之前的有限前缀。
     * 派生关闭动作由 SessionControl 捕获的有限动作集合逐层确认，不读取根 Pending。
     * executor shutdown 先关闭通知权限，迟到 handler 析构不触碰已销毁的服务。
     */
    class SessionDelivery final
    {
        class ContextLifetime final : public Net::execution_context::service
        {
        public:
            inline static Net::execution_context::id id;
            explicit ContextLifetime(Net::execution_context& Value) : service(Value) {}
            std::shared_ptr<std::atomic<bool>> Active{std::make_shared<std::atomic<bool>>(true)};
        private:
            auto shutdown() -> void override { Active->store(false); }
        };
        struct State final
        {
            explicit State(std::shared_ptr<Preview::Executor::ExecutorReclaimer> Value)
                : Reclaimer(std::move(Value)), Signal(Reclaimer->Executor(), 1),
                  ContextActive(Net::use_service<ContextLifetime>(
                      Net::query(Reclaimer->Executor(), Net::execution::context)).Active) {}
            std::shared_ptr<Preview::Executor::ExecutorReclaimer> Reclaimer;
            Net::experimental::concurrent_channel<void(boost::system::error_code)> Signal;
            std::shared_ptr<std::atomic<bool>> ContextActive;
            std::atomic<bool> Delivered{false}, Waiting{false};
            auto Notify(bool Success) -> void
            {
                Delivered.store(Success);
                if (ContextActive->load()) (void)Signal.try_send(boost::system::error_code{});
            }
        };
        struct Fence final
        {
            std::shared_ptr<State> Owner;
            bool Executed{false};
            explicit Fence(std::shared_ptr<State> Value) : Owner(std::move(Value)) {}
            Fence(Fence&& Other) noexcept : Owner(std::move(Other.Owner)), Executed(Other.Executed) {}
            ~Fence() { if (Owner && !Executed) Owner->Notify(false); }
            auto operator()() -> void
            { Executed = true; Owner->Notify(true); }
        };
        struct WaitReservation final
        {
            std::shared_ptr<State> Owner;
            ~WaitReservation() { Owner->Waiting.store(false); }
        };
    public:
        explicit SessionDelivery(std::shared_ptr<Preview::Executor::ExecutorReclaimer> Value)
            : State_(std::make_shared<State>(std::move(Value))) {}
        /** @brief 保活 signal 等待原 executor fence；重复同时等待拒绝，普通失败保留 cause。 */
        [[nodiscard]] auto Await() -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
        { return AwaitState(State_); }
    private:
        [[nodiscard]] static auto AwaitState(std::shared_ptr<State> Value)
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
        {
            co_await Net::this_coro::throw_if_cancelled(false);
            co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
            if (Value->Waiting.exchange(true))
                co_return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::WouldBlock});
            WaitReservation Reservation{Value};
            {
                Value->Delivered.store(false);
                if (!Value->Reclaimer->Post(Fence(Value)))
                    co_return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::Blocked});
                boost::system::error_code Error;
                co_await Value->Signal.async_receive(Net::redirect_error(Net::use_awaitable, Error));
                if (Error) co_return std::unexpected(Preview::Fault::FromNative(static_cast<std::error_code>(Error)));
                if (!Value->Delivered.load()) co_return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::Blocked});
            }
            co_return std::expected<void, Preview::Fault::Failure>{};
        }
        std::shared_ptr<State> State_;
    };
}
