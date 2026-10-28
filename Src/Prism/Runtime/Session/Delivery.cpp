/** @file Delivery.cpp @brief Session 执行器投递屏障实现。 */
#include <Prism/Runtime/Session/Delivery.hpp>

#include <boost/asio/execution_context.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/asio/query.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/error_code.hpp>

#include <atomic>
#include <mutex>
#include <system_error>
#include <utility>

namespace Prism::Runtime
{
    struct SessionDelivery::ContextGate final
    {
        std::mutex Mutex;
        bool Active{true};
    };

    class SessionDelivery::ContextLifetime final : public Net::execution_context::service
    {
    public:
        inline static Net::execution_context::id id;

        explicit ContextLifetime(Net::execution_context& Value)
            : Net::execution_context::service(Value)
        {
        }

        std::shared_ptr<ContextGate> Gate{std::make_shared<ContextGate>()};

    private:
        auto shutdown() -> void override
        {
            const std::lock_guard Lock(Gate->Mutex);
            Gate->Active = false;
        }
    };

    struct SessionDelivery::State final
    {
        explicit State(std::shared_ptr<Prism::Executor::ExecutorReclaimer> Value)
            : Reclaimer(std::move(Value))
        {
        }

        std::shared_ptr<Prism::Executor::ExecutorReclaimer> Reclaimer;
        std::atomic<bool> Waiting{false};
    };

    struct SessionDelivery::Waiter final
    {
        using SignalType = Net::experimental::concurrent_channel<void(boost::system::error_code)>;

        explicit Waiter(Net::any_io_executor Executor)
            : Signal(Executor, 1),
              Gate(Net::use_service<ContextLifetime>(
                  Net::query(Executor, Net::execution::context)).Gate)
        {
        }

        SignalType Signal;
        std::shared_ptr<ContextGate> Gate;
        std::atomic<bool> Delivered{false};
    };

    struct SessionDelivery::Fence final
    {
        explicit Fence(const std::shared_ptr<Waiter>& Value)
            : Target(Value), Gate(Value->Gate)
        {
        }

        Fence(Fence&& Other) noexcept
            : Target(std::move(Other.Target)), Gate(std::move(Other.Gate)), Executed(Other.Executed)
        {
            Other.Executed = true;
        }

        ~Fence()
        {
            if (!Executed) Notify(false);
        }

        auto operator()() -> void
        {
            Executed = true;
            Notify(true);
        }

    private:
        auto Notify(const bool Success) -> void
        {
            if (!Gate) return;
            const std::lock_guard Lock(Gate->Mutex);
            if (!Gate->Active) return;
            const auto Value = Target.lock();
            if (!Value) return;
            Value->Delivered.store(Success, std::memory_order_release);
            (void)Value->Signal.try_send(boost::system::error_code{});
        }

        std::weak_ptr<Waiter> Target;
        std::shared_ptr<ContextGate> Gate;
        bool Executed{false};
    };

    struct SessionDelivery::WaitReservation final
    {
        explicit WaitReservation(std::shared_ptr<State> Value) : Owner(std::move(Value))
        {
        }

        ~WaitReservation()
        {
            Owner->Waiting.store(false, std::memory_order_release);
        }

        std::shared_ptr<State> Owner;
    };

    SessionDelivery::SessionDelivery(
        std::shared_ptr<Prism::Executor::ExecutorReclaimer> Value)
        : State_(std::make_shared<State>(std::move(Value)))
    {
    }

    auto SessionDelivery::AwaitState(std::shared_ptr<State> Value)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        co_await Net::this_coro::throw_if_cancelled(false);
        co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
        if (Value->Waiting.exchange(true))
            co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::WouldBlock});
        WaitReservation Reservation{Value};
        auto CallerExecutor = co_await Net::this_coro::executor;
        auto WaiterValue = std::make_shared<Waiter>(std::move(CallerExecutor));
        if (!Value->Reclaimer->Post(Fence(WaiterValue)))
            co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        boost::system::error_code Error;
        co_await WaiterValue->Signal.async_receive(Net::redirect_error(Net::use_awaitable, Error));
        if (Error)
            co_return std::unexpected(
                Prism::Fault::FromNative(static_cast<std::error_code>(Error)));
        if (!WaiterValue->Delivered.load(std::memory_order_acquire))
            co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        co_return std::expected<void, Prism::Fault::Failure>{};
    }
}
