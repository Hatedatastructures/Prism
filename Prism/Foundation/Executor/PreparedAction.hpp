/** @file PreparedAction.hpp @brief 预建关闭动作及原 executor 失败交付保留。 */
#pragma once
#include <Prism/Foundation/Executor/ExecutorReclaimer.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <expected>
#include <functional>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>
namespace Prism::Executor
{
    /** @brief 冷装配时接管动作闭包和 context；提交不再构造闭包或分配项目控制块。
     * @details 动作只表示同步关闭交付，不代表 I/O drain。闭包必须拥有真实资源或
     * 其关闭 owner，失败由 ClosingStorage 保活；不在错误线程执行或析构实物。
     */
    class PreparedAction final : public ClosingResource, public std::enable_shared_from_this<PreparedAction>
    {
        class NotificationLifetime final : public boost::asio::execution_context::service
        {
        public:
            inline static boost::asio::execution_context::id id;
            explicit NotificationLifetime(boost::asio::execution_context& Context) : service(Context) {}
            std::shared_ptr<std::atomic<bool>> Active{std::make_shared<std::atomic<bool>>(true)};
        private:
            auto shutdown() -> void override { Active->store(false); }
        };
        struct Delivery final
        {
            std::shared_ptr<PreparedAction> Owner;
            bool Executed{false};
            explicit Delivery(std::shared_ptr<PreparedAction> Value) : Owner(std::move(Value)) {}
            Delivery(Delivery&& Other) noexcept : Owner(std::move(Other.Owner)) {}
            ~Delivery()
            {
                if (!Owner) return;
                Owner->Queued_.store(false);
                if (!Executed) { Owner->Unavailable_.store(true); Owner->Storage_->Retain(Owner); }
                else Owner->Finished_.store(true);
                Owner->Notify();
            }
            auto operator()() -> void { Owner->Execute(); Executed = true; }
        };
    public:
        using Action = std::function<std::expected<void, Prism::Fault::Failure>()>;
        PreparedAction(std::shared_ptr<ExecutorReclaimer> Reclaimer, Action Work)
            : Context_(ContextOwner::Find(Reclaimer->Executor())),
              Storage_(ContextOwner::Storage(Reclaimer->Executor())),
              Reclaimer_(std::move(Reclaimer)), Work_(std::move(Work)), Signal_(Reclaimer_->Executor(), 1),
              ContextActive_(boost::asio::use_service<NotificationLifetime>(
                  boost::asio::query(Reclaimer_->Executor(), boost::asio::execution::context)).Active) {}
        /** @brief 请求交付预建动作；错误保留实物，重复请求不重复执行。 */
        [[nodiscard]] auto Submit() -> std::expected<void, Prism::Fault::Failure>
        {
            if (Done_.load(std::memory_order_acquire)) return Result();
            Storage_->Retain(shared_from_this());
            if (!Reclaimer_->CanDispatch())
            {
                Unavailable_.store(true);
                Notify();
                Storage_->Retain(shared_from_this());
                return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            }
            if (Queued_.exchange(true)) return {};
            if (!Reclaimer_->Post(Delivery(shared_from_this())))
            {
                Unavailable_.store(true);
                Notify();
                Storage_->Retain(shared_from_this());
                return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            }
            return {};
        }
        /** @brief 交付等待完成后读取动作值结果；尚未执行返回 WouldBlock。 */
        [[nodiscard]] auto Result() const -> std::expected<void, Prism::Fault::Failure>
        {
            if (!Done_.load(std::memory_order_acquire))
            {
                if (Unavailable_.load()) return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
                return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::WouldBlock});
            }
            if (Failure_.Failed()) return std::unexpected(Failure_);
            return {};
        }
        /** @brief 等待本动作自己的完成通知；兄弟 action/根 pending 不影响边界。
         * @details 取消屏蔽只用于已提交动作的实际交付，失败返回保留 cause 的值。
         */
        [[nodiscard]] auto Await() -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>
        { return AwaitAction(shared_from_this()); }
        auto RequestRetirement() -> void override { (void)Submit(); }
        [[nodiscard]] auto IsRetired() const noexcept -> bool override { return Retired_.load(); }
        [[nodiscard]] auto IsDispatchUnavailable() const noexcept -> bool override { return Unavailable_.load(); }
    private:
        auto Notify() noexcept -> void
        { if (ContextActive_->load()) (void)Signal_.try_send(boost::system::error_code{}); }
        static auto AwaitAction(std::shared_ptr<PreparedAction> Owner)
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            co_await boost::asio::this_coro::throw_if_cancelled(false);
            co_await boost::asio::this_coro::reset_cancellation_state(boost::asio::disable_cancellation());
            while (!Owner->Finished_.load() && !Owner->Unavailable_.load())
            {
                boost::system::error_code Error;
                co_await Owner->Signal_.async_receive(boost::asio::redirect_error(boost::asio::use_awaitable, Error));
                if (Error) co_return std::unexpected(Prism::Fault::FromNative(static_cast<std::error_code>(Error)));
            }
            Owner->Notify();
            if (!Owner->Finished_.load()) co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            co_return Owner->Result();
        }
        auto Execute() -> void
        {
            if (Retired_.load()) return;
            std::expected<void, Prism::Fault::Failure> Result;
            if (Work_) Result = Work_();
            if (!Result) Failure_ = Result.error();
            Done_.store(true, std::memory_order_release);
            if (!Result) return;
            Work_ = {};
            Retired_.store(true);
            Storage_->Collect();
        }
        std::shared_ptr<ContextOwner> Context_;
        std::shared_ptr<ClosingStorage> Storage_;
        std::shared_ptr<ExecutorReclaimer> Reclaimer_;
        Action Work_;
        boost::asio::experimental::concurrent_channel<void(boost::system::error_code)> Signal_;
        std::shared_ptr<std::atomic<bool>> ContextActive_;
        Prism::Fault::Failure Failure_{};
        std::atomic<bool> Done_{false}, Finished_{false};
        std::atomic<bool> Queued_{false}, Retired_{false}, Unavailable_{false};
    };
}
