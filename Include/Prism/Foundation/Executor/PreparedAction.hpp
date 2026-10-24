/** @file PreparedAction.hpp @brief 预建关闭动作及原 executor 失败交付保留。 */
#pragma once
#include <Prism/Foundation/Executor/ExecutorReclaimer.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/execution_context.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/system/error_code.hpp>
#include <atomic>
#include <expected>
#include <functional>
#include <memory>
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
            explicit NotificationLifetime(boost::asio::execution_context& Context);
            std::shared_ptr<std::atomic<bool>> Active{std::make_shared<std::atomic<bool>>(true)};
        private:
            auto shutdown() -> void override;
        };
        struct Delivery final
        {
            std::shared_ptr<PreparedAction> Owner;
            bool Executed{false};
            explicit Delivery(std::shared_ptr<PreparedAction> Value);
            Delivery(Delivery&& Other) noexcept;
            ~Delivery();
            auto operator()() -> void;
        };
    public:
        using Action = std::function<std::expected<void, Prism::Fault::Failure>()>;
        PreparedAction(std::shared_ptr<ExecutorReclaimer> Reclaimer, Action Work);
        /** @brief 请求交付预建动作；错误保留实物，重复请求不重复执行。 */
        [[nodiscard]] auto Submit() -> std::expected<void, Prism::Fault::Failure>;
        /** @brief 交付等待完成后读取动作值结果；尚未执行返回 WouldBlock。 */
        [[nodiscard]] auto Result() const -> std::expected<void, Prism::Fault::Failure>;
        /** @brief 等待本动作自己的完成通知；兄弟 action/根 pending 不影响边界。
         * @details 取消屏蔽只用于已提交动作的实际交付，失败返回保留 cause 的值。
         */
        [[nodiscard]] auto Await() -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>
        { return AwaitAction(shared_from_this()); }
        auto RequestRetirement() -> void override { (void)Submit(); }
        [[nodiscard]] auto IsRetired() const noexcept -> bool override { return Retired_.load(); }
        [[nodiscard]] auto IsDispatchUnavailable() const noexcept -> bool override { return Unavailable_.load(); }
    private:
        auto Notify() noexcept -> void;
        static auto AwaitAction(std::shared_ptr<PreparedAction> Owner)
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>;
        auto Execute() -> void;
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
