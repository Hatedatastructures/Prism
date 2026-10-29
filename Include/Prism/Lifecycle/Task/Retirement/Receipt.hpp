/** @file Receipt.hpp @brief 任务 owner 真正退栈后的可并发回执。 */
#pragma once

#include <Prism/Foundation/Fault/Failure.hpp>

#include <boost/asio/awaitable.hpp>

#include <atomic>
#include <cstddef>
#include <expected>
#include <memory>
#include <vector>

namespace Prism::Lifecycle
{
    namespace Net = boost::asio;

    /** @brief 只在 TaskSubmission 完成异步清理并退栈后发布一次信号。 */
    class TaskRetirementReceipt final
        : public std::enable_shared_from_this<TaskRetirementReceipt>
    {
        struct Waiter;
        using WaiterList = std::vector<std::weak_ptr<Waiter>>;

    public:
        TaskRetirementReceipt() = default;
        ~TaskRetirementReceipt();
        TaskRetirementReceipt(const TaskRetirementReceipt&) = delete;
        auto operator=(const TaskRetirementReceipt&) -> TaskRetirementReceipt& = delete;

        /** @brief 在调用方 executor 等待真实 retirement；取消不解除 owner 回执。 */
        [[nodiscard]] auto WaitAsync() -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;
        /** @brief 在 TaskSubmission completion handler 中广播一次真实 owner 回执。 */
        auto Publish() noexcept -> void;

    private:
        [[nodiscard]] static auto Failed(Prism::Fault::Failure Failure)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;
        [[nodiscard]] static auto WaitAsyncPinned(std::shared_ptr<TaskRetirementReceipt> Self)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;
        [[nodiscard]] auto RegisterWaiter(const std::shared_ptr<Waiter>& Value)
            -> std::expected<void, Prism::Fault::Failure>;

        std::atomic<bool> Retired_{false};
        std::atomic<std::shared_ptr<const WaiterList>> Waiters_;
    };
}
