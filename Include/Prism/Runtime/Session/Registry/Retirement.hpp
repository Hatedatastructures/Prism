/**
 * @file Retirement.hpp
 * @brief Session Registry 内真实 Session owner 的 retirement receipt。
 * @details 每个等待者绑定 SessionControl executor；只有 Registration owner 终结后才发回执。
 */
#pragma once

#include <atomic>
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/system/error_code.hpp>
#include <cstdint>
#include <expected>
#include <memory>

#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Foundation/Fault/FailureState.hpp>
#include <Prism/Runtime/Session/Control.hpp>

namespace Prism::Runtime::Detail
{

    struct SessionRegistryEntry final
    {
        using RetirementSignal = boost::asio::experimental::concurrent_channel<
            void(boost::system::error_code)>;

        struct RetirementWaiter final
        {
            explicit RetirementWaiter(boost::asio::any_io_executor ExecutorValue);

            RetirementSignal Signal;
            std::shared_ptr<RetirementWaiter> Next;
        };

        SessionRegistryEntry(std::shared_ptr<SessionControl> ControlValue,
                             boost::asio::any_io_executor ExecutorValue);

        std::atomic<bool> Removed{false};
        std::atomic<bool> RegistrationPublished{false};
        std::atomic<bool> RetirementAcknowledged{false};
        std::atomic<std::shared_ptr<SessionControl>> Control;
        boost::asio::any_io_executor RetirementExecutor;
        std::atomic<std::shared_ptr<RetirementWaiter>> RetirementWaiters;
        Prism::Fault::FailureState RetirementFailure;
    };

    /** @brief 将逻辑移除与真实 owner 退栈回执分开管理。 */
    class SessionRegistryRetirement final
    {
    public:
        /** @brief Registration owner 自身退出时通知所有退休等待者。 */
        static auto AcknowledgeRetirement(
            const std::shared_ptr<SessionRegistryEntry> &Entry) noexcept -> void;

        /** @brief admission 尚未移交给 Session owner 时通知所有登记等待者。 */
        static auto AcknowledgeRejectedRegistration(
            const std::shared_ptr<SessionRegistryEntry> &Entry) noexcept -> void;

        /** @brief 等待真实 owner 回执；每个等待者独立绑定到 SessionControl executor。 */
        [[nodiscard]] static auto AwaitRetirement(
            const std::shared_ptr<SessionRegistryEntry> &Entry)
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>;

    private:
        static auto PublishRetirementReceipt(
            const std::shared_ptr<SessionRegistryEntry> &Entry) noexcept -> void;

        [[nodiscard]] static auto RetirementResult(
            const std::shared_ptr<SessionRegistryEntry> &Entry)
            -> std::expected<void, Prism::Fault::Failure>;

        static auto RecordFailure(
            const std::shared_ptr<SessionRegistryEntry> &Entry,
            Prism::Fault::Failure Failure) noexcept -> void;

        static auto NotifyWaiter(
            const std::shared_ptr<SessionRegistryEntry> &Entry,
            const std::shared_ptr<SessionRegistryEntry::RetirementWaiter> &Waiter) noexcept -> void;

        static auto CloseWaiter(
            const std::shared_ptr<SessionRegistryEntry> &Entry,
            const std::shared_ptr<SessionRegistryEntry::RetirementWaiter> &Waiter) noexcept -> void;
    };

} // namespace Prism::Runtime::Detail
