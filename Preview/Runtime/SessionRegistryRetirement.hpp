/**
 * @file SessionRegistryRetirement.hpp
 * @brief Session Registry 内真实 Session owner 的 retirement receipt。
 * @details 每个等待者绑定 SessionControl executor；只有 Registration owner 终结后才发回执。
 */
#pragma once

#include <atomic>
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/error_code.hpp>
#include <cstdint>
#include <expected>
#include <memory>
#include <new>
#include <system_error>
#include <utility>

#include <Preview/Foundation/Fault/Code.hpp>
#include <Preview/Foundation/Fault/FailureState.hpp>
#include <Preview/Runtime/SessionControl.hpp>

namespace Preview::Runtime::Detail
{

    struct SessionRegistryEntry final
    {
        using RetirementSignal = boost::asio::experimental::concurrent_channel<
            void(boost::system::error_code)>;

        struct RetirementWaiter final
        {
            explicit RetirementWaiter(boost::asio::any_io_executor ExecutorValue)
                : Signal(std::move(ExecutorValue), 1U)
            {
            }

            RetirementSignal Signal;
            std::shared_ptr<RetirementWaiter> Next;
        };

        SessionRegistryEntry(std::shared_ptr<SessionControl> ControlValue,
                             boost::asio::any_io_executor ExecutorValue)
            : Control(std::move(ControlValue)), RetirementExecutor(std::move(ExecutorValue))
        {
        }

        std::atomic<bool> Removed{false};
        std::atomic<bool> RegistrationPublished{false};
        std::atomic<bool> RetirementAcknowledged{false};
        std::atomic<std::shared_ptr<SessionControl>> Control;
        boost::asio::any_io_executor RetirementExecutor;
        std::atomic<std::shared_ptr<RetirementWaiter>> RetirementWaiters;
        Preview::Fault::FailureState RetirementFailure;
    };

    /** @brief 将逻辑移除与真实 owner 退栈回执分开管理。 */
    class SessionRegistryRetirement final
    {
    public:
        /** @brief Registration owner 自身退出时通知所有退休等待者。 */
        static auto AcknowledgeRetirement(
            const std::shared_ptr<SessionRegistryEntry> &Entry) noexcept -> void
        {
            if (!Entry || !Entry->RegistrationPublished.load(std::memory_order_acquire))
            {
                return;
            }
            PublishRetirementReceipt(Entry);
        }

        /** @brief admission 尚未移交给 Session owner 时通知所有登记等待者。 */
        static auto AcknowledgeRejectedRegistration(
            const std::shared_ptr<SessionRegistryEntry> &Entry) noexcept -> void
        {
            if (!Entry || Entry->RegistrationPublished.load(std::memory_order_acquire))
            {
                return;
            }
            PublishRetirementReceipt(Entry);
        }

        /** @brief 等待真实 owner 回执；每个等待者独立绑定到 SessionControl executor。 */
        [[nodiscard]] static auto AwaitRetirement(
            const std::shared_ptr<SessionRegistryEntry> &Entry)
            -> boost::asio::awaitable<std::expected<void, Preview::Fault::Failure>>
        {
            if (!Entry)
            {
                co_return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::Blocked});
            }
            co_await boost::asio::this_coro::throw_if_cancelled(false);
            auto Result = RetirementResult(Entry);
            if (Result)
            {
                co_return Result;
            }
            if (Entry->RetirementFailure.Load().Failed())
            {
                co_return Result;
            }

            std::shared_ptr<SessionRegistryEntry::RetirementWaiter> Waiter;
            try
            {
                Waiter = std::make_shared<SessionRegistryEntry::RetirementWaiter>(
                    Entry->RetirementExecutor);
            }
            catch (const std::bad_alloc &)
            {
                co_return std::unexpected(Preview::Fault::Failure{
                    Preview::Fault::Code::ResourceUnavailable});
            }
            catch (const boost::system::system_error &Error)
            {
                co_return std::unexpected(Preview::Fault::FromNative(
                    static_cast<std::error_code>(Error.code())));
            }
            catch (const std::system_error &Error)
            {
                co_return std::unexpected(Preview::Fault::FromNative(Error.code()));
            }
            catch (...)
            {
                co_return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::Blocked});
            }

            while (!Entry->RetirementAcknowledged.load(std::memory_order_acquire))
            {
                auto Current = Entry->RetirementWaiters.load(std::memory_order_acquire);
                Waiter->Next = Current;
                if (Entry->RetirementWaiters.compare_exchange_weak(
                        Current, Waiter, std::memory_order_acq_rel,
                        std::memory_order_acquire))
                {
                    break;
                }
            }
            Result = RetirementResult(Entry);
            if (Result || Entry->RetirementFailure.Load().Failed())
            {
                co_return Result;
            }

            boost::system::error_code Error;
            co_await Waiter->Signal.async_receive(
                boost::asio::redirect_error(boost::asio::use_awaitable, Error));
            if (Error)
            {
                const auto Failure = Entry->RetirementFailure.Load();
                if (Failure.Failed())
                {
                    co_return std::unexpected(Failure);
                }
                co_return std::unexpected(Preview::Fault::FromNative(
                    static_cast<std::error_code>(Error)));
            }
            Result = RetirementResult(Entry);
            co_return Result;
        }

    private:
        static auto PublishRetirementReceipt(
            const std::shared_ptr<SessionRegistryEntry> &Entry) noexcept -> void
        {
            if (Entry->RetirementAcknowledged.exchange(true, std::memory_order_acq_rel))
            {
                return;
            }
            auto Waiter = Entry->RetirementWaiters.exchange(
                std::shared_ptr<SessionRegistryEntry::RetirementWaiter>{},
                std::memory_order_acq_rel);
            while (Waiter)
            {
                auto Next = std::move(Waiter->Next);
                NotifyWaiter(Entry, Waiter);
                Waiter = std::move(Next);
            }
        }

        [[nodiscard]] static auto RetirementResult(
            const std::shared_ptr<SessionRegistryEntry> &Entry)
            -> std::expected<void, Preview::Fault::Failure>
        {
            const auto Failure = Entry->RetirementFailure.Load();
            if (Failure.Failed())
            {
                return std::unexpected(Failure);
            }
            if (Entry->RetirementAcknowledged.load(std::memory_order_acquire) &&
                Entry->Removed.load(std::memory_order_acquire))
            {
                return {};
            }
            return std::unexpected(
                Preview::Fault::Failure{Preview::Fault::Code::Blocked});
        }

        static auto RecordFailure(
            const std::shared_ptr<SessionRegistryEntry> &Entry,
            Preview::Fault::Failure Failure) noexcept -> void
        {
            (void)Entry->RetirementFailure.TrySet(Failure);
        }

        static auto NotifyWaiter(
            const std::shared_ptr<SessionRegistryEntry> &Entry,
            const std::shared_ptr<SessionRegistryEntry::RetirementWaiter> &Waiter) noexcept
            -> void
        {
            try
            {
                if (Waiter->Signal.try_send(boost::system::error_code{}))
                {
                    return;
                }
                RecordFailure(Entry,
                    Preview::Fault::Failure{Preview::Fault::Code::Blocked});
                CloseWaiter(Entry, Waiter);
            }
            catch (const boost::system::system_error &Error)
            {
                RecordFailure(Entry, Preview::Fault::FromNative(
                    static_cast<std::error_code>(Error.code())));
                CloseWaiter(Entry, Waiter);
            }
            catch (const std::system_error &Error)
            {
                RecordFailure(Entry, Preview::Fault::FromNative(Error.code()));
                CloseWaiter(Entry, Waiter);
            }
            catch (...)
            {
                RecordFailure(Entry,
                    Preview::Fault::Failure{Preview::Fault::Code::Blocked});
                CloseWaiter(Entry, Waiter);
            }
        }

        static auto CloseWaiter(
            const std::shared_ptr<SessionRegistryEntry> &Entry,
            const std::shared_ptr<SessionRegistryEntry::RetirementWaiter> &Waiter) noexcept
            -> void
        {
            try
            {
                Waiter->Signal.close();
            }
            catch (const boost::system::system_error &Error)
            {
                RecordFailure(Entry, Preview::Fault::FromNative(
                    static_cast<std::error_code>(Error.code())));
            }
            catch (const std::system_error &Error)
            {
                RecordFailure(Entry, Preview::Fault::FromNative(Error.code()));
            }
            catch (...)
            {
                RecordFailure(Entry,
                    Preview::Fault::Failure{Preview::Fault::Code::Blocked});
            }
        }
    };

} // namespace Preview::Runtime::Detail
