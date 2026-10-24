/**
 * @file Maintenance.hpp
 * @brief DNS Resolver 后台维护协程
 * @details 周期执行缓存过期驱逐、single-flight 清理和上游连接池清扫。
 *          通过状态模板接收资源对象，detached 协程不依赖 Resolver 裸指针。
 */

#pragma once

#include <Prism/Foundation/Executor/ClosingStorage.hpp>
#include <Prism/Foundation/Executor/ContextOwner.hpp>
#include <Prism/Foundation/Executor/ExecutorReclaimer.hpp>
#include <Prism/Foundation/Executor/FatalState.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Net/Dns/UpstreamTypes.hpp>
#include <Prism/Net/Dns/Detail/ResolverFailure.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/experimental/channel_error.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/system_error.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <exception>
#include <expected>
#include <memory>
#include <string>
#include <utility>

namespace Prism::Network::Dns::Detail
{

    namespace Net = boost::asio;

    /**
     * @brief 系统 resolver 回退的拥有型输入。
     * @details Pool 只为结果地址列表预约真实块，借用不跨本次查询退回；
     *          executor 驱动 resolver 和其取消/超时组合。
     */
    struct OsResolveRequest final
    {
        Net::any_io_executor Executor;
        std::string Name;
        QType QueryType;
        Memory::BytePool &Pool;
    };

    /**
     * @brief 执行一次按值拥有输入的系统 resolver 查询。
     * @param Request 拥有 executor、规范化域名和查询类型，并借用调用方池至返回。
     * @return 过滤后的系统解析结果；地址进入唯一 AnswerSet 事实，错误写入 QueryResult。
     * @note named runner 不借用 Resolver 或其成员，调用者负责外层 timeout 组合。
     */
    [[nodiscard]] inline auto ResolveOsHost(OsResolveRequest Request)
        -> Net::awaitable<QueryResult>
    {
        Net::ip::tcp::resolver Resolver(Request.Executor);
        boost::system::error_code ErrorCode;
        auto Results = co_await Resolver.async_resolve(
            Request.Name, "0", Net::redirect_error(Net::use_awaitable, ErrorCode));
        QueryResult Result;
        if (ErrorCode)
        {
            Result.Error = ResolverFailureFromBoost(ErrorCode);
            co_return Result;
        }
        for (const auto &Resolved : Results)
        {
            const auto &Address = Resolved.endpoint().address();
            const bool WantV4 = Request.QueryType == QType::A;
            if (Address.is_v4() != WantV4)
            {
                continue;
            }
            const auto Appended = Result.Response.Ips.TryAppend(Address, Request.Pool);
            if (!Appended)
            {
                Result.Error = Appended.error();
                co_return Result;
            }
        }
        if (Result.Response.Ips.Empty())
        {
            Result.Error = Prism::Fault::Failure{Prism::Fault::Code::DnsFailed, {}};
        }
        co_return Result;
    }

    /**
     * @brief 执行 Resolver 后台维护循环
     * @tparam State Resolver 共享状态类型
     * @param state 由共享指针持有的维护状态
     * @return 后台协程
     */
    template <typename State>
    [[nodiscard]] inline auto MaintenanceLoop(std::shared_ptr<State> StateObject)
        -> boost::asio::awaitable<void>
    {
        while (StateObject->Alive_->load(std::memory_order_acquire))
        {
            StateObject->MaintenanceTimer_.expires_after(std::chrono::seconds(30));
            boost::system::error_code ErrorCode;
            co_await StateObject->MaintenanceTimer_.async_wait(
                boost::asio::redirect_error(boost::asio::use_awaitable, ErrorCode));
            if (ErrorCode == boost::asio::error::operation_aborted ||
                !StateObject->Alive_->load(std::memory_order_acquire))
            {
                co_return;
            }
            StateObject->Cache_.EvictExpired();
            StateObject->Coalescer_.FlushCleanup();
            StateObject->Upstream_->ClearIdleConns();
        }
    }

    /**
     * @brief Resolver 专属维护 owner，覆盖已登记 executor 的失败关闭实物。
     * @tparam State 缓存、flight、上游池及其 maintenance timer 的共享状态。
     * @details Control 预先持有 ContextOwner/ClosingStorage；仅在原 executor 上取消 timer，
     *          并由 ClosingStorage 保留 dispatch 被拒绝或 completion handler 被丢弃的 owner。
     */
    template <typename State>
    class MaintenanceOwner final
    {
        template <typename OwnerType>
        struct StopDelivery final
        {
            explicit StopDelivery(std::shared_ptr<OwnerType> OwnerValue)
                : Owner_(std::move(OwnerValue))
            {
            }

            StopDelivery(StopDelivery &&Other) noexcept
                : Owner_(std::move(Other.Owner_)), Executed_(Other.Executed_)
            {
                Other.Executed_ = true;
            }
            StopDelivery(const StopDelivery &) = delete;
            ~StopDelivery()
            {
                if (!Owner_ || Executed_)
                {
                    return;
                }
                Owner_->MarkUnavailable();
            }

            auto operator()() -> void
            {
                const auto Result = Owner_->StopOnExecutor();
                Executed_ = true;
                Owner_->CompleteStopRequest(Result);
            }

            std::shared_ptr<OwnerType> Owner_;
            bool Executed_{false};
        };

        template <typename OwnerType>
        struct CompletionDelivery final
        {
            explicit CompletionDelivery(std::shared_ptr<OwnerType> OwnerValue)
                : Owner_(std::move(OwnerValue))
            {
            }

            CompletionDelivery(CompletionDelivery &&Other) noexcept
                : Owner_(std::move(Other.Owner_)), Executed_(Other.Executed_)
            {
                Other.Executed_ = true;
            }
            CompletionDelivery(const CompletionDelivery &) = delete;
            ~CompletionDelivery()
            {
                if (!Owner_ || Executed_)
                {
                    return;
                }
                Owner_->MarkUnavailable();
            }

            auto operator()(std::exception_ptr ExceptionValue) -> void
            {
                Owner_->CompleteMaintenance(std::move(ExceptionValue));
                Executed_ = true;
            }

            std::shared_ptr<OwnerType> Owner_;
            bool Executed_{false};
        };

        struct Control final : Prism::Executor::ClosingResource,
                              std::enable_shared_from_this<Control>
        {
            using Signal = Net::experimental::channel<void(boost::system::error_code)>;
            enum class StopRequestState : std::uint8_t { Idle, Posting, Posted, Unavailable };

            Control(Net::any_io_executor ExecutorValue, std::shared_ptr<State> StateValue)
                : ContextPin(Prism::Executor::ContextOwner::Find(ExecutorValue)),
                  Fatal(Prism::Executor::FatalState::For(ExecutorValue)),
                  Storage(Prism::Executor::ContextOwner::Storage(ExecutorValue)),
                  Reclaimer(std::make_shared<Prism::Executor::ExecutorReclaimer>(ExecutorValue)),
                  Executor(std::move(ExecutorValue)), StateObject(std::move(StateValue)),
                  Completion(Executor)
            {
            }

            auto RequestStop() -> std::expected<void, Prism::Fault::Failure>
            {
                if (Retired.load(std::memory_order_acquire))
                {
                    return {};
                }
                auto Current = StopStatus.load(std::memory_order_acquire);
                for (;;)
                {
                    if (Current == StopRequestState::Posted ||
                        Current == StopRequestState::Posting)
                    {
                        return {};
                    }
                    if (Current == StopRequestState::Unavailable &&
                        !Reclaimer->CanDispatch())
                    {
                        return std::unexpected(
                            Prism::Fault::Failure{Prism::Fault::Code::Blocked});
                    }
                    if (StopStatus.compare_exchange_weak(Current, StopRequestState::Posting,
                            std::memory_order_acq_rel, std::memory_order_acquire)) break;
                }
                Storage->Retain(this->shared_from_this());
                StopStatus.store(StopRequestState::Posted, std::memory_order_release);
                const auto Posted = Reclaimer->Post(StopDelivery<Control>(this->shared_from_this()));
                if (!Posted)
                {
                    MarkUnavailable();
                    return std::unexpected(Posted.error());
                }
                return {};
            }

            auto MarkUnavailable() noexcept -> void
            {
                if (Retired.load(std::memory_order_acquire)) return;
                StopStatus.store(StopRequestState::Unavailable, std::memory_order_release);
                Storage->Retain(this->shared_from_this());
            }

            auto StopOnExecutor() noexcept -> std::expected<void, Prism::Fault::Failure>
            {
                StateObject->Alive_->store(false, std::memory_order_release);
                try
                {
                    StateObject->MaintenanceTimer_.cancel();
                    return {};
                }
                catch (const boost::system::system_error &Exception)
                {
                    return std::unexpected(Prism::Fault::FromNative(
                        static_cast<std::error_code>(Exception.code())));
                }
                catch (...)
                {
                    Exception = std::current_exception();
                    Fatal->Publish(Exception);
                    return std::unexpected(
                        Prism::Fault::Failure{Prism::Fault::Code::Blocked});
                }
            }

            auto CompleteStopRequest(
                const std::expected<void, Prism::Fault::Failure> &Result) noexcept -> void
            {
                if (!Result)
                {
                    if (FailureValue.Succeeded() && !Exception)
                    {
                        FailureValue = Result.error();
                    }
                    return;
                }
            }

            auto CompleteMaintenance(std::exception_ptr ExceptionValue) -> void
            {
                Finished.store(true, std::memory_order_release);
                if (ExceptionValue)
                {
                    Storage->Retain(this->shared_from_this());
                    Exception = ExceptionValue;
                    Fatal->Publish(ExceptionValue);
                    CloseCompletion();
                    if (!ContextPin)
                    {
                        std::rethrow_exception(ExceptionValue);
                    }
                    return;
                }
                CloseCompletion();
                if (!Exception && FailureValue.Succeeded())
                {
                    Retired.store(true, std::memory_order_release);
                    Storage->Collect();
                }
            }

            auto CloseCompletion() noexcept -> void
            {
                try
                {
                    Completion.close();
                }
                catch (...)
                {
                    const auto Error = std::current_exception();
                    MarkUnavailable();
                    if (!Exception)
                    {
                        Exception = Error;
                    }
                    Fatal->Publish(Error);
                }
            }

            auto RequestRetirement() -> void override
            {
                (void)RequestStop();
            }

            [[nodiscard]] auto IsRetired() const noexcept -> bool override
            {
                return Retired.load(std::memory_order_acquire);
            }

            [[nodiscard]] auto IsDispatchUnavailable() const noexcept -> bool override
            {
                return StopStatus.load(std::memory_order_acquire) ==
                    StopRequestState::Unavailable;
            }

            /** @brief context 在 Shutdown/Storage 收尾前必须由此强 owner 保活。 */
            std::shared_ptr<Prism::Executor::ContextOwner> ContextPin;
            std::shared_ptr<Prism::Executor::FatalState> Fatal;
            std::shared_ptr<Prism::Executor::ClosingStorage> Storage;
            std::shared_ptr<Prism::Executor::ExecutorReclaimer> Reclaimer;
            Net::any_io_executor Executor;
            std::shared_ptr<State> StateObject;
            Signal Completion;
            std::atomic<StopRequestState> StopStatus{StopRequestState::Idle};
            std::atomic<bool> Finished{false};
            std::atomic<bool> Retired{false};
            Prism::Fault::Failure FailureValue;
            std::exception_ptr Exception;
        };

        [[nodiscard]] static auto ShutdownOnExecutor(std::shared_ptr<Control> Owner)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            const auto Requested = Owner->RequestStop();
            if (!Requested)
            {
                co_return std::unexpected(Requested.error());
            }
            if (!Owner->Finished.load(std::memory_order_acquire))
            {
                boost::system::error_code ErrorCode;
                co_await Owner->Completion.async_receive(
                    Net::redirect_error(Net::use_awaitable, ErrorCode));
                if (ErrorCode)
                {
                    if (ErrorCode != Net::experimental::error::channel_closed)
                    {
                        co_return std::unexpected(
                            Prism::Fault::FromNative(static_cast<std::error_code>(ErrorCode)));
                    }
                }
            }
            if (Owner->Exception && !Owner->ContextPin)
            {
                std::rethrow_exception(Owner->Exception);
            }
            if (Owner->FailureValue.Failed())
            {
                co_return std::unexpected(Owner->FailureValue);
            }
            if (!Owner->Finished.load(std::memory_order_acquire) ||
                !Owner->Retired.load(std::memory_order_acquire))
            {
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            }
            co_return std::expected<void, Prism::Fault::Failure>{};
        }

    public:
        MaintenanceOwner(Net::any_io_executor Executor, std::shared_ptr<State> StateValue)
            : Control_(std::make_shared<Control>(std::move(Executor), std::move(StateValue)))
        {
            Net::co_spawn(Control_->Executor, MaintenanceLoop(Control_->StateObject),
                CompletionDelivery<Control>(Control_));
        }

        ~MaintenanceOwner() noexcept
        {
            Control_->RequestRetirement();
        }

        MaintenanceOwner(const MaintenanceOwner &) = delete;
        auto operator=(const MaintenanceOwner &) -> MaintenanceOwner & = delete;

        /** @brief 排空解析调用后，在 resolver 原 executor 等待 maintenance 真实退栈。 */
        [[nodiscard]] auto Shutdown()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
            const auto Requested = Control_->RequestStop();
            if (!Requested)
            {
                co_return std::unexpected(Requested.error());
            }
            co_return co_await Net::co_spawn(
                Control_->Executor, ShutdownOnExecutor(Control_), Net::use_awaitable);
        }

    private:
        std::shared_ptr<Control> Control_;
    };

} // namespace Prism::Network::Dns::Detail
