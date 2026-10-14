/**
 * @file Controller.hpp
 * @brief Operations 管理面的独立 io_context、线程、Router 与 HTTP server owner。
 */

#pragma once

#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Foundation/Fault/FailureState.hpp>
#include <Preview/Operations/HttpServer.hpp>
#include <Preview/Operations/Router.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/system_error.hpp>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <exception>
#include <expected>
#include <memory>
#include <optional>
#include <system_error>
#include <thread>
#include <utility>
#include <variant>

namespace Preview::Operations
{

    namespace Net = boost::asio;

    /**
     * @class Controller
     * @brief 独立拥有管理查询路由、HTTP listener 与管理线程的进程级控制器。
     * @details Start 只在 Application 冷启动路径同步执行；Drain 在调用方 executor
     *          提交到管理 io_context，并以原始绝对 deadline 等待 HTTP 响应退栈。
     *          只有 Drain 成功且管理 io.run 自然返回后才允许 Join。
     */
    class Controller final
    {
    public:
        using Endpoint = HttpServer::Endpoint;
        using Deadline = HttpServer::Deadline;
        using StartResult = HttpServer::StartResult;
        using DrainResult = HttpServer::DrainResult;

        struct Options final
        {
            Endpoint BindEndpoint{Net::ip::address_v4::loopback(), 9090};
            RouterHandlers Handlers{};
            std::size_t MaxOperations{1024};
            std::chrono::milliseconds ReadDeadline{std::chrono::milliseconds{5000}};
            std::chrono::milliseconds DrainTimeout{std::chrono::milliseconds{5000}};
            std::shared_ptr<const BootstrapIdentity> Bootstrap;
            std::shared_ptr<const Web::Catalog> WebResources;
        };

        explicit Controller(Options OptionsValue) : State_(std::make_shared<State>(std::move(OptionsValue)))
        {
        }

        ~Controller() noexcept = default;

        Controller(const Controller&) = delete;
        auto operator=(const Controller&) -> Controller& = delete;
        Controller(Controller&&) = delete;
        auto operator=(Controller&&) -> Controller& = delete;

        /**
         * @brief 冷启动时绑定 HTTP endpoint 并启动独立管理线程。
         * @details 只由非协程 Application::Start 调用；返回实际绑定端点或 listener 错误。
         *          启动协程在管理 io_context 上完成，不借用应用 control executor。
         */
        [[nodiscard]] auto Start() -> StartResult
        {
            if (State_->StartAttempted.exchange(true, std::memory_order_acq_rel))
            {
                return std::unexpected(
                    boost::system::errc::make_error_code(boost::system::errc::operation_in_progress));
            }

            std::optional<StartResult> Result;
            std::exception_ptr Failure;
            Net::co_spawn(State_->Io, State_->Server->Start(),
                [&Result, &Failure](std::exception_ptr Exception, StartResult Started)
                {
                    Failure = std::move(Exception);
                    if (!Failure)
                    {
                        Result.emplace(std::move(Started));
                    }
                });

            while (!Result && !Failure)
            {
                if (State_->Io.run_one() == 0U)
                {
                    State_->Io.restart();
                    if (State_->Io.run_one() == 0U)
                    {
                        State_->Work.reset();
                        return std::unexpected(
                            boost::system::errc::make_error_code(boost::system::errc::operation_canceled));
                    }
                }
            }
            if (Failure)
            {
                State_->Work.reset();
                std::rethrow_exception(Failure);
            }
            if (!Result || !*Result)
            {
                State_->Work.reset();
                if (Result)
                {
                    return std::move(*Result);
                }
                return std::unexpected(
                    boost::system::errc::make_error_code(boost::system::errc::operation_canceled));
            }

            try
            {
                const auto StateValue = State_;
                ManagementThread_ = std::thread([StateValue] { RunManagementIo(StateValue); });
                State_->ThreadStarted.store(true, std::memory_order_release);
            }
            catch (...)
            {
                CloseFailedStart(State_);
                throw;
            }
            return std::move(*Result);
        }

        /**
         * @brief 封闭 HTTP 准入并按绝对 deadline 等待活动响应完整退栈。
         * @param Limit 调用方提供的同一停机绝对期限，不在此处延长。
         * @return listener 的真实 drain 失败和剩余连接数。
         */
        [[nodiscard]] auto Drain(const Deadline Limit) -> Net::awaitable<DrainResult>
        {
            const auto StateValue = State_;
            if (!StateValue->ThreadStarted.load(std::memory_order_acquire))
            {
                co_return DrainResult{Preview::Fault::Failure{Preview::Fault::Code::Blocked}, 0U};
            }
            if (StateValue->DrainStarted.exchange(true, std::memory_order_acq_rel))
            {
                co_return DrainResult{Preview::Fault::Failure{Preview::Fault::Code::Blocked}, 0U};
            }

            const auto CallerExecutor = co_await Net::this_coro::executor;
            using Net::experimental::awaitable_operators::operator||;
            try
            {
                const auto Receipt = std::make_shared<DrainSignal>(CallerExecutor, 1U);
                StateValue->IoExitWaiter.store(Receipt, std::memory_order_release);
                auto Result = co_await Net::co_spawn(StateValue->Io.get_executor(),
                    DrainOnManagementIo(StateValue, Limit), Net::use_awaitable);
                if (Result.Failure.Failed())
                {
                    co_return Result;
                }

                boost::system::error_code ReceiptError;
                const auto ExitRace =
                    co_await (Receipt->async_receive(Net::redirect_error(Net::use_awaitable, ReceiptError)) ||
                        WaitUntil(Limit));
                if (ExitRace.index() == 1U)
                {
                    const auto Error = std::get<1>(ExitRace);
                    if (Error)
                    {
                        const auto Failure = StateValue->IoFailure.Load();
                        if (Failure.Failed())
                        {
                            Result.Failure = Failure;
                        }
                        else
                        {
                            Result.Failure = Preview::Fault::FromNative(static_cast<std::error_code>(Error));
                        }
                    }
                    else
                    {
                        Result.Failure = Preview::Fault::Failure{Preview::Fault::Code::Timeout,
                            std::make_error_code(std::errc::timed_out)};
                    }
                    co_return Result;
                }
                if (ReceiptError)
                {
                    const auto Failure = StateValue->IoFailure.Load();
                    if (Failure.Failed())
                    {
                        Result.Failure = Failure;
                    }
                    else
                    {
                        Result.Failure =
                            Preview::Fault::FromNative(static_cast<std::error_code>(ReceiptError));
                    }
                    co_return Result;
                }

                const auto EventTime = std::get<0>(ExitRace);
                if (EventTime >= Limit)
                {
                    Result.Failure = Preview::Fault::Failure{Preview::Fault::Code::Timeout,
                        std::make_error_code(std::errc::timed_out)};
                    co_return Result;
                }
                if (StateValue->IoFailure.Load().Failed())
                {
                    Result.Failure = StateValue->IoFailure.Load();
                    co_return Result;
                }
                if (!StateValue->IoReturned.load(std::memory_order_acquire))
                {
                    Result.Failure = Preview::Fault::Failure{Preview::Fault::Code::Blocked};
                    co_return Result;
                }
                StateValue->DrainSucceeded.store(true, std::memory_order_release);
                co_return Result;
            }
            catch (...)
            {
                co_return DrainResult{FailureFromException(std::current_exception()), 0U};
            }
        }
        /**
         * @brief 在 Application::Run 返回后回收已自然结束的管理线程。
         * @details 不等待仍在运行的 io.run；调用顺序要求先成功 Drain，且 run 已自然返回。
         */
        [[nodiscard]] auto Join() noexcept -> std::expected<void, Preview::Fault::Failure>
        {
            if (!State_->DrainSucceeded.load(std::memory_order_acquire) ||
                !State_->IoReturned.load(std::memory_order_acquire) || !ManagementThread_.joinable())
            {
                return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::Blocked});
            }
            if (State_->IoFailure.Load().Failed())
            {
                return std::unexpected(State_->IoFailure.Load());
            }
            try
            {
                ManagementThread_.join();
            }
            catch (const std::system_error& Error)
            {
                return std::unexpected(Preview::Fault::FromNative(Error.code()));
            }
            catch (...)
            {
                return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::Blocked});
            }
            return {};
        }

        /** @brief 返回 Start 成功绑定的管理端点值。 */
        [[nodiscard]] auto LocalEndpoint() const -> Endpoint
        {
            return State_->Server->LocalEndpoint();
        }

    private:
        using IoContext = Net::io_context;
        using WorkGuard = Net::executor_work_guard<IoContext::executor_type>;
        using DrainSignal = Net::experimental::concurrent_channel<void(boost::system::error_code, Deadline)>;

        struct State final
        {
            explicit State(Options OptionsValue)
                : Configuration(std::move(OptionsValue)), Io(1), Work(Net::make_work_guard(Io)),
                  OperationsRouter(Io.get_executor(), std::move(Configuration.Handlers),
                      MakeRouterOptions(Configuration)),
                  Server(std::make_unique<HttpServer>(
                      MakeServerOptions(Io.get_executor(), Configuration, OperationsRouter)))
            {
            }

            Options Configuration;
            IoContext Io;
            WorkGuard Work;
            Router OperationsRouter;
            std::unique_ptr<HttpServer> Server;
            std::atomic<bool> StartAttempted{false};
            std::atomic<bool> ThreadStarted{false};
            std::atomic<bool> DrainStarted{false};
            std::atomic<bool> DrainSucceeded{false};
            std::atomic<bool> IoReturned{false};
            Preview::Fault::FailureState IoFailure;
            std::atomic<std::shared_ptr<DrainSignal>> IoExitWaiter;
        };

        [[nodiscard]] static auto MakeRouterOptions(const Options& OptionsValue) -> RouterOptions
        {
            RouterOptions Result;
            Result.Endpoint.Address = OptionsValue.BindEndpoint.address().to_string();
            Result.Endpoint.Port = OptionsValue.BindEndpoint.port();
            Result.MaxOperations = OptionsValue.MaxOperations;
            return Result;
        }

        [[nodiscard]] static auto MakeServerOptions(Net::any_io_executor Executor,
            const Options& OptionsValue, const Router& OperationsRouter) -> HttpServer::Options
        {
            return HttpServer::Options{std::move(Executor), OptionsValue.BindEndpoint, OperationsRouter,
                OptionsValue.ReadDeadline, OptionsValue.DrainTimeout, OptionsValue.Bootstrap,
                OptionsValue.WebResources};
        }

        static auto RecordIoFailure(State& StateValue, Preview::Fault::Failure Failure) noexcept -> void
        {
            (void)StateValue.IoFailure.TrySet(Failure);
        }

        static auto RunManagementIo(const std::shared_ptr<State>& StateValue) noexcept -> void
        {
            while (true)
            {
                try
                {
                    if (StateValue->Io.run() == 0U)
                    {
                        break;
                    }
                }
                catch (const boost::system::system_error& Error)
                {
                    RecordIoFailure(*StateValue,
                        Preview::Fault::FromNative(static_cast<std::error_code>(Error.code())));
                    StateValue->Io.restart();
                }
                catch (const std::system_error& Error)
                {
                    RecordIoFailure(*StateValue, Preview::Fault::FromNative(Error.code()));
                    StateValue->Io.restart();
                }
                catch (...)
                {
                    RecordIoFailure(*StateValue, Preview::Fault::Failure{Preview::Fault::Code::Blocked});
                    StateValue->Io.restart();
                }
            }
            StateValue->IoReturned.store(true, std::memory_order_release);
            PublishIoExit(StateValue);
        }

        [[nodiscard]] static auto FailureFromException(const std::exception_ptr& Exception) noexcept
            -> Preview::Fault::Failure
        {
            if (!Exception)
            {
                return Preview::Fault::Failure{Preview::Fault::Code::Blocked};
            }
            try
            {
                std::rethrow_exception(Exception);
            }
            catch (const boost::system::system_error& Error)
            {
                return Preview::Fault::FromNative(static_cast<std::error_code>(Error.code()));
            }
            catch (const std::system_error& Error)
            {
                return Preview::Fault::FromNative(Error.code());
            }
            catch (...)
            {
                return Preview::Fault::Failure{Preview::Fault::Code::Blocked};
            }
        }

        [[nodiscard]] static auto WaitUntil(const Deadline Limit) -> Net::awaitable<boost::system::error_code>
        {
            const auto Executor = co_await Net::this_coro::executor;
            Net::steady_timer Timer(Executor);
            Timer.expires_at(Limit);
            boost::system::error_code Error;
            co_await Timer.async_wait(Net::redirect_error(Net::use_awaitable, Error));
            co_return Error;
        }
        [[nodiscard]] static auto DrainOnManagementIo(const std::shared_ptr<State>& StateValue,
            const Deadline Limit) -> Net::awaitable<DrainResult>
        {
            auto Result = co_await StateValue->Server->Drain(Limit);
            if (!Result.Failure.Failed())
            {
                if (StateValue->IoFailure.Load().Failed())
                {
                    Result.Failure = StateValue->IoFailure.Load();
                }
                else
                {
                    StateValue->Work.reset();
                }
            }
            co_return Result;
        }

        static auto PublishIoExit(const std::shared_ptr<State>& StateValue) noexcept -> void
        {
            const auto Receipt = StateValue->IoExitWaiter.load(std::memory_order_acquire);
            if (!Receipt)
            {
                return;
            }
            try
            {
                if (!Receipt->try_send(boost::system::error_code{}, std::chrono::steady_clock::now()))
                {
                    RecordIoFailure(*StateValue, Preview::Fault::Failure{Preview::Fault::Code::Blocked});
                    Receipt->close();
                }
            }
            catch (const boost::system::system_error& Error)
            {
                RecordIoFailure(*StateValue,
                    Preview::Fault::FromNative(static_cast<std::error_code>(Error.code())));
                Receipt->close();
            }
            catch (const std::system_error& Error)
            {
                RecordIoFailure(*StateValue, Preview::Fault::FromNative(Error.code()));
                Receipt->close();
            }
            catch (...)
            {
                RecordIoFailure(*StateValue, Preview::Fault::Failure{Preview::Fault::Code::Blocked});
                Receipt->close();
            }
        }

        static auto CloseFailedStart(const std::shared_ptr<State>& StateValue) noexcept -> void
        {
            try
            {
                const auto Closed = StateValue->Server->CloseAdmission();
                if (!Closed)
                {
                    RecordIoFailure(*StateValue, Closed.error());
                }
                StateValue->Io.restart();
                while (StateValue->Io.poll() != 0U)
                {
                }
            }
            catch (const boost::system::system_error& Error)
            {
                RecordIoFailure(*StateValue,
                    Preview::Fault::FromNative(static_cast<std::error_code>(Error.code())));
            }
            catch (const std::system_error& Error)
            {
                RecordIoFailure(*StateValue, Preview::Fault::FromNative(Error.code()));
            }
            catch (...)
            {
                RecordIoFailure(*StateValue, Preview::Fault::Failure{Preview::Fault::Code::Blocked});
            }
            StateValue->Work.reset();
        }

        std::shared_ptr<State> State_;
        std::thread ManagementThread_;
    };

} // namespace Preview::Operations
