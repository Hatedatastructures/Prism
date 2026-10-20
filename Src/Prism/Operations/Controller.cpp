/** @file Controller.cpp @brief 管理 HTTP 控制器启动与排空实现。 */
#include <Prism/Operations/Controller.hpp>

#include <Prism/Foundation/Fault/FailureState.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/error_code.hpp>
#include <boost/system/errc.hpp>
#include <boost/system/system_error.hpp>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <exception>
#include <memory>
#include <optional>
#include <system_error>
#include <thread>
#include <utility>

namespace Prism::Operations
{
    struct Controller::State final
    {
        using IoContext = Net::io_context;
        using WorkGuard = Net::executor_work_guard<IoContext::executor_type>;
        using DrainSignal = Net::experimental::concurrent_channel<
            void(boost::system::error_code, Controller::Deadline)>;

        explicit State(Controller::Options OptionsValue)
            : Configuration(std::move(OptionsValue)), Io(1), Work(Net::make_work_guard(Io)),
              OperationsRouter(Io.get_executor(), std::move(Configuration.Handlers),
                  Controller::MakeRouterOptions(Configuration)),
              Server(std::make_unique<HttpServer>(
                  Controller::MakeServerOptions(Io.get_executor(), Configuration, OperationsRouter)))
        {
        }

        Controller::Options Configuration;
        IoContext Io;
        WorkGuard Work;
        Router OperationsRouter;
        std::unique_ptr<HttpServer> Server;
        std::atomic<bool> StartAttempted{false};
        std::atomic<bool> ThreadStarted{false};
        std::atomic<bool> DrainStarted{false};
        std::atomic<bool> DrainSucceeded{false};
        std::atomic<bool> IoReturned{false};
        Prism::Fault::FailureState IoFailure;
        std::atomic<std::shared_ptr<DrainSignal>> IoExitWaiter;
    };

    Controller::Controller(Options OptionsValue)
        : State_(std::make_shared<State>(std::move(OptionsValue)))
    {
    }

    auto Controller::LocalEndpoint() const -> Endpoint
    {
        return State_->Server->LocalEndpoint();
    }

    auto Controller::Start() -> HttpServerStartResult
    {
        if (State_->StartAttempted.exchange(true, std::memory_order_acq_rel))
        {
            return std::unexpected(
                boost::system::errc::make_error_code(boost::system::errc::operation_in_progress));
        }

        std::optional<HttpServerStartResult> Result;
        std::exception_ptr Failure;
        Net::co_spawn(State_->Io, State_->Server->Start(),
            [&Result, &Failure](std::exception_ptr Exception, HttpServerStartResult Started)
            {
                Failure = std::move(Exception);
                if (!Failure) Result.emplace(std::move(Started));
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
            if (Result) return std::move(*Result);
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

    auto Controller::Drain(const Deadline Limit) -> Net::awaitable<DrainResult>
    {
        const auto StateValue = State_;
        if (!StateValue->ThreadStarted.load(std::memory_order_acquire))
            co_return DrainResult{Prism::Fault::Failure{Prism::Fault::Code::Blocked}, 0U};
        if (StateValue->DrainStarted.exchange(true, std::memory_order_acq_rel))
            co_return DrainResult{Prism::Fault::Failure{Prism::Fault::Code::Blocked}, 0U};

        const auto CallerExecutor = co_await Net::this_coro::executor;
        using Net::experimental::awaitable_operators::operator||;
        try
        {
            const auto Receipt = std::make_shared<State::DrainSignal>(CallerExecutor, 1U);
            StateValue->IoExitWaiter.store(Receipt, std::memory_order_release);
            auto Result = co_await Net::co_spawn(StateValue->Io.get_executor(),
                DrainOnManagementIo(StateValue, Limit), Net::use_awaitable);
            if (Result.Failure.Failed()) co_return Result;

            boost::system::error_code ReceiptError;
            const auto ExitRace = co_await (
                Receipt->async_receive(Net::redirect_error(Net::use_awaitable, ReceiptError)) ||
                WaitUntil(Limit));
            if (ExitRace.index() == 1U)
            {
                const auto Error = std::get<1>(ExitRace);
                if (Error)
                {
                    const auto Failure = StateValue->IoFailure.Load();
                    if (Failure.Failed()) Result.Failure = Failure;
                    else Result.Failure = Prism::Fault::FromNative(static_cast<std::error_code>(Error));
                }
                else
                {
                    Result.Failure = Prism::Fault::Failure{Prism::Fault::Code::Timeout,
                        std::make_error_code(std::errc::timed_out)};
                }
                co_return Result;
            }
            if (ReceiptError)
            {
                const auto Failure = StateValue->IoFailure.Load();
                if (Failure.Failed()) Result.Failure = Failure;
                else Result.Failure = Prism::Fault::FromNative(
                    static_cast<std::error_code>(ReceiptError));
                co_return Result;
            }

            const auto EventTime = std::get<0>(ExitRace);
            if (EventTime >= Limit)
            {
                Result.Failure = Prism::Fault::Failure{Prism::Fault::Code::Timeout,
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
                Result.Failure = Prism::Fault::Failure{Prism::Fault::Code::Blocked};
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

    auto Controller::Join() noexcept -> std::expected<void, Prism::Fault::Failure>
    {
        if (!State_->DrainSucceeded.load(std::memory_order_acquire) ||
            !State_->IoReturned.load(std::memory_order_acquire) || !ManagementThread_.joinable())
            return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        if (State_->IoFailure.Load().Failed())
            return std::unexpected(State_->IoFailure.Load());
        try
        {
            ManagementThread_.join();
        }
        catch (const std::system_error& Error)
        {
            return std::unexpected(Prism::Fault::FromNative(Error.code()));
        }
        catch (...)
        {
            return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        }
        return {};
    }

    auto Controller::MakeRouterOptions(const Options& OptionsValue) -> RouterOptions
    {
        RouterOptions Result;
        Result.Endpoint.Address = OptionsValue.BindEndpoint.address().to_string();
        Result.Endpoint.Port = OptionsValue.BindEndpoint.port();
        Result.MaxOperations = OptionsValue.MaxOperations;
        return Result;
    }

    auto Controller::MakeServerOptions(Net::any_io_executor Executor,
        const Options& OptionsValue, const Router& OperationsRouter) -> HttpServer::Options
    {
        return HttpServer::Options{std::move(Executor), OptionsValue.BindEndpoint, OperationsRouter,
            OptionsValue.ReadDeadline, OptionsValue.DrainTimeout, OptionsValue.Bootstrap,
            OptionsValue.WebResources};
    }

    auto Controller::RecordIoFailure(State& StateValue, Prism::Fault::Failure Failure) noexcept -> void
    {
        (void)StateValue.IoFailure.TrySet(Failure);
    }

    auto Controller::RunManagementIo(const std::shared_ptr<State>& StateValue) noexcept -> void
    {
        while (true)
        {
            try
            {
                if (StateValue->Io.run() == 0U) break;
            }
            catch (const boost::system::system_error& Error)
            {
                RecordIoFailure(*StateValue,
                    Prism::Fault::FromNative(static_cast<std::error_code>(Error.code())));
                StateValue->Io.restart();
            }
            catch (const std::system_error& Error)
            {
                RecordIoFailure(*StateValue, Prism::Fault::FromNative(Error.code()));
                StateValue->Io.restart();
            }
            catch (...)
            {
                RecordIoFailure(*StateValue, Prism::Fault::Failure{Prism::Fault::Code::Blocked});
                StateValue->Io.restart();
            }
        }
        StateValue->IoReturned.store(true, std::memory_order_release);
        PublishIoExit(StateValue);
    }

    auto Controller::FailureFromException(const std::exception_ptr& Exception) noexcept
        -> Prism::Fault::Failure
    {
        if (!Exception) return Prism::Fault::Failure{Prism::Fault::Code::Blocked};
        try
        {
            std::rethrow_exception(Exception);
        }
        catch (const boost::system::system_error& Error)
        {
            return Prism::Fault::FromNative(static_cast<std::error_code>(Error.code()));
        }
        catch (const std::system_error& Error)
        {
            return Prism::Fault::FromNative(Error.code());
        }
        catch (...)
        {
            return Prism::Fault::Failure{Prism::Fault::Code::Blocked};
        }
    }

    auto Controller::WaitUntil(const Deadline Limit) -> Net::awaitable<boost::system::error_code>
    {
        const auto Executor = co_await Net::this_coro::executor;
        Net::steady_timer Timer(Executor);
        Timer.expires_at(Limit);
        boost::system::error_code Error;
        co_await Timer.async_wait(Net::redirect_error(Net::use_awaitable, Error));
        co_return Error;
    }

    auto Controller::DrainOnManagementIo(const std::shared_ptr<State>& StateValue,
        const Deadline Limit) -> Net::awaitable<DrainResult>
    {
        auto Result = co_await StateValue->Server->Drain(Limit);
        if (!Result.Failure.Failed())
        {
            if (StateValue->IoFailure.Load().Failed()) Result.Failure = StateValue->IoFailure.Load();
            else StateValue->Work.reset();
        }
        co_return Result;
    }

    auto Controller::PublishIoExit(const std::shared_ptr<State>& StateValue) noexcept -> void
    {
        const auto Receipt = StateValue->IoExitWaiter.load(std::memory_order_acquire);
        if (!Receipt) return;
        try
        {
            if (!Receipt->try_send(boost::system::error_code{}, std::chrono::steady_clock::now()))
            {
                RecordIoFailure(*StateValue, Prism::Fault::Failure{Prism::Fault::Code::Blocked});
                Receipt->close();
            }
        }
        catch (const boost::system::system_error& Error)
        {
            RecordIoFailure(*StateValue,
                Prism::Fault::FromNative(static_cast<std::error_code>(Error.code())));
            Receipt->close();
        }
        catch (const std::system_error& Error)
        {
            RecordIoFailure(*StateValue, Prism::Fault::FromNative(Error.code()));
            Receipt->close();
        }
        catch (...)
        {
            RecordIoFailure(*StateValue, Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            Receipt->close();
        }
    }

    auto Controller::CloseFailedStart(const std::shared_ptr<State>& StateValue) noexcept -> void
    {
        try
        {
            const auto Closed = StateValue->Server->CloseAdmission();
            if (!Closed) RecordIoFailure(*StateValue, Closed.error());
            StateValue->Io.restart();
            while (StateValue->Io.poll() != 0U) {}
        }
        catch (const boost::system::system_error& Error)
        {
            RecordIoFailure(*StateValue,
                Prism::Fault::FromNative(static_cast<std::error_code>(Error.code())));
        }
        catch (const std::system_error& Error)
        {
            RecordIoFailure(*StateValue, Prism::Fault::FromNative(Error.code()));
        }
        catch (...)
        {
            RecordIoFailure(*StateValue, Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        }
        StateValue->Work.reset();
    }
} // namespace Prism::Operations
