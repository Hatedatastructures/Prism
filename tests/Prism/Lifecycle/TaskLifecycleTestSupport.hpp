/**
 * @file TaskLifecycleTestSupport.hpp
 * @brief TaskLifecycle.cpp 拆分后的模块共享测试夹具与构造辅助。
 */
#pragma once

/**
 * @file TaskLifecycle.cpp
 * @brief Prism 生命周期原语的确定性契约测试
 * @details 这些测试不依赖固定 grace 时间；所有收口都由明确的事件和计数推进。
 */

#include <gtest/gtest.h>

#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <atomic>
#include <barrier>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <expected>
#include <future>
#include <iterator>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <Prism/Lifecycle/CancellationDomain.hpp>
#include <Prism/Lifecycle/TaskRegistry.hpp>
#include <Prism/Foundation/Identifier/Id.hpp>
#include <Prism/Foundation/Executor/ExecutorReclaimer.hpp>
#include <Prism/Runtime/Listener.hpp>
#include <Prism/Runtime/SessionControl.hpp>
#include "TaskHandleTestAccess.hpp"

namespace
{

    namespace Net = boost::asio;
    using Signal = Net::experimental::concurrent_channel<void(boost::system::error_code)>;

    auto WaitForSignal(std::shared_ptr<Signal> Ready) -> Net::awaitable<void>
    {
        boost::system::error_code ErrorCode;
        co_await Ready->async_receive(Net::redirect_error(Net::use_awaitable, ErrorCode));
    }

    auto WaitForSignalAndMark(std::shared_ptr<Signal> Ready,
                              std::shared_ptr<std::atomic<bool>> Started,
                              std::shared_ptr<std::atomic<bool>> Completed) -> Net::awaitable<void>
    {
        Started->store(true, std::memory_order_release);
        Started->notify_all();
        co_await WaitForSignal(std::move(Ready));
        Completed->store(true, std::memory_order_release);
        Completed->notify_all();
    }

    auto SetFlag(std::shared_ptr<std::atomic<bool>> Flag) -> Net::awaitable<void>
    {
        Flag->store(true, std::memory_order_release);
        co_return;
    }

    auto RunCoro(Net::io_context &Ioc, Net::awaitable<void> Operation) -> std::exception_ptr
    {
        std::exception_ptr Failure;
        Net::co_spawn(
            Ioc,
            std::move(Operation),
            [&Failure](std::exception_ptr Error) { Failure = std::move(Error); });
        Ioc.run();
        return Failure;
    }

    auto Identity(Prism::TaskId TaskValue = Prism::TaskId{41}) -> Prism::Lifecycle::TaskIdentity
    {
        return Prism::Lifecycle::TaskIdentity{
            TaskValue,
            Prism::SessionId{7},
            Prism::StreamId{9},
            Prism::WorkerId{11},
            Prism::GenerationId{13}};
    }

    auto Request(Prism::Lifecycle::TaskIdentity IdentityValue,
                 Prism::Lifecycle::TaskCancelFn Cancel = {})
        -> Prism::Lifecycle::TaskRequest
    {
        return Prism::Lifecycle::TaskRequest{
            Prism::Lifecycle::TaskContext{
                IdentityValue.SessionId,
                IdentityValue.StreamId,
                IdentityValue.WorkerId,
                IdentityValue.Generation,
                {}},
            std::move(Cancel)};
    }

    auto RunDrain(Net::io_context &Ioc,
                  Net::awaitable<std::expected<void, Prism::Fault::Failure>> Operation)
        -> std::expected<void, Prism::Fault::Failure>
    {
        std::expected<void, Prism::Fault::Failure> Result;
        std::exception_ptr Failure;
        Net::co_spawn(
            Ioc,
            [Operation = std::move(Operation), &Result]() mutable -> Net::awaitable<void>
            {
                Result = co_await std::move(Operation);
            },
            [&Failure](std::exception_ptr Error) { Failure = std::move(Error); });
        Ioc.run();
        if (Failure) return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::IoError});
        return Result;
    }
































} // namespace
