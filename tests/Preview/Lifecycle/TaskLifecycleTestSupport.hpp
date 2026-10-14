/**
 * @file TaskLifecycleTestSupport.hpp
 * @brief TaskLifecycle.cpp 拆分后的模块共享测试夹具与构造辅助。
 */
#pragma once

/**
 * @file TaskLifecycle.cpp
 * @brief Preview 生命周期原语的确定性契约测试
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

#include <Preview/Lifecycle/CancellationDomain.hpp>
#include <Preview/Lifecycle/TaskRegistry.hpp>
#include <Preview/Foundation/Identifier/Id.hpp>
#include <Preview/Foundation/Executor/ExecutorReclaimer.hpp>
#include <Preview/Runtime/Listener.hpp>
#include <Preview/Runtime/SessionControl.hpp>
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

    auto Identity(Preview::TaskId TaskValue = Preview::TaskId{41}) -> Preview::Lifecycle::TaskIdentity
    {
        return Preview::Lifecycle::TaskIdentity{
            TaskValue,
            Preview::SessionId{7},
            Preview::StreamId{9},
            Preview::WorkerId{11},
            Preview::GenerationId{13}};
    }

    auto Request(Preview::Lifecycle::TaskIdentity IdentityValue,
                 Preview::Lifecycle::TaskCancelFn Cancel = {})
        -> Preview::Lifecycle::TaskRequest
    {
        return Preview::Lifecycle::TaskRequest{
            Preview::Lifecycle::TaskContext{
                IdentityValue.SessionId,
                IdentityValue.StreamId,
                IdentityValue.WorkerId,
                IdentityValue.Generation,
                {}},
            std::move(Cancel)};
    }

    auto RunDrain(Net::io_context &Ioc,
                  Net::awaitable<std::expected<void, Preview::Fault::Failure>> Operation)
        -> std::expected<void, Preview::Fault::Failure>
    {
        std::expected<void, Preview::Fault::Failure> Result;
        std::exception_ptr Failure;
        Net::co_spawn(
            Ioc,
            [Operation = std::move(Operation), &Result]() mutable -> Net::awaitable<void>
            {
                Result = co_await std::move(Operation);
            },
            [&Failure](std::exception_ptr Error) { Failure = std::move(Error); });
        Ioc.run();
        if (Failure) return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::IoError});
        return Result;
    }
































} // namespace

