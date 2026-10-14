/**
 * @file SessionLifecycleTestSupport.hpp
 * @brief SessionLifecycleTest.cpp 拆分后的模块共享测试夹具与构造辅助。
 */
#pragma once

/**
 * @file SessionLifecycleTest.cpp
 * @brief Preview 会话所有权、取消与排空契约测试
 * @details 覆盖 owner-held 资源、取消竞态、异常收口、非合作操作和
 *          listener/controller 的两阶段停机边界。
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/bind_cancellation_slot.hpp>
#include <boost/asio/cancellation_signal.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <future>
#include <memory>
#include <string_view>
#include <stdexcept>
#include <string>
#include <thread>

#include <Preview/Foundation/Utility/Diagnose/Facade.hpp>
#include <Preview/Foundation/Fault/Code.hpp>
#include <Preview/Foundation/Utility/TrafficSink.hpp>
#include <Preview/Account/Account.hpp>
#include <Preview/Net/Dialer/Dialer.hpp>
#include <Preview/Contract/Ingress/DataPlane.hpp>
#include <Preview/Runtime/Listener.hpp>
#include <Preview/Runtime/Session.hpp>
#include <Preview/Runtime/SessionControl.hpp>
#include <Preview/Runtime/SessionRegistry.hpp>
#include <Preview/Runtime/Recognition/Profile.hpp>
#include <Preview/Transport/MemoryStream.hpp>
#include <Preview/Transport/Transmission.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>
#include <TestSupport/Fixtures/StreamFactory.hpp>
#include <TestSupport/Preview/ProviderBindings.hpp>

namespace
{

    namespace Net = boost::asio;
    using ByteChannel = Net::experimental::channel<void(boost::system::error_code)>;
    using ConcurrentSignal =
        Net::experimental::concurrent_channel<void(boost::system::error_code)>;
    using Preview::Testing::RunCoro;

    auto MakeReleaseChannel(Net::any_io_executor Executor) -> std::shared_ptr<ByteChannel>
    {
        return std::make_shared<ByteChannel>(std::move(Executor), 1);
    }

    auto MakeConcurrentSignal(Net::any_io_executor Executor)
        -> std::shared_ptr<ConcurrentSignal>
    {
        return std::make_shared<ConcurrentSignal>(std::move(Executor), 1);
    }

    auto WaitForRelease(const std::shared_ptr<ByteChannel> &Release) -> Net::awaitable<void>
    {
        boost::system::error_code ErrorCode;
        co_await Release->async_receive(Net::redirect_error(Net::use_awaitable, ErrorCode));
    }

    auto WaitForReleaseAndMark(const std::shared_ptr<ByteChannel> &Release,
                               const std::shared_ptr<bool> &Completed) -> Net::awaitable<void>
    {
        co_await WaitForRelease(Release);
        *Completed = true;
    }

    template <typename Signal>
    auto WaitForSignalOrTimeout(const std::shared_ptr<Signal> &SignalValue,
                                Net::io_context &Ioc) -> Net::awaitable<bool>
    {
        Net::steady_timer Timer(Ioc);
        Timer.expires_after(std::chrono::seconds(1));
        using Net::experimental::awaitable_operators::operator||;
        boost::system::error_code ErrorCode;
        auto Race = co_await (SignalValue->async_receive(
                                  Net::redirect_error(Net::use_awaitable, ErrorCode)) ||
                              Timer.async_wait(Net::use_awaitable));
        co_return Race.index() == 0U;
    }

    auto MakeInfo(std::uint64_t Id) -> Preview::Runtime::SessionInfo
    {
        Preview::Runtime::SessionInfo Info;
        Info.Id = Id;
        Info.identity = "user-" + std::to_string(Id);
        Info.peer = "127.0.0.1";
        Info.Target = "example.test:443";
        Info.Protocol = 1;
        return Info;
    }

    auto CheckCurrentIdentity(const std::shared_ptr<Preview::Runtime::SessionControl> &Control,
                              Preview::Lifecycle::TaskIdentity Expected) -> Net::awaitable<void>
    {
        const auto Current = Control->CurrentIdentity();
        EXPECT_EQ(Current.SessionId, Expected.SessionId);
        EXPECT_EQ(Current.WorkerId, Expected.WorkerId);
        EXPECT_TRUE(static_cast<bool>(Current.TaskId));
        co_return;
    }

    class OwnedTrafficSink final : public Preview::Foundation::TrafficSink
    {
    public:
        void Report(Preview::Foundation::TrafficEvent) noexcept override {}
        auto Retire(Preview::Foundation::TrafficRetirement Owner)
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>> override
        { (void)Owner; co_return std::expected<void, Preview::Fault::Failure>{}; }
    };






















} // namespace


