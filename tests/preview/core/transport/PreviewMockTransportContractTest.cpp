/**
 * @file PreviewMockTransportContractTest.cpp
 * @brief Preview mock transport 的事件驱动契约测试
 * @details 验证空读不会通过定时器轮询推进，而是由外部执行器上的
 *          注入、关闭、取消或半关闭事件唤醒。
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>

#include <array>
#include <exception>
#include <memory>
#include <system_error>

#include <preview/Foundation/Error.hpp>
#include <preview/Transport/Transmission.hpp>
#include <TestSupport/Preview/PreviewMockTransport.hpp>

namespace
{

    namespace net = boost::asio;

    struct ReadState
    {
        std::array<std::byte, 4> Buffer{};
        std::error_code Error;
        std::size_t Bytes{0};
        bool Completed{false};
        std::exception_ptr Failure;
    };

    auto StartRead(net::io_context &Ioc,
                   const std::shared_ptr<Preview::PreviewMockTransport> &Transport,
                   ReadState &State) -> void
    {
        net::co_spawn(
            Ioc,
            [Transport, &State]() -> net::awaitable<void>
            {
                State.Bytes = co_await Transport->async_read_some(State.Buffer, State.Error);
                State.Completed = true;
            },
            [&State](std::exception_ptr Failure) { State.Failure = std::move(Failure); });
    }

    TEST(PreviewMockTransportContract, EmptyReadWakesOnInjectedData)
    {
        net::io_context Ioc;
        auto Transport = std::make_shared<Preview::PreviewMockTransport>(Ioc.get_executor());
        ReadState State;
        StartRead(Ioc, Transport, State);
        net::post(Ioc, [Transport]
                  { Transport->InjectRead({0x11U, 0x22U, 0x33U}); });

        Ioc.run();

        ASSERT_FALSE(State.Failure);
        ASSERT_TRUE(State.Completed);
        EXPECT_EQ(State.Error, std::error_code{});
        EXPECT_EQ(State.Bytes, 3U);
        EXPECT_EQ(State.Buffer[0], std::byte{0x11});
        EXPECT_EQ(State.Buffer[2], std::byte{0x33});
    }

    TEST(PreviewMockTransportContract, CloseWakesEmptyReadAsEof)
    {
        net::io_context Ioc;
        auto Transport = std::make_shared<Preview::PreviewMockTransport>(Ioc.get_executor());
        ReadState State;
        StartRead(Ioc, Transport, State);
        net::post(Ioc, [Transport] { Transport->Close(); });

        Ioc.run();

        ASSERT_FALSE(State.Failure);
        ASSERT_TRUE(State.Completed);
        EXPECT_EQ(State.Bytes, 0U);
        EXPECT_EQ(State.Error, std::error_code{});
        EXPECT_TRUE(Transport->IsClosed());
    }

    TEST(PreviewMockTransportContract, CancelWakesEmptyReadWithCanceled)
    {
        net::io_context Ioc;
        auto Transport = std::make_shared<Preview::PreviewMockTransport>(Ioc.get_executor());
        ReadState State;
        StartRead(Ioc, Transport, State);
        net::post(Ioc, [Transport] { Transport->Cancel(); });

        Ioc.run();

        ASSERT_FALSE(State.Failure);
        ASSERT_TRUE(State.Completed);
        EXPECT_EQ(State.Bytes, 0U);
        EXPECT_EQ(State.Error, Preview::make_error_code(Preview::Error::Canceled));
    }

    TEST(PreviewMockTransportContract, ShutdownPreservesWriteDirection)
    {
        net::io_context Ioc;
        auto Transport = std::make_shared<Preview::PreviewMockTransport>(Ioc.get_executor());
        Transport->Shutdown();
        ReadState State;
        StartRead(Ioc, Transport, State);
        std::error_code WriteError;
        std::size_t Written = 0;
        net::co_spawn(
            Ioc,
            [Transport, &WriteError, &Written]() -> net::awaitable<void>
            {
                const std::array<std::byte, 2> Data{std::byte{0x41}, std::byte{0x42}};
                Written = co_await Transport->async_write_some(Data, WriteError);
            },
            net::detached);

        Ioc.run();

        ASSERT_FALSE(State.Failure);
        ASSERT_TRUE(State.Completed);
        EXPECT_EQ(State.Bytes, 0U);
        EXPECT_EQ(State.Error, std::error_code{});
        EXPECT_EQ(Written, 2U);
        EXPECT_EQ(WriteError, std::error_code{});
        EXPECT_TRUE(Transport->IsShutdown());
    }

} // namespace
