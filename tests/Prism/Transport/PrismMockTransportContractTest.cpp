/**
 * @file PrismMockTransportContractTest.cpp
 * @brief Prism mock transport 的事件驱动契约测试
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

#include <Prism/Foundation/Error.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <TestSupport/Prism/PrismMockTransport.hpp>

namespace
{

    namespace Net = boost::asio;

    struct ReadState
    {
        std::array<std::byte, 4> Buffer{};
        Prism::Fault::Failure Error;
        std::size_t Bytes{0};
        bool Completed{false};
        std::exception_ptr Failure;
    };

    auto StartRead(Net::io_context &Ioc,
                   const std::shared_ptr<Prism::PrismMockTransport> &Transport,
                   ReadState &State) -> void
    {
        Net::co_spawn(
            Ioc,
            [Transport, &State]() -> Net::awaitable<void>
            {
                const auto Result = co_await Transport->ReadSome(State.Buffer); State.Bytes = Result.Bytes; State.Error = Result.Failure;
                State.Completed = true;
            },
            [&State](std::exception_ptr Failure) { State.Failure = std::move(Failure); });
    }

    TEST(PrismMockTransportContract, EmptyReadWakesOnInjectedData)
    {
        Net::io_context Ioc;
        auto Transport = std::make_shared<Prism::PrismMockTransport>(Ioc.get_executor());
        ReadState State;
        StartRead(Ioc, Transport, State);
        Net::post(Ioc, [Transport]
                  { Transport->InjectRead({0x11U, 0x22U, 0x33U}); });

        Ioc.run();

        ASSERT_FALSE(State.Failure);
        ASSERT_TRUE(State.Completed);
        EXPECT_EQ(State.Error.Code, Prism::Fault::Code::Success);
        EXPECT_EQ(State.Bytes, 3U);
        EXPECT_EQ(State.Buffer[0], std::byte{0x11});
        EXPECT_EQ(State.Buffer[2], std::byte{0x33});
    }

    TEST(PrismMockTransportContract, CloseWakesEmptyReadAsEof)
    {
        Net::io_context Ioc;
        auto Transport = std::make_shared<Prism::PrismMockTransport>(Ioc.get_executor());
        ReadState State;
        StartRead(Ioc, Transport, State);
        Net::post(Ioc, [Transport] { Transport->Close(); });

        Ioc.run();

        ASSERT_FALSE(State.Failure);
        ASSERT_TRUE(State.Completed);
        EXPECT_EQ(State.Bytes, 0U);
        EXPECT_EQ(State.Error.Code, Prism::Fault::Code::Eof);
        EXPECT_TRUE(Transport->IsClosed());
    }

    TEST(PrismMockTransportContract, CancelWakesEmptyReadWithCanceled)
    {
        Net::io_context Ioc;
        auto Transport = std::make_shared<Prism::PrismMockTransport>(Ioc.get_executor());
        ReadState State;
        StartRead(Ioc, Transport, State);
        Net::post(Ioc, [Transport] { Transport->Cancel(); });

        Ioc.run();

        ASSERT_FALSE(State.Failure);
        ASSERT_TRUE(State.Completed);
        EXPECT_EQ(State.Bytes, 0U);
        EXPECT_EQ(State.Error.Code, Prism::Fault::Code::Canceled);
    }

    TEST(PrismMockTransportContract, ShutdownPreservesWriteDirection)
    {
        Net::io_context Ioc;
        auto Transport = std::make_shared<Prism::PrismMockTransport>(Ioc.get_executor());
        Transport->InjectPeerEof();
        ReadState State;
        StartRead(Ioc, Transport, State);
        Prism::Fault::Failure WriteError;
        std::size_t Written = 0;
        Net::co_spawn(
            Ioc,
            [Transport, &WriteError, &Written]() -> Net::awaitable<void>
            {
                const std::array<std::byte, 2> Data{std::byte{0x41}, std::byte{0x42}};
                Written = ([&](Prism::IoResult Result) { WriteError = Result.Failure; return Result.Bytes; })(co_await Transport->WriteSome(Data));
            },
            Net::detached);

        Ioc.run();

        ASSERT_FALSE(State.Failure);
        ASSERT_TRUE(State.Completed);
        EXPECT_EQ(State.Bytes, 0U);
        EXPECT_EQ(State.Error.Code, Prism::Fault::Code::Eof);
        EXPECT_EQ(Written, 2U);
        EXPECT_TRUE(WriteError.Succeeded());
        EXPECT_TRUE(Transport->PeerEof());
    }

} // namespace
