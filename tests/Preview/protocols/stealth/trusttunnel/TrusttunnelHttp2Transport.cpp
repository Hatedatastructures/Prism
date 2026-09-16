/**
 * @file TrusttunnelHttp2Transport.cpp
 * @brief TrustTunnel 标准 HTTP/2 transport 的队列与 EOF 边界测试
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <memory>
#include <string>
#include <vector>

#include <Preview/Protocols/Trusttunnel/Http2.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    namespace Trusttunnel = Preview::Trusttunnel;

    template <typename Awaitable>
    auto RunCoro(
        Net::io_context &IoContext,
        Awaitable Operation) -> void
    {
        std::exception_ptr Failure;
        auto Completion = [&](std::exception_ptr ErrorValue) -> void
        {
            Failure = std::move(ErrorValue);
            IoContext.stop();
        };
        Net::co_spawn(IoContext, std::move(Operation), std::move(Completion));
        IoContext.run();
        if (Failure)
        {
            std::rethrow_exception(Failure);
        }
    }

    TEST(TrusttunnelHttp2Transport, EofSurvivesFullReceiveQueue)
    {
        Net::io_context IoContext;
        auto OnData = [](std::int32_t, std::span<const std::byte>) -> Net::awaitable<void>
        {
            co_return;
        };
        auto Transport = std::make_shared<Trusttunnel::Http2Transport>(
            IoContext.get_executor(), std::move(OnData));
        const std::array<std::byte, 1> Byte{std::byte{'x'}};
        for (std::size_t Index = 0; Index < 64; ++Index)
        {
            Transport->Push(Byte);
        }
        Transport->NotifyEof();

        std::size_t Blocks = 0;
        std::size_t Eof = 1;
        auto Operation = [&]() -> Net::awaitable<void>
        {
            std::array<std::byte, 1> Buffer{};
            std::error_code ErrorCode;
            while (Blocks < 64)
            {
                const auto ReadSize = co_await Transport->async_read_some(Buffer, ErrorCode);
                EXPECT_FALSE(ErrorCode);
                EXPECT_EQ(ReadSize, 1u);
                if (ErrorCode || ReadSize != 1u)
                {
                    co_return;
                }
                ++Blocks;
            }
            Eof = co_await Transport->async_read_some(Buffer, ErrorCode);
            EXPECT_FALSE(ErrorCode);
            co_return;
        };
        RunCoro(IoContext, std::move(Operation));
        EXPECT_EQ(Blocks, 64u);
        EXPECT_EQ(Eof, 0u);
    }

    TEST(TrusttunnelHttp2Transport, FinishIsQueuedAfterData)
    {
        Net::io_context IoContext;
        std::string Order;
        bool Finished = false;
        auto OnData = [&](std::int32_t, std::span<const std::byte> Data) -> Net::awaitable<void>
        {
            Order.append(reinterpret_cast<const char *>(Data.data()), Data.size());
            co_return;
        };
        auto OnFinish = [&](std::int32_t) -> Net::awaitable<void>
        {
            Finished = true;
            co_return;
        };
        auto Transport = std::make_shared<Trusttunnel::Http2Transport>(
            IoContext.get_executor(), std::move(OnData), std::move(OnFinish));
        Transport->BindStream(1);
        auto Operation = [&]() -> Net::awaitable<void>
        {
            std::error_code ErrorCode;
            const std::array<std::byte, 1> Byte{std::byte{'A'}};
            const auto Written = co_await Transport->async_write_some(Byte, ErrorCode);
            EXPECT_EQ(Written, 1u);
            EXPECT_FALSE(ErrorCode);
            co_await Transport->Finish();
            co_return;
        };
        RunCoro(IoContext, std::move(Operation));
        EXPECT_EQ(Order, "A");
        EXPECT_TRUE(Finished);
    }

    TEST(TrusttunnelHttp2Transport, LargeInboundDataSurvivesWindowRefresh)
    {
        Net::io_context IoContext;
        auto OnData = [](std::int32_t, std::span<const std::byte>) -> Net::awaitable<void>
        {
            co_return;
        };
        auto Transport = std::make_shared<Trusttunnel::Http2Transport>(
            IoContext.get_executor(), std::move(OnData));
        const std::vector<std::byte> Payload(128 * 1024, std::byte{0x4C});
        Transport->Push(Payload);
        Transport->NotifyEof();

        std::vector<std::byte> Received;
        auto Operation = [&]() -> Net::awaitable<void>
        {
            std::array<std::byte, 4096> Buffer{};
            std::error_code ErrorCode;
            while (true)
            {
                const auto ReadSize = co_await Transport->async_read_some(Buffer, ErrorCode);
                EXPECT_FALSE(ErrorCode);
                if (ErrorCode || ReadSize == 0)
                {
                    co_return;
                }
                const auto End = Buffer.begin() + static_cast<std::ptrdiff_t>(ReadSize);
                Received.insert(Received.end(), Buffer.begin(), End);
            }
        };
        RunCoro(IoContext, std::move(Operation));
        EXPECT_EQ(Received, Payload);
    }

} // namespace
