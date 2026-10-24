/**
 * @file TuicEchoTerminalTest.cpp
 * @brief TUIC 互操作共享读写循环的 terminal 与 payload 顺序。
 */

#include "InteropTuicTerminalIo.hpp"
#include "InteropTuicLifecycle.hpp"

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <system_error>
#include <utility>
#include <vector>

#include <Prism/Contract/Io/CarrierActivity.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Protocols/Tuic/Conn.hpp>
#include <TestSupport/Prism/PrismMockTransport.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    using Prism::PrismMockTransport;
    using Prism::Testing::TuicInterop::Detail::CloseAndDrainTuicConnection;
    using Prism::Testing::TuicInterop::Detail::EchoPeerStream;
    using Prism::Testing::TuicInterop::Detail::ReadExpectedPayload;

    [[nodiscard]] auto ExpectedPayload() -> std::vector<std::uint8_t>
    {
        return {0x31U, 0x72U, 0xA4U, 0xD5U};
    }

    [[nodiscard]] auto MakeEofFailure() -> std::error_code
    {
        return Prism::Fault::make_error_code(Prism::Fault::Code::Eof);
    }

    [[nodiscard]] auto MakeTransport(
        Net::io_context &IoContext,
        const std::vector<std::uint8_t> &Input,
        const std::error_code Failure) -> std::shared_ptr<PrismMockTransport>
    {
        auto Transport = std::make_shared<PrismMockTransport>(IoContext.get_executor());
        Transport->ToRead = Input;
        Transport->ReadErrorBytes = Input.size();
        Transport->SetReadError(Failure);
        return Transport;
    }

    [[nodiscard]] auto CloseAndDrain(
        const std::shared_ptr<PrismMockTransport> &Transport) -> Net::awaitable<bool>
    {
        if (!Transport)
        {
            co_return false;
        }
        const auto Closed = Transport->Close();
        const auto Activity = Transport->Activity();
        if (!Closed || !Activity)
        {
            co_return false;
        }
        const auto Drained = co_await Activity->Drain();
        co_return Drained.has_value() && Activity->IsRetired();
    }

    auto RunCoroutine(Net::io_context &IoContext, Net::awaitable<void> Coroutine) -> void
    {
        std::exception_ptr Exception;
        Net::co_spawn(
            IoContext,
            std::move(Coroutine),
            [&Exception, &IoContext](std::exception_ptr Failure)
            {
                Exception = std::move(Failure);
                IoContext.stop();
            });
        IoContext.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    auto VerifyServerEchoesPayloadBeforeEof(
        const std::shared_ptr<PrismMockTransport> &Transport) -> Net::awaitable<void>
    {
        std::array<std::byte, 16> Buffer{};
        const auto Result = co_await EchoPeerStream(*Transport, Buffer);
        EXPECT_TRUE(Result.has_value());
        if (Result)
        {
            EXPECT_EQ(Result->Bytes, ExpectedPayload().size());
            EXPECT_EQ(Result->Terminal.Code, Prism::Fault::Code::Eof);
        }
        EXPECT_EQ(Transport->Written, ExpectedPayload());
        EXPECT_EQ(Transport->ReadsDone, 1U);
        EXPECT_TRUE(co_await CloseAndDrain(Transport));
    }

    auto VerifyServerEchoesPayloadBeforeFailure(
        const std::shared_ptr<PrismMockTransport> &Transport,
        const std::error_code NativeFailure) -> Net::awaitable<void>
    {
        std::array<std::byte, 16> Buffer{};
        const auto Result = co_await EchoPeerStream(*Transport, Buffer);
        EXPECT_FALSE(Result.has_value());
        if (!Result)
        {
            EXPECT_EQ(Result.error().Code, Prism::Fault::Code::ConnectionReset);
            EXPECT_EQ(Result.error().Native, NativeFailure);
        }
        EXPECT_EQ(Transport->Written, ExpectedPayload());
        EXPECT_EQ(Transport->ReadsDone, 1U);
        EXPECT_TRUE(co_await CloseAndDrain(Transport));
    }

    auto VerifyClientAcceptsCompleteEchoEof(
        const std::shared_ptr<PrismMockTransport> &Transport) -> Net::awaitable<void>
    {
        std::array<std::byte, 4> Echo{};
        const auto Result = co_await ReadExpectedPayload(*Transport, Echo);
        EXPECT_TRUE(Result.has_value());
        if (Result)
        {
            EXPECT_EQ(Result->Bytes, Echo.size());
            EXPECT_EQ(Result->Terminal.Code, Prism::Fault::Code::Eof);
        }
        const auto Expected = ExpectedPayload();
        for (std::size_t Index = 0; Index < Echo.size(); ++Index)
        {
            EXPECT_EQ(Echo[Index], static_cast<std::byte>(Expected[Index]));
        }
        EXPECT_EQ(Transport->ReadsDone, 1U);
        EXPECT_TRUE(co_await CloseAndDrain(Transport));
    }

    auto VerifyClientRejectsPartialEchoEof(
        const std::shared_ptr<PrismMockTransport> &Transport) -> Net::awaitable<void>
    {
        std::array<std::byte, 4> Echo{};
        const auto Result = co_await ReadExpectedPayload(*Transport, Echo);
        EXPECT_FALSE(Result.has_value());
        if (!Result)
        {
            EXPECT_EQ(Result.error().Code, Prism::Fault::Code::Eof);
        }
        const auto Expected = ExpectedPayload();
        EXPECT_EQ(Echo[0], static_cast<std::byte>(Expected[0]));
        EXPECT_EQ(Echo[1], static_cast<std::byte>(Expected[1]));
        EXPECT_EQ(Echo[2], std::byte{});
        EXPECT_EQ(Echo[3], std::byte{});
        EXPECT_EQ(Transport->ReadsDone, 1U);
        EXPECT_TRUE(co_await CloseAndDrain(Transport));
    }

    auto VerifyClientRejectsCompleteEchoReset(
        const std::shared_ptr<PrismMockTransport> &Transport,
        const std::error_code NativeFailure) -> Net::awaitable<void>
    {
        std::array<std::byte, 4> Echo{};
        const auto Result = co_await ReadExpectedPayload(*Transport, Echo);
        EXPECT_FALSE(Result.has_value());
        if (!Result)
        {
            EXPECT_EQ(Result.error().Code, Prism::Fault::Code::ConnectionReset);
            EXPECT_EQ(Result.error().Native, NativeFailure);
        }
        const auto Expected = ExpectedPayload();
        for (std::size_t Index = 0; Index < Echo.size(); ++Index)
        {
            EXPECT_EQ(Echo[Index], static_cast<std::byte>(Expected[Index]));
        }
        EXPECT_EQ(Transport->ReadsDone, 1U);
        EXPECT_TRUE(co_await CloseAndDrain(Transport));
    }

    auto VerifyTuicStreamChainDrains(
        const std::shared_ptr<PrismMockTransport> &Transport) -> Net::awaitable<void>
    {
        std::array<std::uint8_t, Prism::Tuic::UuidLen> Uuid{};
        auto Connection = std::make_shared<Prism::Tuic::Conn<>>(Transport, Uuid);
        const auto ConnectionActivity = Connection->Activity();
        const auto ProviderActivity = Transport->Activity();
        const auto Drained = co_await CloseAndDrainTuicConnection(Connection);
        EXPECT_TRUE(Drained);
        EXPECT_NE(ConnectionActivity, nullptr);
        EXPECT_NE(ProviderActivity, nullptr);
        if (!ConnectionActivity || !ProviderActivity) co_return;
        EXPECT_TRUE(ConnectionActivity->IsRetired());
        EXPECT_TRUE(ProviderActivity->IsRetired());
    }
}

TEST(InteropTuicTerminalRead, ServerEchoesPayloadBeforeSameReadEof)
{
    Net::io_context IoContext;
    auto Transport = MakeTransport(IoContext, ExpectedPayload(), MakeEofFailure());
    RunCoroutine(IoContext, VerifyServerEchoesPayloadBeforeEof(Transport));
}

TEST(InteropTuicTerminalRead, ServerEchoesPayloadBeforeSameReadReset)
{
    Net::io_context IoContext;
    const auto Reset = std::make_error_code(std::errc::connection_reset);
    auto Transport = MakeTransport(IoContext, ExpectedPayload(), Reset);
    RunCoroutine(IoContext, VerifyServerEchoesPayloadBeforeFailure(Transport, Reset));
}

TEST(InteropTuicTerminalRead, ClientAcceptsCompleteEchoWithSameReadEof)
{
    Net::io_context IoContext;
    auto Transport = MakeTransport(IoContext, ExpectedPayload(), MakeEofFailure());
    RunCoroutine(IoContext, VerifyClientAcceptsCompleteEchoEof(Transport));
}

TEST(InteropTuicTerminalRead, ClientRejectsPartialEchoWithSameReadEof)
{
    Net::io_context IoContext;
    auto Input = ExpectedPayload();
    Input.resize(2U);
    auto Transport = MakeTransport(IoContext, Input, MakeEofFailure());
    RunCoroutine(IoContext, VerifyClientRejectsPartialEchoEof(Transport));
}

TEST(InteropTuicTerminalRead, ClientRejectsCompleteEchoWithSameReadReset)
{
    Net::io_context IoContext;
    const auto Reset = std::make_error_code(std::errc::connection_reset);
    auto Transport = MakeTransport(IoContext, ExpectedPayload(), Reset);
    RunCoroutine(IoContext, VerifyClientRejectsCompleteEchoReset(Transport, Reset));
}

TEST(InteropTuicLifecycle, CloseWaitsForProtocolAndProviderActivities)
{
    Net::io_context IoContext;
    auto Transport = std::make_shared<PrismMockTransport>(IoContext.get_executor());
    RunCoroutine(IoContext, VerifyTuicStreamChainDrains(Transport));
}
