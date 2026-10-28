/**
 * @file DgramTerminalTest.cpp
 * @brief TUIC 数据报帧读终态与完整字节优先级测试。
 */
#include <gtest/gtest.h>

#include <Prism/Protocols/Tuic/Dgram.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <deque>
#include <memory>
#include <span>
#include <system_error>
#include <utility>
#include <vector>

#include "TerminalReadSupport.hpp"

namespace
{
    namespace Net = boost::asio;
    namespace Tuic = Prism::Tuic;
    namespace Terminal = Prism::Test::TuicTerminalRead;
    using Terminal::CloseAndDrain;
    using Terminal::DrainActivity;
    using Terminal::ReadStep;
    using Terminal::RunCoroutine;
    using Terminal::ScriptedTransport;

    auto MakePacketWire() -> std::vector<std::uint8_t>
    {
        return {0x05, 0x02, 0, 1, 0, 1, 1, 0, 0, 3,
                0x01, 1, 2, 3, 4, 0, 80, 'a', 'b', 'c'};
    }

    auto MakeStreamPacketSteps(Prism::Fault::Failure FinalFailure)
        -> std::deque<ReadStep>
    {
        return {
            {{0x05, 0x02, 0, 1, 0, 1, 1, 0, 0, 3}, {}},
            {{0x01}, {}},
            {{1, 2, 3, 4}, {}},
            {{0, 80}, {}},
            {{'a', 'b', 'c'}, FinalFailure}};
    }

    auto MakeRecoveryPacketWire() -> std::vector<std::uint8_t>
    {
        return {0x05, 0x02, 0, 2, 0, 2, 1, 0, 0, 3,
                0x01, 5, 6, 7, 8, 0, 81, 'd', 'e', 'f'};
    }

    auto VerifyDatagramBeforeIoError(Net::any_io_executor Executor)
        -> Net::awaitable<void>
    {
        std::deque<ReadStep> Steps;
        Steps.push_back({MakePacketWire(), {Prism::Fault::Code::IoError}});
        Steps.push_back({MakeRecoveryPacketWire(), {}});
        auto Upstream = std::make_shared<ScriptedTransport>(
            std::move(Executor), Prism::Transmission::Type::Udp, std::move(Steps));
        auto Dgram = std::make_shared<Tuic::Dgram<>>(Upstream);
        Tuic::Address Source{};
        std::vector<std::uint8_t> Payload;

        const auto PacketError = co_await Dgram->AsyncReceiveFrom(Source, Payload);
        EXPECT_EQ(PacketError, Prism::Error::None);
        EXPECT_EQ(Source.Port, 80);
        EXPECT_EQ(Payload, (std::vector<std::uint8_t>{'a', 'b', 'c'}));
        EXPECT_EQ(Upstream->ReadsDone, 1U);

        const auto TerminalError = co_await Dgram->AsyncReceiveFrom(Source, Payload);
        EXPECT_EQ(TerminalError, Prism::Error::IoError);
        EXPECT_EQ(Upstream->ReadsDone, 1U);

        const auto NextPacketError = co_await Dgram->AsyncReceiveFrom(Source, Payload);
        EXPECT_EQ(NextPacketError, Prism::Error::None);
        EXPECT_EQ(Source.Port, 81);
        EXPECT_EQ(Payload, (std::vector<std::uint8_t>{'d', 'e', 'f'}));
        EXPECT_EQ(Upstream->ReadsDone, 2U);
        EXPECT_TRUE(co_await CloseAndDrain(*Dgram));
        EXPECT_TRUE(co_await DrainActivity(*Upstream));
    }

    auto VerifyStreamDatagramBeforeEof(Net::any_io_executor Executor)
        -> Net::awaitable<void>
    {
        auto Upstream = std::make_shared<ScriptedTransport>(
            std::move(Executor),
            Prism::Transmission::Type::Tcp,
            MakeStreamPacketSteps({Prism::Fault::Code::Eof}));
        auto Dgram = std::make_shared<Tuic::Dgram<>>(Upstream);
        Tuic::Address Source{};
        std::vector<std::uint8_t> Payload;

        const auto PacketError = co_await Dgram->AsyncReceiveFrom(Source, Payload);
        EXPECT_EQ(PacketError, Prism::Error::None);
        EXPECT_EQ(Source.Port, 80);
        EXPECT_EQ(Payload, (std::vector<std::uint8_t>{'a', 'b', 'c'}));
        EXPECT_EQ(Upstream->ReadsDone, 5U);

        const auto TerminalError = co_await Dgram->AsyncReceiveFrom(Source, Payload);
        EXPECT_EQ(TerminalError, Prism::Error::UnexpectedEof);
        EXPECT_EQ(Upstream->ReadsDone, 5U);

        const auto RetryError = co_await Dgram->AsyncReceiveFrom(Source, Payload);
        EXPECT_EQ(RetryError, Prism::Error::UnexpectedEof);
        EXPECT_EQ(Upstream->ReadsDone, 5U);

        EXPECT_TRUE(co_await CloseAndDrain(*Dgram));
        EXPECT_TRUE(co_await DrainActivity(*Upstream));
    }

    auto VerifyStreamHeaderTerminal(
        Net::any_io_executor Executor,
        Prism::Fault::Failure Terminal,
        const Prism::Error ExpectedError) -> Net::awaitable<void>
    {
        std::deque<ReadStep> Steps;
        Steps.push_back({
            {0x05, 0x02, 0, 1, 0, 1, 1, 0, 0, 3}, Terminal});
        auto Upstream = std::make_shared<ScriptedTransport>(
            std::move(Executor), Prism::Transmission::Type::Tcp, std::move(Steps));
        auto Dgram = std::make_shared<Tuic::Dgram<>>(Upstream);
        Tuic::Address Source{};
        Source.Port = 123;
        std::vector<std::uint8_t> Payload{'x'};

        const auto FirstError = co_await Dgram->AsyncReceiveFrom(Source, Payload);
        EXPECT_EQ(FirstError, ExpectedError);
        EXPECT_EQ(Source.Port, 123);
        EXPECT_EQ(Payload, (std::vector<std::uint8_t>{'x'}));
        EXPECT_EQ(Upstream->ReadsDone, 1U);

        const auto RetryError = co_await Dgram->AsyncReceiveFrom(Source, Payload);
        EXPECT_EQ(RetryError, ExpectedError);
        EXPECT_EQ(Upstream->ReadsDone, 1U);

        EXPECT_TRUE(co_await CloseAndDrain(*Dgram));
        EXPECT_TRUE(co_await DrainActivity(*Upstream));
    }

    auto VerifyMalformedStreamHeaderBeforeEof(Net::any_io_executor Executor)
        -> Net::awaitable<void>
    {
        std::deque<ReadStep> Steps;
        Steps.push_back({
            {0x04, 0x02, 0, 1, 0, 1, 1, 0, 0, 3},
            {Prism::Fault::Code::Eof}});
        auto Upstream = std::make_shared<ScriptedTransport>(
            std::move(Executor), Prism::Transmission::Type::Tcp, std::move(Steps));
        auto Dgram = std::make_shared<Tuic::Dgram<>>(Upstream);
        Tuic::Address Source{};
        Source.Port = 123;
        std::vector<std::uint8_t> Payload{'x'};

        const auto ParseError = co_await Dgram->AsyncReceiveFrom(Source, Payload);
        EXPECT_EQ(ParseError, Prism::Error::BadMessage);
        EXPECT_EQ(Source.Port, 123U);
        EXPECT_EQ(Payload, (std::vector<std::uint8_t>{'x'}));
        EXPECT_EQ(Upstream->ReadsDone, 1U);

        const auto TerminalError = co_await Dgram->AsyncReceiveFrom(Source, Payload);
        EXPECT_EQ(TerminalError, Prism::Error::UnexpectedEof);
        EXPECT_EQ(Upstream->ReadsDone, 1U);

        EXPECT_TRUE(co_await CloseAndDrain(*Dgram));
        EXPECT_TRUE(co_await DrainActivity(*Upstream));
    }

    auto VerifyStreamPartialPayloadReset(Net::any_io_executor Executor)
        -> Net::awaitable<void>
    {
        auto Steps = MakeStreamPacketSteps({});
        Steps.back() = {{'a'}, {
            Prism::Fault::Code::IoError,
            std::make_error_code(std::errc::connection_reset)}};
        auto Upstream = std::make_shared<ScriptedTransport>(
            std::move(Executor), Prism::Transmission::Type::Tcp, std::move(Steps));
        auto Dgram = std::make_shared<Tuic::Dgram<>>(Upstream);
        Tuic::Address Source{};
        Source.Port = 123;
        std::vector<std::uint8_t> Payload{'x'};

        const auto FirstError = co_await Dgram->AsyncReceiveFrom(Source, Payload);
        EXPECT_EQ(FirstError, Prism::Error::IoError);
        EXPECT_EQ(Source.Port, 123);
        EXPECT_EQ(Payload, (std::vector<std::uint8_t>{'x'}));
        EXPECT_EQ(Upstream->ReadsDone, 5U);

        const auto RetryError = co_await Dgram->AsyncReceiveFrom(Source, Payload);
        EXPECT_EQ(RetryError, Prism::Error::IoError);
        EXPECT_EQ(Upstream->ReadsDone, 5U);

        EXPECT_TRUE(co_await CloseAndDrain(*Dgram));
        EXPECT_TRUE(co_await DrainActivity(*Upstream));
    }

} // namespace

TEST(TuicTerminalRead, DatagramBytesPrecedeIoError)
{
    Net::io_context IoContext;
    RunCoroutine(IoContext, VerifyDatagramBeforeIoError(IoContext.get_executor()));
}

TEST(TuicTerminalRead, StreamFrameBytesPrecedeEof)
{
    Net::io_context IoContext;
    RunCoroutine(IoContext, VerifyStreamDatagramBeforeEof(IoContext.get_executor()));
}

TEST(TuicTerminalRead, CompleteStreamHeaderEofIsSticky)
{
    Net::io_context IoContext;
    RunCoroutine(
        IoContext,
        VerifyStreamHeaderTerminal(
            IoContext.get_executor(),
            {Prism::Fault::Code::Eof},
            Prism::Error::UnexpectedEof));
}

TEST(TuicTerminalRead, CompleteStreamHeaderResetIsSticky)
{
    Net::io_context IoContext;
    RunCoroutine(
        IoContext,
        VerifyStreamHeaderTerminal(
            IoContext.get_executor(),
            {Prism::Fault::Code::IoError,
             std::make_error_code(std::errc::connection_reset)},
            Prism::Error::IoError));
}

TEST(TuicTerminalRead, CompleteMalformedStreamHeaderPrecedesEof)
{
    Net::io_context IoContext;
    RunCoroutine(IoContext, VerifyMalformedStreamHeaderBeforeEof(IoContext.get_executor()));
}

TEST(TuicTerminalRead, PartialStreamPayloadResetIsSticky)
{
    Net::io_context IoContext;
    RunCoroutine(IoContext, VerifyStreamPartialPayloadReset(IoContext.get_executor()));
}
