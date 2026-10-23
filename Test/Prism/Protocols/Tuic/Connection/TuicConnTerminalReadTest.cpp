/**
 * @file TuicConnTerminalReadTest.cpp
 * @brief TUIC Connect 与 packet frame 读终态测试。
 */
#include <gtest/gtest.h>

#include <Prism/Protocols/Tuic/Conn.hpp>

#include <array>
#include <cstdint>
#include <deque>
#include <iterator>
#include <memory>
#include <span>
#include <system_error>
#include <utility>
#include <vector>

#include "TuicTerminalReadSupport.hpp"

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

    auto MakeConnPacketSteps(Prism::Fault::Failure FinalFailure)
        -> std::deque<ReadStep>
    {
        return {
            {{0x05, 0x02}, {}},
            {{0, 1, 0, 1, 1, 0, 0, 3}, {}},
            {{0x01}, {}},
            {{1, 2, 3, 4}, {}},
            {{0, 80}, {}},
            {{'a', 'b', 'c'}, FinalFailure}};
    }

    auto MakeRecoveryConnPacketSteps() -> std::deque<ReadStep>
    {
        return {
            {{0x05, 0x02}, {}},
            {{0, 2, 0, 2, 1, 0, 0, 3}, {}},
            {{0x01}, {}},
            {{5, 6, 7, 8}, {}},
            {{0, 81}, {}},
            {{'d', 'e', 'f'}, {}}};
    }

    auto VerifyConnFrameBeforeEof(Net::any_io_executor Executor)
        -> Net::awaitable<void>
    {
        auto Upstream = std::make_shared<ScriptedTransport>(
            std::move(Executor),
            Prism::Transmission::Type::Tcp,
            MakeConnPacketSteps({Prism::Fault::Code::Eof}));
        auto Connection = std::make_shared<Tuic::Conn<>>(
            Upstream, std::array<std::uint8_t, Tuic::UuidLen>{});
        Tuic::Address Target{};
        Target.Type = Tuic::AddressType::Ipv4;
        Target.Host = "127.0.0.1";
        Target.Port = 443;
        Connection->MarkAuthenticated();
        EXPECT_EQ(
            co_await Connection->WriteHandshake(Target), Prism::Error::None);

        Tuic::Address Source{};
        std::vector<std::uint8_t> Payload;
        const auto PacketError = co_await Connection->AsyncReceiveDatagram(Source, Payload);
        EXPECT_EQ(PacketError, Prism::Error::None);
        EXPECT_EQ(Source.Port, 80);
        EXPECT_EQ(Payload, (std::vector<std::uint8_t>{'a', 'b', 'c'}));
        const auto ReadsAfterPacket = Upstream->ReadsDone;
        EXPECT_EQ(ReadsAfterPacket, 6U);

        const auto TerminalError = co_await Connection->AsyncReceiveDatagram(Source, Payload);
        EXPECT_EQ(TerminalError, Prism::Error::UnexpectedEof);
        EXPECT_EQ(Upstream->ReadsDone, ReadsAfterPacket);
        EXPECT_TRUE(co_await CloseAndDrain(*Connection));
        EXPECT_TRUE(co_await DrainActivity(*Upstream));
    }

    auto VerifyConnTerminalConsumedOnce(Net::any_io_executor Executor)
        -> Net::awaitable<void>
    {
        auto Steps = MakeConnPacketSteps({Prism::Fault::Code::IoError});
        auto RecoverySteps = MakeRecoveryConnPacketSteps();
        Steps.insert(
            Steps.end(),
            std::make_move_iterator(RecoverySteps.begin()),
            std::make_move_iterator(RecoverySteps.end()));
        auto Upstream = std::make_shared<ScriptedTransport>(
            std::move(Executor), Prism::Transmission::Type::Tcp, std::move(Steps));
        auto Connection = std::make_shared<Tuic::Conn<>>(
            Upstream, std::array<std::uint8_t, Tuic::UuidLen>{});
        Tuic::Address Target{};
        Target.Type = Tuic::AddressType::Ipv4;
        Target.Host = "127.0.0.1";
        Target.Port = 443;
        Connection->MarkAuthenticated();
        EXPECT_EQ(
            co_await Connection->WriteHandshake(Target), Prism::Error::None);

        Tuic::Address Source{};
        std::vector<std::uint8_t> Payload;
        const auto PacketError = co_await Connection->AsyncReceiveDatagram(Source, Payload);
        EXPECT_EQ(PacketError, Prism::Error::None);
        EXPECT_EQ(Payload, (std::vector<std::uint8_t>{'a', 'b', 'c'}));
        const auto TerminalError = co_await Connection->AsyncReceiveDatagram(Source, Payload);
        EXPECT_EQ(TerminalError, Prism::Error::IoError);
        EXPECT_EQ(Upstream->ReadsDone, 6U);
        const auto NextPacketError = co_await Connection->AsyncReceiveDatagram(Source, Payload);
        EXPECT_EQ(NextPacketError, Prism::Error::IoError);
        EXPECT_EQ(Upstream->ReadsDone, 6U);
        EXPECT_TRUE(co_await CloseAndDrain(*Connection));
        EXPECT_TRUE(co_await DrainActivity(*Upstream));
    }

    auto VerifyConnFieldCancelIsSticky(Net::any_io_executor Executor)
        -> Net::awaitable<void>
    {
        std::deque<ReadStep> Steps;
        Steps.push_back({{0x05, 0x02}, {}});
        Steps.push_back({{0, 1, 0, 1, 1, 0, 0, 1}, {}});
        Steps.push_back({{}, {Prism::Fault::Code::Canceled}});
        auto Upstream = std::make_shared<ScriptedTransport>(
            std::move(Executor), Prism::Transmission::Type::Tcp, std::move(Steps));
        auto Connection = std::make_shared<Tuic::Conn<>>(
            Upstream, std::array<std::uint8_t, Tuic::UuidLen>{});
        Connection->MarkAuthenticated();
        Tuic::Address Target{};
        Target.Type = Tuic::AddressType::Ipv4;
        Target.Host = "127.0.0.1";
        Target.Port = 443;
        EXPECT_EQ(co_await Connection->WriteHandshake(Target), Prism::Error::None);

        Tuic::Address Source{};
        std::vector<std::uint8_t> Payload;
        const auto FirstError = co_await Connection->AsyncReceiveDatagram(Source, Payload);
        EXPECT_EQ(FirstError, Prism::Error::Canceled);
        EXPECT_EQ(Upstream->ReadsDone, 3U);

        const auto RetryError = co_await Connection->AsyncReceiveDatagram(Source, Payload);
        EXPECT_EQ(RetryError, Prism::Error::Canceled);
        EXPECT_EQ(Upstream->ReadsDone, 3U);
        EXPECT_TRUE(co_await CloseAndDrain(*Connection));
        EXPECT_TRUE(co_await DrainActivity(*Upstream));
    }

    auto VerifyConnCompleteHandshakeTerminalIsSticky(
        Net::any_io_executor Executor) -> Net::awaitable<void>
    {
        const auto Native = std::make_error_code(std::errc::connection_reset);
        const Prism::Fault::Failure Terminal{Prism::Fault::Code::IoError, Native};
        std::deque<ReadStep> Steps;
        Steps.push_back({{0x05, 0x01}, {}});
        Steps.push_back({{0x01}, {}});
        Steps.push_back({{1, 2, 3, 4}, {}});
        Steps.push_back({{0, 80}, Terminal});
        auto Upstream = std::make_shared<ScriptedTransport>(
            std::move(Executor), Prism::Transmission::Type::Tcp, std::move(Steps));
        auto Connection = std::make_shared<Tuic::Conn<>>(
            Upstream, std::array<std::uint8_t, Tuic::UuidLen>{});
        Connection->MarkAuthenticated();

        const auto [HandshakeError, Request] = co_await Connection->ReadHandshake();
        EXPECT_EQ(HandshakeError, Prism::Error::None);
        EXPECT_EQ(Request.Cmd, Tuic::CmdConnect);
        EXPECT_EQ(Request.dst.Port, 80U);
        EXPECT_EQ(Upstream->ReadsDone, 4U);

        std::array<std::byte, 1> Buffer{};
        const auto FirstRead = co_await Connection->ReadSome(Buffer);
        EXPECT_EQ(FirstRead.Bytes, 0U);
        EXPECT_EQ(FirstRead.Failure.Code, Terminal.Code);
        EXPECT_EQ(FirstRead.Failure.Native, Terminal.Native);
        EXPECT_EQ(Upstream->ReadsDone, 4U);

        const auto RetryRead = co_await Connection->ReadSome(Buffer);
        EXPECT_EQ(RetryRead.Bytes, 0U);
        EXPECT_EQ(RetryRead.Failure.Code, Terminal.Code);
        EXPECT_EQ(RetryRead.Failure.Native, Terminal.Native);
        EXPECT_EQ(Upstream->ReadsDone, 4U);
        EXPECT_TRUE(co_await CloseAndDrain(*Connection));
        EXPECT_TRUE(co_await DrainActivity(*Upstream));
    }

} // namespace

TEST(TuicTerminalRead, ConnFrameBytesPrecedeEof)
{
    Net::io_context IoContext;
    RunCoroutine(IoContext, VerifyConnFrameBeforeEof(IoContext.get_executor()));
}

TEST(TuicTerminalRead, ConnPendingTerminalIsConsumedOnce)
{
    Net::io_context IoContext;
    RunCoroutine(IoContext, VerifyConnTerminalConsumedOnce(IoContext.get_executor()));
}

TEST(TuicTerminalRead, ConnFieldCancelIsStickyAcrossPublicRetry)
{
    Net::io_context IoContext;
    RunCoroutine(IoContext, VerifyConnFieldCancelIsSticky(IoContext.get_executor()));
}

TEST(TuicTerminalRead, ConnHandshakeTerminalIsStickyForRawReads)
{
    Net::io_context IoContext;
    RunCoroutine(
        IoContext,
        VerifyConnCompleteHandshakeTerminalIsSticky(IoContext.get_executor()));
}
