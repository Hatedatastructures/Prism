/**
 * @file DgramFragmentReadTest.cpp
 * @brief TUIC 分片数据报终态边界测试。
 */
#include <gtest/gtest.h>

#include <Prism/Protocols/Tuic/Dgram.hpp>

#include <cstdint>
#include <memory>
#include <span>
#include <string_view>
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

    auto MakeFragmentWire(const std::uint8_t FragmentId, std::string_view Payload)
        -> std::vector<std::uint8_t>
    {
        const auto Size = static_cast<std::uint16_t>(Payload.size());
        std::vector<std::uint8_t> Wire{
            0x05, 0x02, 0, 1, 0, 7, 3, FragmentId,
            static_cast<std::uint8_t>(Size >> 8U),
            static_cast<std::uint8_t>(Size)};
        if (FragmentId == 0U)
        {
            Wire.insert(Wire.end(), {0x01, 1, 2, 3, 4, 0, 80});
        }
        else
        {
            Wire.push_back(0xFF);
        }
        for (const auto Character : Payload)
        {
            Wire.push_back(static_cast<std::uint8_t>(Character));
        }
        return Wire;
    }

    auto VerifyLastFragmentTerminalFollowsPacket(Net::any_io_executor Executor)
        -> Net::awaitable<void>
    {
        std::deque<ReadStep> Steps;
        Steps.push_back({MakeFragmentWire(0, "ab"), {}});
        Steps.push_back({MakeFragmentWire(1, "cd"), {}});
        Steps.push_back({
            MakeFragmentWire(2, "ef"), {Prism::Fault::Code::IoError}});
        auto Upstream = std::make_shared<ScriptedTransport>(
            std::move(Executor), Prism::Transmission::Type::Udp, std::move(Steps));
        auto Dgram = std::make_shared<Tuic::Dgram<>>(Upstream);
        Tuic::Address Source{};
        std::vector<std::uint8_t> Payload;

        const auto PacketError = co_await Dgram->AsyncReceiveFrom(Source, Payload);
        EXPECT_EQ(PacketError, Prism::Error::None);
        EXPECT_EQ(Source.Port, 80);
        EXPECT_EQ(Payload, (std::vector<std::uint8_t>{'a', 'b', 'c', 'd', 'e', 'f'}));
        EXPECT_EQ(Upstream->ReadsDone, 3U);
        const auto TerminalError = co_await Dgram->AsyncReceiveFrom(Source, Payload);
        EXPECT_EQ(TerminalError, Prism::Error::IoError);
        EXPECT_EQ(Upstream->ReadsDone, 3U);
        EXPECT_TRUE(co_await CloseAndDrain(*Dgram));
        EXPECT_TRUE(co_await DrainActivity(*Upstream));
    }

    auto VerifyMiddleFragmentTerminalStopsReceive(Net::any_io_executor Executor)
        -> Net::awaitable<void>
    {
        std::deque<ReadStep> Steps;
        Steps.push_back({MakeFragmentWire(0, "ab"), {}});
        Steps.push_back({
            MakeFragmentWire(1, "cd"), {Prism::Fault::Code::IoError}});
        Steps.push_back({MakeFragmentWire(2, "ef"), {}});
        auto Upstream = std::make_shared<ScriptedTransport>(
            std::move(Executor), Prism::Transmission::Type::Udp, std::move(Steps));
        auto Dgram = std::make_shared<Tuic::Dgram<>>(Upstream);
        Tuic::Address Source{};
        Source.Port = 123;
        std::vector<std::uint8_t> Payload{'x'};

        const auto TerminalError = co_await Dgram->AsyncReceiveFrom(Source, Payload);
        EXPECT_EQ(TerminalError, Prism::Error::IoError);
        EXPECT_EQ(Source.Port, 123);
        EXPECT_EQ(Payload, (std::vector<std::uint8_t>{'x'}));
        EXPECT_EQ(Upstream->ReadsDone, 2U);
        EXPECT_TRUE(co_await CloseAndDrain(*Dgram));
        EXPECT_TRUE(co_await DrainActivity(*Upstream));
    }

} // namespace

TEST(TuicTerminalRead, LastFragmentBytesPrecedeTerminal)
{
    Net::io_context IoContext;
    RunCoroutine(
        IoContext,
        VerifyLastFragmentTerminalFollowsPacket(IoContext.get_executor()));
}

TEST(TuicTerminalRead, MiddleFragmentTerminalStopsReceive)
{
    Net::io_context IoContext;
    RunCoroutine(
        IoContext,
        VerifyMiddleFragmentTerminalStopsReceive(IoContext.get_executor()));
}
