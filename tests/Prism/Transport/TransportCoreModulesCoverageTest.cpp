/**
 * @file TransportCoreModulesCoverageTest.cpp
 * @brief Transport Pad、Preview 和 Snapshot 行为测试。
 */
#include <gtest/gtest.h>
#include "TransportResources.hpp"
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <array>
#include <chrono>
#include <exception>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <Prism/Transport/MemoryStream.hpp>
#include <Prism/Transport/Pad.hpp>
#include <Prism/Transport/Preview.hpp>
#include <Prism/Transport/Replay.hpp>
namespace
{
    namespace Net = boost::asio;
    using Prism::MakeMemoryPair;
    using Prism::MemoryStream;
    template <typename A>
    auto RunCoroutine(Net::io_context &IoContext, A Coroutine) -> void
    {
        std::exception_ptr Exception;
        Net::co_spawn(IoContext, std::move(Coroutine), [&](std::exception_ptr ErrorValue)
        { Exception = ErrorValue; });
        IoContext.run();
        if (Exception) std::rethrow_exception(Exception);
    }

    auto WritePadInput(MemoryStream &Source, const std::string_view Data)
        -> Net::awaitable<void>
    {
        Prism::Fault::Failure ErrorCode;
        ([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Source.WriteSome(std::span<const std::byte>(reinterpret_cast<const std::byte *>(Data.data()), Data.size())));
        EXPECT_TRUE(ErrorCode.Succeeded());
    }

    auto RunPadSink(Prism::Transport::PadTransport &Pad)
        -> Net::awaitable<void>
    {
        std::array<std::byte, 512> Buffer{};
        Prism::Fault::Failure ErrorCode;
        const auto Count = ([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Pad.ReadSome(Buffer));
        EXPECT_TRUE(ErrorCode.Succeeded());
        EXPECT_GT(Count, 0u);
    }

    auto RunDisabledPadSink(Prism::Transport::PadTransport &Pad) -> Net::awaitable<void>
    {
        std::array<std::byte, 128> Buffer{};
        Prism::Fault::Failure ErrorCode;
        const auto Count = ([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Pad.ReadSome(Buffer));
        EXPECT_EQ(Count, 5u);
    }

    auto RunPadRoundtrip(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        using Net::experimental::awaitable_operators::operator&&;
        auto MemoryPair63 = Prism::Testing::MakeOwnedTransportPair(IoContext.get_executor());
        auto& Local = *MemoryPair63.FirstOwner;
        auto& Remote = *MemoryPair63.SecondOwner;
        Prism::Transport::PadConfig Config;
        Config.Targets = *Prism::Transport::ParsePadTargets("64");
        Config.StopAfter = 2;
        auto Pad = std::make_shared<Prism::Transport::PadTransport>(std::make_shared<MemoryStream>(std::move(Remote)), Prism::Testing::MakePadOptions(Config));
        EXPECT_TRUE(Config.Enabled());
        EXPECT_TRUE(Pad->IsOpen());
        const auto Data = std::string("pad-roundtrip-Data");
        co_await (RunPadSink(*Pad) && WritePadInput(Local, Data));
        const auto PadReceipt = co_await Prism::Testing::CloseFixture(Pad);
        Prism::Testing::ExpectFixtureCloseReceipt(PadReceipt);
        const auto LocalReceipt = co_await Prism::Testing::CloseFixture(MemoryPair63.FirstOwner);
        Prism::Testing::ExpectFixtureCloseReceipt(LocalReceipt);
    }

    auto RunPadDisabledPassthrough(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        using Net::experimental::awaitable_operators::operator&&;
        auto MemoryPair62 = Prism::Testing::MakeOwnedTransportPair(IoContext.get_executor());
        auto& Local = *MemoryPair62.FirstOwner;
        auto& Remote = *MemoryPair62.SecondOwner;
        Prism::Transport::PadConfig Config;
        Config.Targets = *Prism::Transport::ParsePadTargets("");
        auto Pad = std::make_shared<Prism::Transport::PadTransport>(std::make_shared<MemoryStream>(std::move(Remote)), Prism::Testing::MakePadOptions(Config));
        EXPECT_FALSE(Config.Enabled());
        const auto Data = std::string("hello");
        co_await (RunDisabledPadSink(*Pad) && WritePadInput(Local, Data));
        const auto PadReceipt = co_await Prism::Testing::CloseFixture(Pad);
        Prism::Testing::ExpectFixtureCloseReceipt(PadReceipt);
        const auto LocalReceipt = co_await Prism::Testing::CloseFixture(MemoryPair62.FirstOwner);
        Prism::Testing::ExpectFixtureCloseReceipt(LocalReceipt);
    }

    auto RunPreviewPreread(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        auto MemoryPair61 = Prism::Testing::MakeOwnedTransportPair(IoContext.get_executor());
        auto& Local = *MemoryPair61.FirstOwner;
        auto& Remote = *MemoryPair61.SecondOwner;
        (void)Local;
        const std::string Head = "preread";
        auto Preread = Prism::Transport::PreviewTransport::Create(std::make_shared<MemoryStream>(std::move(Remote)), {std::span<const std::byte>(reinterpret_cast<const std::byte *>(Head.data()), Head.size()), Prism::Testing::MakeTransportBytes(), {}}).value();
        std::array<std::byte, 16> Buffer{};
        Prism::Fault::Failure ErrorCode;
        const auto Count = ([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Preread->ReadSome(Buffer));
        EXPECT_EQ(Count, 7u);
        const auto PrereadReceipt = co_await Prism::Testing::CloseFixture(Preread);
        Prism::Testing::ExpectFixtureCloseReceipt(PrereadReceipt);
        const auto LocalReceipt = co_await Prism::Testing::CloseFixture(MemoryPair61.FirstOwner);
        Prism::Testing::ExpectFixtureCloseReceipt(LocalReceipt);
    }

    auto RunSnapshotRead(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        auto MemoryPair60 = Prism::Testing::MakeOwnedTransportPair(IoContext.get_executor());
        auto& Local = *MemoryPair60.FirstOwner;
        auto& Remote = *MemoryPair60.SecondOwner;
        auto Snapshot = Prism::Transport::ReplayTransmission::Create(std::make_shared<MemoryStream>(std::move(Remote)), Prism::Transport::ReplayOptions{64U * 1024U, Prism::Transport::ReplayMode::Owned, Prism::Testing::MakeTransportBytes()}).value();
        const auto Data = std::string("snap");
        Prism::Fault::Failure ErrorCode;
        ([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Local.WriteSome(std::span<const std::byte>(reinterpret_cast<const std::byte *>(Data.data()), Data.size())));
        std::array<std::byte, 16> Buffer{};
        const auto Count = ([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Snapshot->ReadSome(Buffer));
        EXPECT_EQ(Count, 4u);
        const auto SnapshotReceipt = co_await Prism::Testing::CloseFixture(Snapshot);
        Prism::Testing::ExpectFixtureCloseReceipt(SnapshotReceipt);
        const auto LocalReceipt = co_await Prism::Testing::CloseFixture(MemoryPair60.FirstOwner);
        Prism::Testing::ExpectFixtureCloseReceipt(LocalReceipt);
    }
}
TEST(CoreModules, PadRoundtrip)
    {
        Net::io_context Ioc;
        RunCoroutine(Ioc, RunPadRoundtrip(Ioc));
    }

TEST(CoreModules, PadDisabledPassthrough)
    {
        Net::io_context Ioc;
        RunCoroutine(Ioc, RunPadDisabledPassthrough(Ioc));
    }

TEST(CoreModules, PreviewPreread)
    {
        Net::io_context Ioc;
        RunCoroutine(Ioc, RunPreviewPreread(Ioc));
    }

TEST(CoreModules, SnapshotRead)
    {
        Net::io_context Ioc;
        RunCoroutine(Ioc, RunSnapshotRead(Ioc));
    }
