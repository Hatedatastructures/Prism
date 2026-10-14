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
#include <Preview/Transport/MemoryStream.hpp>
#include <Preview/Transport/Pad.hpp>
#include <Preview/Transport/Preview.hpp>
#include <Preview/Transport/Replay.hpp>
namespace
{
    namespace Net = boost::asio;
    using Preview::MakeMemoryPair;
    using Preview::MemoryStream;
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
        Preview::Fault::Failure ErrorCode;
        ([&](Preview::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Source.WriteSome(std::span<const std::byte>(reinterpret_cast<const std::byte *>(Data.data()), Data.size())));
        EXPECT_TRUE(ErrorCode.Succeeded());
    }

    auto RunPadSink(Preview::Transport::PadTransport &Pad)
        -> Net::awaitable<void>
    {
        std::array<std::byte, 512> Buffer{};
        Preview::Fault::Failure ErrorCode;
        const auto Count = ([&](Preview::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Pad.ReadSome(Buffer));
        EXPECT_TRUE(ErrorCode.Succeeded());
        EXPECT_GT(Count, 0u);
    }

    auto RunDisabledPadSink(Preview::Transport::PadTransport &Pad) -> Net::awaitable<void>
    {
        std::array<std::byte, 128> Buffer{};
        Preview::Fault::Failure ErrorCode;
        const auto Count = ([&](Preview::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Pad.ReadSome(Buffer));
        EXPECT_EQ(Count, 5u);
    }

    auto RunPadRoundtrip(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        using Net::experimental::awaitable_operators::operator&&;
        auto MemoryPair63 = Preview::Testing::MakeOwnedTransportPair(IoContext.get_executor());
        auto& Local = *MemoryPair63.FirstOwner;
        auto& Remote = *MemoryPair63.SecondOwner;
        Preview::Transport::PadConfig Config;
        Config.Targets = *Preview::Transport::ParsePadTargets("64");
        Config.StopAfter = 2;
        auto Pad = std::make_shared<Preview::Transport::PadTransport>(std::make_shared<MemoryStream>(std::move(Remote)), Preview::Testing::MakePadOptions(Config));
        EXPECT_TRUE(Config.Enabled());
        EXPECT_TRUE(Pad->IsOpen());
        const auto Data = std::string("pad-roundtrip-Data");
        co_await (RunPadSink(*Pad) && WritePadInput(Local, Data));
        const auto PadReceipt = co_await Preview::Testing::CloseFixture(Pad);
        Preview::Testing::ExpectFixtureCloseReceipt(PadReceipt);
        const auto LocalReceipt = co_await Preview::Testing::CloseFixture(MemoryPair63.FirstOwner);
        Preview::Testing::ExpectFixtureCloseReceipt(LocalReceipt);
    }

    auto RunPadDisabledPassthrough(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        using Net::experimental::awaitable_operators::operator&&;
        auto MemoryPair62 = Preview::Testing::MakeOwnedTransportPair(IoContext.get_executor());
        auto& Local = *MemoryPair62.FirstOwner;
        auto& Remote = *MemoryPair62.SecondOwner;
        Preview::Transport::PadConfig Config;
        Config.Targets = *Preview::Transport::ParsePadTargets("");
        auto Pad = std::make_shared<Preview::Transport::PadTransport>(std::make_shared<MemoryStream>(std::move(Remote)), Preview::Testing::MakePadOptions(Config));
        EXPECT_FALSE(Config.Enabled());
        const auto Data = std::string("hello");
        co_await (RunDisabledPadSink(*Pad) && WritePadInput(Local, Data));
        const auto PadReceipt = co_await Preview::Testing::CloseFixture(Pad);
        Preview::Testing::ExpectFixtureCloseReceipt(PadReceipt);
        const auto LocalReceipt = co_await Preview::Testing::CloseFixture(MemoryPair62.FirstOwner);
        Preview::Testing::ExpectFixtureCloseReceipt(LocalReceipt);
    }

    auto RunPreviewPreread(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        auto MemoryPair61 = Preview::Testing::MakeOwnedTransportPair(IoContext.get_executor());
        auto& Local = *MemoryPair61.FirstOwner;
        auto& Remote = *MemoryPair61.SecondOwner;
        (void)Local;
        const std::string Head = "preread";
        auto Preread = Preview::Transport::PreviewTransport::Create(std::make_shared<MemoryStream>(std::move(Remote)), {std::span<const std::byte>(reinterpret_cast<const std::byte *>(Head.data()), Head.size()), Preview::Testing::MakeTransportBytes(), {}}).value();
        std::array<std::byte, 16> Buffer{};
        Preview::Fault::Failure ErrorCode;
        const auto Count = ([&](Preview::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Preread->ReadSome(Buffer));
        EXPECT_EQ(Count, 7u);
        const auto PrereadReceipt = co_await Preview::Testing::CloseFixture(Preread);
        Preview::Testing::ExpectFixtureCloseReceipt(PrereadReceipt);
        const auto LocalReceipt = co_await Preview::Testing::CloseFixture(MemoryPair61.FirstOwner);
        Preview::Testing::ExpectFixtureCloseReceipt(LocalReceipt);
    }

    auto RunSnapshotRead(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        auto MemoryPair60 = Preview::Testing::MakeOwnedTransportPair(IoContext.get_executor());
        auto& Local = *MemoryPair60.FirstOwner;
        auto& Remote = *MemoryPair60.SecondOwner;
        auto Snapshot = Preview::Transport::ReplayTransmission::Create(std::make_shared<MemoryStream>(std::move(Remote)), Preview::Transport::ReplayOptions{64U * 1024U, Preview::Transport::ReplayMode::Owned, Preview::Testing::MakeTransportBytes()}).value();
        const auto Data = std::string("snap");
        Preview::Fault::Failure ErrorCode;
        ([&](Preview::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Local.WriteSome(std::span<const std::byte>(reinterpret_cast<const std::byte *>(Data.data()), Data.size())));
        std::array<std::byte, 16> Buffer{};
        const auto Count = ([&](Preview::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Snapshot->ReadSome(Buffer));
        EXPECT_EQ(Count, 4u);
        const auto SnapshotReceipt = co_await Preview::Testing::CloseFixture(Snapshot);
        Preview::Testing::ExpectFixtureCloseReceipt(SnapshotReceipt);
        const auto LocalReceipt = co_await Preview::Testing::CloseFixture(MemoryPair60.FirstOwner);
        Preview::Testing::ExpectFixtureCloseReceipt(LocalReceipt);
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
