/**
 * @file PreviewTransportTest.cpp
 * @brief 按功能拆分的 GoogleTest 行为契约。
 */

#include <Prism/Foundation/ByteSpan.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Transport/MemoryStream.hpp>
#include <Prism/Transport/Preview.hpp>
#include <Prism/Transport/Replay.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/error_code.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <exception>
#include <future>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <system_error>
#include <utility>

#include <gtest/gtest.h>

#include "../Core/DecoratorSupport.hpp"
#include "../Core/Resources.hpp"

namespace
{
    class PrefixTerminalMock final : public Prism::Transmission
    {
    public:
        explicit PrefixTerminalMock(Net::any_io_executor Executor)
            : Prism::Transmission(Executor), Executor_(std::move(Executor))
        {
        }

        [[nodiscard]] auto Executor() const -> ExecutorType override
        {
            return Executor_;
        }

        [[nodiscard]] auto ReadCalls() const noexcept -> std::size_t
        {
            return ReadCalls_;
        }

        [[nodiscard]] auto WriteCalls() const noexcept -> std::size_t
        {
            return WriteCalls_;
        }

        [[nodiscard]] auto WriteShutdownCalls() const noexcept -> std::size_t
        {
            return WriteShutdownCalls_;
        }

        [[nodiscard]] auto CloseCalls() const noexcept -> std::size_t
        {
            return CloseCalls_;
        }

        [[nodiscard]] auto Written() const noexcept -> const std::string&
        {
            return Written_;
        }

        auto RejectNextClose(Prism::Fault::Failure Failure) -> void
        {
            CloseFailure_.emplace(Failure);
        }

        auto StartRead(std::span<std::byte>, Completion Handler) -> void override
        {
            ++ReadCalls_;
            Prism::Transmission::PostResult(
                Executor_, std::move(Handler),
                {0, {Prism::Fault::Code::WouldBlock}});
        }

        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            ++WriteCalls_;
            if (!Buffer.empty())
            {
                Written_.append(
                    reinterpret_cast<const char*>(Buffer.data()), Buffer.size());
            }
            Prism::Transmission::PostResult(
                Executor_, std::move(Handler), {Buffer.size(), {}});
        }

        auto StartWriteShutdown(Completion Handler) -> void override
        {
            ++WriteShutdownCalls_;
            Prism::Transmission::PostResult(Executor_, std::move(Handler), {});
        }

    protected:
        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            ++CloseCalls_;
            if (CloseFailure_)
            {
                const auto Failure = *CloseFailure_;
                CloseFailure_.reset();
                return std::unexpected(Failure);
            }
            return {};
        }

        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            return {};
        }

    private:
        Net::any_io_executor Executor_;
        std::size_t ReadCalls_{0};
        std::size_t WriteCalls_{0};
        std::size_t WriteShutdownCalls_{0};
        std::size_t CloseCalls_{0};
        std::optional<Prism::Fault::Failure> CloseFailure_;
        std::string Written_;
    };

    auto RunPrefixBytesWithStickyEof(Net::io_context& IoContext)
        -> Net::awaitable<void>
    {
        auto Inner = std::make_shared<PrefixTerminalMock>(IoContext.get_executor());
        const auto Created = Prism::Transport::PreviewTransport::Create(
            Inner, {SvBytes("request-tail"), Prism::Testing::MakeTransportBytes(),
                    {Prism::Fault::Code::Eof}});
        if (!Created)
        {
            ADD_FAILURE() << "PreviewTransport rejected a nonempty EOF prefix";
            co_return;
        }
        const auto Preview = *Created;
        std::array<std::byte, 32> Buffer{};
        EXPECT_FALSE(Preview->Release());

        const auto First = co_await Preview->ReadSome(Buffer);
        EXPECT_EQ(First.Bytes, 12U);
        EXPECT_EQ(First.Failure.Code, Prism::Fault::Code::Eof);
        EXPECT_EQ(Prism::AsStrView(Prism::AsU8(
                      std::span<std::byte>(Buffer).first(First.Bytes))),
                  "request-tail");
        EXPECT_FALSE(Preview->Release());

        const auto Second = co_await Preview->ReadSome(Buffer);
        EXPECT_EQ(Second.Bytes, 0U);
        EXPECT_EQ(Second.Failure.Code, Prism::Fault::Code::Eof);
        EXPECT_EQ(Inner->ReadCalls(), 0U);
        Prism::Testing::ExpectFixtureCloseReceipt(
            co_await Prism::Testing::CloseFixture(Preview));
        Prism::Testing::ExpectFixtureCloseReceipt(
            co_await Prism::Testing::CloseFixture(Inner));
    }

    auto RunTerminalOnlyFailureKeepsWriteHalf(Net::io_context& IoContext)
        -> Net::awaitable<void>
    {
        auto Inner = std::make_shared<PrefixTerminalMock>(IoContext.get_executor());
        auto Bytes = Prism::Testing::MakeTransportBytes();
        const auto AvailableBlocks = Bytes->AvailableBlocks();
        const auto Native = std::make_error_code(std::errc::connection_reset);
        const auto Created = Prism::Transport::PreviewTransport::Create(
            Inner, {{}, Bytes, Prism::Fault::FromNative(Native)});
        if (!Created)
        {
            ADD_FAILURE() << "PreviewTransport rejected a terminal-only prefix";
            co_return;
        }
        const auto Preview = *Created;
        std::array<std::byte, 8> Buffer{};
        EXPECT_NE(dynamic_cast<Prism::Transport::PreviewTransport*>(Preview.get()), nullptr);
        EXPECT_EQ(Bytes->AvailableBlocks(), AvailableBlocks);
        EXPECT_FALSE(Preview->Release());

        const auto First = co_await Preview->ReadSome(Buffer);
        const auto Second = co_await Preview->ReadSome(Buffer);
        EXPECT_EQ(First.Bytes, 0U);
        EXPECT_EQ(Second.Bytes, 0U);
        EXPECT_EQ(First.Failure.Native, Native);
        EXPECT_EQ(Second.Failure.Native, Native);
        EXPECT_FALSE(Preview->Release());

        const auto Written = co_await Preview->WriteSome(SvBytes("upload"));
        EXPECT_EQ(Written.Bytes, 6U);
        EXPECT_TRUE(Written.Failure.Succeeded());
        EXPECT_EQ(Inner->Written(), "upload");
        const auto Shutdown = co_await Preview->WriteShutdown();
        EXPECT_TRUE(Shutdown.has_value());
        EXPECT_EQ(Inner->WriteCalls(), 1U);
        EXPECT_EQ(Inner->WriteShutdownCalls(), 1U);

        const auto Third = co_await Preview->ReadSome(Buffer);
        EXPECT_EQ(Third.Bytes, 0U);
        EXPECT_EQ(Third.Failure.Native, Native);
        EXPECT_EQ(Inner->ReadCalls(), 0U);
        Prism::Testing::ExpectFixtureCloseReceipt(
            co_await Prism::Testing::CloseFixture(Preview));
        Prism::Testing::ExpectFixtureCloseReceipt(
            co_await Prism::Testing::CloseFixture(Inner));
    }

    auto RunEmptyReadPreservesTerminal(Net::io_context& IoContext)
        -> Net::awaitable<void>
    {
        auto Inner = std::make_shared<PrefixTerminalMock>(IoContext.get_executor());
        const auto Native = std::make_error_code(std::errc::connection_reset);
        const auto Created = Prism::Transport::PreviewTransport::Create(
            Inner, {{}, Prism::Testing::MakeTransportBytes(),
                    Prism::Fault::FromNative(Native)});
        if (!Created)
        {
            ADD_FAILURE() << "PreviewTransport rejected a terminal-only prefix";
            co_return;
        }
        const auto Preview = *Created;
        std::span<std::byte> EmptyBuffer;
        const auto EmptyRead = co_await Preview->ReadSome(EmptyBuffer);
        EXPECT_EQ(EmptyRead.Bytes, 0U);
        EXPECT_TRUE(EmptyRead.Failure.Succeeded());

        std::array<std::byte, 8> Buffer{};
        const auto TerminalRead = co_await Preview->ReadSome(Buffer);
        EXPECT_EQ(TerminalRead.Bytes, 0U);
        EXPECT_EQ(TerminalRead.Failure.Native, Native);
        EXPECT_EQ(Inner->ReadCalls(), 0U);
        Prism::Testing::ExpectFixtureCloseReceipt(
            co_await Prism::Testing::CloseFixture(Preview));
        Prism::Testing::ExpectFixtureCloseReceipt(
            co_await Prism::Testing::CloseFixture(Inner));
    }

    auto RunPrereadReturnedFirst(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        auto MemoryPair41 = Prism::Testing::MakeOwnedTransportPair(IoContext.get_executor());
        auto& Local = *MemoryPair41.FirstOwner;
        auto& Remote = *MemoryPair41.SecondOwner;
        auto Source = std::make_shared<Prism::MemoryStream>(std::move(Local));
        auto Destination = std::make_shared<Prism::MemoryStream>(std::move(Remote));
        auto TransportOwner40 = Prism::Transport::PreviewTransport::Create(Destination, {SvBytes("ABCDEF"), Prism::Testing::MakeTransportBytes(), {}}).value();
        auto& Transport = *TransportOwner40;
        std::array<std::byte, 3> Buffer{};
        Prism::Fault::Failure ErrorCode;
        auto Count = ([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Transport.ReadSome(std::span<std::byte>(Buffer)));
        EXPECT_EQ(Count, 3u);
        EXPECT_EQ(Prism::AsStrView(Prism::AsU8(std::span<std::byte>(Buffer))), "ABC");
        Count = ([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Transport.ReadSome(std::span<std::byte>(Buffer)));
        EXPECT_EQ(Count, 3u);
        EXPECT_EQ(Prism::AsStrView(Prism::AsU8(std::span<std::byte>(Buffer))), "DEF");
        Prism::Testing::ExpectFixtureCloseReceipt(co_await Prism::Testing::CloseFixture(TransportOwner40));
        Prism::Testing::ExpectFixtureCloseReceipt(co_await Prism::Testing::CloseFixture(Source));
    }

    auto RunExhaustedDelegatesToInner(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        auto MemoryPair39 = Prism::Testing::MakeOwnedTransportPair(IoContext.get_executor());
        auto& Local = *MemoryPair39.FirstOwner;
        auto& Remote = *MemoryPair39.SecondOwner;
        auto Source = std::make_shared<Prism::MemoryStream>(std::move(Local));
        auto Destination = std::make_shared<Prism::MemoryStream>(std::move(Remote));
        Prism::Fault::Failure ErrorCode;
        ([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Source->WriteSome(SvBytes("XYZ")));
        auto TransportOwner38 = Prism::Transport::PreviewTransport::Create(Destination, {SvBytes("PRE-"), Prism::Testing::MakeTransportBytes(), {}}).value();
        auto& Transport = *TransportOwner38;
        std::array<std::byte, 4> Buffer{};
        auto Count = ([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Transport.ReadSome(std::span<std::byte>(Buffer)));
        EXPECT_EQ(Count, 4u);
        EXPECT_EQ(Prism::AsStrView(Prism::AsU8(std::span<std::byte>(Buffer))), "PRE-");
        Count = ([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Transport.ReadSome(std::span<std::byte>(Buffer)));
        EXPECT_EQ(Count, 3u);
        EXPECT_EQ(Prism::AsStrView(Prism::AsU8(std::span<std::byte>(Buffer).first(3))), "XYZ");
        Prism::Testing::ExpectFixtureCloseReceipt(co_await Prism::Testing::CloseFixture(TransportOwner38));
        Prism::Testing::ExpectFixtureCloseReceipt(co_await Prism::Testing::CloseFixture(Source));
    }

    auto RunEofAfterPreread(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        auto MemoryPair37 = Prism::Testing::MakeOwnedTransportPair(IoContext.get_executor());
        auto& Local = *MemoryPair37.FirstOwner;
        auto& Remote = *MemoryPair37.SecondOwner;
        auto Source = std::make_shared<Prism::MemoryStream>(std::move(Local));
        auto Destination = std::make_shared<Prism::MemoryStream>(std::move(Remote));
        const auto ShutdownResult = co_await Source->WriteShutdown();
        EXPECT_TRUE(ShutdownResult.has_value());
        auto TransportOwner36 = Prism::Transport::PreviewTransport::Create(Destination, {SvBytes("ab"), Prism::Testing::MakeTransportBytes(), {}}).value();
        auto& Transport = *TransportOwner36;
        std::array<std::byte, 4> Buffer{};
        Prism::Fault::Failure ErrorCode;
        auto Count = ([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Transport.ReadSome(std::span<std::byte>(Buffer)));
        EXPECT_EQ(Count, 2u);
        EXPECT_TRUE(ErrorCode.Succeeded());
        Count = ([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Transport.ReadSome(std::span<std::byte>(Buffer)));
        EXPECT_EQ(Count, 0u);
        EXPECT_EQ(ErrorCode.Code, Prism::Fault::Code::Eof);
        Prism::Testing::ExpectFixtureCloseReceipt(co_await Prism::Testing::CloseFixture(TransportOwner36));
        Prism::Testing::ExpectFixtureCloseReceipt(co_await Prism::Testing::CloseFixture(Source));
    }

    auto RunCloseDiscardsUnconsumedPreread(Net::io_context &IoContext)
        -> Net::awaitable<void>
    {
        auto MemoryPair35 = Prism::Testing::MakeOwnedTransportPair(IoContext.get_executor());
        auto& Local = *MemoryPair35.FirstOwner;
        auto& Remote = *MemoryPair35.SecondOwner;
        auto Destination = std::make_shared<Prism::MemoryStream>(std::move(Remote));
        auto TransportOwner34 = Prism::Transport::PreviewTransport::Create(Destination, {SvBytes("cached"), Prism::Testing::MakeTransportBytes(), {}}).value();
        auto& Transport = *TransportOwner34;
        const auto TransportClose = Transport.Close();
        std::array<std::byte, 8> Buffer{};
        Prism::Fault::Failure ErrorCode;
        const auto Count = ([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Transport.ReadSome(Buffer));
        EXPECT_EQ(Count, 0U);
        EXPECT_EQ(ErrorCode.Code, Prism::Fault::Code::Canceled);
        const auto LocalClose = Local.Close();
        const auto TransportDrain = co_await Transport.Activity()->Drain();
        const auto LocalDrain = co_await Local.Activity()->Drain();
        EXPECT_TRUE(TransportClose.has_value());
        EXPECT_TRUE(LocalClose.has_value());
        EXPECT_TRUE(TransportDrain.has_value());
        EXPECT_TRUE(LocalDrain.has_value());
    }

    auto RunCaptureRewindReplay(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        auto MemoryPair33 = Prism::Testing::MakeOwnedTransportPair(IoContext.get_executor());
        auto& Local = *MemoryPair33.FirstOwner;
        auto& Remote = *MemoryPair33.SecondOwner;
        auto Source = std::make_shared<Prism::MemoryStream>(std::move(Local));
        auto Destination = std::make_shared<Prism::MemoryStream>(std::move(Remote));
        Prism::Fault::Failure ErrorCode;
        ([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Source->WriteSome(SvBytes("0123456789")));
        auto Snapshot = Prism::Transport::ReplayTransmission::Create(Destination, Prism::Transport::ReplayOptions{64U * 1024U, Prism::Transport::ReplayMode::Owned, Prism::Testing::MakeTransportBytes()}).value();
        EXPECT_TRUE(Snapshot->CanRewind());
        EXPECT_EQ(Snapshot->NextLayer(), Destination.get());
        std::array<std::byte, 4> Buffer{};
        auto Count = ([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Snapshot->ReadSome(std::span<std::byte>(Buffer)));
        EXPECT_EQ(Count, 4u);
        EXPECT_EQ(Prism::AsStrView(Prism::AsU8(std::span<std::byte>(Buffer))), "0123");
        EXPECT_TRUE(Snapshot->Rewind());
        EXPECT_TRUE(Snapshot->CanRewind());
        Count = ([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Snapshot->ReadSome(std::span<std::byte>(Buffer)));
        EXPECT_EQ(Count, 4u);
        EXPECT_EQ(Prism::AsStrView(Prism::AsU8(std::span<std::byte>(Buffer))), "0123");
        Prism::Testing::ExpectFixtureCloseReceipt(co_await Prism::Testing::CloseFixture(Snapshot));
        Prism::Testing::ExpectFixtureCloseReceipt(co_await Prism::Testing::CloseFixture(Source));
    }

    auto RunCaptureDataWithError(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        auto Inner = std::make_shared<PartialErrorMock>(IoContext.get_executor());
        auto Snapshot = Prism::Transport::ReplayTransmission::Create(Inner, Prism::Transport::ReplayOptions{64U * 1024U, Prism::Transport::ReplayMode::Owned, Prism::Testing::MakeTransportBytes()}).value();
        std::array<std::byte, 3> First{};
        Prism::Fault::Failure ErrorCode;
        const auto FirstRead = ([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Snapshot->ReadSome(First));
        EXPECT_EQ(FirstRead, 3U);
        EXPECT_EQ(ErrorCode.Native, std::make_error_code(std::errc::connection_reset));
        EXPECT_TRUE(Snapshot->Rewind());
        ErrorCode = {};
        std::array<std::byte, 3> Replay{};
        const auto ReplayRead = ([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Snapshot->ReadSome(Replay));
        EXPECT_EQ(ReplayRead, 3U);
        EXPECT_TRUE(ErrorCode.Succeeded());
        EXPECT_EQ(Replay, First);
        Prism::Testing::ExpectFixtureCloseReceipt(co_await Prism::Testing::CloseFixture(Snapshot));
    }

    auto RunRejectsCaptureBeyondConfiguredLimit(Net::io_context &IoContext)
        -> Net::awaitable<void>
    {
        auto MemoryPair32 = Prism::Testing::MakeOwnedTransportPair(IoContext.get_executor());
        auto& Local = *MemoryPair32.FirstOwner;
        auto& Remote = *MemoryPair32.SecondOwner;
        auto Source = std::make_shared<Prism::MemoryStream>(std::move(Local));
        auto Inner = std::make_shared<Prism::MemoryStream>(std::move(Remote));
        Prism::Fault::Failure ErrorCode;
        ([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Source->WriteSome(SvBytes("12345")));
        auto TransportOwner31 = Prism::Transport::ReplayTransmission::Create(Inner, Prism::Transport::ReplayOptions{4, Prism::Transport::ReplayMode::Owned, Prism::Testing::MakeTransportBytes()}).value();
        auto& Snapshot = *TransportOwner31;
        std::array<std::byte, 8> Buffer{};
        const auto First = ([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Snapshot.ReadSome(Buffer));
        EXPECT_EQ(First, 4U);
        EXPECT_TRUE(ErrorCode.Succeeded());
        ErrorCode = {};
        const auto Second = ([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Snapshot.ReadSome(Buffer));
        EXPECT_EQ(Second, 0U);
        EXPECT_EQ(ErrorCode.Code, Prism::Fault::Code::OversizedMsg);
        Prism::Testing::ExpectFixtureCloseReceipt(co_await Prism::Testing::CloseFixture(TransportOwner31));
        Prism::Testing::ExpectFixtureCloseReceipt(co_await Prism::Testing::CloseFixture(Source));
    }

    auto RunContinueAfterRewind(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        auto MemoryPair30 = Prism::Testing::MakeOwnedTransportPair(IoContext.get_executor());
        auto& Local = *MemoryPair30.FirstOwner;
        auto& Remote = *MemoryPair30.SecondOwner;
        auto Source = std::make_shared<Prism::MemoryStream>(std::move(Local));
        auto Destination = std::make_shared<Prism::MemoryStream>(std::move(Remote));
        Prism::Fault::Failure ErrorCode;
        ([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Source->WriteSome(SvBytes("0123456789")));
        auto Snapshot = Prism::Transport::ReplayTransmission::Create(Destination, Prism::Transport::ReplayOptions{64U * 1024U, Prism::Transport::ReplayMode::Owned, Prism::Testing::MakeTransportBytes()}).value();
        std::array<std::byte, 6> Buffer{};
        auto Count = ([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Snapshot->ReadSome(std::span<std::byte>(Buffer)));
        EXPECT_EQ(Count, 6u);
        EXPECT_TRUE(Snapshot->Rewind());
        Count = ([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Snapshot->ReadExact(std::span<std::byte>(Buffer)));
        EXPECT_EQ(Count, 6u);
        EXPECT_EQ(Prism::AsStrView(Prism::AsU8(std::span<std::byte>(Buffer))), "012345");
        std::array<std::byte, 8> Remaining{};
        Count = ([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Snapshot->ReadSome(std::span<std::byte>(Remaining)));
        EXPECT_EQ(Count, 4u);
        EXPECT_EQ(Prism::AsStrView(
                      Prism::AsU8(std::span<std::byte>(Remaining).first(4))), "6789");
        ([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Source->WriteSome(SvBytes("abcd")));
        Count = ([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Snapshot->ReadSome(std::span<std::byte>(Remaining)));
        EXPECT_EQ(Count, 4u);
        EXPECT_EQ(Prism::AsStrView(
                      Prism::AsU8(std::span<std::byte>(Remaining).first(4))), "abcd");
        Prism::Testing::ExpectFixtureCloseReceipt(co_await Prism::Testing::CloseFixture(Snapshot));
        Prism::Testing::ExpectFixtureCloseReceipt(co_await Prism::Testing::CloseFixture(Source));
    }

    auto RunWriteDisablesRewind(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        auto MemoryPair29 = Prism::Testing::MakeOwnedTransportPair(IoContext.get_executor());
        auto& Local = *MemoryPair29.FirstOwner;
        auto& Remote = *MemoryPair29.SecondOwner;
        auto Source = std::make_shared<Prism::MemoryStream>(std::move(Local));
        auto Destination = std::make_shared<Prism::MemoryStream>(std::move(Remote));
        auto Snapshot = Prism::Transport::ReplayTransmission::Create(Destination, Prism::Transport::ReplayOptions{64U * 1024U, Prism::Transport::ReplayMode::Owned, Prism::Testing::MakeTransportBytes()}).value();
        Prism::Fault::Failure ErrorCode;
        const auto Written = ([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Snapshot->WriteSome(SvBytes("out")));
        EXPECT_TRUE(ErrorCode.Succeeded());
        EXPECT_EQ(Written, 3u);
        EXPECT_FALSE(Snapshot->CanRewind());
        std::array<std::byte, 8> Buffer{};
        const auto ReadCount = ([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Source->ReadSome(std::span<std::byte>(Buffer)));
        EXPECT_EQ(ReadCount, 3u);
        EXPECT_EQ(Prism::AsStrView(
                      Prism::AsU8(std::span<std::byte>(Buffer).first(3))), "out");
        const auto SnapshotClose = Snapshot->Close();
        const auto SnapshotCancel = Snapshot->Cancel();
        const auto SnapshotDrain = co_await Snapshot->Activity()->Drain();
        const auto DestinationDrain = co_await Destination->Activity()->Drain();
        EXPECT_TRUE(SnapshotClose.has_value());
        EXPECT_TRUE(SnapshotCancel.has_value());
        EXPECT_TRUE(SnapshotDrain.has_value());
        EXPECT_TRUE(DestinationDrain.has_value());
        EXPECT_FALSE(Destination->IsOpen());
        EXPECT_TRUE(Source->IsOpen());
        Prism::Testing::ExpectFixtureCloseReceipt(co_await Prism::Testing::CloseFixture(Source));
    }

    auto RunRejectsRewindAfterWrite(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        auto MemoryPair28 = Prism::Testing::MakeOwnedTransportPair(IoContext.get_executor());
        auto& Local = *MemoryPair28.FirstOwner;
        auto& Remote = *MemoryPair28.SecondOwner;
        auto Source = std::make_shared<Prism::MemoryStream>(std::move(Local));
        auto Inner = std::make_shared<Prism::MemoryStream>(std::move(Remote));
        Prism::Fault::Failure ErrorCode;
        ([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Source->WriteSome(SvBytes("input")));
        EXPECT_TRUE(ErrorCode.Succeeded());
        auto TransportOwner27 = Prism::Transport::ReplayTransmission::Create(Inner, Prism::Transport::ReplayOptions{64U * 1024U, Prism::Transport::ReplayMode::Owned, Prism::Testing::MakeTransportBytes()}).value();
        auto& Snapshot = *TransportOwner27;
        std::array<std::byte, 2> Prefix{};
        EXPECT_EQ(([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Snapshot.ReadSome(Prefix)), 2U);
        EXPECT_EQ(Prism::AsStrView(Prism::AsU8(Prefix)), "in");
        ([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Snapshot.WriteSome(SvBytes("out")));
        EXPECT_TRUE(ErrorCode.Succeeded());
        EXPECT_FALSE(Snapshot.Rewind());
        std::array<std::byte, 3> Suffix{};
        EXPECT_EQ(([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Snapshot.ReadSome(Suffix)), 3U);
        EXPECT_EQ(Prism::AsStrView(Prism::AsU8(Suffix)), "put");
        Prism::Testing::ExpectFixtureCloseReceipt(co_await Prism::Testing::CloseFixture(TransportOwner27));
        Prism::Testing::ExpectFixtureCloseReceipt(co_await Prism::Testing::CloseFixture(Source));
    }

    auto RunCandidateCloseEscalation(Net::io_context& IoContext) -> Net::awaitable<void>
    {
        auto Inner = std::make_shared<PrefixTerminalMock>(IoContext.get_executor());
        auto Snapshot = Prism::Transport::ReplayTransmission::Create(
            Inner, Prism::Transport::ReplayOptions{
                64U * 1024U, Prism::Transport::ReplayMode::Candidate,
                Prism::Testing::MakeTransportBytes()}).value();

        const auto CandidateClose = Snapshot->Close();
        EXPECT_TRUE(CandidateClose.has_value());
        EXPECT_EQ(Inner->CloseCalls(), 0U);

        const auto Escalated = co_await Snapshot->CloseUnderlying();
        EXPECT_TRUE(Escalated.has_value());
        const auto Drain = co_await Snapshot->Activity()->Drain();
        EXPECT_TRUE(Drain.has_value());
        EXPECT_EQ(Inner->CloseCalls(), 1U);
    }

    auto RunCloseUnderlyingAndDrain(
        std::shared_ptr<Prism::Transport::ReplayTransmission> Snapshot,
        std::shared_ptr<PrefixTerminalMock> Inner) -> Net::awaitable<void>
    {
        const auto Closed = co_await Snapshot->CloseUnderlying();
        EXPECT_TRUE(Closed.has_value());
        const auto Drain = co_await Snapshot->Activity()->Drain();
        EXPECT_TRUE(Drain.has_value());
        EXPECT_EQ(Inner->CloseCalls(), 1U);
    }

    auto RunCloseUnderlyingWithoutPriorClose(Net::io_context& IoContext)
        -> Net::awaitable<void>
    {
        auto Inner = std::make_shared<PrefixTerminalMock>(IoContext.get_executor());
        auto Snapshot = Prism::Transport::ReplayTransmission::Create(
            Inner, {64U * 1024U, Prism::Transport::ReplayMode::Candidate,
                    Prism::Testing::MakeTransportBytes()}).value();
        co_await RunCloseUnderlyingAndDrain(std::move(Snapshot), std::move(Inner));
    }

    auto RunOwnedAndCommittedCloseUnderlying(Net::io_context& IoContext)
        -> Net::awaitable<void>
    {
        auto OwnedInner = std::make_shared<PrefixTerminalMock>(IoContext.get_executor());
        auto Owned = Prism::Transport::ReplayTransmission::Create(
            OwnedInner, {64U * 1024U, Prism::Transport::ReplayMode::Owned,
                        Prism::Testing::MakeTransportBytes()}).value();
        co_await RunCloseUnderlyingAndDrain(std::move(Owned), std::move(OwnedInner));

        auto CommittedInner = std::make_shared<PrefixTerminalMock>(IoContext.get_executor());
        auto Committed = Prism::Transport::ReplayTransmission::Create(
            CommittedInner, {64U * 1024U, Prism::Transport::ReplayMode::Candidate,
                             Prism::Testing::MakeTransportBytes()}).value();
        Committed->Commit();
        co_await RunCloseUnderlyingAndDrain(std::move(Committed), std::move(CommittedInner));
    }

    auto RunInnerCloseRejection(Net::io_context& IoContext) -> Net::awaitable<void>
    {
        auto Inner = std::make_shared<PrefixTerminalMock>(IoContext.get_executor());
        auto Snapshot = Prism::Transport::ReplayTransmission::Create(
            Inner, {64U * 1024U, Prism::Transport::ReplayMode::Candidate,
                    Prism::Testing::MakeTransportBytes()}).value();
        Inner->Activity()->Seal();
        const auto Closed = co_await Snapshot->CloseUnderlying();
        EXPECT_FALSE(Closed);
        if (Closed)
        {
            ADD_FAILURE() << "CloseUnderlying accepted a sealed inner activity";
            co_return;
        }
        EXPECT_EQ(Closed.error().Code, Prism::Fault::Code::Canceled);
        EXPECT_EQ(Inner->CloseCalls(), 0U);
        EXPECT_FALSE(Inner->Activity()->IsRetired());
        EXPECT_FALSE(Snapshot->Activity()->IsRetired());
    }

    auto RunOverlappingCloseUnderlying(Net::io_context& IoContext)
        -> Net::awaitable<void>
    {
        auto Inner = std::make_shared<PrefixTerminalMock>(IoContext.get_executor());
        auto Snapshot = Prism::Transport::ReplayTransmission::Create(
            Inner, {64U * 1024U, Prism::Transport::ReplayMode::Candidate,
                    Prism::Testing::MakeTransportBytes()}).value();
        Net::experimental::channel<void(boost::system::error_code)> Done(IoContext, 1);
        std::optional<Prism::Transmission::ControlResult> First;
        std::exception_ptr Exception;
        Net::co_spawn(IoContext, Snapshot->CloseUnderlying(),
            [&](std::exception_ptr Error, Prism::Transmission::ControlResult Result)
            {
                Exception = std::move(Error);
                First.emplace(std::move(Result));
                (void)Done.try_send(boost::system::error_code{});
            });
        co_await Net::post(IoContext.get_executor(), Net::use_awaitable);
        const auto Overlap = co_await Snapshot->CloseUnderlying();
        EXPECT_FALSE(Overlap);
        if (Overlap)
        {
            ADD_FAILURE() << "overlapping CloseUnderlying was accepted";
            co_return;
        }
        EXPECT_EQ(Overlap.error().Code, Prism::Fault::Code::WouldBlock);
        boost::system::error_code DoneError;
        (void)co_await Done.async_receive(
            Net::redirect_error(Net::use_awaitable, DoneError));
        EXPECT_FALSE(DoneError);
        EXPECT_EQ(Exception, nullptr);
        if (Exception || !First)
        {
            ADD_FAILURE() << "first CloseUnderlying task did not produce a result";
            co_return;
        }
        EXPECT_TRUE(*First);
        if (!*First)
        {
            ADD_FAILURE() << "first CloseUnderlying task failed";
            co_return;
        }
        EXPECT_EQ(Inner->CloseCalls(), 1U);
        const auto Drain = co_await Snapshot->Activity()->Drain();
        EXPECT_TRUE(Drain.has_value());
    }
} // namespace

TEST(PreviewTransport, PrereadReturnedFirst)
    {
        Net::io_context Ioc;
        RunCoro(Ioc, [IocPtr = &Ioc]() -> Net::awaitable<void>
                 { return RunPrereadReturnedFirst(*IocPtr); });
    }

TEST(PreviewTransport, ExhaustedDelegatesToInner)
    {
        Net::io_context Ioc;
        RunCoro(Ioc, [IocPtr = &Ioc]() -> Net::awaitable<void>
                 { return RunExhaustedDelegatesToInner(*IocPtr); });
    }

TEST(PreviewTransport, EofAfterPreread)
    {
        Net::io_context Ioc;
        RunCoro(Ioc, [IocPtr = &Ioc]() -> Net::awaitable<void>
                 { return RunEofAfterPreread(*IocPtr); });
    }

TEST(PreviewTransport, PrefixBytesDeliverEofAndKeepItSticky)
{
    Net::io_context Io;
    RunCoro(Io, RunPrefixBytesWithStickyEof(Io));
}

TEST(PreviewTransport, TerminalOnlyFailureIsStickyAndPreservesWrites)
{
    Net::io_context Io;
    RunCoro(Io, RunTerminalOnlyFailureKeepsWriteHalf(Io));
}

TEST(PreviewTransport, EmptyReadDoesNotConsumeTerminalOnlyFailure)
{
    Net::io_context Io;
    RunCoro(Io, RunEmptyReadPreservesTerminal(Io));
}

TEST(PreviewTransport, CloseDiscardsUnconsumedPreread)
    {
        Net::io_context Ioc;
        RunCoro(Ioc, [IocPtr = &Ioc]() -> Net::awaitable<void>
                 { return RunCloseDiscardsUnconsumedPreread(*IocPtr); });
    }

TEST(PreviewTransport, WrapWithPreviewBehavior)
    {
        Net::io_context Loop;
        auto MemoryPair26 = Prism::Testing::MakeOwnedTransportPair(Loop.get_executor());
        auto& LeftEnd = *MemoryPair26.FirstOwner;
        auto& RightEnd = *MemoryPair26.SecondOwner;
        auto LeftOwner = std::make_shared<Prism::MemoryStream>(std::move(LeftEnd));
        auto RightOwner = std::make_shared<Prism::MemoryStream>(std::move(RightEnd));

        // 空预读 → 不包装
        auto NotWrapped = Prism::Transport::PreviewTransport::Create(LeftOwner, {{}, Prism::Testing::MakeTransportBytes(), {}}).value();
        EXPECT_EQ(NotWrapped.get(), LeftOwner.get());

        // 非空预读 → 包装为 PreviewTransport
        auto Wrapped = Prism::Transport::PreviewTransport::Create(RightOwner, {SvBytes("hello"), Prism::Testing::MakeTransportBytes(), {}}).value();
        auto *PrereadCarrier = dynamic_cast<Prism::Transport::PreviewTransport *>(Wrapped.get());
        ASSERT_NE(PrereadCarrier, nullptr);
        EXPECT_EQ(PrereadCarrier->NextLayer(), RightOwner.get());
        EXPECT_EQ(Wrapped->TransportType(), Prism::Transmission::Type::Tcp);

        // completion-handler 风格预读路径
        std::promise<Prism::IoResult> Done;
        auto CompletedFuture = Done.get_future();
        auto TransportOwner25 = Prism::Transport::PreviewTransport::Create(RightOwner, {SvBytes("hi"), Prism::Testing::MakeTransportBytes(), {}}).value();
        auto& SecondPreread = *TransportOwner25;
        std::array<std::byte, 8> IoBuffer{};
        SecondPreread.ReadSome(std::span<std::byte>(IoBuffer), [&](Prism::IoResult Result)
                            { Done.set_value(Result); });
        Loop.run();
        const auto Result = CompletedFuture.get();
        EXPECT_TRUE(Result.Failure.Succeeded());
        EXPECT_EQ(Result.Bytes, 2u);
        EXPECT_EQ(Prism::AsStrView(Prism::AsU8(std::span<std::byte>(IoBuffer).first(2))), "hi");
        Prism::Testing::ExpectFixtureCloseReceipt(Prism::Testing::DriveClose(Loop, TransportOwner25));
        Prism::Testing::ExpectFixtureCloseReceipt(Prism::Testing::DriveClose(Loop, LeftOwner));
    }

TEST(Snapshot, CaptureRewindReplay)
    {
        Net::io_context Ioc;
        RunCoro(Ioc, [IocPtr = &Ioc]() -> Net::awaitable<void>
                 { return RunCaptureRewindReplay(*IocPtr); });
    }

TEST(Snapshot, CapturesDataReturnedWithError)
    {
        Net::io_context Ioc;
        RunCoro(Ioc, [IocPtr = &Ioc]() -> Net::awaitable<void>
                 { return RunCaptureDataWithError(*IocPtr); });
    }

TEST(Snapshot, RejectsCaptureBeyondConfiguredLimit)
    {
        Net::io_context Ioc;
        RunCoro(Ioc, [IocPtr = &Ioc]() -> Net::awaitable<void>
                 { return RunRejectsCaptureBeyondConfiguredLimit(*IocPtr); });
    }

TEST(Snapshot, ContinueAfterRewind)
    {
        Net::io_context Ioc;
        RunCoro(Ioc, [IocPtr = &Ioc]() -> Net::awaitable<void>
                 { return RunContinueAfterRewind(*IocPtr); });
    }

TEST(Snapshot, WriteDisablesRewind)
    {
        Net::io_context Ioc;
        RunCoro(Ioc, [IocPtr = &Ioc]() -> Net::awaitable<void>
                 { return RunWriteDisablesRewind(*IocPtr); });
    }

TEST(Snapshot, RejectsRewindAfterWrite)
    {
        Net::io_context Ioc;
        RunCoro(Ioc, [IocPtr = &Ioc]() -> Net::awaitable<void>
                 { return RunRejectsRewindAfterWrite(*IocPtr); });
    }

TEST(Snapshot, CandidateCloseEscalationClosesUnderlyingOnceAndDrains)
{
    Net::io_context Io;
    RunCoro(Io, RunCandidateCloseEscalation(Io));
}

TEST(Snapshot, CloseUnderlyingStartsWithoutPriorClose)
{
    Net::io_context Io;
    RunCoro(Io, RunCloseUnderlyingWithoutPriorClose(Io));
}

TEST(Snapshot, CompletedCandidateCloseEscalatesAndDrains)
{
    Net::io_context Io;
    auto Inner = std::make_shared<PrefixTerminalMock>(Io.get_executor());
    auto Snapshot = Prism::Transport::ReplayTransmission::Create(
        Inner, {64U * 1024U, Prism::Transport::ReplayMode::Candidate,
                Prism::Testing::MakeTransportBytes()}).value();
    ASSERT_TRUE(Snapshot->Close());
    ASSERT_EQ(Io.run_one(), 1U);
    EXPECT_EQ(Inner->CloseCalls(), 0U);
    RunCoro(Io, RunCloseUnderlyingAndDrain(std::move(Snapshot), std::move(Inner)));
}

TEST(Snapshot, CloseUnderlyingHonorsOwnedAndCommittedModes)
{
    Net::io_context Io;
    RunCoro(Io, RunOwnedAndCommittedCloseUnderlying(Io));
}

TEST(Snapshot, RejectedInnerClosePreservesFailureWithoutChildDrain)
{
    Net::io_context Io;
    RunCoro(Io, RunInnerCloseRejection(Io));
}

TEST(Snapshot, OverlappingCloseUnderlyingReturnsWouldBlock)
{
    Net::io_context Io;
    RunCoro(Io, RunOverlappingCloseUnderlying(Io));
}
