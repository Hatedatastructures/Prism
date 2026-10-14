/**
 * @file PreviewTransportTest.cpp
 * @brief 按功能拆分的 GoogleTest 行为契约。
 */

#include "TransportDecoratorTestSupport.hpp"
#include "TransportResources.hpp"

namespace
{
    auto RunPrereadReturnedFirst(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        auto MemoryPair41 = Preview::Testing::MakeOwnedTransportPair(IoContext.get_executor());
        auto& Local = *MemoryPair41.FirstOwner;
        auto& Remote = *MemoryPair41.SecondOwner;
        auto Source = std::make_shared<Preview::MemoryStream>(std::move(Local));
        auto Destination = std::make_shared<Preview::MemoryStream>(std::move(Remote));
        auto TransportOwner40 = Preview::Transport::PreviewTransport::Create(Destination, {SvBytes("ABCDEF"), Preview::Testing::MakeTransportBytes(), {}}).value();
        auto& Transport = *TransportOwner40;
        std::array<std::byte, 3> Buffer{};
        Preview::Fault::Failure ErrorCode;
        auto Count = ([&](Preview::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Transport.ReadSome(std::span<std::byte>(Buffer)));
        EXPECT_EQ(Count, 3u);
        EXPECT_EQ(Preview::AsStrView(Preview::AsU8(std::span<std::byte>(Buffer))), "ABC");
        Count = ([&](Preview::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Transport.ReadSome(std::span<std::byte>(Buffer)));
        EXPECT_EQ(Count, 3u);
        EXPECT_EQ(Preview::AsStrView(Preview::AsU8(std::span<std::byte>(Buffer))), "DEF");
        Preview::Testing::ExpectFixtureCloseReceipt(co_await Preview::Testing::CloseFixture(TransportOwner40));
        Preview::Testing::ExpectFixtureCloseReceipt(co_await Preview::Testing::CloseFixture(Source));
    }

    auto RunExhaustedDelegatesToInner(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        auto MemoryPair39 = Preview::Testing::MakeOwnedTransportPair(IoContext.get_executor());
        auto& Local = *MemoryPair39.FirstOwner;
        auto& Remote = *MemoryPair39.SecondOwner;
        auto Source = std::make_shared<Preview::MemoryStream>(std::move(Local));
        auto Destination = std::make_shared<Preview::MemoryStream>(std::move(Remote));
        Preview::Fault::Failure ErrorCode;
        ([&](Preview::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Source->WriteSome(SvBytes("XYZ")));
        auto TransportOwner38 = Preview::Transport::PreviewTransport::Create(Destination, {SvBytes("PRE-"), Preview::Testing::MakeTransportBytes(), {}}).value();
        auto& Transport = *TransportOwner38;
        std::array<std::byte, 4> Buffer{};
        auto Count = ([&](Preview::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Transport.ReadSome(std::span<std::byte>(Buffer)));
        EXPECT_EQ(Count, 4u);
        EXPECT_EQ(Preview::AsStrView(Preview::AsU8(std::span<std::byte>(Buffer))), "PRE-");
        Count = ([&](Preview::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Transport.ReadSome(std::span<std::byte>(Buffer)));
        EXPECT_EQ(Count, 3u);
        EXPECT_EQ(Preview::AsStrView(Preview::AsU8(std::span<std::byte>(Buffer).first(3))), "XYZ");
        Preview::Testing::ExpectFixtureCloseReceipt(co_await Preview::Testing::CloseFixture(TransportOwner38));
        Preview::Testing::ExpectFixtureCloseReceipt(co_await Preview::Testing::CloseFixture(Source));
    }

    auto RunEofAfterPreread(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        auto MemoryPair37 = Preview::Testing::MakeOwnedTransportPair(IoContext.get_executor());
        auto& Local = *MemoryPair37.FirstOwner;
        auto& Remote = *MemoryPair37.SecondOwner;
        auto Source = std::make_shared<Preview::MemoryStream>(std::move(Local));
        auto Destination = std::make_shared<Preview::MemoryStream>(std::move(Remote));
        const auto ShutdownResult = co_await Source->WriteShutdown();
        EXPECT_TRUE(ShutdownResult.has_value());
        auto TransportOwner36 = Preview::Transport::PreviewTransport::Create(Destination, {SvBytes("ab"), Preview::Testing::MakeTransportBytes(), {}}).value();
        auto& Transport = *TransportOwner36;
        std::array<std::byte, 4> Buffer{};
        Preview::Fault::Failure ErrorCode;
        auto Count = ([&](Preview::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Transport.ReadSome(std::span<std::byte>(Buffer)));
        EXPECT_EQ(Count, 2u);
        EXPECT_TRUE(ErrorCode.Succeeded());
        Count = ([&](Preview::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Transport.ReadSome(std::span<std::byte>(Buffer)));
        EXPECT_EQ(Count, 0u);
        EXPECT_EQ(ErrorCode.Code, Preview::Fault::Code::Eof);
        Preview::Testing::ExpectFixtureCloseReceipt(co_await Preview::Testing::CloseFixture(TransportOwner36));
        Preview::Testing::ExpectFixtureCloseReceipt(co_await Preview::Testing::CloseFixture(Source));
    }

    auto RunCloseDiscardsUnconsumedPreread(Net::io_context &IoContext)
        -> Net::awaitable<void>
    {
        auto MemoryPair35 = Preview::Testing::MakeOwnedTransportPair(IoContext.get_executor());
        auto& Local = *MemoryPair35.FirstOwner;
        auto& Remote = *MemoryPair35.SecondOwner;
        auto Destination = std::make_shared<Preview::MemoryStream>(std::move(Remote));
        auto TransportOwner34 = Preview::Transport::PreviewTransport::Create(Destination, {SvBytes("cached"), Preview::Testing::MakeTransportBytes(), {}}).value();
        auto& Transport = *TransportOwner34;
        const auto TransportClose = Transport.Close();
        std::array<std::byte, 8> Buffer{};
        Preview::Fault::Failure ErrorCode;
        const auto Count = ([&](Preview::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Transport.ReadSome(Buffer));
        EXPECT_EQ(Count, 0U);
        EXPECT_EQ(ErrorCode.Code, Preview::Fault::Code::Canceled);
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
        auto MemoryPair33 = Preview::Testing::MakeOwnedTransportPair(IoContext.get_executor());
        auto& Local = *MemoryPair33.FirstOwner;
        auto& Remote = *MemoryPair33.SecondOwner;
        auto Source = std::make_shared<Preview::MemoryStream>(std::move(Local));
        auto Destination = std::make_shared<Preview::MemoryStream>(std::move(Remote));
        Preview::Fault::Failure ErrorCode;
        ([&](Preview::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Source->WriteSome(SvBytes("0123456789")));
        auto Snapshot = Preview::Transport::ReplayTransmission::Create(Destination, Preview::Transport::ReplayOptions{64U * 1024U, Preview::Transport::ReplayMode::Owned, Preview::Testing::MakeTransportBytes()}).value();
        EXPECT_TRUE(Snapshot->CanRewind());
        EXPECT_EQ(Snapshot->NextLayer(), Destination.get());
        std::array<std::byte, 4> Buffer{};
        auto Count = ([&](Preview::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Snapshot->ReadSome(std::span<std::byte>(Buffer)));
        EXPECT_EQ(Count, 4u);
        EXPECT_EQ(Preview::AsStrView(Preview::AsU8(std::span<std::byte>(Buffer))), "0123");
        EXPECT_TRUE(Snapshot->Rewind());
        EXPECT_TRUE(Snapshot->CanRewind());
        Count = ([&](Preview::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Snapshot->ReadSome(std::span<std::byte>(Buffer)));
        EXPECT_EQ(Count, 4u);
        EXPECT_EQ(Preview::AsStrView(Preview::AsU8(std::span<std::byte>(Buffer))), "0123");
        Preview::Testing::ExpectFixtureCloseReceipt(co_await Preview::Testing::CloseFixture(Snapshot));
        Preview::Testing::ExpectFixtureCloseReceipt(co_await Preview::Testing::CloseFixture(Source));
    }

    auto RunCaptureDataWithError(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        auto Inner = std::make_shared<PartialErrorMock>(IoContext.get_executor());
        auto Snapshot = Preview::Transport::ReplayTransmission::Create(Inner, Preview::Transport::ReplayOptions{64U * 1024U, Preview::Transport::ReplayMode::Owned, Preview::Testing::MakeTransportBytes()}).value();
        std::array<std::byte, 3> First{};
        Preview::Fault::Failure ErrorCode;
        const auto FirstRead = ([&](Preview::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Snapshot->ReadSome(First));
        EXPECT_EQ(FirstRead, 3U);
        EXPECT_EQ(ErrorCode.Native, std::make_error_code(std::errc::connection_reset));
        EXPECT_TRUE(Snapshot->Rewind());
        ErrorCode = {};
        std::array<std::byte, 3> Replay{};
        const auto ReplayRead = ([&](Preview::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Snapshot->ReadSome(Replay));
        EXPECT_EQ(ReplayRead, 3U);
        EXPECT_TRUE(ErrorCode.Succeeded());
        EXPECT_EQ(Replay, First);
        Preview::Testing::ExpectFixtureCloseReceipt(co_await Preview::Testing::CloseFixture(Snapshot));
    }

    auto RunRejectsCaptureBeyondConfiguredLimit(Net::io_context &IoContext)
        -> Net::awaitable<void>
    {
        auto MemoryPair32 = Preview::Testing::MakeOwnedTransportPair(IoContext.get_executor());
        auto& Local = *MemoryPair32.FirstOwner;
        auto& Remote = *MemoryPair32.SecondOwner;
        auto Source = std::make_shared<Preview::MemoryStream>(std::move(Local));
        auto Inner = std::make_shared<Preview::MemoryStream>(std::move(Remote));
        Preview::Fault::Failure ErrorCode;
        ([&](Preview::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Source->WriteSome(SvBytes("12345")));
        auto TransportOwner31 = Preview::Transport::ReplayTransmission::Create(Inner, Preview::Transport::ReplayOptions{4, Preview::Transport::ReplayMode::Owned, Preview::Testing::MakeTransportBytes()}).value();
        auto& Snapshot = *TransportOwner31;
        std::array<std::byte, 8> Buffer{};
        const auto First = ([&](Preview::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Snapshot.ReadSome(Buffer));
        EXPECT_EQ(First, 4U);
        EXPECT_TRUE(ErrorCode.Succeeded());
        ErrorCode = {};
        const auto Second = ([&](Preview::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Snapshot.ReadSome(Buffer));
        EXPECT_EQ(Second, 0U);
        EXPECT_EQ(ErrorCode.Code, Preview::Fault::Code::OversizedMsg);
        Preview::Testing::ExpectFixtureCloseReceipt(co_await Preview::Testing::CloseFixture(TransportOwner31));
        Preview::Testing::ExpectFixtureCloseReceipt(co_await Preview::Testing::CloseFixture(Source));
    }

    auto RunContinueAfterRewind(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        auto MemoryPair30 = Preview::Testing::MakeOwnedTransportPair(IoContext.get_executor());
        auto& Local = *MemoryPair30.FirstOwner;
        auto& Remote = *MemoryPair30.SecondOwner;
        auto Source = std::make_shared<Preview::MemoryStream>(std::move(Local));
        auto Destination = std::make_shared<Preview::MemoryStream>(std::move(Remote));
        Preview::Fault::Failure ErrorCode;
        ([&](Preview::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Source->WriteSome(SvBytes("0123456789")));
        auto Snapshot = Preview::Transport::ReplayTransmission::Create(Destination, Preview::Transport::ReplayOptions{64U * 1024U, Preview::Transport::ReplayMode::Owned, Preview::Testing::MakeTransportBytes()}).value();
        std::array<std::byte, 6> Buffer{};
        auto Count = ([&](Preview::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Snapshot->ReadSome(std::span<std::byte>(Buffer)));
        EXPECT_EQ(Count, 6u);
        EXPECT_TRUE(Snapshot->Rewind());
        Count = ([&](Preview::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Snapshot->ReadExact(std::span<std::byte>(Buffer)));
        EXPECT_EQ(Count, 6u);
        EXPECT_EQ(Preview::AsStrView(Preview::AsU8(std::span<std::byte>(Buffer))), "012345");
        std::array<std::byte, 8> Remaining{};
        Count = ([&](Preview::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Snapshot->ReadSome(std::span<std::byte>(Remaining)));
        EXPECT_EQ(Count, 4u);
        EXPECT_EQ(Preview::AsStrView(
                      Preview::AsU8(std::span<std::byte>(Remaining).first(4))), "6789");
        ([&](Preview::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Source->WriteSome(SvBytes("abcd")));
        Count = ([&](Preview::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Snapshot->ReadSome(std::span<std::byte>(Remaining)));
        EXPECT_EQ(Count, 4u);
        EXPECT_EQ(Preview::AsStrView(
                      Preview::AsU8(std::span<std::byte>(Remaining).first(4))), "abcd");
        Preview::Testing::ExpectFixtureCloseReceipt(co_await Preview::Testing::CloseFixture(Snapshot));
        Preview::Testing::ExpectFixtureCloseReceipt(co_await Preview::Testing::CloseFixture(Source));
    }

    auto RunWriteDisablesRewind(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        auto MemoryPair29 = Preview::Testing::MakeOwnedTransportPair(IoContext.get_executor());
        auto& Local = *MemoryPair29.FirstOwner;
        auto& Remote = *MemoryPair29.SecondOwner;
        auto Source = std::make_shared<Preview::MemoryStream>(std::move(Local));
        auto Destination = std::make_shared<Preview::MemoryStream>(std::move(Remote));
        auto Snapshot = Preview::Transport::ReplayTransmission::Create(Destination, Preview::Transport::ReplayOptions{64U * 1024U, Preview::Transport::ReplayMode::Owned, Preview::Testing::MakeTransportBytes()}).value();
        Preview::Fault::Failure ErrorCode;
        const auto Written = ([&](Preview::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Snapshot->WriteSome(SvBytes("out")));
        EXPECT_TRUE(ErrorCode.Succeeded());
        EXPECT_EQ(Written, 3u);
        EXPECT_FALSE(Snapshot->CanRewind());
        std::array<std::byte, 8> Buffer{};
        const auto ReadCount = ([&](Preview::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Source->ReadSome(std::span<std::byte>(Buffer)));
        EXPECT_EQ(ReadCount, 3u);
        EXPECT_EQ(Preview::AsStrView(
                      Preview::AsU8(std::span<std::byte>(Buffer).first(3))), "out");
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
        Preview::Testing::ExpectFixtureCloseReceipt(co_await Preview::Testing::CloseFixture(Source));
    }

    auto RunRejectsRewindAfterWrite(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        auto MemoryPair28 = Preview::Testing::MakeOwnedTransportPair(IoContext.get_executor());
        auto& Local = *MemoryPair28.FirstOwner;
        auto& Remote = *MemoryPair28.SecondOwner;
        auto Source = std::make_shared<Preview::MemoryStream>(std::move(Local));
        auto Inner = std::make_shared<Preview::MemoryStream>(std::move(Remote));
        Preview::Fault::Failure ErrorCode;
        ([&](Preview::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Source->WriteSome(SvBytes("input")));
        EXPECT_TRUE(ErrorCode.Succeeded());
        auto TransportOwner27 = Preview::Transport::ReplayTransmission::Create(Inner, Preview::Transport::ReplayOptions{64U * 1024U, Preview::Transport::ReplayMode::Owned, Preview::Testing::MakeTransportBytes()}).value();
        auto& Snapshot = *TransportOwner27;
        std::array<std::byte, 2> Prefix{};
        EXPECT_EQ(([&](Preview::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Snapshot.ReadSome(Prefix)), 2U);
        EXPECT_EQ(Preview::AsStrView(Preview::AsU8(Prefix)), "in");
        ([&](Preview::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Snapshot.WriteSome(SvBytes("out")));
        EXPECT_TRUE(ErrorCode.Succeeded());
        EXPECT_FALSE(Snapshot.Rewind());
        std::array<std::byte, 3> Suffix{};
        EXPECT_EQ(([&](Preview::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Snapshot.ReadSome(Suffix)), 3U);
        EXPECT_EQ(Preview::AsStrView(Preview::AsU8(Suffix)), "put");
        Preview::Testing::ExpectFixtureCloseReceipt(co_await Preview::Testing::CloseFixture(TransportOwner27));
        Preview::Testing::ExpectFixtureCloseReceipt(co_await Preview::Testing::CloseFixture(Source));
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

TEST(PreviewTransport, CloseDiscardsUnconsumedPreread)
    {
        Net::io_context Ioc;
        RunCoro(Ioc, [IocPtr = &Ioc]() -> Net::awaitable<void>
                 { return RunCloseDiscardsUnconsumedPreread(*IocPtr); });
    }

TEST(PreviewTransport, WrapWithPreviewBehavior)
    {
        Net::io_context Loop;
        auto MemoryPair26 = Preview::Testing::MakeOwnedTransportPair(Loop.get_executor());
        auto& LeftEnd = *MemoryPair26.FirstOwner;
        auto& RightEnd = *MemoryPair26.SecondOwner;
        auto LeftOwner = std::make_shared<Preview::MemoryStream>(std::move(LeftEnd));
        auto RightOwner = std::make_shared<Preview::MemoryStream>(std::move(RightEnd));

        // 空预读 → 不包装
        auto NotWrapped = Preview::Transport::PreviewTransport::Create(LeftOwner, {{}, Preview::Testing::MakeTransportBytes(), {}}).value();
        EXPECT_EQ(NotWrapped.get(), LeftOwner.get());

        // 非空预读 → 包装为 PreviewTransport
        auto Wrapped = Preview::Transport::PreviewTransport::Create(RightOwner, {SvBytes("hello"), Preview::Testing::MakeTransportBytes(), {}}).value();
        auto *PrereadCarrier = dynamic_cast<Preview::Transport::PreviewTransport *>(Wrapped.get());
        ASSERT_NE(PrereadCarrier, nullptr);
        EXPECT_EQ(PrereadCarrier->NextLayer(), RightOwner.get());
        EXPECT_EQ(Wrapped->TransportType(), Preview::Transmission::Type::Tcp);

        // completion-handler 风格预读路径
        std::promise<Preview::IoResult> Done;
        auto CompletedFuture = Done.get_future();
        auto TransportOwner25 = Preview::Transport::PreviewTransport::Create(RightOwner, {SvBytes("hi"), Preview::Testing::MakeTransportBytes(), {}}).value();
        auto& SecondPreread = *TransportOwner25;
        std::array<std::byte, 8> IoBuffer{};
        SecondPreread.ReadSome(std::span<std::byte>(IoBuffer), [&](Preview::IoResult Result)
                            { Done.set_value(Result); });
        Loop.run();
        const auto Result = CompletedFuture.get();
        EXPECT_TRUE(Result.Failure.Succeeded());
        EXPECT_EQ(Result.Bytes, 2u);
        EXPECT_EQ(Preview::AsStrView(Preview::AsU8(std::span<std::byte>(IoBuffer).first(2))), "hi");
        Preview::Testing::ExpectFixtureCloseReceipt(Preview::Testing::DriveClose(Loop, TransportOwner25));
        Preview::Testing::ExpectFixtureCloseReceipt(Preview::Testing::DriveClose(Loop, LeftOwner));
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
