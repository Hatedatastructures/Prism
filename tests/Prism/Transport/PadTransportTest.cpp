/**
 * @file PadTransportTest.cpp
 * @brief 按功能拆分的 GoogleTest 行为契约。
 */

#include "TransportDecoratorTestSupport.hpp"
#include "TransportResources.hpp"

namespace
{
    /**
     * @brief 验证固定 pad target 的小包补齐和大包零填充。
     * @param Pad 待测试的 pad owner。
     * @param Sink 接收 wire 数据的 mock owner。
     * @return 完成两次边界写入及长度断言的异步操作。
     */
    auto RunPadMinBoundary(Prism::Transport::PadTransport &Pad, FakeSink &Sink)
        -> Net::awaitable<void>
    {
        std::array<std::byte, 3> Small{std::byte{1}, std::byte{2}, std::byte{3}};
        std::array<std::byte, 8> Large{};
        Prism::Fault::Failure ErrorCode;
        const auto SmallCount = ([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Pad.WriteSome(std::span<const std::byte>(Small)));
        EXPECT_TRUE(ErrorCode.Succeeded());
        EXPECT_EQ(SmallCount, 3u);
        EXPECT_EQ(Sink.Written_.size(), 5u);

        const auto LargeCount = ([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Pad.WriteSome(std::span<const std::byte>(Large)));
        EXPECT_TRUE(ErrorCode.Succeeded());
        EXPECT_EQ(LargeCount, 8u);
        EXPECT_EQ(Sink.Written_.size(), 13u);
    }

    /**
     * @brief 验证启用/禁用 padding 通过 memory pipe 保持原始 payload。
     * @param IoContext 驱动两个 memory endpoint 的执行器。
     * @return 完成写入、读取和逐字节 payload 对拍的异步操作。
     */
    auto RunPadDataPassthrough(Net::io_context &IoContext) -> Net::awaitable<void>
    {
        auto MemoryPair24 = Prism::Testing::MakeOwnedTransportPair(IoContext.get_executor());
        auto& Local = *MemoryPair24.FirstOwner;
        auto& Remote = *MemoryPair24.SecondOwner;
        auto Source = std::make_shared<Prism::MemoryStream>(std::move(Local));
        auto Destination = std::make_shared<Prism::MemoryStream>(std::move(Remote));

        Prism::Transport::PadConfig Config;
        auto TransportOwner23 = std::make_shared<Prism::Transport::PadTransport>(Source, Prism::Testing::MakePadOptions(Config));
        auto& Pad = *TransportOwner23;
        const std::string_view Message = "hello world, padding must not corrupt me";
        Prism::Fault::Failure ErrorCode;
        const auto Written = ([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Pad.WriteSome(SvBytes(Message)));
        EXPECT_TRUE(ErrorCode.Succeeded());
        EXPECT_EQ(Written, Message.size());

        std::vector<std::byte> Buffer(Message.size());
        const auto ReadCount = ([&](Prism::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Destination->ReadExact(std::span<std::byte>(Buffer)));
        EXPECT_TRUE(ErrorCode.Succeeded());
        EXPECT_EQ(ReadCount, Message.size());
        EXPECT_EQ(Prism::AsStrView(Prism::AsU8(std::span<const std::byte>(Buffer))), Message);
        const auto PadReceipt = co_await Prism::Testing::CloseFixture(TransportOwner23);
        const auto SourceDrain = co_await Source->Activity()->Drain();
        const auto DestinationReceipt = co_await Prism::Testing::CloseFixture(Destination);
        Prism::Testing::ExpectFixtureCloseReceipt(PadReceipt);
        EXPECT_TRUE(SourceDrain.has_value());
        Prism::Testing::ExpectFixtureCloseReceipt(DestinationReceipt);
    }
} // namespace

TEST(PadTransport, EnabledDisabled)
    {
        Prism::Transport::PadConfig Def;
        EXPECT_TRUE(Def.Enabled());

        Prism::Transport::PadConfig Off;
        Off.Targets = *Prism::Transport::ParsePadTargets("");
        EXPECT_FALSE(Off.Enabled());

        // 禁用填充：透传零开销（写入字节数 == 数据长度）
        Net::io_context Loop;
        auto OutputSink = std::make_shared<FakeSink>(Loop.get_executor());
        auto TransportOwner22 = std::make_shared<Prism::Transport::PadTransport>(OutputSink, Prism::Testing::MakePadOptions(Off));
        auto& Padding = *TransportOwner22;
        const std::string_view Message = "raw-passthrough";
        Prism::Fault::Failure OperationFailure;
        Net::co_spawn(
            Loop,
                 [&]() -> Net::awaitable<void>
            {
                const auto ByteCount = ([&](Prism::IoResult Result) { OperationFailure = Result.Failure; return Result.Bytes; })(co_await Padding.WriteSome(SvBytes(Message)));
                EXPECT_EQ(ByteCount, Message.size());
                EXPECT_TRUE(OperationFailure.Succeeded());
            },
            Net::detached);
        Loop.run();
        EXPECT_EQ(OutputSink->Written_.size(), Message.size());
        EXPECT_EQ(Prism::AsStrView(Prism::AsU8(std::span<const std::byte>(OutputSink->Written_))), Message);
        Prism::Testing::ExpectFixtureCloseReceipt(Prism::Testing::DriveClose(Loop, TransportOwner22));
        EXPECT_TRUE(Prism::Testing::DriveDrain(Loop, OutputSink).has_value());
    }

TEST(PadTransport, RandomSourceFailureStopsEnabledPadding)
    {
        Net::io_context Ioc;
        auto Sink = std::make_shared<FakeSink>(Ioc.get_executor());
        Prism::Transport::PadConfig Config;
        Config.Targets = *Prism::Transport::ParsePadTargets("5");
        auto TransportOwner21 = std::make_shared<Prism::Transport::PadTransport>(Sink, Prism::Testing::MakePadOptions(Config, [](std::uint8_t *, int) { return 0; }));
        auto& Pad = *TransportOwner21;

        EXPECT_FALSE(Pad.IsValid());
        RunCoro(Ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     Prism::Fault::Failure Error;
                     const auto Count = ([&](Prism::IoResult Result) { Error = Result.Failure; return Result.Bytes; })(co_await Pad.WriteSome(SvBytes("abc")));
                     EXPECT_EQ(Count, 0U);
                     EXPECT_EQ(Error.Code, Prism::Fault::Code::CryptoError);
                     EXPECT_TRUE(Sink->Written_.empty());
                 });
        Prism::Testing::ExpectFixtureCloseReceipt(Prism::Testing::DriveClose(Ioc, TransportOwner21));
        EXPECT_TRUE(Prism::Testing::DriveDrain(Ioc, Sink).has_value());
    }

TEST(PadTransport, MinBoundaryPadToTarget)
    {
        // 固定目标 "5"：小数据补齐到 5 字节，大数据零填充
        Net::io_context Loop;
        auto OutputSink = std::make_shared<FakeSink>(Loop.get_executor());
        Prism::Transport::PadConfig Configuration;
        Configuration.Targets = *Prism::Transport::ParsePadTargets("5");
        Configuration.MaxPadBytes = 0; // 数据 >= 目标时零填充，保证确定性
        auto TransportOwner20 = std::make_shared<Prism::Transport::PadTransport>(OutputSink, Prism::Testing::MakePadOptions(Configuration));
        auto& Padding = *TransportOwner20;

        RunCoro(Loop, RunPadMinBoundary(Padding, *OutputSink));
        Prism::Testing::ExpectFixtureCloseReceipt(Prism::Testing::DriveClose(Loop, TransportOwner20));
        EXPECT_TRUE(Prism::Testing::DriveDrain(Loop, OutputSink).has_value());
    }

TEST(PadTransport, MaxBoundaryRange)
    {
        // 区间 "80-150"：填充后总大小必须落在区间内
        Net::io_context Loop;
        auto OutputSink = std::make_shared<FakeSink>(Loop.get_executor());
        Prism::Transport::PadConfig Configuration;
        Configuration.Targets = *Prism::Transport::ParsePadTargets("80-150");
        auto TransportOwner19 = std::make_shared<Prism::Transport::PadTransport>(OutputSink, Prism::Testing::MakePadOptions(Configuration));
        auto& Padding = *TransportOwner19;

        const std::string_view Message = "ten-Bytes";
        Prism::Fault::Failure OperationFailure;
        Net::co_spawn(
            Loop,
                 [&]() -> Net::awaitable<void>
            {
                const auto ByteCount = ([&](Prism::IoResult Result) { OperationFailure = Result.Failure; return Result.Bytes; })(co_await Padding.WriteSome(SvBytes(Message)));
                EXPECT_TRUE(OperationFailure.Succeeded());
                EXPECT_EQ(ByteCount, Message.size());
            },
            Net::detached);
        Loop.run();
        ASSERT_GE(OutputSink->Written_.size(), 80u);
        ASSERT_LE(OutputSink->Written_.size(), 150u);
        // 数据前缀完好
        const auto Wire = Prism::AsStrView(Prism::AsU8(std::span<const std::byte>(OutputSink->Written_)));
        EXPECT_EQ(Wire.substr(0, Message.size()), Message);
        Prism::Testing::ExpectFixtureCloseReceipt(Prism::Testing::DriveClose(Loop, TransportOwner19));
        EXPECT_TRUE(Prism::Testing::DriveDrain(Loop, OutputSink).has_value());
    }

TEST(PadTransport, DataPassthroughOverPipe)
    {
        // 经 memory pair 往返：填充不破坏数据
        Net::io_context Loop;
        RunCoro(Loop, RunPadDataPassthrough(Loop));
    }

TEST(PadTransport, LargeChunkBypass)
    {
        // 数据 + 填充 > pad_buf_（16384+256）→ 直接透传
        Net::io_context Loop;
        auto OutputSink = std::make_shared<FakeSink>(Loop.get_executor());
        Prism::Transport::PadConfig Configuration;
        auto TransportOwner18 = std::make_shared<Prism::Transport::PadTransport>(OutputSink, Prism::Testing::MakePadOptions(Configuration));
        auto& Padding = *TransportOwner18;

        constexpr std::size_t Big = 17000;
        std::vector<std::byte> Payload(Big, std::byte{0x5A});
        Prism::Fault::Failure OperationFailure;
        Net::co_spawn(
            Loop,
                 [&]() -> Net::awaitable<void>
            {
                const auto ByteCount = ([&](Prism::IoResult Result) { OperationFailure = Result.Failure; return Result.Bytes; })(co_await Padding.WriteSome(std::span<const std::byte>(Payload)));
                EXPECT_TRUE(OperationFailure.Succeeded());
                EXPECT_EQ(ByteCount, Big);
            },
            Net::detached);
        Loop.run();
        ASSERT_EQ(OutputSink->Written_.size(), Big);
        EXPECT_EQ(OutputSink->Written_[0], std::byte{0x5A});
        EXPECT_EQ(OutputSink->Written_[Big - 1], std::byte{0x5A});
        Prism::Testing::ExpectFixtureCloseReceipt(Prism::Testing::DriveClose(Loop, TransportOwner18));
        EXPECT_TRUE(Prism::Testing::DriveDrain(Loop, OutputSink).has_value());
    }

TEST(PadTransport, RandomPaddingDeterminism)
    {
        // 两个独立 pad（不同 CSPRNG 密钥）写相同数据：填充内容不同但数据不破坏
        Net::io_context Loop;
        auto Sink1 = std::make_shared<FakeSink>(Loop.get_executor());
        auto Sink2 = std::make_shared<FakeSink>(Loop.get_executor());
        Prism::Transport::PadConfig Configuration;
        Configuration.Targets = *Prism::Transport::ParsePadTargets("30-50");
        auto TransportOwner17 = std::make_shared<Prism::Transport::PadTransport>(Sink1, Prism::Testing::MakePadOptions(Configuration));
        auto& Pad1 = *TransportOwner17;
        auto TransportOwner16 = std::make_shared<Prism::Transport::PadTransport>(Sink2, Prism::Testing::MakePadOptions(Configuration));
        auto& Pad2 = *TransportOwner16;

        const std::string_view Message = "0123456789";
        Prism::Fault::Failure OperationFailure;
        Net::co_spawn(
            Loop,
                 [&]() -> Net::awaitable<void>
            {
                const auto N1 = ([&](Prism::IoResult Result) { OperationFailure = Result.Failure; return Result.Bytes; })(co_await Pad1.WriteSome(SvBytes(Message)));
                EXPECT_EQ(N1, Message.size());
                EXPECT_TRUE(OperationFailure.Succeeded());
                const auto N2 = ([&](Prism::IoResult Result) { OperationFailure = Result.Failure; return Result.Bytes; })(co_await Pad2.WriteSome(SvBytes(Message)));
                EXPECT_EQ(N2, Message.size());
                EXPECT_TRUE(OperationFailure.Succeeded());
            },
            Net::detached);
        Loop.run();

        ASSERT_GE(Sink1->Written_.size(), 30u);
        ASSERT_LE(Sink1->Written_.size(), 50u);
        ASSERT_GE(Sink2->Written_.size(), 30u);
        ASSERT_LE(Sink2->Written_.size(), 50u);
        const auto W1 = Prism::AsStrView(Prism::AsU8(std::span<const std::byte>(Sink1->Written_)));
        const auto W2 = Prism::AsStrView(Prism::AsU8(std::span<const std::byte>(Sink2->Written_)));
        EXPECT_EQ(W1.substr(0, Message.size()), Message);
        EXPECT_EQ(W2.substr(0, Message.size()), Message);
        EXPECT_NE(W1, W2); // 不同密钥 → 不同填充
        Prism::Testing::ExpectFixtureCloseReceipt(Prism::Testing::DriveClose(Loop, TransportOwner16));
        EXPECT_TRUE(Prism::Testing::DriveDrain(Loop, Sink2).has_value());
        Prism::Testing::ExpectFixtureCloseReceipt(Prism::Testing::DriveClose(Loop, TransportOwner17));
        EXPECT_TRUE(Prism::Testing::DriveDrain(Loop, Sink1).has_value());
    }

TEST(PadTransport, StopAfterPassthrough)
    {
        // StopAfter = 2：前两次填充，之后透传
        Net::io_context Loop;
        auto OutputSink = std::make_shared<FakeSink>(Loop.get_executor());
        Prism::Transport::PadConfig Configuration;
        Configuration.Targets = *Prism::Transport::ParsePadTargets("20");
        Configuration.StopAfter = 2;
        auto TransportOwner15 = std::make_shared<Prism::Transport::PadTransport>(OutputSink, Prism::Testing::MakePadOptions(Configuration));
        auto& Padding = *TransportOwner15;

        const std::string_view Message = "abc";
        Prism::Fault::Failure OperationFailure;
        Net::co_spawn(
            Loop,
                 [&]() -> Net::awaitable<void>
            {
                for (std::size_t Iteration = 0; Iteration < 3; ++Iteration)
                {
                    const auto ByteCount = ([&](Prism::IoResult Result) { OperationFailure = Result.Failure; return Result.Bytes; })(co_await Padding.WriteSome(SvBytes(Message)));
                    EXPECT_EQ(ByteCount, 3u);
                    EXPECT_TRUE(OperationFailure.Succeeded());
                }
            },
            Net::detached);
        Loop.run();

        ASSERT_EQ(OutputSink->Written_.size(), 20u + 20u + 3u); // 2 次补齐到 20 + 1 次透传
        const auto Wire = Prism::AsStrView(Prism::AsU8(std::span<const std::byte>(OutputSink->Written_)));
        EXPECT_EQ(Wire.substr(0, 3), "abc");
        EXPECT_EQ(Wire.substr(20, 3), "abc");
        EXPECT_EQ(Wire.substr(40, 3), "abc");
        Prism::Testing::ExpectFixtureCloseReceipt(Prism::Testing::DriveClose(Loop, TransportOwner15));
        EXPECT_TRUE(Prism::Testing::DriveDrain(Loop, OutputSink).has_value());
    }
