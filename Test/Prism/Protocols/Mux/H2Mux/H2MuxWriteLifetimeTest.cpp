/**
 * @file H2MuxWriteLifetimeTest.cpp
 * @brief 按功能拆分的 GoogleTest 行为契约。
 */

#include "H2MuxLifetimeSupport.hpp"

namespace
{

    struct StreamWriteScenario final
    {
        Prism::SharedTransmission Stream;
        std::array<std::byte, 32> Payload;
        std::size_t &WritesCompleted;
    };

    /// 写入一条虚拟流并记录完整帧是否完成。
    auto RunStreamWrite(StreamWriteScenario Scenario) -> Net::awaitable<void>
    {
        const auto Result = co_await Scenario.Stream->WriteSome(
            std::span<const std::byte>(Scenario.Payload));
        if (!Result.Failure.Failed() && Result.Bytes == Scenario.Payload.size())
        {
            ++Scenario.WritesCompleted;
        }
    }

    struct ConcurrentWritesScenario final
    {
        std::shared_ptr<Prism::Mux::H2Mux::Http2Server> Server;
        Prism::SharedTransmission ClientTransport;
        std::size_t &Accepted;
        std::size_t &WritesCompleted;
        std::size_t &FramesParsed;
        bool &FeedFailed;
        Watchdog Guard;
        Net::io_context &Io;
    };

    /// 并发写入多条 H2 流并逐帧校验客户端收到的完整字节流。
    auto RunConcurrentWrites(ConcurrentWritesScenario Scenario) -> Net::awaitable<void>
    {
        auto Client = std::make_shared<Prism::Http2::Session>(
            Scenario.ClientTransport->Executor(), false);
        Client->SendSettings();
        for (std::size_t Index = 0; Index < 4; ++Index)
        {
            const auto Opened = Client->OpenStream(
                Prism::Http2::HeaderList{{":method", "CONNECT"}, {":authority", "example.test:443"}}, false);
            if (!Opened)
            {
                ADD_FAILURE() << "failed to open reset streams";
                co_await DrainHttp2Server(Scenario.Server);
                Scenario.Guard.Cancel();
                co_return;
            }
        }
        std::vector<std::byte> Wire;
        if (!Client->Collect(Wire))
        {
            co_await DrainHttp2Server(Scenario.Server);
            Scenario.Guard.Cancel();
            co_return;
        }
        const auto WriteResult = co_await Scenario.ClientTransport->WriteSome(
            std::span<const std::byte>(Wire));
        EXPECT_FALSE(WriteResult.Failure.Failed());

        std::vector<Prism::SharedTransmission> Streams;
        for (std::size_t Index = 0; Index < 4; ++Index)
        {
            auto Stream = co_await Scenario.Server->AcceptStream();
            if (!Stream)
            {
                break;
            }
            Streams.push_back(std::move(Stream));
        }
        Scenario.Accepted = Streams.size();
        if (Scenario.Accepted != 4)
        {
            co_await DrainHttp2Server(Scenario.Server);
            Scenario.Guard.Cancel();
            co_return;
        }

        std::array<std::byte, 32> Payload{};
        for (std::size_t Index = 0; Index < Payload.size(); ++Index)
        {
            Payload[Index] = static_cast<std::byte>(Index);
        }
        for (const auto &Stream : Streams)
        {
            Net::co_spawn(Stream->Executor(), RunStreamWrite(
                StreamWriteScenario{Stream, Payload, Scenario.WritesCompleted}), Net::detached);
        }

        std::vector<std::byte> Received;
        Net::steady_timer Settle(Scenario.ClientTransport->Executor());
        Settle.expires_after(std::chrono::milliseconds(150));
        co_await Settle.async_wait(Net::use_awaitable);
        while (true)
        {
            std::array<std::byte, 4096> Buffer{};
            Scenario.ClientTransport->SetTimeout(std::chrono::milliseconds(20));
            const auto ReadResult = co_await Scenario.ClientTransport->ReadSome(
                std::span<std::byte>(Buffer));
            const auto Count = ReadResult.Bytes;
            if (Count == 0 || ReadResult.Failure.Failed())
            {
                break;
            }
            Received.insert(Received.end(), Buffer.begin(),
                            Buffer.begin() + static_cast<std::ptrdiff_t>(Count));
        }
        Scenario.ClientTransport->SetTimeout(std::chrono::milliseconds(0));

        std::size_t Offset = 0;
        std::size_t FrameCount = 0;
        while (Offset + 9U <= Received.size())
        {
            const auto Length =
                (static_cast<std::size_t>(std::to_integer<std::uint8_t>(Received[Offset]))
                 << 16U) |
                (static_cast<std::size_t>(std::to_integer<std::uint8_t>(Received[Offset + 1]))
                 << 8U) |
                static_cast<std::size_t>(std::to_integer<std::uint8_t>(Received[Offset + 2]));
            if (Length > 16384U || Offset + 9U + Length > Received.size())
            {
                Scenario.FeedFailed = true;
                break;
            }
            Offset += 9U + Length;
            ++FrameCount;
        }
        if (Offset != Received.size())
        {
            Scenario.FeedFailed = true;
        }
        Scenario.FramesParsed = FrameCount;
        co_await DrainHttp2Server(Scenario.Server);
        Scenario.Guard.Cancel();
    }

    struct ConcurrentCloseScenario final
    {
        std::shared_ptr<Prism::Mux::H2Mux::Http2Server> Server;
        Prism::SharedTransmission ClientTransport;
        std::size_t &Accepted;
        std::size_t &WritesCompleted;
        std::size_t &ClosesIssued;
        Watchdog Guard;
        Net::io_context &Io;
    };

    struct CloseWriteScenario final
    {
        Prism::SharedTransmission Stream;
        std::array<std::byte, 32> Payload;
        std::size_t &WritesCompleted;
        std::size_t &ClosesIssued;
    };

    auto RunCloseWrite(CloseWriteScenario Scenario) -> Net::awaitable<void>
    {
        const auto WriteResult = co_await Scenario.Stream->WriteSome(
            std::span<const std::byte>(Scenario.Payload));
        if (!WriteResult.Failure.Failed() && WriteResult.Bytes == Scenario.Payload.size())
        {
            ++Scenario.WritesCompleted;
        }
        const auto CloseResult = Scenario.Stream->Close();
        EXPECT_TRUE(CloseResult);
        ++Scenario.ClosesIssued;
        const auto ActivityDrain = co_await Scenario.Stream->Activity()->Drain();
        EXPECT_TRUE(ActivityDrain);
        const auto TerminationDrain = co_await std::static_pointer_cast<Prism::Mux::H2Mux::Http2Stream>(
            Scenario.Stream)->DrainTerminations();
        EXPECT_TRUE(TerminationDrain);
    }

    /// 并发写入并关闭多条流，验证共享 writer 和兄弟流的独立收口。
    auto RunConcurrentClose(ConcurrentCloseScenario Scenario) -> Net::awaitable<void>
    {
        auto Client = std::make_shared<Prism::Http2::Session>(
            Scenario.ClientTransport->Executor(), false);
        Client->SendSettings();
        for (std::size_t Index = 0; Index < 4; ++Index)
        {
            const auto Opened = Client->OpenStream(
                Prism::Http2::HeaderList{{":method", "CONNECT"}, {":authority", "example.test:443"}}, false);
            if (!Opened)
            {
                ADD_FAILURE() << "failed to open write streams";
                co_await DrainHttp2Server(Scenario.Server);
                Scenario.Guard.Cancel();
                co_return;
            }
        }
        std::vector<std::byte> Wire;
        if (!Client->Collect(Wire))
        {
            co_await DrainHttp2Server(Scenario.Server);
            Scenario.Guard.Cancel();
            co_return;
        }
        const auto WriteResult = co_await Scenario.ClientTransport->WriteSome(
            std::span<const std::byte>(Wire));
        EXPECT_FALSE(WriteResult.Failure.Failed());

        std::vector<Prism::SharedTransmission> Streams;
        for (std::size_t Index = 0; Index < 4; ++Index)
        {
            auto Stream = co_await Scenario.Server->AcceptStream();
            if (!Stream)
            {
                break;
            }
            Streams.push_back(std::move(Stream));
        }
        Scenario.Accepted = Streams.size();
        if (Scenario.Accepted != 4)
        {
            co_await DrainHttp2Server(Scenario.Server);
            Scenario.Guard.Cancel();
            co_return;
        }

        const std::array<std::byte, 32> Payload{};
        for (const auto &Stream : Streams)
        {
            Net::co_spawn(Stream->Executor(),
                          RunCloseWrite(CloseWriteScenario{
                              Stream, Payload, Scenario.WritesCompleted, Scenario.ClosesIssued}),
                          Net::detached);
        }

        Net::steady_timer Settle(Scenario.ClientTransport->Executor());
        Settle.expires_after(std::chrono::milliseconds(400));
        co_await Settle.async_wait(Net::use_awaitable);
        co_await DrainHttp2Server(Scenario.Server);
        Scenario.Guard.Cancel();
    }

    struct CancelSiblingScenario final
    {
        std::shared_ptr<Prism::Mux::H2Mux::Http2Server> Server;
        Prism::SharedTransmission ClientTransport;
        std::size_t &Accepted;
        std::size_t &SiblingWrites;
        Watchdog Guard;
        Net::io_context &Io;
    };

    /// 取消第一条流后写入兄弟流，验证取消不会关闭共享会话。
    auto RunCancelSibling(CancelSiblingScenario Scenario) -> Net::awaitable<void>
    {
        auto Client = std::make_shared<Prism::Http2::Session>(
            Scenario.ClientTransport->Executor(), false);
        Client->SendSettings();
        for (std::size_t Index = 0; Index < 3; ++Index)
        {
            const auto Opened = Client->OpenStream(
                Prism::Http2::HeaderList{{":method", "CONNECT"}, {":authority", "example.test:443"}}, false);
            if (!Opened)
            {
                ADD_FAILURE() << "failed to open peer-reset streams";
                co_await DrainHttp2Server(Scenario.Server);
                Scenario.Guard.Cancel();
                co_return;
            }
        }
        std::vector<std::byte> Wire;
        if (!Client->Collect(Wire))
        {
            co_await DrainHttp2Server(Scenario.Server);
            Scenario.Guard.Cancel();
            co_return;
        }
        const auto WriteResult = co_await Scenario.ClientTransport->WriteSome(
            std::span<const std::byte>(Wire));
        (void)WriteResult;

        std::vector<Prism::SharedTransmission> Streams;
        for (std::size_t Index = 0; Index < 3; ++Index)
        {
            auto Stream = co_await Scenario.Server->AcceptStream();
            if (!Stream)
            {
                break;
            }
            Streams.push_back(std::move(Stream));
        }
        Scenario.Accepted = Streams.size();
        if (Scenario.Accepted < 2)
        {
            co_await DrainHttp2Server(Scenario.Server);
            Scenario.Guard.Cancel();
            co_return;
        }

        const auto CancelResult = Streams[0]->Cancel();
        EXPECT_TRUE(CancelResult);
        const auto CloseResult = Streams[0]->Close();
        EXPECT_TRUE(CloseResult);
        const auto ActivityDrain = co_await Streams[0]->Activity()->Drain();
        EXPECT_TRUE(ActivityDrain);
        const auto TerminationDrain = co_await std::static_pointer_cast<Prism::Mux::H2Mux::Http2Stream>(
            Streams[0])->DrainTerminations();
        EXPECT_TRUE(TerminationDrain);
        EXPECT_TRUE(Streams[0]->Activity()->IsRetired());
        for (int Index = 0; Index < 4; ++Index)
        {
            co_await Net::post(Streams[1]->Executor(), Net::use_awaitable);
        }

        std::array<std::byte, 16> Payload{};
        for (std::size_t Index = 1; Index < Streams.size(); ++Index)
        {
            const auto WriteResult = co_await Streams[Index]->WriteSome(
                std::span<const std::byte>(Payload));
            if (!WriteResult.Failure.Failed() && WriteResult.Bytes == Payload.size())
            {
                ++Scenario.SiblingWrites;
            }
        }
        co_await DrainHttp2Server(Scenario.Server);
        Scenario.Guard.Cancel();
    }
}

TEST(H2MuxStreamLifetime, ConcurrentStreamWritesStayFramed)
    {
        // 生产证据：Trojan + H2Mux 在 8 路并发下出现 502/超时，
        // 而顺序请求全部成功。根因是 Http2State::Flush() 可被多个
        // Http2Stream 并发调用，WriteAll 挂起时帧会交错写入底层传输。
        // 本测试让 4 条流并发写，断言对端读到的字节流始终是完整、
        // 可解析的 HTTP/2 帧序列。
        Net::io_context Io;
        auto [ServerRaw, ClientRaw] = Prism::MakeMemoryPair(Io.get_executor());
        auto Probe = std::make_shared<WriteProbe>();
        auto ServerTransport = std::make_shared<DelayedWriteTransmission>(
            std::make_shared<Prism::MemoryStream>(std::move(ServerRaw)), Probe);
        auto Server = std::make_shared<Prism::Mux::H2Mux::Http2Server>(
            ServerTransport, 4U);
        auto ClientTransport = std::make_shared<Prism::MemoryStream>(std::move(ClientRaw));
        constexpr std::size_t StreamCount = 4;
        std::size_t Accepted = 0;
        std::size_t WritesCompleted = 0;
        std::size_t FramesParsed = 0;
        bool FeedFailed = false;
        Watchdog Guard(Io, std::chrono::seconds(5));
        auto RunResult = std::make_shared<ServerRunObservation>();

        StartServerRun(Io.get_executor(), Server, RunResult);
        Net::co_spawn(Io, RunConcurrentWrites(ConcurrentWritesScenario{
                                Server, ClientTransport, Accepted, WritesCompleted,
                                FramesParsed, FeedFailed, Guard, Io}),
                      Net::detached);

        Io.run();

        EXPECT_FALSE(*Guard.Timeouted);
        EXPECT_TRUE(RunResult->Completed);
        EXPECT_FALSE(RunResult->Threw);
        EXPECT_TRUE(RunResult->Succeeded);
        EXPECT_TRUE(RunResult->Retired);
        EXPECT_EQ(Accepted, StreamCount);
        EXPECT_EQ(WritesCompleted, StreamCount);
        EXPECT_FALSE(FeedFailed);
        EXPECT_GT(FramesParsed, 0U);
        EXPECT_EQ(Probe->Maximum.load(std::memory_order_acquire), 1);
    }

TEST(H2MuxStreamLifetime, ConcurrentStreamWritesAndCloseKeepSiblingStreamsUsable)
    {
        // 真实 Mihomo H2Mux 失败形状：多条流同时收到上游响应时，某条流在
        // 关闭路径占用共享 writer，兄弟流的响应写回被拖到客户端超时。
        // 这里同时写入并关闭四条虚拟流，要求每条流都完成自己的响应和 FIN。
        Net::io_context Io;
        auto [ServerRaw, ClientRaw] = Prism::MakeMemoryPair(Io.get_executor());
        auto Probe = std::make_shared<WriteProbe>();
        auto ServerTransport = std::make_shared<DelayedWriteTransmission>(
            std::make_shared<Prism::MemoryStream>(std::move(ServerRaw)), Probe);
        auto Server = std::make_shared<Prism::Mux::H2Mux::Http2Server>(
            ServerTransport, 4U);
        auto ClientTransport = std::make_shared<Prism::MemoryStream>(std::move(ClientRaw));
        constexpr std::size_t StreamCount = 4;
        std::size_t Accepted = 0;
        std::size_t WritesCompleted = 0;
        std::size_t ClosesIssued = 0;
        Watchdog Guard(Io, std::chrono::seconds(5));
        auto RunResult = std::make_shared<ServerRunObservation>();

        StartServerRun(Io.get_executor(), Server, RunResult);
        Net::co_spawn(Io, RunConcurrentClose(ConcurrentCloseScenario{
                                Server, ClientTransport, Accepted, WritesCompleted,
                                ClosesIssued, Guard, Io}),
                      Net::detached);

        Io.run();

        EXPECT_FALSE(*Guard.Timeouted);
        EXPECT_TRUE(RunResult->Completed);
        EXPECT_FALSE(RunResult->Threw);
        EXPECT_TRUE(RunResult->Succeeded);
        EXPECT_TRUE(RunResult->Retired);
        EXPECT_EQ(Accepted, StreamCount);
        EXPECT_EQ(WritesCompleted, StreamCount);
        EXPECT_EQ(ClosesIssued, StreamCount);
        EXPECT_EQ(Probe->Maximum.load(std::memory_order_acquire), 1);
    }

TEST(H2MuxStreamLifetime, CancelingOneStreamKeepsSiblingStreamsUsable)
    {
        // 生产证据：Trojan + H2Mux 并发下间歇失败（多轮 2/8~7/8），
        // 诊断显示 accept-wait 次数远多于 accepted，且一次 stream-request
        // 失败后整条会话再无流被接受。
        // 根因：Http2Stream::Cancel() 调用 State_->Raw->Cancel()，而 Raw 是
        // 整个会话共享的底层传输；取消单条流会连带取消所有兄弟流。
        // 本测试取消一条流后，断言兄弟流仍可正常读写。
        Net::io_context Io;
        auto [ServerRaw, ClientRaw] = Prism::MakeMemoryPair(Io.get_executor());
        auto Server = std::make_shared<Prism::Mux::H2Mux::Http2Server>(
            std::make_shared<Prism::MemoryStream>(std::move(ServerRaw)), 3U);
        auto ClientTransport = std::make_shared<Prism::MemoryStream>(std::move(ClientRaw));
        constexpr std::size_t StreamCount = 3;
        std::size_t Accepted = 0;
        std::size_t SiblingWrites = 0;
        Watchdog Guard(Io, std::chrono::seconds(3));
        auto RunResult = std::make_shared<ServerRunObservation>();

        StartServerRun(Io.get_executor(), Server, RunResult);
        Net::co_spawn(Io, RunCancelSibling(CancelSiblingScenario{
                                Server, ClientTransport, Accepted, SiblingWrites, Guard, Io}),
                      Net::detached);

        Io.run();

        EXPECT_FALSE(*Guard.Timeouted);
        EXPECT_TRUE(RunResult->Completed);
        EXPECT_FALSE(RunResult->Threw);
        EXPECT_TRUE(RunResult->Succeeded);
        EXPECT_TRUE(RunResult->Retired);
        EXPECT_EQ(Accepted, StreamCount);
        EXPECT_EQ(SiblingWrites, StreamCount - 1);
    }

TEST(H2MuxStreamLifetime, PartialWriteFailureDrainsPendingReadAndStreamEnd)
    {
        Net::io_context Io;
        auto [ServerRaw, ClientRaw] = Prism::MakeMemoryPair(Io.get_executor());
        auto State = std::make_shared<WriteFailureScenario>(Io);
        State->Transport = std::make_shared<ScriptedWriteTransmission>(
            std::make_shared<Prism::MemoryStream>(std::move(ServerRaw)));
        State->Client = std::make_shared<Prism::MemoryStream>(std::move(ClientRaw));
        State->Server = std::make_shared<Prism::Mux::H2Mux::Http2Server>(State->Transport, 1U);
        const auto WeakServer = std::weak_ptr<Prism::Mux::H2Mux::Http2Server>(State->Server);
        Net::co_spawn(Io, RunWriteFailureScenario(State),
            [State](std::exception_ptr Failure)
            {
                if (Failure) State->Failure = Failure;
            });
        Io.run();

        EXPECT_FALSE(*State->Guard.Timeouted);
        ASSERT_FALSE(State->Failure);
        ASSERT_TRUE(State->RunCompleted);
        EXPECT_FALSE(State->RunThrew);
        EXPECT_TRUE(State->RunFailure.Failed());
        EXPECT_TRUE(State->Server->IsRetired());
        EXPECT_EQ(State->RunFailure.Native, State->WriteError);
        ASSERT_TRUE(State->Stream);
        EXPECT_EQ(State->Written, 0U);
        EXPECT_TRUE(State->WriteError);
        EXPECT_TRUE(State->ReadCompleted);
        EXPECT_EQ(State->ReadBytes, 0U);
        EXPECT_EQ(State->ReadError, Prism::Fault::ToNative(
            Prism::Fault::Failure{Prism::Fault::Code::Eof}));
        EXPECT_EQ(State->Transport->Writes(), 3U);
        const auto WeakStream = std::weak_ptr<Prism::Mux::H2Mux::Http2Stream>(State->Stream);
        State->Stream.reset();
        State->Server.reset();
        EXPECT_TRUE(CloseAndDrain(Io, State->Client));
        EXPECT_TRUE(WeakStream.expired());
        EXPECT_TRUE(WeakServer.expired());
    }

