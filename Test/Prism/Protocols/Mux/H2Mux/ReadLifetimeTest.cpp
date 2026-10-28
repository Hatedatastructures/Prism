/**
 * @file ReadLifetimeTest.cpp
 * @brief 按功能拆分的 GoogleTest 行为契约。
 */

#include "LifetimeSupport.hpp"

#include <Prism/Protocols/Http2/Detail/Frame.hpp>

namespace
{

    struct CloseReadScenario final
    {
        std::shared_ptr<Http2State> State;
        bool &Completed;
        std::size_t &ReadBytes;
        std::error_code &ReadError;
        Watchdog Guard;
        Net::io_context &Io;
    };

    /// 先关闭虚拟流再发起读取，验证封止后的准入精确返回 Canceled。
    auto RunCloseRead(CloseReadScenario Scenario) -> Net::awaitable<void>
    {
        auto Stream = std::make_shared<Http2Stream>(Scenario.State, 3);
        const auto CloseResult = Stream->Close();
        EXPECT_TRUE(CloseResult);
        for (int Index = 0; Index < 4; ++Index)
        {
            co_await Net::post(Scenario.State->Strand, Net::use_awaitable);
        }
        std::array<std::byte, 16> Buffer{};
        const auto ReadResult = co_await Stream->ReadSome(std::span<std::byte>(Buffer));
        Scenario.ReadBytes = ReadResult.Bytes;
        Scenario.ReadError = Prism::Fault::ToNative(ReadResult.Failure);
        const auto ActivityDrain = co_await Stream->Activity()->Drain();
        EXPECT_TRUE(ActivityDrain);
        const auto TerminationDrain = co_await Stream->DrainTerminations();
        EXPECT_TRUE(TerminationDrain);
        Scenario.Completed = true;
        Scenario.Guard.Cancel();
        Scenario.Io.stop();
    }

    struct ShutdownWriteScenario final
    {
        std::shared_ptr<Prism::Mux::H2Mux::Http2Server> Server;
        Prism::SharedTransmission ServerTransport;
        Prism::SharedTransmission ClientTransport;
        std::size_t &Written;
        std::error_code &WriteError;
        bool &ShutdownSucceeded;
    };

    /// 建立正式 CONNECT stream，关闭写方向后继续使用共享连接传输。
    auto RunShutdownWrite(ShutdownWriteScenario Scenario) -> Net::awaitable<void>
    {
        auto Client = std::make_shared<Prism::Http2::Session>(
            Scenario.ClientTransport->Executor(), false);
        Client->SendSettings();
        const Prism::Http2::HeaderList Headers{
            {":method", "CONNECT"}, {":authority", "example.test:443"}};
        const auto Opened = Client->OpenStream(Headers, false);
        if (!Opened)
        {
            ADD_FAILURE() << "failed to open CONNECT stream";
            Scenario.Server->Close();
            co_return;
        }
        std::vector<std::byte> Wire;
        if (!Client->Collect(Wire))
        {
            ADD_FAILURE() << "failed to collect CONNECT request";
            Scenario.Server->Close();
            co_return;
        }
        const auto RequestWrite = co_await Scenario.ClientTransport->WriteExact(Wire);
        if (RequestWrite.Failure.Failed() || RequestWrite.Bytes != Wire.size())
        {
            ADD_FAILURE() << "failed to deliver CONNECT request";
            Scenario.Server->Close();
            co_return;
        }
        const auto Stream = co_await Scenario.Server->AcceptStream();
        if (!Stream)
        {
            ADD_FAILURE() << "server did not admit CONNECT stream";
            Scenario.Server->Close();
            co_return;
        }
        const auto ShutdownResult = co_await Stream->WriteShutdown();
        Scenario.ShutdownSucceeded = static_cast<bool>(ShutdownResult);
        EXPECT_TRUE(ShutdownResult);
        const std::array<std::byte, 4> Payload{
            std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04}};
        const auto WriteResult = co_await Scenario.ServerTransport->WriteSome(Payload);
        Scenario.Written = WriteResult.Bytes;
        Scenario.WriteError = Prism::Fault::ToNative(WriteResult.Failure);
        EXPECT_TRUE(Stream->Close());
        Scenario.Server->Close();
    }

    struct AcceptStreamsScenario final
    {
        std::shared_ptr<Prism::Mux::H2Mux::Http2Server> Server;
        Prism::SharedTransmission ClientTransport;
        std::size_t &Accepted;
        Net::io_context &Io;
    };

    /// 注入多条 CONNECT 流并逐条接受，验证通知不会丢失。
    auto RunAcceptStreams(AcceptStreamsScenario Scenario) -> Net::awaitable<void>
    {
        auto Client = std::make_shared<Prism::Http2::Session>(
            Scenario.ClientTransport->Executor(), false);
        Client->SendSettings();
        const Prism::Http2::HeaderList Headers{
            {":method", "CONNECT"}, {":authority", "example.test:443"}};
        for (std::size_t Index = 0; Index < 4; ++Index)
        {
            const auto Opened = Client->OpenStream(Headers, false);
            if (!Opened)
            {
                ADD_FAILURE() << "failed to open reset streams";
                co_await DrainHttp2Server(Scenario.Server);
                co_return;
            }
        }
        std::vector<std::byte> Wire;
        if (!Client->Collect(Wire))
        {
            co_await DrainHttp2Server(Scenario.Server);
            co_return;
        }
        const auto WriteResult = co_await Scenario.ClientTransport->WriteSome(
            std::span<const std::byte>(Wire));
        EXPECT_FALSE(WriteResult.Failure.Failed());
        if (WriteResult.Failure.Failed())
        {
            co_await DrainHttp2Server(Scenario.Server);
            co_return;
        }

        for (std::size_t Index = 0; Index < 4; ++Index)
        {
            auto Stream = co_await Scenario.Server->AcceptStream();
            if (!Stream)
            {
                break;
            }
            ++Scenario.Accepted;
            EXPECT_TRUE(Stream->Close());
        }
        Scenario.Server->Close();
    }

    struct ServerCloseReadScenario final
    {
        std::shared_ptr<Prism::Mux::H2Mux::Http2Server> Server;
        Prism::SharedTransmission ClientTransport;
        bool &Accepted;
        bool &Completed;
        std::size_t &ReadBytes;
        std::error_code &ReadError;
        Watchdog Guard;
        Net::io_context &Io;
    };

    struct PendingReadScenario final
    {
        Prism::SharedTransmission Stream;
        bool &Completed;
        std::size_t &ReadBytes;
        std::error_code &ReadError;
    };

    auto RunPendingRead(PendingReadScenario Scenario) -> Net::awaitable<void>
    {
        std::array<std::byte, 16> Buffer{};
        const auto ReadResult = co_await Scenario.Stream->ReadSome(std::span<std::byte>(Buffer));
        Scenario.ReadBytes = ReadResult.Bytes;
        Scenario.ReadError = Prism::Fault::ToNative(ReadResult.Failure);
        Scenario.Completed = true;
    }

    /// 让服务端关闭唤醒挂起读，验证已注册流的 EOF 生命周期。
    auto RunServerCloseRead(ServerCloseReadScenario Scenario) -> Net::awaitable<void>
    {
        auto Client = std::make_shared<Prism::Http2::Session>(
            Scenario.ClientTransport->Executor(), false);
        Client->SendSettings();
        const auto OpenedStream = Client->OpenStream(
            Prism::Http2::HeaderList{{":method", "CONNECT"}, {":authority", "example.test:443"}}, false);
        if (!OpenedStream)
        {
            ADD_FAILURE() << "failed to open read stream";
            co_await DrainHttp2Server(Scenario.Server);
            Scenario.Guard.Cancel();
            Scenario.Completed = true;
            co_return;
        }
        const auto ClientStreamId = *OpenedStream;
        EXPECT_GT(ClientStreamId, 0);
        std::vector<std::byte> Wire;
        EXPECT_TRUE(Client->Collect(Wire));
        const auto WriteResult = co_await Scenario.ClientTransport->WriteSome(
            std::span<const std::byte>(Wire));
        EXPECT_FALSE(WriteResult.Failure.Failed());
        if (WriteResult.Failure.Failed())
        {
            co_await DrainHttp2Server(Scenario.Server);
            Scenario.Guard.Cancel();
            Scenario.Completed = true;
            co_return;
        }

        auto Stream = co_await Scenario.Server->AcceptStream();
        EXPECT_TRUE(Stream);
        Scenario.Accepted = static_cast<bool>(Stream);
        if (!Stream)
        {
            co_await DrainHttp2Server(Scenario.Server);
            Scenario.Guard.Cancel();
            Scenario.Completed = true;
            co_return;
        }

        Net::co_spawn(Stream->Executor(),
                      RunPendingRead(PendingReadScenario{
                          Stream, Scenario.Completed, Scenario.ReadBytes, Scenario.ReadError}),
                      Net::detached);
        for (int Index = 0; Index < 4; ++Index)
        {
            co_await Net::post(Stream->Executor(), Net::use_awaitable);
        }
        Scenario.Server->Close();
        Net::steady_timer Settle(Stream->Executor());
        Settle.expires_after(std::chrono::milliseconds(50));
        co_await Settle.async_wait(Net::use_awaitable);
        EXPECT_TRUE(Stream->Close());
        const auto ActivityDrain = co_await Stream->Activity()->Drain();
        EXPECT_TRUE(ActivityDrain);
        const auto TerminationDrain = co_await Stream->DrainTerminations();
        EXPECT_TRUE(TerminationDrain);
        const auto ServerDrain = co_await Scenario.Server->Drain();
        EXPECT_TRUE(ServerDrain);
        Scenario.Guard.Cancel();
    }

    struct StreamReadObservation final
    {
        explicit StreamReadObservation(Net::any_io_executor Executor) : Done(Executor, 1) {}
        std::array<std::byte, 8> Buffer{};
        Prism::IoResult Result{};
        bool Completed{false};
        Net::experimental::channel<void(boost::system::error_code)> Done;
    };

    struct AdmissionRetirementResult final
    {
        explicit AdmissionRetirementResult(Net::io_context &Io)
            : Guard(Io, std::chrono::seconds(3))
        {
        }
        Watchdog Guard;
        bool Completed{false};
        bool UnacceptedActivityDrained{false};
        bool UnacceptedActivityRetired{false};
        std::exception_ptr Failure;
    };

    auto ConfigureSession(const std::shared_ptr<Http2State> &State) -> void
    {
        State->Session = std::make_shared<Prism::Http2::Session>(State->Strand, true);
        const auto WeakState = std::weak_ptr<Http2State>(State);
        State->Session->OnHeaders = [WeakState](
            const std::int32_t StreamId,
            const Prism::Http2::HeaderList &Headers,
            const bool EndStream)
        {
            if (const auto Value = WeakState.lock()) Value->OnHeaders(StreamId, Headers, EndStream);
        };
        State->Session->OnData = [WeakState](
            const std::int32_t StreamId, const std::span<const std::byte> Data)
        {
            if (const auto Value = WeakState.lock()) Value->OnData(StreamId, Data);
        };
        State->Session->OnStreamClose = [WeakState](
            const Prism::Http2::StreamReceiveClosure &Closure)
        {
            if (const auto Value = WeakState.lock()) Value->OnRemoteClose(Closure);
        };
    }

    [[nodiscard]] auto FeedClientFrames(
        const std::shared_ptr<Http2State> &State,
        const std::shared_ptr<Prism::Http2::Session> &Client) -> bool
    {
        std::vector<std::byte> Wire;
        if (!Client->Collect(Wire)) return false;
        std::error_code ErrorCode;
        if (!State->Session->Feed(Wire, ErrorCode) || ErrorCode) return false;
        State->ApplyRefusedStreams();
        return true;
    }

    [[nodiscard]] auto HasReset(
        const std::vector<std::byte> &Wire,
        const std::uint32_t StreamId,
        const std::uint32_t ErrorCode) -> bool
    {
        std::size_t Offset = 0;
        while (Offset < Wire.size())
        {
            const auto Remaining = std::span<const std::byte>(Wire).subspan(Offset);
            const auto Header = Prism::Http2::Detail::ParseFrameHeader(Remaining);
            if (!Header || Prism::Http2::Detail::FrameHeaderSize + Header->Length > Remaining.size()) return false;
            if (Header->Type == Prism::Http2::Detail::FrameType::RstStream && Header->StreamId == StreamId)
            {
                const auto Payload = Remaining.subspan(Prism::Http2::Detail::FrameHeaderSize, Header->Length);
                return Payload.size() == 4U && Prism::Http2::Detail::DecodeU32(Payload) == ErrorCode;
            }
            Offset += Prism::Http2::Detail::FrameHeaderSize + Header->Length;
        }
        return false;
    }

    auto ReadStreamOnce(
        const std::shared_ptr<Http2Stream> &Stream,
        const std::shared_ptr<StreamReadObservation> &Observation) -> Net::awaitable<void>
    {
        Observation->Result = co_await Stream->ReadSome(Observation->Buffer);
        Observation->Completed = true;
        (void)Observation->Done.try_send(boost::system::error_code{});
    }

    auto RunAdmissionRetirement(
        const std::shared_ptr<Http2State> &State,
        const Prism::SharedTransmission &ClientRaw,
        AdmissionRetirementResult &Result) -> Net::awaitable<void>
    {
        ConfigureSession(State);
        const auto Started = State->StartRetirementPump();
        EXPECT_TRUE(Started);
        if (!Started) co_return;
        auto Client = std::make_shared<Prism::Http2::Session>(ClientRaw->Executor(), false);
        Client->SendSettings();
        const Prism::Http2::HeaderList Headers{
            {":method", "CONNECT"}, {":authority", "example.test:443"}};
        const auto FirstStream = Client->OpenStream(Headers, false);
        const auto SecondStream = Client->OpenStream(Headers, false);
        if (!FirstStream || !SecondStream)
        {
            ADD_FAILURE() << "failed to open stream pair";
            co_return;
        }
        const auto FirstId = *FirstStream;
        const auto SecondId = *SecondStream;
        EXPECT_EQ(FirstId, 1);
        EXPECT_EQ(SecondId, 3);
        EXPECT_TRUE(FeedClientFrames(State, Client));
        if (State->Incoming.size() != 1U || State->Streams.size() != 1U) co_return;
        auto Stream = State->Incoming.front();
        State->Incoming.pop_front();
        Stream->MarkIncomingPending(false);
        std::vector<std::byte> Wire;
        EXPECT_TRUE(State->Session->Collect(Wire));
        EXPECT_TRUE(HasReset(Wire, 3U, Prism::Http2::ErrorRefusedStream));

        const auto ThirdStream = Client->OpenStream(Headers, false);
        if (!ThirdStream)
        {
            ADD_FAILURE() << "failed to open third stream";
            co_return;
        }
        const auto ThirdId = *ThirdStream;
        EXPECT_EQ(ThirdId, 5);
        EXPECT_TRUE(FeedClientFrames(State, Client));
        Wire.clear();
        (void)State->Session->Collect(Wire);
        EXPECT_TRUE(HasReset(Wire, 5U, Prism::Http2::ErrorRefusedStream));
        EXPECT_EQ(State->Streams.size(), 1U);

        auto Read = std::make_shared<StreamReadObservation>(State->Strand);
        Net::co_spawn(Stream->Executor(), ReadStreamOnce(Stream, Read), Net::detached);
        co_await Net::post(State->Strand, Net::use_awaitable);
        EXPECT_FALSE(Read->Completed);
        const std::array<std::byte, 3> Payload{std::byte{1}, std::byte{2}, std::byte{3}};
        EXPECT_EQ(Client->SubmitData(FirstId, Payload, true), Prism::Http2::SubmitDataStatus::Accepted);
        EXPECT_TRUE(FeedClientFrames(State, Client));
        co_await Read->Done.async_receive(Net::use_awaitable);
        EXPECT_TRUE(Read->Completed);
        EXPECT_EQ(Read->Result.Bytes, Payload.size());
        EXPECT_FALSE(Read->Result.Failure.Failed());
        EXPECT_TRUE(std::equal(Payload.begin(), Payload.end(), Read->Buffer.begin()));
        EXPECT_EQ(State->Streams.size(), 1U);

        const auto FourthStream = Client->OpenStream(Headers, false);
        if (!FourthStream)
        {
            ADD_FAILURE() << "failed to open fourth stream";
            co_return;
        }
        const auto FourthId = *FourthStream;
        EXPECT_EQ(FourthId, 7);
        EXPECT_TRUE(FeedClientFrames(State, Client));
        Wire.clear();
        (void)State->Session->Collect(Wire);
        EXPECT_TRUE(HasReset(Wire, 7U, Prism::Http2::ErrorRefusedStream));
        EXPECT_EQ(State->Streams.size(), 1U);

        const auto Closed = Stream->Close();
        EXPECT_TRUE(Closed);
        const auto Activity = co_await Stream->Activity()->Drain();
        EXPECT_TRUE(Activity);
        const auto Terminations = co_await Stream->DrainTerminations();
        EXPECT_TRUE(Terminations);
        State->Notify.reset();
        while (State->Streams.contains(FirstId))
        {
            State->Notify.reset();
            if (!State->Streams.contains(FirstId)) break;
            co_await State->Notify.async_receive(Net::use_awaitable);
        }
        EXPECT_FALSE(State->Streams.contains(FirstId));

        const auto FifthStream = Client->OpenStream(Headers, false);
        if (!FifthStream)
        {
            ADD_FAILURE() << "failed to open fifth stream";
            co_return;
        }
        const auto FifthId = *FifthStream;
        EXPECT_EQ(FifthId, 9);
        EXPECT_TRUE(FeedClientFrames(State, Client));
        EXPECT_EQ(State->Streams.size(), 1U);
        EXPECT_EQ(State->Incoming.size(), 1U);
        EXPECT_EQ(State->Incoming.front()->StreamId(), FifthId);
        const auto Unaccepted = State->Incoming.front();
        const auto UnacceptedActivity = Unaccepted->Activity();
        State->Close();
        const auto Drained = co_await State->Tasks->Drain();
        EXPECT_TRUE(Drained);
        const auto ActivityDrained = co_await UnacceptedActivity->Drain();
        const auto StreamsDrained = co_await State->DrainStreams();
        Result.UnacceptedActivityDrained =
            static_cast<bool>(ActivityDrained) && StreamsDrained;
        Result.UnacceptedActivityRetired = UnacceptedActivity->IsRetired();
        EXPECT_TRUE(StreamsDrained);
        EXPECT_TRUE(State->Streams.empty());
        Result.Guard.Cancel();
        Result.Completed = true;
    }
}

TEST(H2MuxStreamLifetime, CloseThenReadReturnsCanceledWithoutCrash)
    {
        Net::io_context Io;
        auto State = MakeState(Io);
        bool Completed = false;
        std::size_t ReadBytes = 999;
        std::error_code ReadError = std::make_error_code(std::errc::io_error);
        Watchdog Guard(Io, std::chrono::seconds(3));

        Net::co_spawn(Io, RunCloseRead(CloseReadScenario{
                                State, Completed, ReadBytes, ReadError, Guard, Io}),
                      Net::detached);

        Io.run();

        EXPECT_FALSE(*Guard.Timeouted);
        EXPECT_TRUE(Completed);
        EXPECT_EQ(ReadBytes, 0U);
        EXPECT_EQ(ReadError, Prism::Fault::ToNative(
            Prism::Fault::Failure{Prism::Fault::Code::Canceled}));
    }

TEST(H2MuxStreamLifetime, ShutdownKeepsSharedTransportWritable)
    {
        Net::io_context Io;
        auto [ServerRaw, ClientRaw] = Prism::MakeMemoryPair(Io.get_executor());
        auto ServerTransport =
            std::make_shared<Prism::MemoryStream>(std::move(ServerRaw));
        auto ClientTransport =
            std::make_shared<Prism::MemoryStream>(std::move(ClientRaw));
        auto Server = std::make_shared<Prism::Mux::H2Mux::Http2Server>(
            ServerTransport, 1U);
        std::size_t Written = 0;
        std::error_code WriteError = std::make_error_code(std::errc::io_error);
        bool ShutdownSucceeded = false;
        auto RunResult = std::make_shared<ServerRunObservation>();
        Watchdog Guard(Io, std::chrono::seconds(3));
        RunResult->OnCompleted = [&Guard] { Guard.Cancel(); };

        StartServerRun(Io.get_executor(), Server, RunResult);
        Net::co_spawn(Io, RunShutdownWrite(ShutdownWriteScenario{
                                Server, ServerTransport, ClientTransport, Written, WriteError,
                                ShutdownSucceeded}),
                      Net::detached);

        Io.run();

        EXPECT_FALSE(*Guard.Timeouted);
        EXPECT_TRUE(RunResult->Completed);
        EXPECT_TRUE(RunResult->Succeeded);
        EXPECT_TRUE(RunResult->Retired);
        EXPECT_TRUE(ShutdownSucceeded);
        EXPECT_FALSE(WriteError);
        EXPECT_EQ(Written, 4U);
    }

TEST(H2MuxStreamLifetime, AcceptStreamDeliversAllQueuedStreamsWithoutLoss)
    {
        // 生产证据：Trojan + H2Mux 在 8 路并发下间歇失败（5 轮中 2 轮失败，
        // 最差 2/8），失败会话在 Stage=mux started 后卡满客户端 10s 超时。
        // 根因：AcceptStream 用 Notify.reset() + async_receive 等待，
        // 而 OnHeaders 对每个新流只 try_send 一次；通道容量为 1 时
        // 并发入队的信号会丢失，导致已排队的流无人唤醒。
        // 本测试一次性注入 4 条流，断言全部可被 AcceptStream 取出。
        Net::io_context Io;
        auto [ServerRaw, ClientRaw] = Prism::MakeMemoryPair(Io.get_executor());
        auto Server = std::make_shared<Prism::Mux::H2Mux::Http2Server>(
            std::make_shared<Prism::MemoryStream>(std::move(ServerRaw)), 4U);
        auto ClientTransport = std::make_shared<Prism::MemoryStream>(std::move(ClientRaw));
        constexpr std::size_t StreamCount = 4;
        std::size_t Accepted = 0;
        Watchdog Guard(Io, std::chrono::seconds(3));
        auto RunResult = std::make_shared<ServerRunObservation>();
        RunResult->OnCompleted = [&Guard] { Guard.Cancel(); };

        StartServerRun(Io.get_executor(), Server, RunResult);
        Net::co_spawn(Io, RunAcceptStreams(AcceptStreamsScenario{
                                Server, ClientTransport, Accepted, Io}),
                      Net::detached);

        Io.run();

        EXPECT_FALSE(*Guard.Timeouted);
        EXPECT_TRUE(RunResult->Completed);
        EXPECT_FALSE(RunResult->Threw);
        EXPECT_TRUE(RunResult->Succeeded)
            << "H2 服务端 Run 失败，Code="
            << static_cast<int>(RunResult->Failure.Code)
            << " Native=" << RunResult->Failure.Native.category().name()
            << '/' << RunResult->Failure.Native.value();
        EXPECT_TRUE(RunResult->Retired);
        EXPECT_EQ(Accepted, StreamCount);
    }

TEST(H2MuxStreamLifetime, ServerCloseWakesPendingStreamReadWithEof)
    {
        Net::io_context Io;
        auto [ServerRaw, ClientRaw] = Prism::MakeMemoryPair(Io.get_executor());
        auto Server = std::make_shared<Prism::Mux::H2Mux::Http2Server>(
            std::make_shared<Prism::MemoryStream>(std::move(ServerRaw)), 1U);
        auto ClientTransport = std::make_shared<Prism::MemoryStream>(std::move(ClientRaw));
        bool Accepted = false;
        bool Completed = false;
        std::size_t ReadBytes = 999;
        std::error_code ReadError = std::make_error_code(std::errc::io_error);
        Watchdog Guard(Io, std::chrono::seconds(3));
        auto RunResult = std::make_shared<ServerRunObservation>();

        StartServerRun(Io.get_executor(), Server, RunResult);
        Net::co_spawn(Io, RunServerCloseRead(ServerCloseReadScenario{
                                Server, ClientTransport, Accepted, Completed, ReadBytes,
                                ReadError, Guard, Io}),
                      Net::detached);

        Io.run();

        EXPECT_FALSE(*Guard.Timeouted);
        EXPECT_TRUE(RunResult->Completed);
        EXPECT_FALSE(RunResult->Threw);
        EXPECT_TRUE(RunResult->Succeeded);
        EXPECT_TRUE(RunResult->Retired);
        EXPECT_TRUE(Accepted);
        EXPECT_TRUE(Completed);
        EXPECT_EQ(ReadBytes, 0U);
        EXPECT_EQ(ReadError, Prism::Fault::ToNative(
            Prism::Fault::Failure{Prism::Fault::Code::Eof}));
    }

TEST(H2MuxStreamLifetime, AdmissionWaitsForRemoteAndLocalTerminalAndTrackedIo)
    {
        Net::io_context Io;
        auto [ServerRaw, ClientRaw] = Prism::MakeMemoryPair(Io.get_executor());
        auto State = std::make_shared<Http2State>(
            std::make_shared<Prism::MemoryStream>(std::move(ServerRaw)), 1U);
        auto ClientRawValue = std::make_shared<Prism::MemoryStream>(std::move(ClientRaw));
        AdmissionRetirementResult Result(Io);

        Net::co_spawn(State->Strand, RunAdmissionRetirement(State, ClientRawValue, Result),
            [&State, &Result](std::exception_ptr Failure)
            {
                Result.Failure = Failure;
                State->Close();
            });
        Io.run();
        if (*Result.Guard.Timeouted)
        {
            Io.restart();
            State->Close();
            Io.run();
        }

        EXPECT_FALSE(*Result.Guard.Timeouted);
        EXPECT_FALSE(Result.Failure);
        EXPECT_TRUE(Result.Completed);
        EXPECT_TRUE(Result.UnacceptedActivityDrained);
        EXPECT_TRUE(Result.UnacceptedActivityRetired);
        EXPECT_TRUE(State->Streams.empty());
    }
