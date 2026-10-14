/**
 * @file MuxSessionTest.cpp
 * @brief 多路复用会话测试（smux / yamux / h2mux 独立实现）
 * @details 覆盖：Open/Accept、双向数据传输、多流并发、FIN 关闭语义。
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include <Preview/Transport/MemoryStream.hpp>
#include <Preview/Protocols/Mux/H2Mux/H2Mux.hpp>
#include <Preview/Protocols/Mux/Smux/Smux.hpp>
#include <Preview/Protocols/Mux/Yamux/Yamux.hpp>
#include <Preview/Lifecycle/TaskRegistry.hpp>
#include "MuxSessionTestSupport.hpp"
#include <gtest/gtest.h>

    namespace
    {
    namespace Net = boost::asio;
    namespace Smux = Preview::Mux::Smux::Detail;
    namespace Yamux = Preview::Mux::Yamux::Detail;
    namespace SmuxApi = Preview::Mux::Smux;
    namespace YamuxApi = Preview::Mux::Yamux;
    namespace H2Mux = Preview::Mux::H2Mux;
    using Preview::Error;
    using Preview::MakeMemoryPair;
    using Preview::MemoryStream;
    using Preview::Testing::MuxSession::DrainClosedSessionActivity;
    using Preview::Testing::MuxSession::DrainSessionFixture;
    using Preview::Testing::MuxSession::ExpectIoSuccess;
    using Preview::Testing::MuxSession::RunFactorySmux;
    using Preview::Testing::MuxSession::RunJoinedCoro;
    using Preview::Testing::MuxSession::RunSessionBody;
    using Preview::Testing::MuxSession::RunSmuxMultiStream;
    using Preview::Testing::MuxSession::SessionFixture;
    using Preview::Testing::MuxSession::SessionRequest;

    auto WriteWire(std::shared_ptr<Preview::Transmission> Peer,
                   std::vector<std::uint8_t> Wire) -> Net::awaitable<Preview::IoResult>
    {
        co_return co_await Peer->WriteExact(std::as_bytes(std::span(Wire)));
    }

    /// 通用会话测试：Client/Server 值对象执行完整回显和关闭。
    template <typename Client, typename Server>
    auto RunSession(SessionRequest<Client, Server> Request) -> std::size_t
    {
        auto [ClientRaw, ServerRaw] = MakeMemoryPair(Request.Ioc.get_executor());
        Request.ClientRaw = std::make_shared<MemoryStream>(std::move(ClientRaw));
        Request.ServerRaw = std::make_shared<MemoryStream>(std::move(ServerRaw));
        EXPECT_TRUE(Request.Client.Connect(Request.ClientRaw));
        EXPECT_TRUE(Request.Server.Accept(Request.ServerRaw));
        RunJoinedCoro(Request.Ioc, RunSessionBody(Request), [&Request] { return CloseSessionPair(Request); });
        return Request.Received;
    }

    /// 驱动 Yamux SYN 并确认服务端收到流。
    auto RunYamuxSynWindowUpdate(Net::io_context &Ioc, YamuxApi::Server<> &Server,
                                 std::shared_ptr<MemoryStream> Peer) -> Net::awaitable<void>
    {
        const auto Open = Yamux::Codec::BuildOpen(1);
        const auto Write = co_await WriteWire(Peer, Open);
        ExpectIoSuccess(Write, Open.size());
        co_await Net::post(Ioc.get_executor(), Net::use_awaitable);
        auto Stream = co_await Server.AcceptStream();
        EXPECT_NE(Stream, nullptr);
        co_await Server.Session()->Close();
    }

    /// 注入无 SYN 的 Yamux 数据并确认会话拒绝隐式开流。
    auto RunYamuxUnknownData(SessionFixture<Yamux::Codec> &Fixture)
        -> Net::awaitable<void>
    {
        const auto Data = Yamux::BuildData(
            Yamux::Flags::None, 1,
            std::span<const std::uint8_t>{reinterpret_cast<const std::uint8_t *>("stray"), 5});
        const auto Write = co_await WriteWire(Fixture.Peer, Data);
        ExpectIoSuccess(Write, Data.size());
        const auto FrameLoop = co_await Fixture.Session->Tasks()->Drain();
        EXPECT_TRUE(FrameLoop);
        EXPECT_EQ(Fixture.Session->StreamCount(), 0u);
        co_await DrainClosedSessionActivity(Fixture);
        EXPECT_FALSE(Fixture.Session->IsOpen());
        co_await DrainSessionFixture(Fixture);
    }

    /// 注入无 SYN 的 Smux 数据并确认会话拒绝隐式开流。
    auto RunSmuxUnknownData(SessionFixture<Smux::Codec> &Fixture)
        -> Net::awaitable<void>
    {
        const auto Data = Smux::Codec::BuildData(
            1, std::span<const std::uint8_t>{reinterpret_cast<const std::uint8_t *>("stray"), 5});
        const auto Write = co_await WriteWire(Fixture.Peer, Data);
        ExpectIoSuccess(Write, Data.size());
        const auto FrameLoop = co_await Fixture.Session->Tasks()->Drain();
        EXPECT_TRUE(FrameLoop);
        EXPECT_EQ(Fixture.Session->StreamCount(), 0u);
        co_await DrainClosedSessionActivity(Fixture);
        EXPECT_FALSE(Fixture.Session->IsOpen());
        co_await DrainSessionFixture(Fixture);
    }

    /// 在对端 FIN 后注入数据，确认会话报告协议错误并收口。
    auto RunDataAfterPeerFin(SessionFixture<Smux::Codec> &Fixture)
        -> Net::awaitable<void>
    {
        const auto Open = Smux::Codec::BuildOpen(1);
        const auto OpenWrite = co_await WriteWire(Fixture.Peer, Open);
        ExpectIoSuccess(OpenWrite, Open.size());
        auto Stream = co_await Fixture.Session->AcceptStream();
        EXPECT_NE(Stream, nullptr);
        if (!Stream)
        {
            co_await DrainSessionFixture(Fixture);
            co_return;
        }
        const auto Fin = Smux::Codec::BuildFin(1);
        const auto FinWrite = co_await WriteWire(Fixture.Peer, Fin);
        ExpectIoSuccess(FinWrite, Fin.size());
        const auto Data = Smux::Codec::BuildData(
            1, std::span<const std::uint8_t>{reinterpret_cast<const std::uint8_t *>("late"), 4});
        const auto DataWrite = co_await WriteWire(Fixture.Peer, Data);
        ExpectIoSuccess(DataWrite, Data.size());
        const auto FrameLoop = co_await Fixture.Session->Tasks()->Drain();
        EXPECT_TRUE(FrameLoop);
        co_await DrainClosedSessionActivity(Fixture);
        EXPECT_FALSE(Fixture.Session->IsOpen());
        co_await DrainSessionFixture(Fixture);
    }

    /// 注入重复 Smux SYN，确认重复流被视为协议错误。
    auto RunDuplicateSmuxSyn(SessionFixture<Smux::Codec> &Fixture)
        -> Net::awaitable<void>
    {
        const auto Open = Smux::Codec::BuildOpen(1);
        const auto Write = co_await WriteWire(Fixture.Peer, Open);
        ExpectIoSuccess(Write, Open.size());
        auto Stream = co_await Fixture.Session->AcceptStream();
        EXPECT_NE(Stream, nullptr);
        if (!Stream)
        {
            co_await DrainSessionFixture(Fixture);
            co_return;
        }
        const auto DuplicateWrite = co_await WriteWire(Fixture.Peer, Open);
        ExpectIoSuccess(DuplicateWrite, Open.size());
        const auto FrameLoop = co_await Fixture.Session->Tasks()->Drain();
        EXPECT_TRUE(FrameLoop);
        co_await DrainClosedSessionActivity(Fixture);
        EXPECT_FALSE(Fixture.Session->IsOpen());
        co_await DrainSessionFixture(Fixture);
    }

    using CompletionChannel = Net::experimental::channel<void(boost::system::error_code)>;

    /// 读取 Yamux 数据并核对流级与会话级窗口更新帧。
    auto RunYamuxRxConsumption(
        Net::io_context &Ioc,
        std::shared_ptr<Preview::Mux::Session<Yamux::Codec>> Session,
        std::shared_ptr<MemoryStream> Peer) -> Net::awaitable<void>
    {
        const auto Open = Yamux::Codec::BuildOpen(1);
        const std::string Payload = "window-credit";
        const auto Data = Yamux::BuildData(
            Yamux::Flags::None, 1,
            std::span<const std::uint8_t>{
                reinterpret_cast<const std::uint8_t *>(Payload.data()), Payload.size()});
        const auto OpenWrite = co_await WriteWire(Peer, Open);
        const auto DataWrite = co_await WriteWire(Peer, Data);
        ExpectIoSuccess(OpenWrite, Open.size());
        ExpectIoSuccess(DataWrite, Data.size());
        co_await Net::post(Ioc.get_executor(), Net::use_awaitable);

        auto Stream = co_await Session->AcceptStream();
        EXPECT_NE(Stream, nullptr);
        if (!Stream)
        {
            co_await Session->Close();
            co_return;
        }
        std::array<std::uint8_t, 64> Buffer{};
        const auto Read = co_await Stream->ReadSome(Buffer);
        EXPECT_EQ(Read, Payload.size());

        Peer->SetTimeout(std::chrono::milliseconds(25));
        std::array<std::uint8_t, Yamux::FrameHdrsize> AckWire{};
        const auto AckRead = co_await Peer->ReadSome(
            std::span<std::byte>(reinterpret_cast<std::byte *>(AckWire.data()), AckWire.size()));
        ExpectIoSuccess(AckRead, AckWire.size());
        if (AckRead.Bytes == AckWire.size())
        {
            Yamux::FrameHeader Ack{};
            EXPECT_EQ(Yamux::ParseHeader(AckWire, Ack), Error::None);
            EXPECT_EQ(Ack.Type, Yamux::MessageType::WindowUpdate);
            EXPECT_EQ(Ack.flag, Yamux::Flags::Ack);
            EXPECT_EQ(Ack.StreamId, 1u);
            EXPECT_EQ(Ack.length, Yamux::DefaultWindow);
        }
        std::array<std::uint8_t, Yamux::FrameHdrsize> WindowWire{};
        const auto WindowRead = co_await Peer->ReadSome(
            std::span<std::byte>(reinterpret_cast<std::byte *>(WindowWire.data()), WindowWire.size()));
        ExpectIoSuccess(WindowRead, WindowWire.size());
        if (WindowRead.Bytes == WindowWire.size())
        {
            Yamux::FrameHeader Window{};
            EXPECT_EQ(Yamux::ParseHeader(WindowWire, Window), Error::None);
            EXPECT_EQ(Window.Type, Yamux::MessageType::WindowUpdate);
            EXPECT_EQ(Window.flag, Yamux::Flags::None);
            EXPECT_EQ(Window.StreamId, 1u);
            EXPECT_EQ(Window.length, Payload.size());
        }
        co_await Session->Close();
    }

    struct YamuxWriteRequest final
    {
        std::shared_ptr<Preview::Mux::StreamTransmission> Stream;
        std::array<std::uint8_t, 3> Payload;
        Preview::IoResult &Result;
    };

    auto RunYamuxWrite(YamuxWriteRequest Request) -> Net::awaitable<void>
    {
        Request.Result = co_await Request.Stream->WriteExact(
            std::as_bytes(std::span(Request.Payload)));
    }

    /// 验证对端窗口耗尽时写入保持挂起，补充窗口后再完成。
    auto RunYamuxSendWindow(
        Net::io_context &Ioc,
        std::shared_ptr<Preview::Mux::Session<Yamux::Codec>> Session,
        std::shared_ptr<MemoryStream> Peer) -> Net::awaitable<void>
    {
        const auto Open = Yamux::BuildWinupd(Yamux::Flags::Syn, 1, 2);
        const auto OpenWrite = co_await WriteWire(
            Peer, std::vector<std::uint8_t>(Open.begin(), Open.end()));
        ExpectIoSuccess(OpenWrite, Open.size());
        co_await Net::post(Ioc.get_executor(), Net::use_awaitable);
        auto Handle = co_await Session->AcceptStream();
        EXPECT_NE(Handle, nullptr);
        if (!Handle)
        {
            co_await Session->Close();
            co_return;
        }
        auto Stream = std::make_shared<Preview::Mux::StreamTransmission>(
            std::move(Handle));

        auto Done = std::make_shared<CompletionChannel>(Ioc.get_executor(), 1);
        Preview::IoResult Result;
        std::exception_ptr WriterFailure;
        const std::array<std::uint8_t, 3> Payload{0x31, 0x32, 0x33};
        Net::co_spawn(Ioc, RunYamuxWrite(YamuxWriteRequest{Stream, Payload, Result}),
                      [&Done, &WriterFailure](std::exception_ptr Failure)
                      {
                          WriterFailure = std::move(Failure);
                          (void)Done->try_send(boost::system::error_code{});
                      });
        co_await Net::post(Ioc.get_executor(), Net::use_awaitable);
        co_await Net::post(Ioc.get_executor(), Net::use_awaitable);
        const auto CompletedBeforeCredit = Done->try_receive(
            [](boost::system::error_code) {});
        EXPECT_FALSE(CompletedBeforeCredit);
        if (CompletedBeforeCredit)
        {
            co_await Session->Close();
            co_return;
        }
        const auto Credit = Yamux::Codec::BuildWindowUpdate(1, 1);
        const auto CreditWrite = co_await WriteWire(Peer, Credit);
        ExpectIoSuccess(CreditWrite, Credit.size());
        co_await Done->async_receive(Net::use_awaitable);
        EXPECT_FALSE(WriterFailure);
        EXPECT_EQ(Result.Bytes, Payload.size());
        EXPECT_TRUE(Result.Failure.Succeeded());
        EXPECT_FALSE(Result.Failure.Native);
        co_await Session->Close();
    }

    /// 发送 Yamux RST 后读取对端输出，确认不会返回窗口信用。
    auto RunYamuxRst(
        Net::io_context &Ioc,
        std::shared_ptr<Preview::Mux::Session<Yamux::Codec>> Session,
        std::shared_ptr<MemoryStream> Peer) -> Net::awaitable<void>
    {
        const auto Syn = Yamux::BuildData(Yamux::Flags::Syn, 1, std::span<const std::uint8_t>{});
        const auto SynWrite = co_await WriteWire(Peer, Syn);
        ExpectIoSuccess(SynWrite, Syn.size());
        co_await Net::post(Ioc.get_executor(), Net::use_awaitable);
        auto Stream = co_await Session->AcceptStream();
        EXPECT_NE(Stream, nullptr);
        if (!Stream)
        {
            co_await Session->Close();
            co_return;
        }
        Peer->SetTimeout(std::chrono::milliseconds(25));
        std::array<std::uint8_t, Yamux::FrameHdrsize> AckWire{};
        const auto AckRead = co_await Peer->ReadSome(
            std::span<std::byte>(reinterpret_cast<std::byte *>(AckWire.data()), AckWire.size()));
        ExpectIoSuccess(AckRead, AckWire.size());
        const auto Payload = std::array<std::uint8_t, 5>{1, 2, 3, 4, 5};
        const auto Data = Yamux::BuildData(Yamux::Flags::None, 1, Payload);
        const auto DataWrite = co_await WriteWire(Peer, Data);
        ExpectIoSuccess(DataWrite, Data.size());
        co_await Net::post(Ioc.get_executor(), Net::use_awaitable);
        const auto Reset = Yamux::BuildData(Yamux::Flags::Rst, 1, std::span<const std::uint8_t>{});
        const auto ResetWrite = co_await WriteWire(Peer, Reset);
        ExpectIoSuccess(ResetWrite, Reset.size());
        co_await Net::post(Ioc.get_executor(), Net::use_awaitable);
        co_await Net::post(Ioc.get_executor(), Net::use_awaitable);
        std::array<std::uint8_t, Yamux::FrameHdrsize> Unexpected{};
        const auto Read = co_await Peer->ReadSome(
            std::span<std::byte>(reinterpret_cast<std::byte *>(Unexpected.data()), Unexpected.size()));
        EXPECT_EQ(Read.Bytes, 0u);
        EXPECT_EQ(Read.Failure.Code, Preview::Fault::Code::Timeout);
        EXPECT_FALSE(Read.Failure.Native);
        co_await Session->Close();
    }

    auto RunTaskRegistryClose(
        Net::io_context &Ioc,
        std::shared_ptr<Preview::Mux::Session<Smux::Codec>> Session,
        std::shared_ptr<Preview::Lifecycle::TaskRegistry> Control) -> Net::awaitable<void>
    {
        co_await Net::post(Ioc.get_executor(), Net::use_awaitable);
        EXPECT_GT(Control->Stats().Started, 0U);
        EXPECT_EQ(Control->Stats().Active, 1U);
        const auto Listed = co_await Control->ListTasks(
            Preview::Lifecycle::TaskRegistryListRequest{
                .Session = Preview::SessionId{41},
                .Worker = Preview::WorkerId{2},
                .Generation = Preview::GenerationId{1},
                .Cursor = 0U,
                .Limit = 10U});
        EXPECT_TRUE(Listed);
        if (Listed)
        {
            EXPECT_EQ(Listed->Items.size(), 1U);
            if (Listed->Items.size() == 1U)
            {
                const auto &Identity = Listed->Items.front().Identity;
                EXPECT_TRUE(Identity.TaskId);
                EXPECT_EQ(Identity.SessionId, Preview::SessionId{41});
                EXPECT_EQ(Identity.StreamId, Preview::StreamId{});
                EXPECT_EQ(Identity.WorkerId, Preview::WorkerId{2});
                EXPECT_EQ(Identity.Generation, Preview::GenerationId{1});
                EXPECT_EQ(Identity.ParentTaskId, Preview::TaskId{});
            }
        }
        co_await Session->Close();
        co_await Control->Drain();
        EXPECT_EQ(Control->Stats().Active, 0U);
        EXPECT_FALSE(Session->IsOpen());
    }

    auto RunTaskRegistryCancel(
        Net::io_context &Ioc,
        std::shared_ptr<Preview::Mux::Session<Smux::Codec>> Session,
        std::shared_ptr<Preview::Lifecycle::TaskRegistry> Control) -> Net::awaitable<void>
    {
        co_await Net::post(Ioc.get_executor(), Net::use_awaitable);
        (void)Control->Cancel();
        co_await Control->Drain();
        EXPECT_EQ(Control->Stats().Active, 0U);
        EXPECT_FALSE(Session->IsOpen());
    }

    auto RunClosingOwner(
        Net::io_context &Ioc,
        std::shared_ptr<Preview::Mux::Session<Smux::Codec>> Session,
        std::shared_ptr<Preview::Lifecycle::TaskRegistry> Control) -> Net::awaitable<void>
    {
        co_await Net::post(Ioc.get_executor(), Net::use_awaitable);
        auto Stream = co_await Session->OpenStream();
        EXPECT_TRUE(Stream);
        if (!Stream)
        {
            co_return;
        }
        EXPECT_EQ(Session->StreamCount(), 1U);
        co_await Session->Close();
        EXPECT_FALSE(Stream->IsOpen());
        co_await Control->Drain();
        EXPECT_EQ(Control->Stats().Active, 0U);
        EXPECT_EQ(Session->StreamCount(), 0U);
    }

    TEST(MuxSession, SmuxEcho)
    {
        Net::io_context ioc;
        SmuxApi::Client cl;
        SmuxApi::Server sv;
        EXPECT_EQ(RunSession(SessionRequest{ ioc, cl, sv, 100 * 1024 }), 100 * 1024u);
    }

    TEST(MuxSession, YamuxEcho)
    {
        Net::io_context ioc;
        YamuxApi::Client cl;
        YamuxApi::Server sv;
        EXPECT_EQ(RunSession(SessionRequest{ ioc, cl, sv, 100 * 1024 }), 100 * 1024u);
    }

    TEST(MuxSession, H2muxEcho)
    {
        Net::io_context ioc;
        H2Mux::Client cl;
        H2Mux::Server sv;
        EXPECT_EQ(RunSession(SessionRequest{ ioc, cl, sv, 100 * 1024 }), 100 * 1024u);
    }

    TEST(MuxSession, YamuxSynWindowUpdateReachesServerAccept)
    {
        Net::io_context Ioc;
        auto [Raw, PeerRaw] = MakeMemoryPair(Ioc.get_executor());
        auto Peer = std::make_shared<MemoryStream>(std::move(PeerRaw));
        YamuxApi::Server Server;
        Preview::Mux::SessionOptions Options;
        Options.timeout = std::chrono::milliseconds(25);
        ASSERT_TRUE(Server.Accept(std::make_shared<MemoryStream>(std::move(Raw)), Options));

        RunJoinedCoro(Ioc, RunYamuxSynWindowUpdate(Ioc, Server, Peer),
            [&Server, Peer]
            { return Preview::Testing::MuxSession::CloseSessionAndPeer(Server.Session(), Peer); });
    }

    TEST(MuxSession, YamuxUnknownDataWithoutSynDoesNotImplicitlyOpen)
    {
        Net::io_context Ioc;
        auto [Raw, PeerRaw] = MakeMemoryPair(Ioc.get_executor());
        auto SessionRaw = std::make_shared<MemoryStream>(std::move(Raw));
        auto Peer = std::make_shared<MemoryStream>(std::move(PeerRaw));
        Preview::Mux::SessionOptions Options;
        Options.Role = Preview::Role::Server;
        SessionFixture<Yamux::Codec> Fixture{
            .Session = Preview::Mux::Session<Yamux::Codec>::Create(SessionRaw, Options),
            .Raw = std::move(SessionRaw),
            .Peer = std::move(Peer)};
        ASSERT_TRUE(Fixture.Session);

        RunJoinedCoro(Ioc, RunYamuxUnknownData(Fixture),
            [&Fixture] { return DrainSessionFixture(Fixture); });
    }

    TEST(MuxSession, SmuxUnknownDataWithoutSynDoesNotImplicitlyOpen)
    {
        Net::io_context Ioc;
        auto [Raw, PeerRaw] = MakeMemoryPair(Ioc.get_executor());
        auto SessionRaw = std::make_shared<MemoryStream>(std::move(Raw));
        auto Peer = std::make_shared<MemoryStream>(std::move(PeerRaw));
        Preview::Mux::SessionOptions Options;
        Options.Role = Preview::Role::Server;
        SessionFixture<Smux::Codec> Fixture{
            .Session = Preview::Mux::Session<Smux::Codec>::Create(SessionRaw, Options),
            .Raw = std::move(SessionRaw),
            .Peer = std::move(Peer)};
        ASSERT_TRUE(Fixture.Session);

        RunJoinedCoro(Ioc, RunSmuxUnknownData(Fixture),
            [&Fixture] { return DrainSessionFixture(Fixture); });
    }

    TEST(MuxSession, DataAfterPeerFinIsProtocolError)
    {
        Net::io_context Ioc;
        auto [Raw, PeerRaw] = MakeMemoryPair(Ioc.get_executor());
        auto SessionRaw = std::make_shared<MemoryStream>(std::move(Raw));
        auto Peer = std::make_shared<MemoryStream>(std::move(PeerRaw));
        Preview::Mux::SessionOptions Options;
        Options.Role = Preview::Role::Server;
        SessionFixture<Smux::Codec> Fixture{
            .Session = Preview::Mux::Session<Smux::Codec>::Create(SessionRaw, Options),
            .Raw = std::move(SessionRaw),
            .Peer = std::move(Peer)};
        ASSERT_TRUE(Fixture.Session);

        RunJoinedCoro(Ioc, RunDataAfterPeerFin(Fixture),
            [&Fixture] { return DrainSessionFixture(Fixture); });
    }

    TEST(MuxSession, DuplicateSmuxSynIsProtocolError)
    {
        Net::io_context Ioc;
        auto [Raw, PeerRaw] = MakeMemoryPair(Ioc.get_executor());
        auto SessionRaw = std::make_shared<MemoryStream>(std::move(Raw));
        auto Peer = std::make_shared<MemoryStream>(std::move(PeerRaw));
        Preview::Mux::SessionOptions Options;
        Options.Role = Preview::Role::Server;
        SessionFixture<Smux::Codec> Fixture{
            .Session = Preview::Mux::Session<Smux::Codec>::Create(SessionRaw, Options),
            .Raw = std::move(SessionRaw),
            .Peer = std::move(Peer)};
        ASSERT_TRUE(Fixture.Session);

        RunJoinedCoro(Ioc, RunDuplicateSmuxSyn(Fixture),
            [&Fixture] { return DrainSessionFixture(Fixture); });
    }

    TEST(MuxSession, YamuxRxConsumptionSendsWindowUpdate)
    {
        Net::io_context Ioc;
        auto [Raw, PeerRaw] = MakeMemoryPair(Ioc.get_executor());
        auto Peer = std::make_shared<MemoryStream>(std::move(PeerRaw));
        Preview::Mux::SessionOptions Options;
        Options.Role = Preview::Role::Server;
        Options.timeout = std::chrono::milliseconds(100);
        auto Session = Preview::Mux::Session<Yamux::Codec>::Create(
            std::make_shared<MemoryStream>(std::move(Raw)), Options);
        ASSERT_TRUE(Session);

        RunJoinedCoro(Ioc, RunYamuxRxConsumption(Ioc, Session, Peer),
            [Session, Peer]
            { return Preview::Testing::MuxSession::CloseSessionAndPeer(Session, Peer); });
    }

    TEST(MuxSession, YamuxSendHonorsPeerAdvertisedWindow)
    {
        Net::io_context Ioc;
        auto [Raw, PeerRaw] = MakeMemoryPair(Ioc.get_executor());
        auto Peer = std::make_shared<MemoryStream>(std::move(PeerRaw));
        Preview::Mux::SessionOptions Options;
        Options.Role = Preview::Role::Server;
        auto Session = Preview::Mux::Session<Yamux::Codec>::Create(
            std::make_shared<MemoryStream>(std::move(Raw)), Options);
        ASSERT_TRUE(Session);

        RunJoinedCoro(Ioc, RunYamuxSendWindow(Ioc, Session, Peer),
            [Session, Peer]
            { return Preview::Testing::MuxSession::CloseSessionAndPeer(Session, Peer); });
    }

    TEST(MuxSession, YamuxRstDoesNotReturnWindowCredit)
    {
        Net::io_context Ioc;
        auto [Raw, PeerRaw] = MakeMemoryPair(Ioc.get_executor());
        auto Peer = std::make_shared<MemoryStream>(std::move(PeerRaw));
        Preview::Mux::SessionOptions Options;
        Options.Role = Preview::Role::Server;
        auto Session = Preview::Mux::Session<Yamux::Codec>::Create(
            std::make_shared<MemoryStream>(std::move(Raw)), Options);
        ASSERT_TRUE(Session);

        RunJoinedCoro(Ioc, RunYamuxRst(Ioc, Session, Peer),
            [Session, Peer]
            { return Preview::Testing::MuxSession::CloseSessionAndPeer(Session, Peer); });
    }

    TEST(MuxSession, SmuxMultiStream)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        SmuxApi::Client cl;
        SmuxApi::Server sv;
        SessionRequest Request{ioc, cl, sv, 0U};
        Request.ClientRaw = std::make_shared<MemoryStream>(std::move(a));
        Request.ServerRaw = std::make_shared<MemoryStream>(std::move(b));
        ASSERT_TRUE(cl.Connect(Request.ClientRaw));
        ASSERT_TRUE(sv.Accept(Request.ServerRaw));

        RunJoinedCoro(ioc, RunSmuxMultiStream(Request), [&Request] { return CloseSessionPair(Request); });
    }

    TEST(MuxSession, FactorySmux)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        SmuxApi::Client cl;
        SmuxApi::Server sv;
        SessionRequest Request{ioc, cl, sv, 0U};
        Request.ClientRaw = std::make_shared<MemoryStream>(std::move(a));
        Request.ServerRaw = std::make_shared<MemoryStream>(std::move(b));
        ASSERT_TRUE(cl.Connect(Request.ClientRaw));
        ASSERT_TRUE(sv.Accept(Request.ServerRaw));
        RunJoinedCoro(ioc, RunFactorySmux(Request), [&Request] { return CloseSessionPair(Request); });
    }

    TEST(MuxSession, TaskRegistryOwnsFrameLoopUntilClose)
    {
        Net::io_context Ioc;
        auto [Raw, PeerRaw] = MakeMemoryPair(Ioc.get_executor());
        auto Peer = std::make_shared<MemoryStream>(std::move(PeerRaw));
        auto Control = std::make_shared<Preview::Lifecycle::TaskRegistry>(Ioc.get_executor());
        Preview::Mux::SessionOptions Options;
        Options.Registry = Control;
        Options.Identity.SessionId = Preview::SessionId{41};
        Options.Identity.WorkerId = Preview::WorkerId{2};
        Options.Identity.Generation = Preview::GenerationId{1};
        auto Session = Preview::Mux::Session<Smux::Codec>::Create(
            std::make_shared<MemoryStream>(std::move(Raw)), Options);
        ASSERT_TRUE(Session);

        RunJoinedCoro(Ioc, RunTaskRegistryClose(Ioc, Session, Control), [Session, Peer]
            { return Preview::Testing::MuxSession::CloseSessionAndPeer(Session, Peer); });

        EXPECT_EQ(Session->StreamCount(), 0U);
        (void)Peer;
    }

    TEST(MuxSession, TaskRegistryCancellationReleasesFrameLoop)
    {
        Net::io_context Ioc;
        auto [Raw, PeerRaw] = MakeMemoryPair(Ioc.get_executor());
        auto Peer = std::make_shared<MemoryStream>(std::move(PeerRaw));
        auto Control = std::make_shared<Preview::Lifecycle::TaskRegistry>(Ioc.get_executor());
        Preview::Mux::SessionOptions Options;
        Options.Registry = Control;
        Options.Identity.SessionId = Preview::SessionId{42};
        auto Session = Preview::Mux::Session<Smux::Codec>::Create(
            std::make_shared<MemoryStream>(std::move(Raw)), Options);
        ASSERT_TRUE(Session);

        RunJoinedCoro(Ioc, RunTaskRegistryCancel(Ioc, Session, Control), [Session, Peer]
            { return Preview::Testing::MuxSession::CloseSessionAndPeer(Session, Peer); });

        (void)Peer;
    }

    TEST(MuxSession, ClosingOwnerInvalidatesVirtualStreamAndDrainsWriter)
    {
        Net::io_context Ioc;
        auto [Raw, PeerRaw] = MakeMemoryPair(Ioc.get_executor());
        auto Peer = std::make_shared<MemoryStream>(std::move(PeerRaw));
        auto Control = std::make_shared<Preview::Lifecycle::TaskRegistry>(Ioc.get_executor());
        Preview::Mux::SessionOptions Options;
        Options.Registry = Control;
        Options.Identity.SessionId = Preview::SessionId{43};
        auto Session = Preview::Mux::Session<Smux::Codec>::Create(
            std::make_shared<MemoryStream>(std::move(Raw)), Options);
        ASSERT_TRUE(Session);

        RunJoinedCoro(Ioc, RunClosingOwner(Ioc, Session, Control), [Session, Peer]
            { return Preview::Testing::MuxSession::CloseSessionAndPeer(Session, Peer); });

        (void)Peer;
    }

} // namespace
