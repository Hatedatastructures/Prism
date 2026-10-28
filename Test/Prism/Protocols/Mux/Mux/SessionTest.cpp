/**
 * @file SessionTest.cpp
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

#include <Prism/Transport/MemoryStream.hpp>
#include <Prism/Protocols/Mux/H2Mux/H2Mux.hpp>
#include <Prism/Protocols/Mux/Smux/Smux.hpp>
#include <Prism/Protocols/Mux/Yamux/Yamux.hpp>
#include <Prism/Lifecycle/Task/Registry.hpp>
#include "SessionTestSupport.hpp"
#include <gtest/gtest.h>

    namespace
    {
    namespace Net = boost::asio;
    namespace SmuxWire = Prism::Mux::Smux::Detail;
    namespace YamuxWire = Prism::Mux::Yamux::Detail;
    namespace SmuxApi = Prism::Mux::Smux;
    namespace YamuxApi = Prism::Mux::Yamux;
    namespace H2Mux = Prism::Mux::H2Mux;
    using Prism::Error;
    using Prism::MakeMemoryPair;
    using Prism::MemoryStream;
    using Prism::Testing::MuxSession::DrainClosedSessionActivity;
    using Prism::Testing::MuxSession::DrainSessionFixture;
    using Prism::Testing::MuxSession::ExpectIoSuccess;
    using Prism::Testing::MuxSession::RunFactorySmux;
    using Prism::Testing::MuxSession::RunJoinedCoro;
    using Prism::Testing::MuxSession::RunSessionBody;
    using Prism::Testing::MuxSession::RunSmuxMultiStream;
    using Prism::Testing::MuxSession::SessionFixture;
    using Prism::Testing::MuxSession::SessionRequest;

    auto WriteWire(std::shared_ptr<Prism::Transmission> Peer,
                   std::vector<std::uint8_t> Wire) -> Net::awaitable<Prism::IoResult>
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
        const auto Open = YamuxWire::Codec::BuildOpen(1);
        const auto Write = co_await WriteWire(Peer, Open);
        ExpectIoSuccess(Write, Open.size());
        co_await Net::post(Ioc.get_executor(), Net::use_awaitable);
        auto Stream = co_await Server.AcceptStream();
        EXPECT_NE(Stream, nullptr);
        co_await Server.Session()->Close();
    }

    /// 注入无 SYN 的 Yamux 数据并确认会话拒绝隐式开流。
    auto RunYamuxUnknownData(SessionFixture<YamuxWire::Codec> &Fixture)
        -> Net::awaitable<void>
    {
        const auto Data = YamuxWire::BuildData(
            YamuxApi::Flags::None, 1,
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
    auto RunSmuxUnknownData(SessionFixture<SmuxWire::Codec> &Fixture)
        -> Net::awaitable<void>
    {
        const auto Data = SmuxWire::Codec::BuildData(
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
    auto RunDataAfterPeerFin(SessionFixture<SmuxWire::Codec> &Fixture)
        -> Net::awaitable<void>
    {
        const auto Open = SmuxWire::Codec::BuildOpen(1);
        const auto OpenWrite = co_await WriteWire(Fixture.Peer, Open);
        ExpectIoSuccess(OpenWrite, Open.size());
        auto Stream = co_await Fixture.Session->AcceptStream();
        EXPECT_NE(Stream, nullptr);
        if (!Stream)
        {
            co_await DrainSessionFixture(Fixture);
            co_return;
        }
        const auto Fin = SmuxWire::Codec::BuildFin(1);
        const auto FinWrite = co_await WriteWire(Fixture.Peer, Fin);
        ExpectIoSuccess(FinWrite, Fin.size());
        const auto Data = SmuxWire::Codec::BuildData(
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
    auto RunDuplicateSmuxSyn(SessionFixture<SmuxWire::Codec> &Fixture)
        -> Net::awaitable<void>
    {
        const auto Open = SmuxWire::Codec::BuildOpen(1);
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
        std::shared_ptr<Prism::Mux::Session<YamuxWire::Codec>> Session,
        std::shared_ptr<MemoryStream> Peer) -> Net::awaitable<void>
    {
        const auto Open = YamuxWire::Codec::BuildOpen(1);
        const std::string Payload = "window-credit";
        const auto Data = YamuxWire::BuildData(
            YamuxApi::Flags::None, 1,
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
        std::array<std::uint8_t, YamuxApi::FrameHdrsize> AckWire{};
        const auto AckRead = co_await Peer->ReadSome(
            std::span<std::byte>(reinterpret_cast<std::byte *>(AckWire.data()), AckWire.size()));
        ExpectIoSuccess(AckRead, AckWire.size());
        if (AckRead.Bytes == AckWire.size())
        {
            YamuxApi::FrameHeader Ack{};
            EXPECT_EQ(YamuxWire::ParseHeader(AckWire, Ack), Error::None);
            EXPECT_EQ(Ack.Type, YamuxApi::MessageType::WindowUpdate);
            EXPECT_EQ(Ack.flag, YamuxApi::Flags::Ack);
            EXPECT_EQ(Ack.StreamId, 1u);
            EXPECT_EQ(Ack.length, YamuxApi::DefaultWindow);
        }
        std::array<std::uint8_t, YamuxApi::FrameHdrsize> WindowWire{};
        const auto WindowRead = co_await Peer->ReadSome(
            std::span<std::byte>(reinterpret_cast<std::byte *>(WindowWire.data()), WindowWire.size()));
        ExpectIoSuccess(WindowRead, WindowWire.size());
        if (WindowRead.Bytes == WindowWire.size())
        {
            YamuxApi::FrameHeader Window{};
            EXPECT_EQ(YamuxWire::ParseHeader(WindowWire, Window), Error::None);
            EXPECT_EQ(Window.Type, YamuxApi::MessageType::WindowUpdate);
            EXPECT_EQ(Window.flag, YamuxApi::Flags::None);
            EXPECT_EQ(Window.StreamId, 1u);
            EXPECT_EQ(Window.length, Payload.size());
        }
        co_await Session->Close();
    }

    struct YamuxWriteRequest final
    {
        std::shared_ptr<Prism::Mux::StreamTransmission> Stream;
        std::array<std::uint8_t, 3> Payload;
        Prism::IoResult &Result;
    };

    auto RunYamuxWrite(YamuxWriteRequest Request) -> Net::awaitable<void>
    {
        Request.Result = co_await Request.Stream->WriteExact(
            std::as_bytes(std::span(Request.Payload)));
    }

    /// 验证对端窗口耗尽时写入保持挂起，补充窗口后再完成。
    auto RunYamuxSendWindow(
        Net::io_context &Ioc,
        std::shared_ptr<Prism::Mux::Session<YamuxWire::Codec>> Session,
        std::shared_ptr<MemoryStream> Peer) -> Net::awaitable<void>
    {
        const auto Open = YamuxWire::BuildWinupd(YamuxApi::Flags::Syn, 1, 2);
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
        auto Stream = std::make_shared<Prism::Mux::StreamTransmission>(
            std::move(Handle));

        auto Done = std::make_shared<CompletionChannel>(Ioc.get_executor(), 1);
        Prism::IoResult Result;
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
        const auto Credit = YamuxWire::Codec::BuildWindowUpdate(1, 1);
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
        std::shared_ptr<Prism::Mux::Session<YamuxWire::Codec>> Session,
        std::shared_ptr<MemoryStream> Peer) -> Net::awaitable<void>
    {
        const auto Syn = YamuxWire::BuildData(YamuxApi::Flags::Syn, 1, std::span<const std::uint8_t>{});
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
        std::array<std::uint8_t, YamuxApi::FrameHdrsize> AckWire{};
        const auto AckRead = co_await Peer->ReadSome(
            std::span<std::byte>(reinterpret_cast<std::byte *>(AckWire.data()), AckWire.size()));
        ExpectIoSuccess(AckRead, AckWire.size());
        const auto Payload = std::array<std::uint8_t, 5>{1, 2, 3, 4, 5};
        const auto Data = YamuxWire::BuildData(YamuxApi::Flags::None, 1, Payload);
        const auto DataWrite = co_await WriteWire(Peer, Data);
        ExpectIoSuccess(DataWrite, Data.size());
        co_await Net::post(Ioc.get_executor(), Net::use_awaitable);
        const auto Reset = YamuxWire::BuildData(YamuxApi::Flags::Rst, 1, std::span<const std::uint8_t>{});
        const auto ResetWrite = co_await WriteWire(Peer, Reset);
        ExpectIoSuccess(ResetWrite, Reset.size());
        co_await Net::post(Ioc.get_executor(), Net::use_awaitable);
        co_await Net::post(Ioc.get_executor(), Net::use_awaitable);
        std::array<std::uint8_t, YamuxApi::FrameHdrsize> Unexpected{};
        const auto Read = co_await Peer->ReadSome(
            std::span<std::byte>(reinterpret_cast<std::byte *>(Unexpected.data()), Unexpected.size()));
        EXPECT_EQ(Read.Bytes, 0u);
        EXPECT_EQ(Read.Failure.Code, Prism::Fault::Code::Timeout);
        EXPECT_FALSE(Read.Failure.Native);
        co_await Session->Close();
    }

    auto RunTaskRegistryClose(
        Net::io_context &Ioc,
        std::shared_ptr<Prism::Mux::Session<SmuxWire::Codec>> Session,
        std::shared_ptr<Prism::Lifecycle::TaskRegistry> Control) -> Net::awaitable<void>
    {
        co_await Net::post(Ioc.get_executor(), Net::use_awaitable);
        EXPECT_GT(Control->Stats().Started, 0U);
        EXPECT_EQ(Control->Stats().Active, 1U);
        const auto Listed = co_await Control->ListTasks(
            Prism::Lifecycle::TaskRegistryListRequest{
                .Session = Prism::SessionId{41},
                .Worker = Prism::WorkerId{2},
                .Generation = Prism::GenerationId{1},
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
                EXPECT_EQ(Identity.SessionId, Prism::SessionId{41});
                EXPECT_EQ(Identity.StreamId, Prism::StreamId{});
                EXPECT_EQ(Identity.WorkerId, Prism::WorkerId{2});
                EXPECT_EQ(Identity.Generation, Prism::GenerationId{1});
                EXPECT_EQ(Identity.ParentTaskId, Prism::TaskId{});
            }
        }
        co_await Session->Close();
        co_await Control->Drain();
        EXPECT_EQ(Control->Stats().Active, 0U);
        EXPECT_FALSE(Session->IsOpen());
    }

    auto RunTaskRegistryCancel(
        Net::io_context &Ioc,
        std::shared_ptr<Prism::Mux::Session<SmuxWire::Codec>> Session,
        std::shared_ptr<Prism::Lifecycle::TaskRegistry> Control) -> Net::awaitable<void>
    {
        co_await Net::post(Ioc.get_executor(), Net::use_awaitable);
        (void)Control->Cancel();
        co_await Control->Drain();
        EXPECT_EQ(Control->Stats().Active, 0U);
        EXPECT_FALSE(Session->IsOpen());
    }

    auto RunClosingOwner(
        Net::io_context &Ioc,
        std::shared_ptr<Prism::Mux::Session<SmuxWire::Codec>> Session,
        std::shared_ptr<Prism::Lifecycle::TaskRegistry> Control) -> Net::awaitable<void>
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
        Prism::Mux::SessionOptions Options;
        Options.timeout = std::chrono::milliseconds(25);
        ASSERT_TRUE(Server.Accept(std::make_shared<MemoryStream>(std::move(Raw)), Options));

        RunJoinedCoro(Ioc, RunYamuxSynWindowUpdate(Ioc, Server, Peer),
            [&Server, Peer]
            { return Prism::Testing::MuxSession::CloseSessionAndPeer(Server.Session(), Peer); });
    }

    TEST(MuxSession, YamuxUnknownDataWithoutSynDoesNotImplicitlyOpen)
    {
        Net::io_context Ioc;
        auto [Raw, PeerRaw] = MakeMemoryPair(Ioc.get_executor());
        auto SessionRaw = std::make_shared<MemoryStream>(std::move(Raw));
        auto Peer = std::make_shared<MemoryStream>(std::move(PeerRaw));
        Prism::Mux::SessionOptions Options;
        Options.Role = Prism::Mux::Role::Server;
        SessionFixture<YamuxWire::Codec> Fixture{
            .Session = Prism::Mux::Session<YamuxWire::Codec>::Create(SessionRaw, Options),
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
        Prism::Mux::SessionOptions Options;
        Options.Role = Prism::Mux::Role::Server;
        SessionFixture<SmuxWire::Codec> Fixture{
            .Session = Prism::Mux::Session<SmuxWire::Codec>::Create(SessionRaw, Options),
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
        Prism::Mux::SessionOptions Options;
        Options.Role = Prism::Mux::Role::Server;
        SessionFixture<SmuxWire::Codec> Fixture{
            .Session = Prism::Mux::Session<SmuxWire::Codec>::Create(SessionRaw, Options),
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
        Prism::Mux::SessionOptions Options;
        Options.Role = Prism::Mux::Role::Server;
        SessionFixture<SmuxWire::Codec> Fixture{
            .Session = Prism::Mux::Session<SmuxWire::Codec>::Create(SessionRaw, Options),
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
        Prism::Mux::SessionOptions Options;
        Options.Role = Prism::Mux::Role::Server;
        Options.timeout = std::chrono::milliseconds(100);
        auto Session = Prism::Mux::Session<YamuxWire::Codec>::Create(
            std::make_shared<MemoryStream>(std::move(Raw)), Options);
        ASSERT_TRUE(Session);

        RunJoinedCoro(Ioc, RunYamuxRxConsumption(Ioc, Session, Peer),
            [Session, Peer]
            { return Prism::Testing::MuxSession::CloseSessionAndPeer(Session, Peer); });
    }

    TEST(MuxSession, YamuxSendHonorsPeerAdvertisedWindow)
    {
        Net::io_context Ioc;
        auto [Raw, PeerRaw] = MakeMemoryPair(Ioc.get_executor());
        auto Peer = std::make_shared<MemoryStream>(std::move(PeerRaw));
        Prism::Mux::SessionOptions Options;
        Options.Role = Prism::Mux::Role::Server;
        auto Session = Prism::Mux::Session<YamuxWire::Codec>::Create(
            std::make_shared<MemoryStream>(std::move(Raw)), Options);
        ASSERT_TRUE(Session);

        RunJoinedCoro(Ioc, RunYamuxSendWindow(Ioc, Session, Peer),
            [Session, Peer]
            { return Prism::Testing::MuxSession::CloseSessionAndPeer(Session, Peer); });
    }

    TEST(MuxSession, YamuxRstDoesNotReturnWindowCredit)
    {
        Net::io_context Ioc;
        auto [Raw, PeerRaw] = MakeMemoryPair(Ioc.get_executor());
        auto Peer = std::make_shared<MemoryStream>(std::move(PeerRaw));
        Prism::Mux::SessionOptions Options;
        Options.Role = Prism::Mux::Role::Server;
        auto Session = Prism::Mux::Session<YamuxWire::Codec>::Create(
            std::make_shared<MemoryStream>(std::move(Raw)), Options);
        ASSERT_TRUE(Session);

        RunJoinedCoro(Ioc, RunYamuxRst(Ioc, Session, Peer),
            [Session, Peer]
            { return Prism::Testing::MuxSession::CloseSessionAndPeer(Session, Peer); });
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
        auto Control = std::make_shared<Prism::Lifecycle::TaskRegistry>(Ioc.get_executor());
        Prism::Mux::SessionOptions Options;
        Options.Registry = Control;
        Options.Identity.SessionId = Prism::SessionId{41};
        Options.Identity.WorkerId = Prism::WorkerId{2};
        Options.Identity.Generation = Prism::GenerationId{1};
        auto Session = Prism::Mux::Session<SmuxWire::Codec>::Create(
            std::make_shared<MemoryStream>(std::move(Raw)), Options);
        ASSERT_TRUE(Session);

        RunJoinedCoro(Ioc, RunTaskRegistryClose(Ioc, Session, Control), [Session, Peer]
            { return Prism::Testing::MuxSession::CloseSessionAndPeer(Session, Peer); });

        EXPECT_EQ(Session->StreamCount(), 0U);
        (void)Peer;
    }

    TEST(MuxSession, TaskRegistryCancellationReleasesFrameLoop)
    {
        Net::io_context Ioc;
        auto [Raw, PeerRaw] = MakeMemoryPair(Ioc.get_executor());
        auto Peer = std::make_shared<MemoryStream>(std::move(PeerRaw));
        auto Control = std::make_shared<Prism::Lifecycle::TaskRegistry>(Ioc.get_executor());
        Prism::Mux::SessionOptions Options;
        Options.Registry = Control;
        Options.Identity.SessionId = Prism::SessionId{42};
        auto Session = Prism::Mux::Session<SmuxWire::Codec>::Create(
            std::make_shared<MemoryStream>(std::move(Raw)), Options);
        ASSERT_TRUE(Session);

        RunJoinedCoro(Ioc, RunTaskRegistryCancel(Ioc, Session, Control), [Session, Peer]
            { return Prism::Testing::MuxSession::CloseSessionAndPeer(Session, Peer); });

        (void)Peer;
    }

    TEST(MuxSession, ClosingOwnerInvalidatesVirtualStreamAndDrainsWriter)
    {
        Net::io_context Ioc;
        auto [Raw, PeerRaw] = MakeMemoryPair(Ioc.get_executor());
        auto Peer = std::make_shared<MemoryStream>(std::move(PeerRaw));
        auto Control = std::make_shared<Prism::Lifecycle::TaskRegistry>(Ioc.get_executor());
        Prism::Mux::SessionOptions Options;
        Options.Registry = Control;
        Options.Identity.SessionId = Prism::SessionId{43};
        auto Session = Prism::Mux::Session<SmuxWire::Codec>::Create(
            std::make_shared<MemoryStream>(std::move(Raw)), Options);
        ASSERT_TRUE(Session);

        RunJoinedCoro(Ioc, RunClosingOwner(Ioc, Session, Control), [Session, Peer]
            { return Prism::Testing::MuxSession::CloseSessionAndPeer(Session, Peer); });

        (void)Peer;
    }

} // namespace
