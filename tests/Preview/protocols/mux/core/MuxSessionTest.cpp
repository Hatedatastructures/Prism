/**
 * @file MuxSessionTest.cpp
 * @brief 多路复用会话测试（smux / yamux / h2mux 独立实现）
 * @details 覆盖：Open/Accept、双向数据传输、多流并发、FIN 关闭语义。
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <chrono>
#include <memory>
#include <string>
#include <vector>

#include <Preview/Transport/MemoryStream.hpp>
#include <Preview/Protocols/Mux/H2Mux/H2Mux.hpp>
#include <Preview/Protocols/Mux/Smux/Smux.hpp>
#include <Preview/Protocols/Mux/Yamux/Yamux.hpp>
#include <Preview/Runtime/SessionControl.hpp>
#include <gtest/gtest.h>

    namespace
    {
    namespace Net = boost::asio;
    namespace Smux = Preview::Mux::Smux;
    namespace Yamux = Preview::Mux::Yamux;
    namespace H2Mux = Preview::Mux::H2Mux;
    using Preview::Error;
    using Preview::MakeMemoryPair;
    using Preview::MemoryStream;

    template <typename A>
    auto run_coro(Net::io_context &ioc, A coro) -> void
    {
        std::exception_ptr ep;
        Net::co_spawn(ioc, std::move(coro),
                      [&](std::exception_ptr e)
                      {
                          ep = e;
                          ioc.stop();
                      });
        ioc.run();
        if (ep)
        {
            std::rethrow_exception(ep);
        }
    }

    /// 通用会话测试：cl/sv 为 (Client, Server) 值对象，payload 回显
    template <typename Client, typename Server>
    auto run_session(Net::io_context &ioc, Client &cl, Server &sv, const std::size_t payload_size)
        -> std::size_t
    {
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        EXPECT_TRUE(cl.Connect(std::make_shared<MemoryStream>(std::move(a))));
        EXPECT_TRUE(sv.Accept(std::make_shared<MemoryStream>(std::move(b))));

        std::size_t received = 0;
        run_coro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto server_coro = [&]() -> Net::awaitable<void>
                     {
                         auto s = co_await sv.AcceptStream();
                         if (!s)
                         {
                             EXPECT_TRUE(false) << "Accept Failed";
                             co_return;
                         }
                         std::array<std::byte, 64 * 1024> buf{};
                         while (true)
                         {
                             std::error_code ec;
                             const auto n = co_await s->async_read_some(std::span<std::byte>(buf), ec);
                             if (ec || n == 0)
                             {
                                 break;
                             }
                             received += n;
                             ec.clear();
                             (void)co_await s->async_write_some(std::span<const std::byte>(buf.data(), n),
                                                                ec);
                         }
                         s->Close();
                     };
                     Net::co_spawn(ioc.get_executor(), server_coro(), Net::detached);

                     auto s = co_await cl.OpenStream();
                     if (!s)
                     {
                         EXPECT_TRUE(false) << "Open Failed";
                         co_return;
                     }
                     std::string payload(payload_size, 'M');
                     std::error_code ec;
                     (void)co_await s->async_write_some(
                         std::span<const std::byte>(reinterpret_cast<const std::byte *>(payload.data()),
                                                    payload.size()),
                         ec);
                     std::string echoed;
                     std::array<std::byte, 64 * 1024> buf{};
                     while (echoed.size() < payload.size())
                     {
                         ec.clear();
                         const auto n = co_await s->async_read_some(std::span<std::byte>(buf), ec);
                         if (ec || n == 0)
                         {
                             break;
                         }
                         echoed.append(reinterpret_cast<const char *>(buf.data()), n);
                     }
                     EXPECT_EQ(echoed, payload);
                     s->Close();
                     cl.Close();
                     sv.Close();
                 });
        return received;
    }

    TEST(MuxSession, SmuxEcho)
    {
        Net::io_context ioc;
        Smux::Client cl;
        Smux::Server sv;
        EXPECT_EQ(run_session(ioc, cl, sv, 100 * 1024), 100 * 1024u);
    }

    TEST(MuxSession, YamuxEcho)
    {
        Net::io_context ioc;
        Yamux::Client cl;
        Yamux::Server sv;
        EXPECT_EQ(run_session(ioc, cl, sv, 100 * 1024), 100 * 1024u);
    }

    TEST(MuxSession, H2muxEcho)
    {
        Net::io_context ioc;
        H2Mux::Client cl;
        H2Mux::Server sv;
        EXPECT_EQ(run_session(ioc, cl, sv, 100 * 1024), 100 * 1024u);
    }

    TEST(MuxSession, YamuxSynWindowUpdateReachesServerAccept)
    {
        Net::io_context Ioc;
        auto [Raw, PeerRaw] = MakeMemoryPair(Ioc.get_executor());
        auto Peer = std::make_shared<MemoryStream>(std::move(PeerRaw));
        Yamux::Server Server;
        Preview::Mux::SessionOptions Options;
        Options.timeout = std::chrono::milliseconds(25);
        ASSERT_TRUE(Server.Accept(std::make_shared<MemoryStream>(std::move(Raw)), Options));

        run_coro(Ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     const auto Open = Yamux::Codec::BuildOpen(1);
                     const auto WriteError = co_await Peer->WriteAll(Open);
                     EXPECT_FALSE(WriteError);
                     co_await Net::post(Ioc.get_executor(), Net::use_awaitable);

                     auto Stream = co_await Server.AcceptStream();
                     EXPECT_NE(Stream, nullptr);
                     co_await Server.Session()->Close();
                 });
    }

    TEST(MuxSession, YamuxUnknownDataWithoutSynDoesNotImplicitlyOpen)
    {
        Net::io_context Ioc;
        auto [Raw, PeerRaw] = MakeMemoryPair(Ioc.get_executor());
        auto Peer = std::make_shared<MemoryStream>(std::move(PeerRaw));
        Preview::Mux::SessionOptions Options;
        Options.Role = Preview::Role::Server;
        auto Session = Preview::Mux::Session<Yamux::Codec>::Create(
            std::make_shared<MemoryStream>(std::move(Raw)), Options);
        ASSERT_TRUE(Session);

        run_coro(Ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     const auto Data = Yamux::BuildData(
                         Yamux::Flags::None, 1,
                         std::span<const std::uint8_t>{reinterpret_cast<const std::uint8_t *>("stray"), 5});
                     const auto WriteError = co_await Peer->WriteAll(Data);
                     EXPECT_FALSE(WriteError);
                     co_await Net::post(Ioc.get_executor(), Net::use_awaitable);
                     EXPECT_FALSE(Session->IsOpen());
                     EXPECT_EQ(Session->StreamCount(), 0u);
                     co_await Session->Close();
                 });
    }

    TEST(MuxSession, SmuxUnknownDataWithoutSynDoesNotImplicitlyOpen)
    {
        Net::io_context Ioc;
        auto [Raw, PeerRaw] = MakeMemoryPair(Ioc.get_executor());
        auto Peer = std::make_shared<MemoryStream>(std::move(PeerRaw));
        Preview::Mux::SessionOptions Options;
        Options.Role = Preview::Role::Server;
        auto Session = Preview::Mux::Session<Smux::Codec>::Create(
            std::make_shared<MemoryStream>(std::move(Raw)), Options);
        ASSERT_TRUE(Session);

        run_coro(Ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     const auto Data = Smux::Codec::BuildData(
                         1, std::span<const std::uint8_t>{
                                reinterpret_cast<const std::uint8_t *>("stray"), 5});
                     EXPECT_FALSE(co_await Peer->WriteAll(Data));
                     co_await Net::post(Ioc.get_executor(), Net::use_awaitable);
                     EXPECT_FALSE(Session->IsOpen());
                     EXPECT_EQ(Session->StreamCount(), 0u);
                     co_await Session->Close();
                 });
    }

    TEST(MuxSession, DataAfterPeerFinIsProtocolError)
    {
        Net::io_context Ioc;
        auto [Raw, PeerRaw] = MakeMemoryPair(Ioc.get_executor());
        auto Peer = std::make_shared<MemoryStream>(std::move(PeerRaw));
        Preview::Mux::SessionOptions Options;
        Options.Role = Preview::Role::Server;
        auto Session = Preview::Mux::Session<Smux::Codec>::Create(
            std::make_shared<MemoryStream>(std::move(Raw)), Options);
        ASSERT_TRUE(Session);

        run_coro(Ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     EXPECT_FALSE(co_await Peer->WriteAll(Smux::Codec::BuildOpen(1)));
                     co_await Net::post(Ioc.get_executor(), Net::use_awaitable);
                     auto Stream = co_await Session->AcceptStream();
                     EXPECT_NE(Stream, nullptr);
                     if (!Stream)
                     {
                         co_await Session->Close();
                         co_return;
                     }

                     EXPECT_FALSE(co_await Peer->WriteAll(Smux::Codec::BuildFin(1)));
                     const auto Data = Smux::Codec::BuildData(
                         1, std::span<const std::uint8_t>{
                                reinterpret_cast<const std::uint8_t *>("late"), 4});
                     EXPECT_FALSE(co_await Peer->WriteAll(Data));
                     co_await Net::post(Ioc.get_executor(), Net::use_awaitable);
                     EXPECT_FALSE(Session->IsOpen());
                     co_await Session->Close();
                 });
    }

    TEST(MuxSession, DuplicateSmuxSynIsProtocolError)
    {
        Net::io_context Ioc;
        auto [Raw, PeerRaw] = MakeMemoryPair(Ioc.get_executor());
        auto Peer = std::make_shared<MemoryStream>(std::move(PeerRaw));
        Preview::Mux::SessionOptions Options;
        Options.Role = Preview::Role::Server;
        auto Session = Preview::Mux::Session<Smux::Codec>::Create(
            std::make_shared<MemoryStream>(std::move(Raw)), Options);
        ASSERT_TRUE(Session);

        run_coro(Ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     const auto Open = Smux::Codec::BuildOpen(1);
                     EXPECT_FALSE(co_await Peer->WriteAll(Open));
                     co_await Net::post(Ioc.get_executor(), Net::use_awaitable);
                     auto Stream = co_await Session->AcceptStream();
                     EXPECT_NE(Stream, nullptr);
                     if (!Stream)
                     {
                         co_await Session->Close();
                         co_return;
                     }
                     EXPECT_FALSE(co_await Peer->WriteAll(Open));
                     co_await Net::post(Ioc.get_executor(), Net::use_awaitable);
                     EXPECT_FALSE(Session->IsOpen());
                     co_await Session->Close();
                 });
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

        run_coro(Ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     const auto Open = Yamux::Codec::BuildOpen(1);
                     const std::string Payload = "window-credit";
                     const auto Data = Yamux::BuildData(
                         Yamux::Flags::None, 1,
                         std::span<const std::uint8_t>{
                             reinterpret_cast<const std::uint8_t *>(Payload.data()), Payload.size()});
                     EXPECT_FALSE(co_await Peer->WriteAll(Open));
                     EXPECT_FALSE(co_await Peer->WriteAll(Data));
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
                     std::error_code AckError;
                     AckError.clear();
                     const auto AckRead = co_await Peer->async_read_some(
                         std::span<std::byte>(reinterpret_cast<std::byte *>(AckWire.data()), AckWire.size()),
                         AckError);
                     EXPECT_EQ(AckRead, AckWire.size());
                     if (AckRead == AckWire.size())
                     {
                         Yamux::FrameHeader Ack{};
                         EXPECT_EQ(Yamux::ParseHeader(AckWire, Ack), Error::None);
                         EXPECT_EQ(Ack.Type, Yamux::MessageType::WindowUpdate);
                         EXPECT_EQ(Ack.flag, Yamux::Flags::Ack);
                         EXPECT_EQ(Ack.StreamId, 1u);
                         EXPECT_EQ(Ack.length, Yamux::DefaultWindow);
                     }
                     std::array<std::uint8_t, Yamux::FrameHdrsize> WindowWire{};
                     std::error_code ErrorCode;
                     ErrorCode.clear();
                     const auto WindowRead = co_await Peer->async_read_some(
                         std::span<std::byte>(reinterpret_cast<std::byte *>(WindowWire.data()), WindowWire.size()),
                         ErrorCode);
                     EXPECT_EQ(WindowRead, WindowWire.size());
                     if (WindowRead == WindowWire.size())
                     {
                         Yamux::FrameHeader Window{};
                         EXPECT_EQ(Yamux::ParseHeader(WindowWire, Window), Error::None);
                         EXPECT_EQ(Window.Type, Yamux::MessageType::WindowUpdate);
                         EXPECT_EQ(Window.flag, Yamux::Flags::None);
                         EXPECT_EQ(Window.StreamId, 1u);
                         EXPECT_EQ(Window.length, Payload.size());
                     }
                     co_await Session->Close();
                 });
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

        run_coro(Ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     const auto Open = Yamux::BuildWinupd(Yamux::Flags::Syn, 1, 2);
                     EXPECT_FALSE(co_await Peer->WriteAll(Open));
                     co_await Net::post(Ioc.get_executor(), Net::use_awaitable);
                     auto Stream = co_await Session->AcceptStream();
                     EXPECT_NE(Stream, nullptr);
                     if (!Stream)
                     {
                         co_await Session->Close();
                         co_return;
                     }

                     using ErrorChannel = Net::experimental::channel<void(boost::system::error_code)>;
                     auto Done = std::make_shared<ErrorChannel>(Ioc.get_executor(), 1);
                     Preview::ProtocolEc Result;
                     const std::array<std::uint8_t, 3> Payload{0x31, 0x32, 0x33};
                     Net::co_spawn(
                         Ioc,
                         [Stream, Payload, &Result, Done]() -> Net::awaitable<void>
                         {
                             Result = co_await Stream->WriteAll(Payload);
                             (void)Done->try_send(boost::system::error_code{});
                         },
                         Net::detached);
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

                     EXPECT_FALSE(co_await Peer->WriteAll(Yamux::Codec::BuildWindowUpdate(1, 1)));
                     co_await Done->async_receive(Net::use_awaitable);
                     EXPECT_FALSE(Result);
                     co_await Session->Close();
                 });
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

        run_coro(Ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     EXPECT_FALSE(co_await Peer->WriteAll(
                         Yamux::BuildData(Yamux::Flags::Syn, 1,
                                          std::span<const std::uint8_t>{})));
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
                     std::error_code AckError;
                     const auto AckRead = co_await Peer->async_read_some(
                         std::span<std::byte>(reinterpret_cast<std::byte *>(AckWire.data()), AckWire.size()),
                         AckError);
                     EXPECT_EQ(AckRead, AckWire.size());

                     const auto Payload = std::array<std::uint8_t, 5>{1, 2, 3, 4, 5};
                     EXPECT_FALSE(co_await Peer->WriteAll(
                         Yamux::BuildData(Yamux::Flags::None, 1, Payload)));
                     co_await Net::post(Ioc.get_executor(), Net::use_awaitable);
                     EXPECT_FALSE(co_await Peer->WriteAll(
                         Yamux::BuildData(Yamux::Flags::Rst, 1,
                                          std::span<const std::uint8_t>{})));
                     co_await Net::post(Ioc.get_executor(), Net::use_awaitable);
                     co_await Net::post(Ioc.get_executor(), Net::use_awaitable);

                     std::array<std::uint8_t, Yamux::FrameHdrsize> Unexpected{};
                     std::error_code ErrorCode;
                     const auto Read = co_await Peer->async_read_some(
                         std::span<std::byte>(reinterpret_cast<std::byte *>(Unexpected.data()), Unexpected.size()),
                         ErrorCode);
                     EXPECT_EQ(Read, 0u);
                     co_await Session->Close();
                 });
    }

    TEST(MuxSession, SmuxMultiStream)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        Smux::Client cl;
        Smux::Server sv;
        ASSERT_TRUE(cl.Connect(std::make_shared<MemoryStream>(std::move(a))));
        ASSERT_TRUE(sv.Accept(std::make_shared<MemoryStream>(std::move(b))));

        constexpr int kStreams = 8;
        constexpr std::size_t kPayload = 64 * 1024;
        run_coro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto server_coro = [&]() -> Net::awaitable<void>
                     {
                         std::array<std::byte, 4096> buf{};
                         for (int i = 0; i < kStreams; ++i)
                         {
                             auto s = co_await sv.AcceptStream();
                             if (!s)
                             {
                                 continue;
                             }
                             std::size_t got = 0;
                             while (got < kPayload)
                             {
                                 std::error_code ec;
                                 const auto n = co_await s->async_read_some(std::span<std::byte>(buf), ec);
                                 if (ec || n == 0)
                                 {
                                     break;
                                 }
                                 got += n;
                             }
                             EXPECT_EQ(got, kPayload);
                             s->Close();
                         }
                     };
                     Net::co_spawn(ioc.get_executor(), server_coro(), Net::detached);

                     std::string payload(kPayload, 'C');
                     for (int i = 0; i < kStreams; ++i)
                     {
                         auto s = co_await cl.OpenStream();
                         if (!s)
                         {
                             continue;
                         }
                         std::error_code ec;
                         (void)co_await s->async_write_some(
                             std::span<const std::byte>(reinterpret_cast<const std::byte *>(payload.data()),
                                                        payload.size()),
                             ec);
                         s->Close();
                         // 让出调度：保证对端 Accept 与帧循环有机会推进
                         co_await Net::post(ioc.get_executor(), Net::use_awaitable);
                     }
                     cl.Close();
                     sv.Close();
                 });
    }

    TEST(MuxSession, FactorySmux)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        Smux::Client cl;
        Smux::Server sv;
        ASSERT_TRUE(cl.Connect(std::make_shared<MemoryStream>(std::move(a))));
        ASSERT_TRUE(sv.Accept(std::make_shared<MemoryStream>(std::move(b))));
        run_coro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto server_coro = [&]() -> Net::awaitable<void>
                     {
                         auto s = co_await sv.AcceptStream();
                         if (!s)
                         {
                             co_return;
                         }
                         std::array<std::byte, 4096> buf{};
                         while (true)
                         {
                             std::error_code ec;
                             const auto n = co_await s->async_read_some(std::span<std::byte>(buf), ec);
                             if (ec || n == 0)
                             {
                                 break;
                             }
                         }
                         s->Close();
                     };
                     Net::co_spawn(ioc.get_executor(), server_coro(), Net::detached);
                     auto s = co_await cl.OpenStream();
                     if (!s)
                     {
                         co_return;
                     }
                     const std::string payload = "factory smux";
                     std::error_code ec;
                     (void)co_await s->async_write_some(
                         std::span<const std::byte>(reinterpret_cast<const std::byte *>(payload.data()),
                                                    payload.size()),
                         ec);
                     s->Close();
                     cl.Close();
                     sv.Close();
                 });
    }

    TEST(MuxSession, SessionControlOwnsFrameLoopUntilClose)
    {
        Net::io_context Ioc;
        auto [Raw, PeerRaw] = MakeMemoryPair(Ioc.get_executor());
        auto Peer = std::make_shared<MemoryStream>(std::move(PeerRaw));
        auto Control = std::make_shared<Preview::Runtime::SessionControl>(Ioc.get_executor());
        Preview::Mux::SessionOptions Options;
        Options.Control = Control;
        Options.Identity.SessionId = Preview::SessionId{41};
        Options.Identity.WorkerId = Preview::WorkerId{2};
        auto Session = Preview::Mux::Session<Smux::Codec>::Create(
            std::make_shared<MemoryStream>(std::move(Raw)), Options);
        ASSERT_TRUE(Session);

        run_coro(Ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     co_await Net::post(Ioc.get_executor(), Net::use_awaitable);
                     EXPECT_GT(Control->Metrics().Started, 0U);
                     EXPECT_EQ(Control->CurrentIdentity().SessionId, Preview::SessionId{41});
                     co_await Session->Close();
                     co_await Control->Drain();
                     EXPECT_EQ(Control->Metrics().Active, 0U);
                     EXPECT_FALSE(Session->IsOpen());
                 });

        EXPECT_EQ(Session->StreamCount(), 0U);
        (void)Peer;
    }

    TEST(MuxSession, SessionControlCancellationReleasesFrameLoop)
    {
        Net::io_context Ioc;
        auto [Raw, PeerRaw] = MakeMemoryPair(Ioc.get_executor());
        auto Peer = std::make_shared<MemoryStream>(std::move(PeerRaw));
        auto Control = std::make_shared<Preview::Runtime::SessionControl>(Ioc.get_executor());
        Preview::Mux::SessionOptions Options;
        Options.Control = Control;
        Options.Identity.SessionId = Preview::SessionId{42};
        auto Session = Preview::Mux::Session<Smux::Codec>::Create(
            std::make_shared<MemoryStream>(std::move(Raw)), Options);
        ASSERT_TRUE(Session);

        run_coro(Ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     co_await Net::post(Ioc.get_executor(), Net::use_awaitable);
                     Control->Cancel();
                     co_await Control->Drain();
                     EXPECT_EQ(Control->Metrics().Active, 0U);
                     EXPECT_FALSE(Session->IsOpen());
                 });

        (void)Peer;
    }

    TEST(MuxSession, ClosingOwnerInvalidatesVirtualStreamAndDrainsWriter)
    {
        Net::io_context Ioc;
        auto [Raw, PeerRaw] = MakeMemoryPair(Ioc.get_executor());
        auto Peer = std::make_shared<MemoryStream>(std::move(PeerRaw));
        auto Control = std::make_shared<Preview::Runtime::SessionControl>(Ioc.get_executor());
        Preview::Mux::SessionOptions Options;
        Options.Control = Control;
        Options.Identity.SessionId = Preview::SessionId{43};
        auto Session = Preview::Mux::Session<Smux::Codec>::Create(
            std::make_shared<MemoryStream>(std::move(Raw)), Options);
        ASSERT_TRUE(Session);

        run_coro(Ioc,
                 [&]() -> Net::awaitable<void>
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
                     EXPECT_EQ(Control->Metrics().Active, 0U);
                     EXPECT_EQ(Session->StreamCount(), 0U);
                 });

        (void)Peer;
    }

} // namespace
