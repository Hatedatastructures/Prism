/**
 * @file SessionDeep.cpp
 * @brief 多路复用会话分支覆盖测试（smux/yamux/h2mux）
 * @details 补充 MuxSessionTest 未覆盖的分支：
 * 1. 多流并发数据完整性
 * 2. 会话关闭后操作失败
 * 3. 对端关闭后会话自动关闭（帧循环检测 EOF）
 * 4. smux/yamux/h2mux 帧头构建/解析边界
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <memory>
#include <string>
#include <vector>

#include <Prism/Transport/MemoryStream.hpp>
#include <Prism/Protocols/Mux/H2Mux/H2Mux.hpp>
#include <Prism/Protocols/Mux/Smux/Smux.hpp>
#include <Prism/Protocols/Mux/Yamux/Yamux.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    namespace Smux = Prism::Mux::Smux;
    namespace Yamux = Prism::Mux::Yamux;
    namespace SmuxWire = Prism::Mux::Smux::Detail;
    namespace YamuxWire = Prism::Mux::Yamux::Detail;
    namespace H2Mux = Prism::Mux::H2Mux;
    using Prism::Error;
    using Prism::MakeMemoryPair;
    using Prism::MemoryStream;

    template <typename A>
    auto RunCoro(Net::io_context &Ioc, A Coroutine) -> void
    {
        std::exception_ptr Exception;
        Net::co_spawn(Ioc, std::move(Coroutine),
                      [&](std::exception_ptr ErrorValue)
                      {
                          Exception = ErrorValue;
                          Ioc.stop();
                      });
        Ioc.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    auto RunConcurrentStreamReceiver(Smux::Server<> &Server) -> Net::awaitable<void>
    {
        for (std::uint32_t Index = 1; Index <= 3; ++Index)
        {
            auto Stream = co_await Server.AcceptStream();
            if (!Stream)
            {
                co_return;
            }
            const auto Expected = "Stream-" + std::to_string(Index) + "-payload";
            std::array<std::byte, 128> Buffer{};
            std::string Received;
            while (Received.size() < Expected.size())
            {
                const auto Read = co_await Stream->ReadSome(std::span<std::byte>(Buffer));
                EXPECT_FALSE(Read.Failure.Failed());
                if (Read.Failure.Failed() || Read.Bytes == 0)
                {
                    break;
                }
                Received.append(reinterpret_cast<const char *>(Buffer.data()), Read.Bytes);
            }
            EXPECT_EQ(Received, Expected);
            (void)Stream->Close();
        }
    }

    auto RunConcurrentStreamSender(Smux::Client<> &Client) -> Net::awaitable<void>
    {
        for (std::uint32_t Index = 1; Index <= 3; ++Index)
        {
            auto Stream = co_await Client.OpenStream();
            if (!Stream)
            {
                EXPECT_TRUE(false) << "OpenStream Failed";
                co_await Client.Session()->Close();
                co_return;
            }
            const std::string Payload = "Stream-" + std::to_string(Index) + "-payload";
            const auto PayloadBytes = std::span<const std::byte>(
                reinterpret_cast<const std::byte *>(Payload.data()), Payload.size());
            std::size_t Written = 0;
            while (Written < PayloadBytes.size())
            {
                const auto Write = co_await Stream->WriteSome(PayloadBytes.subspan(Written));
                EXPECT_FALSE(Write.Failure.Failed());
                if (Write.Failure.Failed() || Write.Bytes == 0)
                {
                    co_await Client.Session()->Close();
                    co_return;
                }
                Written += Write.Bytes;
            }
            (void)Stream->Close();
        }
    }

    /// 运行三条并发 Smux 流并等待收发双方真实退出。
    auto RunConcurrentStreams(Smux::Client<> &Client,
                              Smux::Server<> &Server) -> Net::awaitable<void>
    {
        using Net::experimental::awaitable_operators::operator&&;
        co_await (RunConcurrentStreamReceiver(Server) && RunConcurrentStreamSender(Client));
        co_await Client.Session()->Close();
        co_await Server.Session()->Close();
    }

    auto RunClosedSession(Smux::Client<> &Client) -> Net::awaitable<void>
    {
        co_await Client.Session()->Close();
        auto Stream = co_await Client.OpenStream();
        EXPECT_FALSE(Stream);
    }

    auto RunFactoryHandshake(
        Smux::Client<> &Client,
        MemoryStream Local,
        MemoryStream Peer) -> Net::awaitable<void>
    {
        auto PeerOwner = std::make_shared<MemoryStream>(std::move(Peer));
        const auto PeerClose = PeerOwner->Close();
        EXPECT_TRUE(PeerClose);
        if (!Client.Connect(std::make_shared<MemoryStream>(std::move(Local))))
        {
            EXPECT_TRUE(false) << "Connect Failed";
            co_return;
        }
        const auto PeerActivity = PeerOwner->Activity();
        EXPECT_TRUE(PeerActivity);
        if (!PeerActivity)
        {
            co_await Client.Session()->Close();
            co_return;
        }
        const auto PeerDrained = co_await PeerActivity->Drain();
        EXPECT_TRUE(PeerDrained);
        const auto Drained = co_await Client.Session()->Tasks()->Drain();
        EXPECT_TRUE(Drained);
        EXPECT_FALSE(Client.IsOpen());
        co_await Client.Session()->Close();
    }

    // ── 1. 多流并发数据完整性 ──

    TEST(MuxSessionDeep, ConcurrentStreamsDataIntegrity)
    {
        Net::io_context ioc;
        Smux::Client cl;
        Smux::Server sv;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        ASSERT_TRUE(cl.Connect(std::make_shared<MemoryStream>(std::move(a))));
        ASSERT_TRUE(sv.Accept(std::make_shared<MemoryStream>(std::move(b))));

        RunCoro(ioc, RunConcurrentStreams(cl, sv));
    }

    // ── 2. 会话关闭后操作 ──

    TEST(MuxSessionDeep, ClosedSessionOpsFail)
    {
        Net::io_context ioc;
        Smux::Client cl;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        ASSERT_TRUE(cl.Connect(std::make_shared<MemoryStream>(std::move(a))));

        RunCoro(ioc, RunClosedSession(cl));
     }

    // ── 3. 对端关闭后会话自动关闭 ──

    TEST(MuxSessionDeep, FactoryHandshakeFail)
    {
        Net::io_context ioc;
        Smux::Client cl;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        RunCoro(ioc, RunFactoryHandshake(cl, std::move(a), std::move(b)));
     }

    // ── 4. smux 帧头构建/解析 ──

    TEST(MuxSessionDeep, SmuxHeaderBuildParse)
    {
        Smux::FrameHeader hdr;
        hdr.cmd = Smux::Command::Push;
        hdr.StreamId = 7;
        const std::array<std::uint8_t, 2> payload{0xAA, 0xBB};
        auto Frame = SmuxWire::Build(hdr, payload);
        Smux::FrameHeader out;
        EXPECT_EQ(SmuxWire::ParseHeader(Frame, out), Error::None);
        EXPECT_EQ(out.cmd, Smux::Command::Push);
        EXPECT_EQ(out.StreamId, 7U);
    }

    // ── 5. yamux 帧头构建/解析 ──

    TEST(MuxSessionDeep, YamuxHeaderBuildParse)
    {
        Yamux::FrameHeader hdr;
        hdr.version = 0;
        hdr.Type = Yamux::MessageType::Data;
        hdr.flag = Yamux::Flags::None;
        hdr.StreamId = 9;
        const std::array<std::uint8_t, 3> payload{1, 2, 3};
        auto Frame = YamuxWire::Build(hdr, payload);
        Yamux::FrameHeader out;
        EXPECT_EQ(YamuxWire::ParseHeader(Frame, out), Error::None);
        EXPECT_EQ(out.Type, Yamux::MessageType::Data);
        EXPECT_EQ(out.StreamId, 9U);
    }

    // ── 6. h2mux 帧头构建/解析 ──

    TEST(MuxSessionDeep, H2muxHeaderBuildParse)
    {
        const std::array<std::uint8_t, 2> payload{0x10, 0x20};
        auto Frame = H2Mux::Build(H2Mux::FrameType::Data, 3, payload);
        EXPECT_EQ(Frame.size(), 9U + 2U);
        H2Mux::FrameHeader out;
        EXPECT_EQ(H2Mux::ParseHeader(Frame, out), Error::None);
        EXPECT_EQ(out.Type, H2Mux::FrameType::Data);
        EXPECT_EQ(out.StreamId, 3U);
    }

} // namespace
