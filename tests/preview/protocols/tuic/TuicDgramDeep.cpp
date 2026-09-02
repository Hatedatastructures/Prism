/**
 * @file TuicDgramDeep.cpp
 * @brief Tuic UDP 数据包连接（Dgram 装饰器）深度测试
 * @details 覆盖 Dgram 全部方法：Executor / TransportType / 透传读写 /
 *          Close / Cancel / NextLayer / Release / Stream，以及
 *          AsyncSendTo / AsyncReceiveFrom 的成功与错误分支
 *          （EOF、坏帧、地址类型、底层 IO 错误）。
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>

#include <algorithm>
#include <array>
#include <memory>
#include <string>
#include <vector>

#include <preview/Transport/MemoryStream.hpp>
#include <preview/Transport/Unreliable.hpp>
#include <preview/Protocols/Tuic/Dgram.hpp>
#include <preview/Protocols/Tuic/Tuic.hpp>
#include <gtest/gtest.h>

namespace
{
    using namespace Preview;
    namespace net = boost::asio;

    /**
     * @brief 驱动协程运行
     */
    template <typename A>
    auto run_coro(net::io_context &ioc, A coro) -> void
    {
        // 同一 io_context 可能被多次驱动，restart() 重置 stopped 标志
        ioc.restart();
        std::exception_ptr ep;
        net::co_spawn(ioc, std::move(coro),
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

    /**
     * @brief 构造 ipv4 目标地址
     */
    auto make_dst() -> Tuic::Address
    {
        Tuic::Address dst{};
        dst.Type = Tuic::AddressType::Ipv4;
        dst.Host = "93.184.216.34";
        dst.Port = 443;
        return dst;
    }

    TEST(TuicWireContract, UsesV5CommandAndAddressValues)
    {
        EXPECT_EQ(Tuic::ProtocolVersion, 0x05);
        EXPECT_EQ(Tuic::CmdAuthenticate, 0x00);
        EXPECT_EQ(Tuic::CmdConnect, 0x01);
        EXPECT_EQ(Tuic::CmdPacket, 0x02);
        EXPECT_EQ(Tuic::CmdDissociate, 0x03);
        EXPECT_EQ(Tuic::CmdHeartbeat, 0x04);
        EXPECT_EQ(static_cast<std::uint8_t>(Tuic::AddressType::Domain), 0x00);
        EXPECT_EQ(static_cast<std::uint8_t>(Tuic::AddressType::Ipv4), 0x01);
        EXPECT_EQ(static_cast<std::uint8_t>(Tuic::AddressType::Ipv6), 0x02);
        EXPECT_EQ(static_cast<std::uint8_t>(Tuic::AddressType::None), 0xFF);
    }

    TEST(TuicWireContract, AuthenticateFrameCarriesExactCredentials)
    {
        const std::array<std::uint8_t, Tuic::UuidLen> Uuid{
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
        const std::array<std::uint8_t, Tuic::TokenLen> Token{
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
            0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F};
        const auto Wire = Tuic::BuildAuthenticate(Uuid, Token);
        ASSERT_EQ(Wire.size(), Tuic::AuthenticateFrameLen);
        EXPECT_EQ(Wire[0], 0x05);
        EXPECT_EQ(Wire[1], 0x00);
        EXPECT_TRUE(std::equal(Uuid.begin(), Uuid.end(), Wire.begin() + 2));
        EXPECT_TRUE(std::equal(Token.begin(), Token.end(), Wire.begin() + 2 + Tuic::UuidLen));

        Tuic::AuthenticateFrame Parsed{};
        std::size_t Consumed = 0;
        EXPECT_EQ(Tuic::ParseAuthenticate(Wire, Parsed, Consumed), Error::None);
        EXPECT_EQ(Consumed, Tuic::AuthenticateFrameLen);
        EXPECT_EQ(Parsed.Uuid, Uuid);
        EXPECT_EQ(Parsed.Token, Token);
    }

    TEST(TuicDgram, DecoratorBasics)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        auto peer = std::make_shared<MemoryStream>(std::move(b));
        auto Dgram = std::make_shared<Tuic::Dgram<>>(std::make_shared<MemoryStream>(std::move(a)));

        EXPECT_EQ(Dgram->TransportType(), Transmission::Type::Udp);
        (void)Dgram->Executor();
        EXPECT_NE(Dgram->NextLayer(), nullptr);
        const auto *cdgram = Dgram.get();
        EXPECT_NE(cdgram->NextLayer(), nullptr);
        EXPECT_NE(Dgram->Stream(), nullptr);
        EXPECT_EQ(Dgram->lowest_layer<MemoryStream>(), Dgram->Stream().get());

        // 透传读写（双向）
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     std::error_code ec;
                     std::array<std::byte, 8> wbuf{std::byte{0x11}};
                     const auto w = co_await Dgram->async_write_some(std::span<const std::byte>(wbuf), ec);
                     EXPECT_EQ(w, 8u);
                     std::array<std::byte, 8> rbuf{};
                     const auto r = co_await peer->async_read_some(std::span<std::byte>(rbuf), ec);
                     EXPECT_EQ(r, 8u);
                     EXPECT_EQ(static_cast<std::uint8_t>(rbuf[0]), 0x11);

                     const auto w2 = co_await peer->async_write_some(std::span<const std::byte>(wbuf), ec);
                     EXPECT_EQ(w2, 8u);
                     const auto r2 = co_await Dgram->async_read_some(std::span<std::byte>(rbuf), ec);
                     EXPECT_EQ(r2, 8u);
                     EXPECT_EQ(static_cast<std::uint8_t>(rbuf[0]), 0x11);
                 });

        Dgram->Cancel();
        Dgram->Close();
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     std::error_code ec;
                     std::array<std::byte, 8> rbuf{};
                     const auto r = co_await Dgram->async_read_some(std::span<std::byte>(rbuf), ec);
                     EXPECT_EQ(r, 0u);
                 });
        // Release 转移底层所有权
        auto upstream = Dgram->Release();
        EXPECT_NE(upstream, nullptr);
        EXPECT_EQ(Dgram->Stream(), nullptr);
    }

    TEST(TuicDgram, SendAndReceiveRoundtrip)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        auto peer = std::make_shared<MemoryStream>(std::move(b));
        auto Dgram = std::make_shared<Tuic::Dgram<>>(std::make_shared<MemoryStream>(std::move(a)));

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 发送数据报（对端读取 wire 帧）
                     const std::string payload = "hello Dgram";
                     const auto serr =
                         co_await Dgram->AsyncSendTo(make_dst(), AsU8Span(payload));
                     EXPECT_EQ(serr, Error::None);

                     // 对端用 Codec 解析帧
                     std::array<std::uint8_t, 512> raw{};
                     std::error_code ec;
                     const auto n = co_await peer->async_read_some(AsBytes(std::span<std::uint8_t>(raw)), ec);
                     Tuic::Message msg;
                     std::size_t consumed = 0;
                     const auto perr = Tuic::Parse(std::span<const std::uint8_t>(raw.data(), n), msg, consumed);
                     EXPECT_EQ(perr, Error::None);
                     EXPECT_EQ(msg.Cmd, Tuic::CmdPacket);
                     EXPECT_EQ(msg.AssocId, 0u);
                      EXPECT_EQ(msg.PktId, 0u);
                     EXPECT_EQ(msg.dst.Host, "93.184.216.34");
                     EXPECT_EQ(msg.dst.Port, 443u);
                     EXPECT_EQ(msg.payload, payload);

                     // 回传一帧 packet（ipv4 地址）→ Dgram 接收
                      // 回传帧保持完整数据报边界，接收端一次解析整个 packet。
                     Tuic::Message Reply;
                     Reply.Cmd = Tuic::CmdPacket;
                     Reply.AssocId = 7;
                      Reply.PktId = 1;
                     Reply.dst = make_dst();
                     Reply.payload = "pong";
                    const auto wire = Tuic::Build(Reply);
                    const auto werr = co_await peer->WriteAll(wire);
                    EXPECT_FALSE(werr);

                     Tuic::Address src{};
                     std::vector<std::uint8_t> out;
                     const auto rerr = co_await Dgram->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(rerr, Error::None);
                     EXPECT_EQ(src.Type, Tuic::AddressType::Ipv4);
                 });
    }

    TEST(TuicDgram, PacketCarriesSizeAndFragmentFields)
    {
        Tuic::Message Message;
        Message.Cmd = Tuic::CmdPacket;
        Message.AssocId = 0x1234;
        Message.PktId = 0x5678;
        Message.FragTotal = 2;
        Message.FragId = 0;
        Message.dst = make_dst();
        Message.payload = "payload";
        const auto Wire = Tuic::Build(Message);
        ASSERT_GE(Wire.size(), 10u);
        EXPECT_EQ(Wire[2], 0x12);
        EXPECT_EQ(Wire[3], 0x34);
        EXPECT_EQ(Wire[4], 0x56);
        EXPECT_EQ(Wire[5], 0x78);
        EXPECT_EQ(Wire[6], 2);
        EXPECT_EQ(Wire[7], 0);
        EXPECT_EQ(Wire[8], 0);
        EXPECT_EQ(Wire[9], 7);
        Tuic::Message Parsed;
        std::size_t Consumed = 0;
        EXPECT_EQ(Tuic::Parse(Wire, Parsed, Consumed), Error::None);
        EXPECT_EQ(Consumed, Wire.size());
        EXPECT_EQ(Parsed.AssocId, Message.AssocId);
        EXPECT_EQ(Parsed.PktId, Message.PktId);
        EXPECT_EQ(Parsed.FragTotal, Message.FragTotal);
        EXPECT_EQ(Parsed.FragId, Message.FragId);
        EXPECT_EQ(Parsed.Size, Message.payload.size());
        EXPECT_EQ(Parsed.payload, Message.payload);
    }

    TEST(TuicDgram, RawUdpDatagramKeepsFrameBoundary)
    {
        net::io_context ioc;
        auto RawServer = std::make_shared<Preview::Transport::Unreliable>(ioc.get_executor());
        auto RawClient = std::make_shared<Preview::Transport::Unreliable>(ioc.get_executor());
        boost::system::error_code OpenEc;
        RawServer->NativeSocket().open(net::ip::udp::v4(), OpenEc);
        RawServer->NativeSocket().bind({net::ip::address_v4::loopback(), 0}, OpenEc);
        EXPECT_FALSE(OpenEc);
        const auto ServerEndpoint = RawServer->NativeSocket().local_endpoint();
        EXPECT_TRUE(RawClient->Connect("127.0.0.1:" + std::to_string(ServerEndpoint.port())));
        auto Server = std::make_shared<Tuic::Dgram<>>(RawServer);
        auto Client = std::make_shared<Tuic::Dgram<>>(RawClient);
        const auto Payload = std::string("tuic-udp-payload");
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     const auto Sent = co_await Client->AsyncSendTo(make_dst(), AsU8Span(std::string_view(Payload)));
                     EXPECT_EQ(Sent, Error::None);
                     Tuic::Address Target;
                     std::vector<std::uint8_t> Received;
                     const auto Err = co_await Server->AsyncReceiveFrom(Target, Received);
                     EXPECT_EQ(Err, Error::None);
                     EXPECT_EQ(Target.Host, "93.184.216.34");
                     EXPECT_EQ(std::string(Received.begin(), Received.end()), Payload);
                     Server->Close();
                     Client->Close();
                 });
    }

    TEST(TuicDgram, ReceiveIpv6AndDomain)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        auto peer = std::make_shared<MemoryStream>(std::move(b));
        auto Dgram = std::make_shared<Tuic::Dgram<>>(std::make_shared<MemoryStream>(std::move(a)));

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // IPv6 地址（地址类型由首片 ATYP 字段携带）
                     Tuic::Message m6;
                     m6.Cmd = Preview::Tuic::CmdPacket;
                     m6.PktId = 1;
                     m6.dst.Type = Tuic::AddressType::Ipv6;
                     m6.dst.Host.assign(16, 'x');
                     m6.dst.Port = 8080;
                    m6.payload = "v6";
                    const auto w6 = co_await peer->WriteAll(Tuic::Build(m6));
                    EXPECT_FALSE(w6);

                     Tuic::Address src{};
                     std::vector<std::uint8_t> out;
                     EXPECT_EQ(co_await Dgram->AsyncReceiveFrom(src, out), Error::None);
                     EXPECT_EQ(src.Type, Tuic::AddressType::Ipv6);

                     // 域名地址
                     Tuic::Message md;
                     md.Cmd = Preview::Tuic::CmdPacket;
                     md.PktId = 2;
                     md.dst.Type = Tuic::AddressType::Domain;
                     md.dst.Host = "example.com";
                     md.dst.Port = 80;
                    md.payload = "dom";
                    const auto wd = co_await peer->WriteAll(Tuic::Build(md));
                    EXPECT_FALSE(wd);

                     EXPECT_EQ(co_await Dgram->AsyncReceiveFrom(src, out), Error::None);
                     EXPECT_EQ(src.Type, Tuic::AddressType::Domain);
                 });
    }

    TEST(TuicDgram, ReceiveErrorBranches)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        auto peer = std::make_shared<MemoryStream>(std::move(b));
        auto Dgram = std::make_shared<Tuic::Dgram<>>(std::make_shared<MemoryStream>(std::move(a)));

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     Tuic::Address src{};
                     std::vector<std::uint8_t> out;

                     // 底层 EOF → unexpected_eof（头部读失败）
                     peer->Close();
                     EXPECT_EQ(co_await Dgram->AsyncReceiveFrom(src, out), Error::UnexpectedEof);

                     // 非法地址类型 → bad_message（ReadAddressBody default 分支）
                     Tuic::Message badatyp;
                     badatyp.Cmd = Preview::Tuic::CmdPacket;
                     badatyp.dst.Type = static_cast<Tuic::AddressType>(0x7F);
                     const auto wb2 = co_await peer->WriteAll(Tuic::Build(badatyp));
                     EXPECT_FALSE(wb2);
                     EXPECT_EQ(co_await Dgram->AsyncReceiveFrom(src, out), Error::BadMessage);

                     // 头部不足（< 10 字节）→ unexpected_eof
                     const std::array<std::uint8_t, 5> short_head{0x05, 0x02, 0, 0, 0};
                     const auto wb3 = co_await peer->WriteAll(short_head);
                     EXPECT_FALSE(wb3);
                     EXPECT_EQ(co_await Dgram->AsyncReceiveFrom(src, out), Error::UnexpectedEof);
                 });
    }

    TEST(TuicDgram, SendIoError)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        auto peer = std::make_shared<MemoryStream>(std::move(b));
        auto Dgram = std::make_shared<Tuic::Dgram<>>(std::make_shared<MemoryStream>(std::move(a)));

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 对端全关 → 写入失败 → io_error
                     peer->Close();
                     const std::string_view one{"x"};
                     const auto err = co_await Dgram->AsyncSendTo(make_dst(), AsU8Span(one));
                     EXPECT_EQ(err, Error::IoError);
                 });
    }

} // namespace
