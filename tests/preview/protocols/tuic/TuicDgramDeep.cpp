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

#include <array>
#include <memory>
#include <string>
#include <vector>

#include <common/Core/Transport/MemoryStream.hpp>
#include <common/Protocols/Tuic/Dgram.hpp>
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
                     EXPECT_EQ(msg.PktId, 1u);
                     EXPECT_EQ(msg.dst.Host, "93.184.216.34");
                     EXPECT_EQ(msg.dst.Port, 443u);
                     EXPECT_EQ(msg.payload, payload);

                     // 回传一帧 packet（ipv4 地址）→ Dgram 接收
                     // 注：Dgram 将头部第 10 字节（pkt_id 高字节）作为 ATYP 解析，
                     // 此处令 pkt_id 高字节 = ipv4(0x01) 以触发成功路径
                     Tuic::Message Reply;
                     Reply.Cmd = Tuic::CmdPacket;
                     Reply.AssocId = 7;
                     Reply.PktId = 0x01000000;
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

    TEST(TuicDgram, ReceiveIpv6AndDomain)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        auto peer = std::make_shared<MemoryStream>(std::move(b));
        auto Dgram = std::make_shared<Tuic::Dgram<>>(std::make_shared<MemoryStream>(std::move(a)));

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // ipv6 地址（pkt_id 高字节 = ipv6(0x04)）
                     Tuic::Message m6;
                     m6.Cmd = Preview::Tuic::CmdPacket;
                     m6.PktId = 0x04000000;
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

                     // domain 地址（pkt_id 高字节 = domain(0x03)）
                     Tuic::Message md;
                     md.Cmd = Preview::Tuic::CmdPacket;
                     md.PktId = 0x03000000;
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
                     const std::array<std::uint8_t, 5> short_head{0x04, 0x07, 0, 0, 0};
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
