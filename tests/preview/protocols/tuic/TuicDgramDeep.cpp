/**
 * @file TuicDgramDeep.cpp
 * @brief Tuic UDP 数据包连接（dgram 装饰器）深度测试
 * @details 覆盖 dgram 全部方法：executor / transport_type / 透传读写 /
 *          close / cancel / next_layer / release / stream，以及
 *          async_send_to / async_receive_from 的成功与错误分支
 *          （EOF、坏帧、地址类型、底层 IO 错误）。
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>

#include <array>
#include <memory>
#include <string>
#include <vector>

#include <common/core/transport/memory_stream.hpp>
#include <common/protocols/tuic/dgram.hpp>
#include <gtest/gtest.h>

namespace
{
    using namespace preview;
    namespace net = boost::asio;

    /**
     * @brief 驱动协程运行
     */
    template <typename A>
    auto run_coro(net::io_context &ioc, A coro) -> void
    {
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
    auto make_dst() -> tuic::address
    {
        tuic::address dst{};
        dst.type = tuic::address_type::ipv4;
        dst.host = "93.184.216.34";
        dst.port = 443;
        return dst;
    }

    TEST(TuicDgram, DecoratorBasics)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        auto peer = std::make_shared<memory_stream>(std::move(b));
        auto dgram = std::make_shared<tuic::dgram<>>(std::make_shared<memory_stream>(std::move(a)));

        EXPECT_EQ(dgram->transport_type(), transmission::type::udp);
        (void)dgram->executor();
        EXPECT_NE(dgram->next_layer(), nullptr);
        const auto *cdgram = dgram.get();
        EXPECT_NE(cdgram->next_layer(), nullptr);
        EXPECT_NE(dgram->stream(), nullptr);
        EXPECT_EQ(dgram->lowest_layer<memory_stream>(), dgram->stream().get());

        // 透传读写（双向）
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     std::error_code ec;
                     std::array<std::byte, 8> wbuf{std::byte{0x11}};
                     const auto w = co_await dgram->async_write_some(std::span<const std::byte>(wbuf), ec);
                     EXPECT_EQ(w, 8u);
                     std::array<std::byte, 8> rbuf{};
                     const auto r = co_await peer->async_read_some(std::span<std::byte>(rbuf), ec);
                     EXPECT_EQ(r, 8u);
                     EXPECT_EQ(static_cast<std::uint8_t>(rbuf[0]), 0x11);

                     const auto w2 = co_await peer->async_write_some(std::span<const std::byte>(wbuf), ec);
                     EXPECT_EQ(w2, 8u);
                     const auto r2 = co_await dgram->async_read_some(std::span<std::byte>(rbuf), ec);
                     EXPECT_EQ(r2, 8u);
                     EXPECT_EQ(static_cast<std::uint8_t>(rbuf[0]), 0x11);
                 });

        dgram->cancel();
        dgram->close();
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     std::error_code ec;
                     std::array<std::byte, 8> rbuf{};
                     const auto r = co_await dgram->async_read_some(std::span<std::byte>(rbuf), ec);
                     EXPECT_EQ(r, 0u);
                 });
        // release 转移底层所有权
        auto upstream = dgram->release();
        EXPECT_NE(upstream, nullptr);
        EXPECT_EQ(dgram->stream(), nullptr);
    }

    TEST(TuicDgram, SendAndReceiveRoundtrip)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        auto peer = std::make_shared<memory_stream>(std::move(b));
        auto dgram = std::make_shared<tuic::dgram<>>(std::make_shared<memory_stream>(std::move(a)));

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 发送数据报（对端读取 wire 帧）
                     const std::string payload = "hello dgram";
                     const auto serr =
                         co_await dgram->async_send_to(make_dst(), as_u8_span(payload));
                     EXPECT_EQ(serr, error::none);

                     // 对端用 codec 解析帧
                     std::array<std::uint8_t, 512> raw{};
                     std::error_code ec;
                     const auto n = co_await peer->async_read_some(as_bytes(std::span<std::uint8_t>(raw)), ec);
                     tuic::message msg;
                     std::size_t consumed = 0;
                     const auto perr = tuic::parse(std::span<const std::uint8_t>(raw.data(), n), msg, consumed);
                     EXPECT_EQ(perr, error::none);
                     EXPECT_EQ(msg.cmd, tuic::cmd_packet);
                     EXPECT_EQ(msg.assoc_id, 0u);
                     EXPECT_EQ(msg.pkt_id, 1u);
                     EXPECT_EQ(msg.dst.host, "93.184.216.34");
                     EXPECT_EQ(msg.dst.port, 443u);
                     EXPECT_EQ(msg.payload, payload);

                     // 回传一帧 packet（ipv4 地址）→ dgram 接收
                     // 注：dgram 将头部第 10 字节（pkt_id 高字节）作为 ATYP 解析，
                     // 此处令 pkt_id 高字节 = ipv4(0x01) 以触发成功路径
                     tuic::message reply;
                     reply.cmd = tuic::cmd_packet;
                     reply.assoc_id = 7;
                     reply.pkt_id = 0x01000000;
                     reply.dst = make_dst();
                     reply.payload = "pong";
                    const auto wire = tuic::build(reply);
                    const auto werr = co_await peer->write_all(wire);
                    EXPECT_FALSE(werr);

                     tuic::address src{};
                     std::vector<std::uint8_t> out;
                     const auto rerr = co_await dgram->async_receive_from(src, out);
                     EXPECT_EQ(rerr, error::none);
                     EXPECT_EQ(src.type, tuic::address_type::ipv4);
                 });
    }

    TEST(TuicDgram, ReceiveIpv6AndDomain)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        auto peer = std::make_shared<memory_stream>(std::move(b));
        auto dgram = std::make_shared<tuic::dgram<>>(std::make_shared<memory_stream>(std::move(a)));

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // ipv6 地址（pkt_id 高字节 = ipv6(0x04)）
                     tuic::message m6;
                     m6.cmd = tuic::cmd_packet;
                     m6.pkt_id = 0x04000000;
                     m6.dst.type = tuic::address_type::ipv6;
                     m6.dst.host.assign(16, 'x');
                     m6.dst.port = 8080;
                    m6.payload = "v6";
                    const auto w6 = co_await peer->write_all(tuic::build(m6));
                    EXPECT_FALSE(w6);

                     tuic::address src{};
                     std::vector<std::uint8_t> out;
                     EXPECT_EQ(co_await dgram->async_receive_from(src, out), error::none);
                     EXPECT_EQ(src.type, tuic::address_type::ipv6);

                     // domain 地址（pkt_id 高字节 = domain(0x03)）
                     tuic::message md;
                     md.cmd = tuic::cmd_packet;
                     md.pkt_id = 0x03000000;
                     md.dst.type = tuic::address_type::domain;
                     md.dst.host = "example.com";
                     md.dst.port = 80;
                    md.payload = "dom";
                    const auto wd = co_await peer->write_all(tuic::build(md));
                    EXPECT_FALSE(wd);

                     EXPECT_EQ(co_await dgram->async_receive_from(src, out), error::none);
                     EXPECT_EQ(src.type, tuic::address_type::domain);
                 });
    }

    TEST(TuicDgram, ReceiveErrorBranches)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        auto peer = std::make_shared<memory_stream>(std::move(b));
        auto dgram = std::make_shared<tuic::dgram<>>(std::make_shared<memory_stream>(std::move(a)));

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     tuic::address src{};
                     std::vector<std::uint8_t> out;

                     // 底层 EOF → unexpected_eof（头部读失败）
                     peer->close();
                     EXPECT_EQ(co_await dgram->async_receive_from(src, out), error::unexpected_eof);

                     // 非法地址类型 → bad_message（read_address_body default 分支）
                     tuic::message badatyp;
                     badatyp.cmd = tuic::cmd_packet;
                     badatyp.dst.type = static_cast<tuic::address_type>(0x7F);
                     const auto wb2 = co_await peer->write_all(tuic::build(badatyp));
                     EXPECT_FALSE(wb2);
                     EXPECT_EQ(co_await dgram->async_receive_from(src, out), error::bad_message);

                     // 头部不足（< 10 字节）→ unexpected_eof
                     const std::array<std::uint8_t, 5> short_head{0x04, 0x07, 0, 0, 0};
                     const auto wb3 = co_await peer->write_all(short_head);
                     EXPECT_FALSE(wb3);
                     EXPECT_EQ(co_await dgram->async_receive_from(src, out), error::unexpected_eof);
                 });
    }

    TEST(TuicDgram, SendIoError)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        auto peer = std::make_shared<memory_stream>(std::move(b));
        auto dgram = std::make_shared<tuic::dgram<>>(std::make_shared<memory_stream>(std::move(a)));

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 对端全关 → 写入失败 → io_error
                     peer->close();
                     const std::string_view one{"x"};
                     const auto err = co_await dgram->async_send_to(make_dst(), as_u8_span(one));
                     EXPECT_EQ(err, error::io_error);
                 });
    }

} // namespace
