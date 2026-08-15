/**
 * @file Ss2022CodecDeep.cpp
 * @brief Shadowsocks 2022 codec / conn / dgram 剩余分支深度测试
 * @details 覆盖 encode_address / parse_address / parse_var_header 的
 *          ipv6 与截断分支、chunk_codec 的起始 nonce 与全部错误路径、
 *          UDP 数据报编解码的成功与错误路径、握手 parser 的错误分支，
 *          conn / dgram 装饰器透传方法。
 */

#include <boost/asio/buffer.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <common/core/transport/memory_stream.hpp>
#include <common/proxy/shadowsocks2022/codec.hpp>
#include <common/proxy/shadowsocks2022/conn.hpp>
#include <common/proxy/shadowsocks2022/dgram.hpp>
#include <common/proxy/shadowsocks2022/shadowsocks2022.hpp>
#include <gtest/gtest.h>

namespace
{
    using namespace psmtest;
    namespace ss = psmtest::ss2022;
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
     * @brief 从初始值列表构造字节向量
     */
    auto make_bytes(std::initializer_list<std::uint8_t> list) -> std::vector<std::uint8_t>
    {
        return std::vector<std::uint8_t>(list);
    }

    TEST(Ss2022CodecDeep, AddressBranches)
    {
        // encode_address ipv6
        ss::address addr{};
        addr.type = ss::address_type::ipv6;
        addr.host.assign(16, 'q');
        addr.port = 8080;
        const auto v6 = ss::encode_address(addr);
        EXPECT_EQ(v6.size(), 19u);
        EXPECT_EQ(v6[0], 0x04);

        // parse_address ipv4 截断
        std::size_t off = 0;
        EXPECT_EQ(ss::parse_address(std::span<const std::uint8_t>(make_bytes({0x01, 8, 8})), addr, off),
                  error::need_more);
        // parse_address ipv6 截断 + 成功
        off = 0;
        std::vector<std::uint8_t> p6{0x04};
        p6.insert(p6.end(), 5, 0x42);
        EXPECT_EQ(ss::parse_address(p6, addr, off), error::need_more);
        off = 0;
        p6.assign(17, 0);
        p6[0] = 0x04;
        p6.insert(p6.end(), 2, 0);
        EXPECT_EQ(ss::parse_address(p6, addr, off), error::none);
        EXPECT_EQ(addr.host, std::string(16, 0));

        // parse_var_header 各分支
        std::span<const std::uint8_t> payload;
        // ipv4 截断
        EXPECT_EQ(ss::parse_var_header(std::span<const std::uint8_t>(make_bytes({0x01, 8, 8})), addr, payload),
                  error::need_more);
        // ipv6 截断
        EXPECT_EQ(ss::parse_var_header(std::span<const std::uint8_t>(make_bytes({0x04, 1})), addr, payload),
                  error::need_more);
        // ipv6 成功
        std::vector<std::uint8_t> var6{0x04};
        var6.insert(var6.end(), 16, 0x42);
        var6.push_back(0x00);
        var6.push_back(0x50);
        var6.push_back(0x00);
        var6.push_back(0x00);
        var6.push_back('x');
        EXPECT_EQ(ss::parse_var_header(var6, addr, payload), error::none);
        EXPECT_EQ(addr.type, ss::address_type::ipv6);
        EXPECT_EQ(addr.port, 80u);
        EXPECT_EQ(payload.size(), 1u);
        // domain 长度截断
        std::vector<std::uint8_t> dom{0x03, 0x05, 'a'};
        EXPECT_EQ(ss::parse_var_header(dom, addr, payload), error::need_more);
        // domain 成功
        std::vector<std::uint8_t> dom_ok{0x03, 0x03, 'a', 'b', 'c', 0x00, 0x50, 0x00, 0x00};
        EXPECT_EQ(ss::parse_var_header(dom_ok, addr, payload), error::none);
        EXPECT_EQ(addr.host, "abc");
    }

    TEST(Ss2022CodecDeep, ChunkCodecErrors)
    {
        std::array<std::uint8_t, 16> key{};
        // start_nonce > 0 → inc_nonce 路径
        ss::chunk_codec codec(std::span<const std::uint8_t>(key), 3);
        ss::chunk_codec dec(std::span<const std::uint8_t>(key), 3);

        // open_len：头部不足
        EXPECT_FALSE(codec.open_len(std::span<const std::uint8_t>(make_bytes({1, 2}))).has_value());
        // 坏密文
        std::vector<std::uint8_t> bad(18, 0);
        bad[17] = 0xFF;
        EXPECT_FALSE(codec.open_len(bad).has_value());

        // seal + open 成功路径
        const auto wire = dec.seal(as_u8_span(std::string_view{"hello"}));
        std::size_t consumed = 0;
        const auto plain = codec.open(wire, consumed);
        EXPECT_EQ(plain.size(), 5u);
        EXPECT_EQ(std::string_view(reinterpret_cast<const char *>(plain.data()), plain.size()), "hello");
        EXPECT_EQ(consumed, wire.size());

        // 结束块
        ss::chunk_codec codec2(std::span<const std::uint8_t>(key), 3);
        ss::chunk_codec dec2(std::span<const std::uint8_t>(key), 3);
        const auto fin = dec2.finish();
        std::size_t fin_consumed = 0;
        EXPECT_TRUE(codec2.open(fin, fin_consumed).empty());
        EXPECT_EQ(fin_consumed, 18u);

        // open：数据不足（长度块后缺载荷）
        ss::chunk_codec codec3(std::span<const std::uint8_t>(key), 3);
        ss::chunk_codec dec3(std::span<const std::uint8_t>(key), 3);
        const auto big = dec3.seal(as_u8_span(std::string_view{"12345678"}));
        std::size_t c3 = 0;
        EXPECT_TRUE(codec3.open(std::span<const std::uint8_t>(big).first(20), c3).empty());

        // open_payload：载荷过短 / 校验失败
        ss::chunk_codec codec4(std::span<const std::uint8_t>(key), 3);
        EXPECT_TRUE(codec4.open_payload(std::span<const std::uint8_t>(make_bytes({1, 2}))).empty());
        std::vector<std::uint8_t> bad_body(17, 0);
        bad_body[16] = 0xFF;
        EXPECT_TRUE(codec4.open_payload(bad_body).empty());

        // 超长长度块（> max_chunk_size = 0xFFFF）
        ss::chunk_codec codec5(std::span<const std::uint8_t>(key), 3);
        ss::chunk_codec dec5(std::span<const std::uint8_t>(key), 3);
        std::vector<std::uint8_t> big_payload(20000, 0xAB);
        const auto big_wire = dec5.seal(big_payload);
        EXPECT_FALSE(codec5.open_len(std::span<const std::uint8_t>(big_wire).first(18)).has_value());
    }

    TEST(Ss2022CodecDeep, SessionKeyAndUdp)
    {
        std::array<std::uint8_t, 16> psk{};
        psk.fill(0x11);
        std::array<std::uint8_t, 16> salt{};
        salt.fill(0x22);
        const auto key = ss::session_key(psk, salt, 16);
        EXPECT_EQ(key.size(), 16u);

        // build_udp_packet 成功
        ss::address dst{};
        dst.type = ss::address_type::ipv4;
        dst.host = "1.2.3.4";
        dst.port = 443;
        const auto packet = ss::build_udp_packet(
            ss::udp_build_input{key, 7, &dst, as_u8_span(std::string_view{"data"})});
        EXPECT_GT(packet.size(), 16u);

        // parse_udp_packet 成功
        ss::address out_dst{};
        std::vector<std::uint8_t> out_payload;
        EXPECT_EQ(ss::parse_udp_packet(ss::udp_parse_input{key, packet, &out_dst, &out_payload}), error::none);
        EXPECT_EQ(out_dst.host, "1.2.3.4");
        EXPECT_EQ(std::string_view(reinterpret_cast<const char *>(out_payload.data()), out_payload.size()),
                  "data");

        // 空 target → bad_length
        EXPECT_EQ(ss::parse_udp_packet(ss::udp_parse_input{key, packet, nullptr, &out_payload}),
                  error::bad_length);
        // 短包 → bad_length
        EXPECT_EQ(ss::parse_udp_packet(ss::udp_parse_input{key, std::span<const std::uint8_t>(packet).first(10),
                                                           &out_dst, &out_payload}),
                  error::bad_length);
        // SessionID 不匹配 → bad_auth
        std::array<std::uint8_t, 16> wrong_key{};
        wrong_key.fill(0x99);
        EXPECT_EQ(ss::parse_udp_packet(ss::udp_parse_input{wrong_key, packet, &out_dst, &out_payload}),
                  error::bad_auth);
        // 类型字节非法 → bad_message
        auto bad_type = packet;
        bad_type[16] = 0x02;
        EXPECT_EQ(ss::parse_udp_packet(ss::udp_parse_input{key, bad_type, &out_dst, &out_payload}),
                  error::bad_message);
        // 载荷 tag 校验失败 → bad_auth
        auto bad_tag = packet;
        bad_tag.back() ^= 0x01;
        EXPECT_EQ(ss::parse_udp_packet(ss::udp_parse_input{key, bad_tag, &out_dst, &out_payload}),
                  error::bad_auth);
    }

    TEST(Ss2022CodecDeep, HandshakeParserErrors)
    {
        std::array<std::uint8_t, 16> psk{};
        psk.fill(0x11);

        // serializer 生成合法握手包
        ss::serializer ser(psk);
        ss::message msg{};
        msg.dst.type = ss::address_type::ipv4;
        msg.dst.host = "8.8.8.8";
        msg.dst.port = 53;
        msg.initial_payload = "hello";
        ser.reset(msg, 1000);
        std::array<std::uint8_t, 2048> buf{};
        std::error_code ec;
        const auto n = ser.get(boost::asio::buffer(buf.data(), buf.size()), ec);
        const auto wire = std::vector<std::uint8_t>(buf.begin(), buf.begin() + n);

        // parser 成功
        ss::parser p(psk);
        EXPECT_EQ(p.put(boost::asio::buffer(wire), ec), wire.size());
        EXPECT_TRUE(p.is_done());
        EXPECT_EQ(p.get().dst.host, "8.8.8.8");
        EXPECT_EQ(p.get().initial_payload, "hello");

        // 数据不足
        p.reset();
        EXPECT_EQ(p.put(boost::asio::buffer(make_bytes({0x01})), ec), 0u);
        EXPECT_EQ(ec, make_error_code(error::need_more));

        // 固定头解密失败（篡改）→ auth_failed
        p.reset();
        auto tampered = wire;
        tampered[30] ^= 0x01;
        EXPECT_EQ(p.put(boost::asio::buffer(tampered), ec), 0u);
        EXPECT_EQ(ec, make_error_code(error::auth_failed));

        // 变长头不足（截断尾部）→ need_more
        p.reset();
        const auto truncated = std::vector<std::uint8_t>(wire.begin(), wire.end() - 40);
        EXPECT_EQ(p.put(boost::asio::buffer(truncated), ec), 0u);
        EXPECT_EQ(ec, make_error_code(error::need_more));

        // 变长头解密失败 → auth_failed
        p.reset();
        auto tampered2 = wire;
        tampered2[tampered2.size() - 1] ^= 0x01;
        EXPECT_EQ(p.put(boost::asio::buffer(tampered2), ec), 0u);
        EXPECT_EQ(ec, make_error_code(error::auth_failed));
    }

    TEST(Ss2022CodecDeep, ConnAndDgramDecorators)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());
        auto peer = std::make_shared<memory_stream>(std::move(b));
        std::array<std::uint8_t, 16> key{};
        key.fill(0x55);

        // dgram 装饰器
        auto dg = std::make_shared<shadowsocks2022::dgram<>>(std::make_shared<memory_stream>(std::move(a)), key);
        EXPECT_EQ(dg->transport_type(), transmission::type::udp);
        (void)dg->executor();
        EXPECT_NE(dg->next_layer(), nullptr);
        const auto *cdg = dg.get();
        EXPECT_NE(cdg->next_layer(), nullptr);
        EXPECT_NE(dg->stream(), nullptr);
        dg->cancel();
        dg->close();
        EXPECT_NE(dg->release(), nullptr);

        // dgram 收发往返
        auto [c, d] = make_memory_pair(ioc.get_executor());
        auto peer2 = std::make_shared<memory_stream>(std::move(d));
        auto dg2 = std::make_shared<shadowsocks2022::dgram<>>(std::make_shared<memory_stream>(std::move(c)), key);
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     ss::address dst{};
                     dst.type = ss::address_type::domain;
                     dst.host = "example.com";
                     dst.port = 80;
                     const auto serr = co_await dg2->async_send_to(dst, as_u8_span(std::string_view{"pkt"}));
                     EXPECT_EQ(serr, error::none);
                     std::array<std::uint8_t, 2048> raw{};
                     std::error_code ec;
                     const auto rn = co_await peer2->async_read_some(as_bytes(std::span<std::uint8_t>(raw)), ec);
                     const auto back = std::vector<std::uint8_t>(raw.begin(), raw.begin() + rn);
                     const auto werr = co_await peer2->write_all(back);
                     EXPECT_FALSE(werr);
                     ss::address src{};
                     std::vector<std::uint8_t> payload;
                     const auto rerr = co_await dg2->async_receive_from(src, payload);
                     EXPECT_EQ(rerr, error::none);
                     EXPECT_EQ(src.host, "example.com");
                 });

        // conn：完整握手（fake server 响应）+ 装饰器方法 + 数据面
        auto [e, f] = make_memory_pair(ioc.get_executor());
        auto server_side = std::make_shared<memory_stream>(std::move(f));
        auto cn = std::make_shared<shadowsocks2022::conn<>>("pw");

        // 未握手读写 → not_open
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     std::error_code ec;
                     std::array<std::byte, 4> buf{};
                     const auto r = co_await cn->async_read_some(std::span<std::byte>(buf), ec);
                     EXPECT_EQ(r, 0u);
                     EXPECT_TRUE(ec);
                     ec.clear();
                     const auto w = co_await cn->async_write_some(std::span<const std::byte>(buf), ec);
                     EXPECT_EQ(w, 0u);
                     EXPECT_TRUE(ec);
                 });

        // fake server：解析 salt → 派生 key → 响应固定头
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     std::array<std::uint8_t, 16 + 45 + 128> buf{};
                     std::error_code ec;
                     const auto n = co_await server_side->async_read_some(
                         as_bytes(std::span<std::uint8_t>(buf)), ec);
                     EXPECT_GT(n, 16u + 45u);
                     const auto salt = std::span<const std::uint8_t>(buf.data(), 16);
                     const auto skey =
                         ss::session_key(shadowsocks2022::derive_psk("pw"), salt, 16);
                     ss::chunk_codec resp_codec(skey);
                     std::array<std::uint8_t, ss::fixed_hdr_plain> plain{};
                     plain[0] = ss::header_type_server;
                     const auto enc = resp_codec.seal(plain);
                     const auto werr = co_await server_side->write_all(enc);
                     EXPECT_FALSE(werr);
                 });
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     ss::address target{};
                     target.type = ss::address_type::domain;
                     target.host = "example.com";
                     target.port = 443;
                     const auto herr = co_await cn->write_handshake(std::make_shared<memory_stream>(std::move(e)),
                                                                   target);
                     EXPECT_EQ(herr, error::none);

                     // 装饰器方法
                     (void)cn->executor();
                     EXPECT_NE(cn->next_layer(), nullptr);
                     const auto *ccn = cn.get();
                     EXPECT_NE(ccn->next_layer(), nullptr);
                     cn->cancel();
                     EXPECT_NE(cn->release(), nullptr);

                     // UDP 数据面（握手后）
                     ss::address dst{};
                     dst.type = ss::address_type::ipv4;
                     dst.host = "1.2.3.4";
                     dst.port = 53;
                     const auto serr =
                         co_await cn->async_send_datagram(dst, as_u8_span(std::string_view{"udp"}));
                     EXPECT_EQ(serr, error::none);
                 });
    }

} // namespace
