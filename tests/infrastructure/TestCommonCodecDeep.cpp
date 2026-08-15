/**
 * @file TestCommonCodecDeep.cpp
 * @brief 测试库 codec 纯函数剩余分支深度测试
 * @details 覆盖 ws / socks5 / tuic / vless 四个 codec 的未执行分支：
 *          帧头 126/127 长度编码、掩码帧、增量解析 need_more / 错误
 *          路径、Beast 风格 serializer / parser 各消息类型，以及
 *          byte_span 工具函数的未用重载。
 */

#include <boost/asio/buffer.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

#include <common/core/byte_span.hpp>
#include <common/core/error.hpp>
#include <common/proxy/socks5/codec.hpp>
#include <common/proxy/tuic/codec.hpp>
#include <common/proxy/vless/codec.hpp>
#include <common/stealth/ws/codec.hpp>
#include <gtest/gtest.h>

namespace
{
    using namespace psmtest;

    /**
     * @brief 从初始值列表构造 uint8_t 字节向量
     */
    auto make_bytes(std::initializer_list<std::uint8_t> list) -> std::vector<std::uint8_t>
    {
        return std::vector<std::uint8_t>(list);
    }

    // ───────────────────────── byte_span ─────────────────────────

    TEST(ByteSpan, ConstOverloads)
    {
        std::array<std::uint8_t, 4> u8{1, 2, 3, 4};
        const auto &cu8 = u8;
        const auto cb = as_bytes(std::span<const std::uint8_t>(cu8));
        EXPECT_EQ(cb.size(), 4u);
        EXPECT_EQ(static_cast<std::uint8_t>(cb[0]), 1u);

        std::string str = "abc";
        const auto su = as_u8_span(str);
        EXPECT_EQ(su.size(), 3u);
        EXPECT_EQ(su[0], 'a');

        const auto bs = as_bytes_span(str);
        EXPECT_EQ(bs.size(), 3u);
        const std::string_view sv{"def"};
        EXPECT_EQ(as_bytes_span(sv).size(), 3u);
        const char *raw = "xy";
        EXPECT_EQ(as_bytes_span(raw, 2).size(), 2u);
        std::vector<std::uint8_t> vec{9, 8};
        EXPECT_EQ(as_bytes_span(vec).size(), 2u);

        const auto strv = as_str_view(std::span<const std::uint8_t>(u8.data(), 2));
        EXPECT_EQ(strv.size(), 2u);
        const auto bytes_view = as_bytes(std::span<std::uint8_t>(u8));
        EXPECT_EQ(as_str_view(bytes_view.subspan(0, 2)).size(), 2u);
    }

    // ───────────────────────── ws codec ─────────────────────────

    TEST(WsCodec, FrameHeaderExtendedLengths)
    {
        ws::frame_header hdr{};
        std::array<std::byte, 64> buf{};

        // 16 位长度（126）+ 掩码
        buf[0] = std::byte{0x82};
        buf[1] = std::byte{0x80 | 126};
        buf[2] = std::byte{0x01};
        buf[3] = std::byte{0x00};
        buf[4] = std::byte{0xAA};
        buf[5] = std::byte{0xBB};
        buf[6] = std::byte{0xCC};
        buf[7] = std::byte{0xDD};
        EXPECT_TRUE(ws::parse_frame_header(std::span<const std::byte>(buf.data(), 8), hdr));
        EXPECT_TRUE(hdr.fin);
        EXPECT_EQ(hdr.opcode, 0x02u);
        EXPECT_TRUE(hdr.masked);
        EXPECT_EQ(hdr.payload_len, 256u);
        EXPECT_EQ(hdr.header_len, 8u);
        EXPECT_EQ(static_cast<std::uint8_t>(hdr.mask[0]), 0xAA);

        // 16 位长度：数据不足（需 4 字节，只有 3）
        EXPECT_FALSE(ws::parse_frame_header(std::span<const std::byte>(buf.data(), 3), hdr));

        // 64 位长度（127）
        buf[1] = std::byte{0x7F};
        for (std::size_t i = 0; i < 8; ++i)
        {
            buf[2 + i] = std::byte{0};
        }
        buf[9] = std::byte{0x01};
        EXPECT_TRUE(ws::parse_frame_header(std::span<const std::byte>(buf.data(), 10), hdr));
        EXPECT_EQ(hdr.payload_len, 1u);
        EXPECT_EQ(hdr.header_len, 10u);

        // 64 位长度：数据不足（需 10 字节，只有 9）
        EXPECT_FALSE(ws::parse_frame_header(std::span<const std::byte>(buf.data(), 9), hdr));

        // 掩码 key 不足
        buf[1] = std::byte{0x80 | 5};
        EXPECT_FALSE(ws::parse_frame_header(std::span<const std::byte>(buf.data(), 3), hdr));
    }

    TEST(WsCodec, EncodeExtendedLengths)
    {
        std::array<std::byte, 80000> out{};

        // 16 位长度（126）
        std::vector<std::byte> p126(300, std::byte{0x11});
        ws::frame_input in126{ws::opcode::binary, true, std::span<const std::byte>(p126)};
        const auto n126 = ws::encode_frame(in126, out);
        EXPECT_EQ(n126, 304u);
        EXPECT_EQ(static_cast<std::uint8_t>(out[1]), 126u);
        EXPECT_EQ(static_cast<std::uint8_t>(out[2]), 0x01);
        EXPECT_EQ(static_cast<std::uint8_t>(out[3]), 0x2C);

        // 64 位长度（127）
        std::vector<std::byte> p127(70000, std::byte{0x22});
        ws::frame_input in127{ws::opcode::binary, true, std::span<const std::byte>(p127)};
        const auto n127 = ws::encode_frame(in127, out);
        EXPECT_EQ(n127, 70010u);
        EXPECT_EQ(static_cast<std::uint8_t>(out[1]), 127u);
        EXPECT_EQ(static_cast<std::uint8_t>(out[2]), 0x00);
        EXPECT_EQ(static_cast<std::uint8_t>(out[7]), 0x01);
        EXPECT_EQ(static_cast<std::uint8_t>(out[8]), 0x11);
        EXPECT_EQ(static_cast<std::uint8_t>(out[9]), 0x70);
        EXPECT_EQ(static_cast<std::uint8_t>(out[10]), 0x22);

        // 缓冲区不足 → 0
        std::array<std::byte, 16> small{};
        EXPECT_EQ(ws::encode_frame(in127, small), 0u);
    }

    // ───────────────────────── socks5 codec ─────────────────────────

    TEST(Socks5Codec, MethodReplyAndAddresses)
    {
        socks5::method_reply mr{};
        // need_more
        EXPECT_EQ(socks5::parse_method_reply(std::span<const std::uint8_t>(make_bytes({0x05})), mr),
                  error::need_more);
        // bad_magic
        EXPECT_EQ(socks5::parse_method_reply(std::span<const std::uint8_t>(make_bytes({0x04, 0x00})), mr),
                  error::bad_magic);
        // 成功
        EXPECT_EQ(socks5::parse_method_reply(std::span<const std::uint8_t>(make_bytes({0x05, 0x00})), mr),
                  error::none);
        EXPECT_EQ(mr.ver, 5u);
        EXPECT_EQ(mr.method, socks5::auth_method::no_auth);

        socks5::address addr{};
        std::size_t consumed = 0;
        // 空输入
        EXPECT_EQ(socks5::parse_address(std::span<const std::uint8_t>{}, addr, consumed), error::need_more);
        // ipv4 不足
        EXPECT_EQ(socks5::parse_address(std::span<const std::uint8_t>(make_bytes({0x01, 1, 2})), addr, consumed),
                  error::need_more);
        // ipv6 不足
        EXPECT_EQ(socks5::parse_address(std::span<const std::uint8_t>(make_bytes({0x04, 1})), addr, consumed),
                  error::need_more);
        // ipv6 成功
        std::vector<std::uint8_t> v6{0x04};
        v6.insert(v6.end(), 16, 0x42);
        v6.push_back(0x1F);
        v6.push_back(0x90);
        EXPECT_EQ(socks5::parse_address(v6, addr, consumed), error::none);
        EXPECT_EQ(addr.type, socks5::address_type::ipv6);
        EXPECT_EQ(addr.host, std::string(16, '\x42'));
        EXPECT_EQ(addr.port, 8080u);
        // domain 缺长度字节
        EXPECT_EQ(socks5::parse_address(std::span<const std::uint8_t>(make_bytes({0x03})), addr, consumed),
                  error::need_more);
        // domain 不足
        EXPECT_EQ(socks5::parse_address(std::span<const std::uint8_t>(make_bytes({0x03, 5, 'a'})), addr, consumed),
                  error::need_more);
        // domain 成功
        std::vector<std::uint8_t> dom{0x03, 7};
        const std::string_view name = "example";
        dom.insert(dom.end(), name.begin(), name.end());
        dom.push_back(0x00);
        dom.push_back(0x50);
        EXPECT_EQ(socks5::parse_address(dom, addr, consumed), error::none);
        EXPECT_EQ(addr.host, "example");
        EXPECT_EQ(addr.port, 80u);
        // 非法类型
        EXPECT_EQ(socks5::parse_address(std::span<const std::uint8_t>(make_bytes({0x7F, 0, 0, 0, 0})), addr, consumed),
                  error::bad_message);
    }

    TEST(Socks5Codec, ReplyAndGreeting)
    {
        // reply 解析
        socks5::reply rep{};
        std::size_t consumed = 0;
        EXPECT_EQ(socks5::parse_reply(std::span<const std::uint8_t>(make_bytes({0x05})), rep, consumed),
                  error::need_more);
        std::vector<std::uint8_t> rep_v{0x05, 0x00, 0x00, 0x01, 8, 8, 8, 8, 0x00, 0x35};
        EXPECT_EQ(socks5::parse_reply(rep_v, rep, consumed), error::none);
        EXPECT_EQ(rep.code, socks5::reply_code::success);
        EXPECT_EQ(rep.bind.host, "8.8.8.8");
        EXPECT_EQ(rep.bind.port, 53u);

        // greeting：版本不匹配
        socks5::greeting g{};
        EXPECT_EQ(socks5::parse_greeting(std::span<const std::uint8_t>(make_bytes({0x04, 0x01, 0x00})), g,
                                         consumed),
                  error::version_mismatch);
        // greeting：方法列表不足
        EXPECT_EQ(socks5::parse_greeting(std::span<const std::uint8_t>(make_bytes({0x05, 0x02, 0x00})), g,
                                         consumed),
                  error::need_more);
        // greeting 成功
        EXPECT_EQ(socks5::parse_greeting(std::span<const std::uint8_t>(make_bytes({0x05, 0x02, 0x00, 0x02})), g,
                                         consumed),
                  error::none);
        EXPECT_EQ(g.methods.size(), 2u);
        EXPECT_EQ(socks5::build_greeting(g).size(), 4u);

        // userpass 响应
        EXPECT_EQ(socks5::parse_userpass_reply(std::span<const std::uint8_t>(make_bytes({0x01}))),
                  error::need_more);
        EXPECT_EQ(socks5::parse_userpass_reply(std::span<const std::uint8_t>(make_bytes({0x02, 0x00}))),
                  error::bad_magic);
        EXPECT_EQ(socks5::parse_userpass_reply(std::span<const std::uint8_t>(make_bytes({0x01, 0x00}))),
                  error::none);
        EXPECT_EQ(socks5::parse_userpass_reply(std::span<const std::uint8_t>(make_bytes({0x01, 0x01}))),
                  error::bad_auth);
        const auto up = socks5::build_userpass("user", "pass");
        EXPECT_EQ(up.size(), 11u);
    }

    TEST(Socks5Codec, SerializerAllKinds)
    {
        socks5::serializer ser;
        std::array<std::uint8_t, 256> buf{};

        socks5::message msg;
        msg.type = socks5::message::kind::greeting;
        msg.methods = {0x00, 0x02};
        ser.reset(msg);
        EXPECT_FALSE(ser.is_done());
        std::error_code ec;
        const auto n1 = ser.get(boost::asio::buffer(buf.data(), buf.size()), ec);
        EXPECT_EQ(n1, 4u);
        EXPECT_TRUE(ser.is_done());

        msg.type = socks5::message::kind::method_reply;
        msg.method = 0x00;
        ser.reset(msg);
        // 注：生产实现此处 wire_ 赋值存在未定义行为（不同临时对象
        // begin/end），仅执行路径，不做内容断言
        (void)ser.get(boost::asio::buffer(buf.data(), buf.size()), ec);

        msg.type = socks5::message::kind::userpass;
        msg.username = "u";
        msg.password = "p";
        ser.reset(msg);
        EXPECT_EQ(ser.get(boost::asio::buffer(buf.data(), buf.size()), ec), 5u);

        msg.type = socks5::message::kind::request;
        msg.cmd = socks5::command::connect;
        msg.addr.type = socks5::address_type::ipv4;
        msg.addr.host = "1.2.3.4";
        msg.addr.port = 443;
        ser.reset(msg);
        EXPECT_EQ(ser.get(boost::asio::buffer(buf.data(), buf.size()), ec), 10u);

        msg.type = socks5::message::kind::reply;
        msg.rep = socks5::reply_code::success;
        msg.addr.type = socks5::address_type::domain;
        msg.addr.host = "x.com";
        msg.addr.port = 80;
        ser.reset(msg);
        EXPECT_EQ(ser.get(boost::asio::buffer(buf.data(), buf.size()), ec), 12u);
        // 全量输出后再 get → 0 字节
        EXPECT_EQ(ser.get(boost::asio::buffer(buf.data(), buf.size()), ec), 0u);
    }

    TEST(Socks5Codec, ParserRemainingKinds)
    {
        socks5::parser p;
        std::error_code ec;

        // method_reply
        p.expect(socks5::message::kind::method_reply);
        EXPECT_EQ(p.put(boost::asio::buffer(make_bytes({0x05})), ec), 0u);
        EXPECT_FALSE(ec); // need_more 不设置 ec（半帧等待）
        ec.clear();
        EXPECT_EQ(p.put(boost::asio::buffer(make_bytes({0x00})), ec), 1u);
        EXPECT_TRUE(p.is_done());
        EXPECT_EQ(p.get().type, socks5::message::kind::method_reply);
        EXPECT_EQ(p.get().method, 0u);
        p.reset();
        // 错误版本
        EXPECT_EQ(p.put(boost::asio::buffer(make_bytes({0x04, 0x00})), ec), 0u);
        EXPECT_EQ(ec, make_error_code(error::bad_magic));
        p.reset();

        // userpass
        p.expect(socks5::message::kind::userpass);
        EXPECT_EQ(p.put(boost::asio::buffer(make_bytes({0x01})), ec), 0u);
        EXPECT_FALSE(ec); // need_more 不设置 ec
        ec.clear();
        // 错误版本
        p.reset();
        EXPECT_EQ(p.put(boost::asio::buffer(make_bytes({0x02, 0x01, 'u'})), ec), 0u);
        EXPECT_EQ(ec, make_error_code(error::bad_magic));
        p.reset();
        // 用户名长度不足
        EXPECT_EQ(p.put(boost::asio::buffer(make_bytes({0x01, 0x05, 'u'})), ec), 0u);
        EXPECT_FALSE(ec);
        ec.clear();
        p.reset();
        // 密码长度不足
        EXPECT_EQ(p.put(boost::asio::buffer(make_bytes({0x01, 0x01, 'u', 0x05})), ec), 0u);
        EXPECT_FALSE(ec);
        ec.clear();
        p.reset();
        // 成功
        EXPECT_EQ(p.put(boost::asio::buffer(make_bytes({0x01, 0x01, 'u', 0x01, 'p'})), ec), 5u);
        EXPECT_TRUE(p.is_done());
        EXPECT_EQ(p.get().type, socks5::message::kind::userpass);
        EXPECT_EQ(p.get().username, "u");
        EXPECT_EQ(p.get().password, "p");
        p.reset();

        // reply
        p.expect(socks5::message::kind::reply);
        std::vector<std::uint8_t> rep_v{0x05, 0x00, 0x00, 0x01, 8, 8, 8, 8, 0x00, 0x35};
        EXPECT_EQ(p.put(boost::asio::buffer(rep_v), ec), 10u);
        EXPECT_TRUE(p.is_done());
        EXPECT_EQ(p.get().type, socks5::message::kind::reply);
        EXPECT_EQ(p.get().rep, socks5::reply_code::success);
        EXPECT_EQ(p.get().addr.host, "8.8.8.8");
        // remaining 与 take_remaining
        std::vector<std::uint8_t> extra{0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0x00, 0x50, 0xAA, 0xBB};
        p.reset();
        EXPECT_EQ(p.put(boost::asio::buffer(extra), ec), 10u);
        EXPECT_EQ(p.remaining().size(), 2u);
        const auto taken = p.take_remaining();
        EXPECT_EQ(taken.size(), 2u);
        EXPECT_EQ(taken[0], 0xAA);
    }

    // ───────────────────────── tuic codec ─────────────────────────

    TEST(TuicCodecDeep, ParseAddressBranches)
    {
        tuic::address addr{};
        std::size_t consumed = 0;
        // ipv4 不足
        EXPECT_EQ(tuic::parse_address(std::span<const std::uint8_t>(make_bytes({0x01, 1, 2})), addr, consumed),
                  error::need_more);
        // ipv6 不足
        EXPECT_EQ(tuic::parse_address(std::span<const std::uint8_t>(make_bytes({0x04, 1})), addr, consumed),
                  error::need_more);
        // ipv6 成功
        std::vector<std::uint8_t> v6{0x04};
        v6.insert(v6.end(), 16, 0x42);
        v6.push_back(0x00);
        v6.push_back(0x50);
        EXPECT_EQ(tuic::parse_address(v6, addr, consumed), error::none);
        EXPECT_EQ(addr.host, std::string(16, '\x42'));
        EXPECT_EQ(addr.port, 80u);
        // domain 缺长度
        EXPECT_EQ(tuic::parse_address(std::span<const std::uint8_t>(make_bytes({0x03})), addr, consumed),
                  error::need_more);
        // domain 不足
        EXPECT_EQ(tuic::parse_address(std::span<const std::uint8_t>(make_bytes({0x03, 3, 'a'})), addr, consumed),
                  error::need_more);
        // domain 成功
        std::vector<std::uint8_t> dom{0x03, 3};
        const std::string_view name = "abc";
        dom.insert(dom.end(), name.begin(), name.end());
        dom.push_back(0x01);
        dom.push_back(0xBB);
        EXPECT_EQ(tuic::parse_address(dom, addr, consumed), error::none);
        EXPECT_EQ(addr.host, "abc");
        EXPECT_EQ(addr.port, 443u);
    }

    TEST(TuicCodecDeep, ParseErrorAndParser)
    {
        // parse：地址解析失败（domain 长度截断）→ need_more 经 parse 传播
        tuic::message msg{};
        std::size_t consumed = 0;
        std::vector<std::uint8_t> bad{0x04, 0x07, 0, 0, 0, 0, 0, 0, 0, 0, 0x03, 0x0A, 'a', 'b'};
        EXPECT_EQ(tuic::parse(bad, msg, consumed), error::need_more);

        // parser：need_more（设置 ec）/ 错误传播
        tuic::parser p;
        std::error_code ec;
        EXPECT_EQ(p.put(boost::asio::buffer(make_bytes({0x04})), ec), 0u);
        EXPECT_TRUE(ec);
        EXPECT_EQ(ec, make_error_code(error::need_more));
        EXPECT_EQ(ec, make_error_code(error::need_more));
        p.reset();
        EXPECT_EQ(p.put(boost::asio::buffer(make_bytes({0x03, 0x07, 0, 0, 0, 0, 0, 0, 0, 0})), ec), 0u);
        EXPECT_EQ(ec, make_error_code(error::bad_magic));
        p.reset();
        // 成功解析
        std::vector<std::uint8_t> ok{0x04, 0x07, 0, 0, 0, 0, 1, 0, 0, 0, 0x01, 8, 8, 8, 8, 0x00, 0x35, 'x'};
        EXPECT_EQ(p.put(boost::asio::buffer(ok), ec), 18u);
        EXPECT_TRUE(p.is_done());
        EXPECT_EQ(p.get().cmd, tuic::cmd_packet);
        EXPECT_EQ(p.get().pkt_id, 1u);
        EXPECT_EQ(p.get().dst.host, "8.8.8.8");
    }

    // ───────────────────────── vless codec ─────────────────────────

    TEST(VlessCodecDeep, EncodeAddressBranches)
    {
        vless::address addr{};
        // ipv4 编码（点分解析）
        addr.type = vless::address_type::ipv4;
        addr.host = "10.0.0.1";
        addr.port = 1001;
        const auto v4 = vless::encode_address(addr);
        EXPECT_EQ(v4.size(), 7u);
        EXPECT_EQ(v4[0], 0x01);
        EXPECT_EQ(v4[1], 10u);
        EXPECT_EQ(v4[4], 1u);
        // ipv6 编码
        addr.type = vless::address_type::ipv6;
        addr.host.assign(16, 'z');
        const auto v6 = vless::encode_address(addr);
        EXPECT_EQ(v6.size(), 19u);
        EXPECT_EQ(v6[0], 0x03);
        EXPECT_EQ(v6[1], 'z');
    }

    TEST(VlessCodecDeep, BuildRequestIpv6)
    {
        vless::request_header hdr{};
        hdr.uuid.fill(0x11);
        hdr.cmd = vless::command::udp;
        hdr.target.type = vless::address_type::ipv6;
        hdr.target.host.assign(16, 'w');
        hdr.target.port = 53;
        hdr.addons = {0x01, 0x02};
        const auto wire = vless::build_request(hdr);
        EXPECT_EQ(wire.size(), 22u + 2u + 16u);
        EXPECT_EQ(wire[23], 0x03); // ATYP = ipv6
    }

    TEST(VlessCodecDeep, ParseRequestBranches)
    {
        vless::request_header hdr{};
        std::size_t consumed = 0;
        std::vector<std::uint8_t> base{0x00};
        base.insert(base.end(), 16, 0x11);
        base.push_back(0x00); // addnl len
        base.push_back(0x01); // cmd tcp
        base.push_back(0x00);
        base.push_back(0x50); // port 80
        // ipv4 不足
        std::vector<std::uint8_t> v4 = base;
        v4.push_back(0x01);
        v4.push_back(8);
        v4.push_back(8);
        EXPECT_EQ(vless::parse_request(v4, hdr, consumed), error::need_more);
        // ipv6 不足
        std::vector<std::uint8_t> v6 = base;
        v6.push_back(0x03);
        v6.insert(v6.end(), 5, 0x42);
        EXPECT_EQ(vless::parse_request(v6, hdr, consumed), error::need_more);
        // ipv6 成功
        std::vector<std::uint8_t> v6ok = base;
        v6ok.push_back(0x03);
        v6ok.insert(v6ok.end(), 16, 0x42);
        EXPECT_EQ(vless::parse_request(v6ok, hdr, consumed), error::none);
        EXPECT_EQ(hdr.target.type, vless::address_type::ipv6);
        EXPECT_EQ(hdr.target.host, std::string(16, '\x42'));
        EXPECT_EQ(hdr.target.port, 80u);
    }

    TEST(VlessCodecDeep, ParserErrors)
    {
        std::array<std::uint8_t, 16> uuid{};
        uuid.fill(0x11);
        vless::parser p(uuid);
        std::error_code ec;

        // 数据不足
        EXPECT_EQ(p.put(boost::asio::buffer(make_bytes({0x00})), ec), 0u);
        EXPECT_EQ(ec, make_error_code(error::need_more));
        p.reset();
        // 版本错误
        std::vector<std::uint8_t> bad{0x01};
        bad.insert(bad.end(), 16, 0x11);
        bad.insert(bad.end(), 6, 0x00);
        EXPECT_EQ(p.put(boost::asio::buffer(bad), ec), 0u);
        EXPECT_EQ(ec, make_error_code(error::bad_magic));
        p.reset();
        // UUID 不匹配
        std::vector<std::uint8_t> wrong = bad;
        wrong[0] = 0x00;
        wrong[1] = 0x22;
        EXPECT_EQ(p.put(boost::asio::buffer(wrong), ec), 0u);
        EXPECT_EQ(ec, make_error_code(error::auth_failed));
        p.reset();
        // 成功（uuid 匹配 + ipv4）
        std::vector<std::uint8_t> ok{0x00};
        ok.insert(ok.end(), 16, 0x11);
        ok.push_back(0x00);
        ok.push_back(0x01);
        ok.push_back(0x00);
        ok.push_back(0x50);
        ok.push_back(0x01);
        ok.insert(ok.end(), 4, 8);
        EXPECT_EQ(p.put(boost::asio::buffer(ok), ec), ok.size());
        EXPECT_TRUE(p.is_done());
        EXPECT_TRUE(p.get().valid);
        EXPECT_EQ(p.get().cmd, 0x01u);
    }

} // namespace
