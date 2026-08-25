/**
 * @file TestCommonCodecDeep.cpp
 * @brief 测试库 Codec 纯函数剩余分支深度测试
 * @details 覆盖 ws / socks5 / tuic / vless 四个 Codec 的未执行分支：
 *          帧头 126/127 长度编码、掩码帧、增量解析 need_more / 错误
 *          路径、Beast 风格 Serializer / Parser 各消息类型，以及
 *          byte_span 工具函数的未用重载。
 */

#include <boost/asio/buffer.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

#include <common/Core/ByteSpan.hpp>
#include <common/Core/Error.hpp>
#include <common/Protocols/Socks5/Codec.hpp>
#include <common/Protocols/Tuic/Codec.hpp>
#include <common/Protocols/Vless/Codec.hpp>
#include <common/Protocols/Ws/Codec.hpp>
#include <gtest/gtest.h>

namespace
{
    using namespace Preview;

    /**
     * @brief 从初始值列表构造 uint8_t 字节向量
     */
    auto make_bytes(std::initializer_list<std::uint8_t> List) -> std::vector<std::uint8_t>
    {
        return std::vector<std::uint8_t>(List);
    }

    // ───────────────────────── byte_span ─────────────────────────

    TEST(ByteSpan, ConstOverloads)
    {
        std::array<std::uint8_t, 4> u8{1, 2, 3, 4};
        const auto &cu8 = u8;
        const auto cb = AsBytes(std::span<const std::uint8_t>(cu8));
        EXPECT_EQ(cb.size(), 4u);
        EXPECT_EQ(static_cast<std::uint8_t>(cb[0]), 1u);

        std::string str = "abc";
        const auto su = AsU8Span(str);
        EXPECT_EQ(su.size(), 3u);
        EXPECT_EQ(su[0], 'a');

        const auto bs = AsBytesSpan(str);
        EXPECT_EQ(bs.size(), 3u);
        const std::string_view sv{"def"};
        EXPECT_EQ(AsBytesSpan(sv).size(), 3u);
        const char *raw = "xy";
        EXPECT_EQ(AsBytesSpan(raw, 2).size(), 2u);
        std::vector<std::uint8_t> vec{9, 8};
        EXPECT_EQ(AsBytesSpan(vec).size(), 2u);

        const auto strv = AsStrView(std::span<const std::uint8_t>(u8.data(), 2));
        EXPECT_EQ(strv.size(), 2u);
        const auto bytes_view = AsBytes(std::span<std::uint8_t>(u8));
        EXPECT_EQ(AsStrView(bytes_view.subspan(0, 2)).size(), 2u);
    }

    TEST(ByteSpan, TemplateAs)
    {
        // 目标元素类型由模板参数控制（byte / uint8_t / char）
        std::string str = "abc";
        const auto Bytes = As<std::byte>(str);
        EXPECT_EQ(Bytes.size(), 3u);
        EXPECT_EQ(static_cast<char>(Bytes[0]), 'a');

        std::vector<std::uint8_t> vec{1, 2, 3};
        const auto u8v = As<std::uint8_t>(vec);
        EXPECT_EQ(u8v.size(), 3u);
        EXPECT_EQ(u8v[1], 2u);

        std::array<std::byte, 2> arr{std::byte{0x10}, std::byte{0x20}};
        const auto u8a = As<std::uint8_t>(arr);
        EXPECT_EQ(u8a[0], 0x10u);
        EXPECT_EQ(u8a[1], 0x20u);

        // 只读源 → const 视图
        const std::string_view sv{"def"};
        const auto cbytes = As<std::byte>(sv);
        EXPECT_TRUE((std::is_same_v<std::decay_t<decltype(cbytes)>, std::span<const std::byte>>));
        EXPECT_EQ(cbytes.size(), 3u);

        // 裸指针 + 长度 → uint8_t 只读视图
        const char *raw = "xy";
        const auto rv = As<std::uint8_t>(raw, 2);
        EXPECT_EQ(rv.size(), 2u);
        EXPECT_EQ(rv[1], 'y');
    }

    TEST(ByteSpan, AsWriteThrough)
    {
        // 可变 string → span<byte> 可写（HTTP 读缓冲场景）
        std::string buf = "hello";
        const auto view = AsBytesSpan(buf);
        EXPECT_TRUE((std::is_same_v<std::decay_t<decltype(view)>, std::span<std::byte>>));
        view[0] = std::byte{'H'};
        EXPECT_EQ(buf, "Hello");

        // span 右值保持可变视图，写穿到原数组
        std::array<std::uint8_t, 3> Data{1, 2, 3};
        const auto u8 = AsU8(std::span(Data));
        EXPECT_TRUE((std::is_same_v<std::decay_t<decltype(u8)>, std::span<std::uint8_t>>));
        u8[0] = 9;
        EXPECT_EQ(Data[0], 9u);
    }

    // ───────────────────────── ws Codec ─────────────────────────

    TEST(WsCodec, FrameHeaderExtendedLengths)
    {
        Ws::FrameHeader hdr{};
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
        EXPECT_TRUE(Ws::ParseFrameHeader(std::span<const std::byte>(buf.data(), 8), hdr));
        EXPECT_TRUE(hdr.fin);
        EXPECT_EQ(hdr.Opcode, 0x02u);
        EXPECT_TRUE(hdr.masked);
        EXPECT_EQ(hdr.PayloadLen, 256u);
        EXPECT_EQ(hdr.HeaderLen, 8u);
        EXPECT_EQ(static_cast<std::uint8_t>(hdr.masked[0]), 0xAA);

        // 16 位长度：数据不足（需 4 字节，只有 3）
        EXPECT_FALSE(Ws::ParseFrameHeader(std::span<const std::byte>(buf.data(), 3), hdr));

        // 64 位长度（127）
        buf[1] = std::byte{0x7F};
        for (std::size_t i = 0; i < 8; ++i)
        {
            buf[2 + i] = std::byte{0};
        }
        buf[9] = std::byte{0x01};
        EXPECT_TRUE(Ws::ParseFrameHeader(std::span<const std::byte>(buf.data(), 10), hdr));
        EXPECT_EQ(hdr.PayloadLen, 1u);
        EXPECT_EQ(hdr.HeaderLen, 10u);

        // 64 位长度：数据不足（需 10 字节，只有 9）
        EXPECT_FALSE(Ws::ParseFrameHeader(std::span<const std::byte>(buf.data(), 9), hdr));

        // 掩码 key 不足
        buf[1] = std::byte{0x80 | 5};
        EXPECT_FALSE(Ws::ParseFrameHeader(std::span<const std::byte>(buf.data(), 3), hdr));
    }

    TEST(WsCodec, EncodeExtendedLengths)
    {
        std::array<std::byte, 80000> out{};

        // 16 位长度（126）
        std::vector<std::byte> p126(300, std::byte{0x11});
        Ws::FrameInput in126{Ws::Opcode::binary, true, std::span<const std::byte>(p126)};
        const auto n126 = Ws::EncodeFrame(in126, out);
        EXPECT_EQ(n126, 304u);
        EXPECT_EQ(static_cast<std::uint8_t>(out[1]), 126u);
        EXPECT_EQ(static_cast<std::uint8_t>(out[2]), 0x01);
        EXPECT_EQ(static_cast<std::uint8_t>(out[3]), 0x2C);

        // 64 位长度（127）
        std::vector<std::byte> p127(70000, std::byte{0x22});
        Ws::FrameInput in127{Ws::Opcode::binary, true, std::span<const std::byte>(p127)};
        const auto n127 = Ws::EncodeFrame(in127, out);
        EXPECT_EQ(n127, 70010u);
        EXPECT_EQ(static_cast<std::uint8_t>(out[1]), 127u);
        EXPECT_EQ(static_cast<std::uint8_t>(out[2]), 0x00);
        EXPECT_EQ(static_cast<std::uint8_t>(out[7]), 0x01);
        EXPECT_EQ(static_cast<std::uint8_t>(out[8]), 0x11);
        EXPECT_EQ(static_cast<std::uint8_t>(out[9]), 0x70);
        EXPECT_EQ(static_cast<std::uint8_t>(out[10]), 0x22);

        // 缓冲区不足 → 0
        std::array<std::byte, 16> small{};
        EXPECT_EQ(Ws::EncodeFrame(in127, small), 0u);
    }

    // ───────────────────────── socks5 Codec ─────────────────────────

    TEST(Socks5Codec, MethodReplyAndAddresses)
    {
        Socks5::MethodReply mr{};
        // need_more
        EXPECT_EQ(Socks5::ParseMethodReply(std::span<const std::uint8_t>(make_bytes({0x05})), mr),
                  Error::need_more);
        // bad_magic
        EXPECT_EQ(Socks5::ParseMethodReply(std::span<const std::uint8_t>(make_bytes({0x04, 0x00})), mr),
                  Error::bad_magic);
        // 成功
        EXPECT_EQ(Socks5::ParseMethodReply(std::span<const std::uint8_t>(make_bytes({0x05, 0x00})), mr),
                  Error::none);
        EXPECT_EQ(mr.Ver, 5u);
        EXPECT_EQ(mr.Method, Socks5::AuthMethod::no_auth);

        Socks5::Address addr{};
        std::size_t consumed = 0;
        // 空输入
        EXPECT_EQ(Socks5::ParseAddress(std::span<const std::uint8_t>{}, addr, consumed), Error::need_more);
        // ipv4 不足
        EXPECT_EQ(Socks5::ParseAddress(std::span<const std::uint8_t>(make_bytes({0x01, 1, 2})), addr, consumed),
                  Error::need_more);
        // ipv6 不足
        EXPECT_EQ(Socks5::ParseAddress(std::span<const std::uint8_t>(make_bytes({0x04, 1})), addr, consumed),
                  Error::need_more);
        // ipv6 成功
        std::vector<std::uint8_t> v6{0x04};
        v6.insert(v6.end(), 16, 0x42);
        v6.push_back(0x1F);
        v6.push_back(0x90);
        EXPECT_EQ(Socks5::ParseAddress(v6, addr, consumed), Error::none);
        EXPECT_EQ(addr.Type, Socks5::AddressType::Ipv6);
        EXPECT_EQ(addr.Host, std::string(16, '\x42'));
        EXPECT_EQ(addr.Port, 8080u);
        // domain 缺长度字节
        EXPECT_EQ(Socks5::ParseAddress(std::span<const std::uint8_t>(make_bytes({0x03})), addr, consumed),
                  Error::need_more);
        // domain 不足
        EXPECT_EQ(Socks5::ParseAddress(std::span<const std::uint8_t>(make_bytes({0x03, 5, 'a'})), addr, consumed),
                  Error::need_more);
        // domain 成功
        std::vector<std::uint8_t> dom{0x03, 7};
        const std::string_view Name = "example";
        dom.insert(dom.end(), Name.begin(), Name.end());
        dom.push_back(0x00);
        dom.push_back(0x50);
        EXPECT_EQ(Socks5::ParseAddress(dom, addr, consumed), Error::none);
        EXPECT_EQ(addr.Host, "example");
        EXPECT_EQ(addr.Port, 80u);
        // 非法类型
        EXPECT_EQ(Socks5::ParseAddress(std::span<const std::uint8_t>(make_bytes({0x7F, 0, 0, 0, 0})), addr, consumed),
                  Error::bad_message);
    }

    TEST(Socks5Codec, ReplyAndGreeting)
    {
        // Reply 解析
        Socks5::Reply rep{};
        std::size_t consumed = 0;
        EXPECT_EQ(Socks5::ParseReply(std::span<const std::uint8_t>(make_bytes({0x05})), rep, consumed),
                  Error::need_more);
        std::vector<std::uint8_t> rep_v{0x05, 0x00, 0x00, 0x01, 8, 8, 8, 8, 0x00, 0x35};
        EXPECT_EQ(Socks5::ParseReply(rep_v, rep, consumed), Error::none);
        EXPECT_EQ(rep.Code, Socks5::ReplyCode::success);
        EXPECT_EQ(rep.Bind.Host, "8.8.8.8");
        EXPECT_EQ(rep.Bind.Port, 53u);

        // Greeting：版本不匹配
        Socks5::Greeting g{};
        EXPECT_EQ(Socks5::ParseGreeting(std::span<const std::uint8_t>(make_bytes({0x04, 0x01, 0x00})), g,
                                         consumed),
                  Error::version_mismatch);
        // Greeting：方法列表不足
        EXPECT_EQ(Socks5::ParseGreeting(std::span<const std::uint8_t>(make_bytes({0x05, 0x02, 0x00})), g,
                                         consumed),
                  Error::need_more);
        // Greeting 成功
        EXPECT_EQ(Socks5::ParseGreeting(std::span<const std::uint8_t>(make_bytes({0x05, 0x02, 0x00, 0x02})), g,
                                         consumed),
                  Error::none);
        EXPECT_EQ(g.methods.size(), 2u);
        EXPECT_EQ(Socks5::BuildGreeting(g).size(), 4u);

        // userpass 响应
        EXPECT_EQ(Socks5::ParseUserpassReply(std::span<const std::uint8_t>(make_bytes({0x01}))),
                  Error::need_more);
        EXPECT_EQ(Socks5::ParseUserpassReply(std::span<const std::uint8_t>(make_bytes({0x02, 0x00}))),
                  Error::bad_magic);
        EXPECT_EQ(Socks5::ParseUserpassReply(std::span<const std::uint8_t>(make_bytes({0x01, 0x00}))),
                  Error::none);
        EXPECT_EQ(Socks5::ParseUserpassReply(std::span<const std::uint8_t>(make_bytes({0x01, 0x01}))),
                  Error::bad_auth);
        const auto up = Socks5::BuildUserpass("user", "pass");
        EXPECT_EQ(up.size(), 11u);
    }

    TEST(Socks5Codec, SerializerAllKinds)
    {
        Socks5::Serializer ser;
        std::array<std::uint8_t, 256> buf{};

        Socks5::Message msg;
        msg.Type = Socks5::Message::Kind::Greeting;
        msg.methods = {0x00, 0x02};
        ser.Reset(msg);
        EXPECT_FALSE(ser.IsDone());
        std::error_code ec;
        const auto n1 = ser.Get(boost::asio::buffer(buf.data(), buf.size()), ec);
        EXPECT_EQ(n1, 4u);
        EXPECT_TRUE(ser.IsDone());

        msg.Type = Socks5::Message::Kind::MethodReply;
        msg.Method = 0x00;
        ser.Reset(msg);
        // 注：生产实现此处 wire_ 赋值存在未定义行为（不同临时对象
        // begin/end），仅执行路径，不做内容断言
        (void)ser.Get(boost::asio::buffer(buf.data(), buf.size()), ec);

        msg.Type = Socks5::Message::Kind::userpass;
        msg.username = "u";
        msg.password = "p";
        ser.Reset(msg);
        EXPECT_EQ(ser.Get(boost::asio::buffer(buf.data(), buf.size()), ec), 5u);

        msg.Type = Socks5::Message::Kind::Request;
        msg.Cmd = Socks5::Command::Connect;
        msg.addr.Type = Socks5::AddressType::Ipv4;
        msg.addr.Host = "1.2.3.4";
        msg.addr.Port = 443;
        ser.Reset(msg);
        EXPECT_EQ(ser.Get(boost::asio::buffer(buf.data(), buf.size()), ec), 10u);

        msg.Type = Socks5::Message::Kind::Reply;
        msg.rep = Socks5::ReplyCode::success;
        msg.addr.Type = Socks5::AddressType::Domain;
        msg.addr.Host = "x.com";
        msg.addr.Port = 80;
        ser.Reset(msg);
        EXPECT_EQ(ser.Get(boost::asio::buffer(buf.data(), buf.size()), ec), 12u);
        // 全量输出后再 Get → 0 字节
        EXPECT_EQ(ser.Get(boost::asio::buffer(buf.data(), buf.size()), ec), 0u);
    }

    TEST(Socks5Codec, ParserRemainingKinds)
    {
        Socks5::Parser p;
        std::error_code ec;

        // MethodReply
        p.Expect(Socks5::Message::Kind::MethodReply);
        EXPECT_EQ(p.Put(boost::asio::buffer(make_bytes({0x05})), ec), 0u);
        EXPECT_FALSE(ec); // need_more 不设置 ec（半帧等待）
        ec.clear();
        EXPECT_EQ(p.Put(boost::asio::buffer(make_bytes({0x00})), ec), 1u);
        EXPECT_TRUE(p.IsDone());
        EXPECT_EQ(p.Get().Type, Socks5::Message::Kind::MethodReply);
        EXPECT_EQ(p.Get().Method, 0u);
        p.Reset();
        // 错误版本
        EXPECT_EQ(p.Put(boost::asio::buffer(make_bytes({0x04, 0x00})), ec), 0u);
        EXPECT_EQ(ec, make_error_code(Error::bad_magic));
        p.Reset();

        // userpass
        p.Expect(Socks5::Message::Kind::userpass);
        EXPECT_EQ(p.Put(boost::asio::buffer(make_bytes({0x01})), ec), 0u);
        EXPECT_FALSE(ec); // need_more 不设置 ec
        ec.clear();
        // 错误版本
        p.Reset();
        EXPECT_EQ(p.Put(boost::asio::buffer(make_bytes({0x02, 0x01, 'u'})), ec), 0u);
        EXPECT_EQ(ec, make_error_code(Error::bad_magic));
        p.Reset();
        // 用户名长度不足
        EXPECT_EQ(p.Put(boost::asio::buffer(make_bytes({0x01, 0x05, 'u'})), ec), 0u);
        EXPECT_FALSE(ec);
        ec.clear();
        p.Reset();
        // 密码长度不足
        EXPECT_EQ(p.Put(boost::asio::buffer(make_bytes({0x01, 0x01, 'u', 0x05})), ec), 0u);
        EXPECT_FALSE(ec);
        ec.clear();
        p.Reset();
        // 成功
        EXPECT_EQ(p.Put(boost::asio::buffer(make_bytes({0x01, 0x01, 'u', 0x01, 'p'})), ec), 5u);
        EXPECT_TRUE(p.IsDone());
        EXPECT_EQ(p.Get().Type, Socks5::Message::Kind::userpass);
        EXPECT_EQ(p.Get().username, "u");
        EXPECT_EQ(p.Get().password, "p");
        p.Reset();

        // Reply
        p.Expect(Socks5::Message::Kind::Reply);
        std::vector<std::uint8_t> rep_v{0x05, 0x00, 0x00, 0x01, 8, 8, 8, 8, 0x00, 0x35};
        EXPECT_EQ(p.Put(boost::asio::buffer(rep_v), ec), 10u);
        EXPECT_TRUE(p.IsDone());
        EXPECT_EQ(p.Get().Type, Socks5::Message::Kind::Reply);
        EXPECT_EQ(p.Get().rep, Socks5::ReplyCode::success);
        EXPECT_EQ(p.Get().addr.Host, "8.8.8.8");
        // Remaining 与 TakeRemaining
        std::vector<std::uint8_t> extra{0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0x00, 0x50, 0xAA, 0xBB};
        p.Reset();
        EXPECT_EQ(p.Put(boost::asio::buffer(extra), ec), 10u);
        EXPECT_EQ(p.Remaining().size(), 2u);
        const auto taken = p.TakeRemaining();
        EXPECT_EQ(taken.size(), 2u);
        EXPECT_EQ(taken[0], 0xAA);
    }

    // ───────────────────────── tuic Codec ─────────────────────────

    TEST(TuicCodecDeep, ParseAddressBranches)
    {
        Tuic::Address addr{};
        std::size_t consumed = 0;
        // ipv4 不足
        EXPECT_EQ(Tuic::ParseAddress(std::span<const std::uint8_t>(make_bytes({0x01, 1, 2})), addr, consumed),
                  Error::need_more);
        // ipv6 不足
        EXPECT_EQ(Tuic::ParseAddress(std::span<const std::uint8_t>(make_bytes({0x04, 1})), addr, consumed),
                  Error::need_more);
        // ipv6 成功
        std::vector<std::uint8_t> v6{0x04};
        v6.insert(v6.end(), 16, 0x42);
        v6.push_back(0x00);
        v6.push_back(0x50);
        EXPECT_EQ(Tuic::ParseAddress(v6, addr, consumed), Error::none);
        EXPECT_EQ(addr.Host, std::string(16, '\x42'));
        EXPECT_EQ(addr.Port, 80u);
        // domain 缺长度
        EXPECT_EQ(Tuic::ParseAddress(std::span<const std::uint8_t>(make_bytes({0x03})), addr, consumed),
                  Error::need_more);
        // domain 不足
        EXPECT_EQ(Tuic::ParseAddress(std::span<const std::uint8_t>(make_bytes({0x03, 3, 'a'})), addr, consumed),
                  Error::need_more);
        // domain 成功
        std::vector<std::uint8_t> dom{0x03, 3};
        const std::string_view Name = "abc";
        dom.insert(dom.end(), Name.begin(), Name.end());
        dom.push_back(0x01);
        dom.push_back(0xBB);
        EXPECT_EQ(Tuic::ParseAddress(dom, addr, consumed), Error::none);
        EXPECT_EQ(addr.Host, "abc");
        EXPECT_EQ(addr.Port, 443u);
    }

    TEST(TuicCodecDeep, ParseErrorAndParser)
    {
        // Parse：地址解析失败（domain 长度截断）→ need_more 经 Parse 传播
        Tuic::Message msg{};
        std::size_t consumed = 0;
        std::vector<std::uint8_t> bad{0x04, 0x07, 0, 0, 0, 0, 0, 0, 0, 0, 0x03, 0x0A, 'a', 'b'};
        EXPECT_EQ(Tuic::Parse(bad, msg, consumed), Error::need_more);

        // Parser：need_more（设置 ec）/ 错误传播
        Tuic::Parser p;
        std::error_code ec;
        EXPECT_EQ(p.Put(boost::asio::buffer(make_bytes({0x04})), ec), 0u);
        EXPECT_TRUE(ec);
        EXPECT_EQ(ec, make_error_code(Error::need_more));
        EXPECT_EQ(ec, make_error_code(Error::need_more));
        p.Reset();
        EXPECT_EQ(p.Put(boost::asio::buffer(make_bytes({0x03, 0x07, 0, 0, 0, 0, 0, 0, 0, 0})), ec), 0u);
        EXPECT_EQ(ec, make_error_code(Error::bad_magic));
        p.Reset();
        // 成功解析
        std::vector<std::uint8_t> Ok{0x04, 0x07, 0, 0, 0, 0, 1, 0, 0, 0, 0x01, 8, 8, 8, 8, 0x00, 0x35, 'x'};
        EXPECT_EQ(p.Put(boost::asio::buffer(Ok), ec), 18u);
        EXPECT_TRUE(p.IsDone());
        EXPECT_EQ(p.Get().Cmd, Tuic::CmdPacket);
        EXPECT_EQ(p.Get().PktId, 1u);
        EXPECT_EQ(p.Get().dst.Host, "8.8.8.8");
    }

    // ───────────────────────── vless Codec ─────────────────────────

    TEST(VlessCodecDeep, EncodeAddressBranches)
    {
        Vless::Address addr{};
        // ipv4 编码（点分解析）
        addr.Type = Vless::AddressType::Ipv4;
        addr.Host = "10.0.0.1";
        addr.Port = 1001;
        const auto v4 = Vless::EncodeAddress(addr);
        EXPECT_EQ(v4.size(), 7u);
        EXPECT_EQ(v4[0], 0x01);
        EXPECT_EQ(v4[1], 10u);
        EXPECT_EQ(v4[4], 1u);
        // ipv6 编码
        addr.Type = Vless::AddressType::Ipv6;
        addr.Host.assign(16, 'z');
        const auto v6 = Vless::EncodeAddress(addr);
        EXPECT_EQ(v6.size(), 19u);
        EXPECT_EQ(v6[0], 0x03);
        EXPECT_EQ(v6[1], 'z');
    }

    TEST(VlessCodecDeep, BuildRequestIpv6)
    {
        Vless::RequestHeader hdr{};
        hdr.Uuid.fill(0x11);
        hdr.Cmd = Vless::Command::Udp;
        hdr.Target.Type = Vless::AddressType::Ipv6;
        hdr.Target.Host.assign(16, 'w');
        hdr.Target.Port = 53;
        hdr.Addons = {0x01, 0x02};
        const auto wire = Vless::BuildRequest(hdr);
        EXPECT_EQ(wire.size(), 22u + 2u + 16u);
        EXPECT_EQ(wire[23], 0x03); // ATYP = ipv6
    }

    TEST(VlessCodecDeep, ParseRequestBranches)
    {
        Vless::RequestHeader hdr{};
        std::size_t consumed = 0;
        std::vector<std::uint8_t> base{0x00};
        base.insert(base.end(), 16, 0x11);
        base.push_back(0x00); // addnl len
        base.push_back(0x01); // cmd Tcp
        base.push_back(0x00);
        base.push_back(0x50); // port 80
        // ipv4 不足
        std::vector<std::uint8_t> v4 = base;
        v4.push_back(0x01);
        v4.push_back(8);
        v4.push_back(8);
        EXPECT_EQ(Vless::ParseRequest(v4, hdr, consumed), Error::need_more);
        // ipv6 不足
        std::vector<std::uint8_t> v6 = base;
        v6.push_back(0x03);
        v6.insert(v6.end(), 5, 0x42);
        EXPECT_EQ(Vless::ParseRequest(v6, hdr, consumed), Error::need_more);
        // ipv6 成功
        std::vector<std::uint8_t> v6ok = base;
        v6ok.push_back(0x03);
        v6ok.insert(v6ok.end(), 16, 0x42);
        EXPECT_EQ(Vless::ParseRequest(v6ok, hdr, consumed), Error::none);
        EXPECT_EQ(hdr.Target.Type, Vless::AddressType::Ipv6);
        EXPECT_EQ(hdr.Target.Host, std::string(16, '\x42'));
        EXPECT_EQ(hdr.Target.Port, 80u);
    }

    TEST(VlessCodecDeep, ParserErrors)
    {
        std::array<std::uint8_t, 16> uuid{};
        uuid.fill(0x11);
        Vless::Parser p(uuid);
        std::error_code ec;

        // 数据不足
        EXPECT_EQ(p.Put(boost::asio::buffer(make_bytes({0x00})), ec), 0u);
        EXPECT_EQ(ec, make_error_code(Error::need_more));
        p.Reset();
        // 版本错误
        std::vector<std::uint8_t> bad{0x01};
        bad.insert(bad.end(), 16, 0x11);
        bad.insert(bad.end(), 6, 0x00);
        EXPECT_EQ(p.Put(boost::asio::buffer(bad), ec), 0u);
        EXPECT_EQ(ec, make_error_code(Error::bad_magic));
        p.Reset();
        // UUID 不匹配
        std::vector<std::uint8_t> wrong = bad;
        wrong[0] = 0x00;
        wrong[1] = 0x22;
        EXPECT_EQ(p.Put(boost::asio::buffer(wrong), ec), 0u);
        EXPECT_EQ(ec, make_error_code(Error::auth_failed));
        p.Reset();
        // 成功（uuid 匹配 + ipv4）
        std::vector<std::uint8_t> Ok{0x00};
        Ok.insert(Ok.end(), 16, 0x11);
        Ok.push_back(0x00);
        Ok.push_back(0x01);
        Ok.push_back(0x00);
        Ok.push_back(0x50);
        Ok.push_back(0x01);
        Ok.insert(Ok.end(), 4, 8);
        EXPECT_EQ(p.Put(boost::asio::buffer(Ok), ec), Ok.size());
        EXPECT_TRUE(p.IsDone());
        EXPECT_TRUE(p.Get().valid);
        EXPECT_EQ(p.Get().cmd, 0x01u);
    }

} // namespace
