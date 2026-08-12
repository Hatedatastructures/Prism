/**
 * @file Socks5BeastTest.cpp
 * @brief SOCKS5 Beast 风格组件测试
 * @details 覆盖：parser 增量解析（半包/粘包）、serializer 输出、
 *          错误处理（版本/命令/地址非法）。
 */

#include <common/proxy/socks5/socks5.hpp>

#include <gtest/gtest.h>

namespace
{
    using namespace psmtest;

    /// 构造 greeting 消息
    auto make_greeting() -> socks5::message
    {
        socks5::message msg;
        msg.type = socks5::message::kind::greeting;
        msg.methods = {socks5::auth_none};
        return msg;
    }

    /// 构造 request 消息
    auto make_request() -> socks5::message
    {
        socks5::message msg;
        msg.type = socks5::message::kind::request;
        msg.cmd = socks5::command::connect;
        msg.addr.type = socks5::address_type::ipv4;
        msg.addr.host = "127.0.0.1";
        msg.addr.port = 8080;
        return msg;
    }

    TEST(Socks5Beast, SerializerGreeting)
    {
        socks5::serializer s;
        s.reset(make_greeting());
        std::error_code ec;
        std::array<std::uint8_t, 64> out{};
        const auto n = s.get(net::mutable_buffer(out.data(), out.size()), ec);
        EXPECT_FALSE(ec);
        EXPECT_EQ(n, 3);
        EXPECT_EQ(out[0], 0x05);
        EXPECT_EQ(out[1], 0x01);
        EXPECT_EQ(out[2], 0x00);
        EXPECT_TRUE(s.is_done());
    }

    TEST(Socks5Beast, SerializerRequest)
    {
        socks5::serializer s;
        s.reset(make_request());
        std::error_code ec;
        std::array<std::uint8_t, 64> out{};
        const auto n = s.get(net::mutable_buffer(out.data(), out.size()), ec);
        EXPECT_FALSE(ec);
        EXPECT_EQ(n, 10);
        // [05 01 00 01 7F 00 00 01 1F 90]
        EXPECT_EQ(out[0], 0x05);
        EXPECT_EQ(out[1], 0x01);
        EXPECT_EQ(out[3], 0x01);
        EXPECT_EQ(out[4], 127);
        EXPECT_EQ(out[8], 0x1F);
        EXPECT_EQ(out[9], 0x90);
    }

    TEST(Socks5Beast, ParserFullFrame)
    {
        // greeting 一次喂入
        socks5::serializer s;
        s.reset(make_greeting());
        std::array<std::uint8_t, 64> wire{};
        std::error_code ec;
        s.get(net::mutable_buffer(wire.data(), wire.size()), ec);

        socks5::parser p;
        p.expect(socks5::message::kind::greeting);
        const auto consumed = p.put(net::const_buffer(wire.data(), 3), ec);
        EXPECT_FALSE(ec);
        EXPECT_EQ(consumed, 3);
        EXPECT_TRUE(p.is_done());
        EXPECT_EQ(p.get().type, socks5::message::kind::greeting);
        EXPECT_EQ(p.get().methods.size(), 1u);
        EXPECT_EQ(p.get().methods[0], socks5::auth_none);
    }

    TEST(Socks5Beast, ParserIncrementalHalfFrame)
    {
        socks5::parser p;
        p.expect(socks5::message::kind::greeting);
        std::error_code ec;

        // 半包：先喂 2 字节
        std::array<std::uint8_t, 2> part1{0x05, 0x01};
        const auto n1 = p.put(net::const_buffer(part1.data(), part1.size()), ec);
        EXPECT_FALSE(ec);
        EXPECT_EQ(n1, 0); // 未消费（不足完整帧）
        EXPECT_FALSE(p.is_done());

        // 补全
        std::array<std::uint8_t, 1> part2{0x00};
        const auto n2 = p.put(net::const_buffer(part2.data(), part2.size()), ec);
        EXPECT_FALSE(ec);
        EXPECT_EQ(n2, 1);
        EXPECT_TRUE(p.is_done());
        EXPECT_EQ(p.get().methods[0], socks5::auth_none);
    }

    TEST(Socks5Beast, ParserPipelinedFrames)
    {
        // 粘包：request + greeting 同包
        socks5::serializer sr;
        sr.reset(make_request());
        std::array<std::uint8_t, 64> wire{};
        std::error_code ec;
        const auto req_len = sr.get(net::mutable_buffer(wire.data(), wire.size()), ec);

        socks5::parser p;
        p.expect(socks5::message::kind::request);
        const auto consumed = p.put(net::const_buffer(wire.data(), req_len), ec);
        EXPECT_FALSE(ec);
        EXPECT_EQ(consumed, req_len);
        EXPECT_TRUE(p.is_done());
        EXPECT_EQ(p.get().type, socks5::message::kind::request);
        EXPECT_EQ(p.get().cmd, socks5::command::connect);
        EXPECT_EQ(p.get().addr.host, "127.0.0.1");
        EXPECT_EQ(p.get().addr.port, 8080);
    }

    TEST(Socks5Beast, ParserRejectsBadVersion)
    {
        socks5::parser p;
        p.expect(socks5::message::kind::greeting);
        std::error_code ec;
        std::array<std::uint8_t, 3> bad{0x04, 0x01, 0x00};
        p.put(net::const_buffer(bad.data(), bad.size()), ec);
        EXPECT_EQ(ec, error::version_mismatch);
    }

    TEST(Socks5Beast, ParserRejectsBadCommand)
    {
        socks5::parser p;
        p.expect(socks5::message::kind::request);
        std::error_code ec;
        // 非法命令 0x09
        std::array<std::uint8_t, 7> bad{0x05, 0x09, 0x00, 0x01, 127, 0, 0};
        p.put(net::const_buffer(bad.data(), bad.size()), ec);
        EXPECT_EQ(ec, error::not_supported);
    }

    TEST(Socks5Beast, ParserRejectsBadAddressType)
    {
        socks5::parser p;
        p.expect(socks5::message::kind::request);
        std::error_code ec;
        std::array<std::uint8_t, 4> bad{0x05, 0x01, 0x00, 0x09};
        p.put(net::const_buffer(bad.data(), bad.size()), ec);
        EXPECT_EQ(ec, error::bad_message);
    }

    TEST(Socks5Beast, ParserResetReuse)
    {
        socks5::parser p;
        p.expect(socks5::message::kind::greeting);
        std::error_code ec;
        std::array<std::uint8_t, 3> g{0x05, 0x01, 0x00};
        p.put(net::const_buffer(g.data(), g.size()), ec);
        EXPECT_TRUE(p.is_done());

        p.reset();
        p.expect(socks5::message::kind::greeting);
        p.put(net::const_buffer(g.data(), g.size()), ec);
        EXPECT_TRUE(p.is_done());
        EXPECT_EQ(p.get().methods.size(), 1u);
    }

} // namespace
