/**
 * @file Socks5BeastTest.cpp
 * @brief SOCKS5 Beast 风格组件测试
 * @details 覆盖：Parser 增量解析（半包/粘包）、Serializer 输出、
 *          错误处理（版本/命令/地址非法）。
 */

#include <common/Protocols/Socks5/Socks5.hpp>
#include <gtest/gtest.h>

namespace
{
    using namespace Preview;

    /// 构造 Greeting 消息
    auto make_greeting() -> Socks5::Message
    {
        Socks5::Message msg;
        msg.Type = Socks5::Message::Kind::Greeting;
        msg.methods = {Socks5::AuthNone};
        return msg;
    }

    /// 构造 Request 消息
    auto make_request() -> Socks5::Message
    {
        Socks5::Message msg;
        msg.Type = Socks5::Message::Kind::Request;
        msg.Cmd = Socks5::Command::Connect;
        msg.addr.Type = Socks5::AddressType::Ipv4;
        msg.addr.Host = "127.0.0.1";
        msg.addr.Port = 8080;
        return msg;
    }

    TEST(Socks5Beast, SerializerGreeting)
    {
        Socks5::Serializer s;
        s.Reset(make_greeting());
        std::error_code ec;
        std::array<std::uint8_t, 64> out{};
        const auto n = s.Get(net::mutable_buffer(out.data(), out.size()), ec);
        EXPECT_FALSE(ec);
        EXPECT_EQ(n, 3);
        EXPECT_EQ(out[0], 0x05);
        EXPECT_EQ(out[1], 0x01);
        EXPECT_EQ(out[2], 0x00);
        EXPECT_TRUE(s.IsDone());
    }

    TEST(Socks5Beast, SerializerRequest)
    {
        Socks5::Serializer s;
        s.Reset(make_request());
        std::error_code ec;
        std::array<std::uint8_t, 64> out{};
        const auto n = s.Get(net::mutable_buffer(out.data(), out.size()), ec);
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
        // Greeting 一次喂入
        Socks5::Serializer s;
        s.Reset(make_greeting());
        std::array<std::uint8_t, 64> wire{};
        std::error_code ec;
        s.Get(net::mutable_buffer(wire.data(), wire.size()), ec);

        Socks5::Parser p;
        p.Expect(Socks5::Message::Kind::Greeting);
        const auto consumed = p.Put(net::const_buffer(wire.data(), 3), ec);
        EXPECT_FALSE(ec);
        EXPECT_EQ(consumed, 3);
        EXPECT_TRUE(p.IsDone());
        EXPECT_EQ(p.Get().Type, Socks5::Message::Kind::Greeting);
        EXPECT_EQ(p.Get().methods.size(), 1u);
        EXPECT_EQ(p.Get().methods[0], Socks5::AuthNone);
    }

    TEST(Socks5Beast, ParserIncrementalHalfFrame)
    {
        Socks5::Parser p;
        p.Expect(Socks5::Message::Kind::Greeting);
        std::error_code ec;

        // 半包：先喂 2 字节
        std::array<std::uint8_t, 2> part1{0x05, 0x01};
        const auto n1 = p.Put(net::const_buffer(part1.data(), part1.size()), ec);
        EXPECT_FALSE(ec);
        EXPECT_EQ(n1, 0); // 未消费（不足完整帧）
        EXPECT_FALSE(p.IsDone());

        // 补全
        std::array<std::uint8_t, 1> part2{0x00};
        const auto n2 = p.Put(net::const_buffer(part2.data(), part2.size()), ec);
        EXPECT_FALSE(ec);
        EXPECT_EQ(n2, 1);
        EXPECT_TRUE(p.IsDone());
        EXPECT_EQ(p.Get().methods[0], Socks5::AuthNone);
    }

    TEST(Socks5Beast, ParserPipelinedFrames)
    {
        // 粘包：Request + Greeting 同包
        Socks5::Serializer sr;
        sr.Reset(make_request());
        std::array<std::uint8_t, 64> wire{};
        std::error_code ec;
        const auto req_len = sr.Get(net::mutable_buffer(wire.data(), wire.size()), ec);

        Socks5::Parser p;
        p.Expect(Socks5::Message::Kind::Request);
        const auto consumed = p.Put(net::const_buffer(wire.data(), req_len), ec);
        EXPECT_FALSE(ec);
        EXPECT_EQ(consumed, req_len);
        EXPECT_TRUE(p.IsDone());
        EXPECT_EQ(p.Get().Type, Socks5::Message::Kind::Request);
        EXPECT_EQ(p.Get().Cmd, Socks5::Command::Connect);
        EXPECT_EQ(p.Get().addr.Host, "127.0.0.1");
        EXPECT_EQ(p.Get().addr.Port, 8080);
    }

    TEST(Socks5Beast, ParserRejectsBadVersion)
    {
        Socks5::Parser p;
        p.Expect(Socks5::Message::Kind::Greeting);
        std::error_code ec;
        std::array<std::uint8_t, 3> bad{0x04, 0x01, 0x00};
        p.Put(net::const_buffer(bad.data(), bad.size()), ec);
        EXPECT_EQ(ec, Error::version_mismatch);
    }

    TEST(Socks5Beast, ParserRejectsBadCommand)
    {
        Socks5::Parser p;
        p.Expect(Socks5::Message::Kind::Request);
        std::error_code ec;
        // 非法命令 0x09
        std::array<std::uint8_t, 7> bad{0x05, 0x09, 0x00, 0x01, 127, 0, 0};
        p.Put(net::const_buffer(bad.data(), bad.size()), ec);
        EXPECT_EQ(ec, Error::not_supported);
    }

    TEST(Socks5Beast, ParserRejectsBadAddressType)
    {
        Socks5::Parser p;
        p.Expect(Socks5::Message::Kind::Request);
        std::error_code ec;
        std::array<std::uint8_t, 4> bad{0x05, 0x01, 0x00, 0x09};
        p.Put(net::const_buffer(bad.data(), bad.size()), ec);
        EXPECT_EQ(ec, Error::bad_message);
    }

    TEST(Socks5Beast, ParserResetReuse)
    {
        Socks5::Parser p;
        p.Expect(Socks5::Message::Kind::Greeting);
        std::error_code ec;
        std::array<std::uint8_t, 3> g{0x05, 0x01, 0x00};
        p.Put(net::const_buffer(g.data(), g.size()), ec);
        EXPECT_TRUE(p.IsDone());

        p.Reset();
        p.Expect(Socks5::Message::Kind::Greeting);
        p.Put(net::const_buffer(g.data(), g.size()), ec);
        EXPECT_TRUE(p.IsDone());
        EXPECT_EQ(p.Get().methods.size(), 1u);
    }

} // namespace
