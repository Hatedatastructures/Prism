/**
 * @file SingmuxRequest.cpp
 * @brief sing-mux StreamRequest 解析测试
 * @details 验证二进制 StreamRequest 解析：flags、地址类型、端口。
 */

#include <prism/protocol/multiplex/h2mux/singmux.hpp>

#include <gtest/gtest.h>

namespace
{
    using psm::multiplex::h2mux::parse_sing_request;

    auto bytes_of(const std::initializer_list<std::uint8_t> list) -> std::vector<std::byte>
    {
        std::vector<std::byte> out;
        for (const auto b : list)
            out.push_back(static_cast<std::byte>(b));
        return out;
    }
}

TEST(SingmuxRequest, TcpDomain)
{
    // flags=0 (TCP)，addrType=0x03 域名 "example.com"，port 443
    auto data = bytes_of({0x00, 0x00, 0x03, 11});
    const std::string domain = "example.com";
    for (const auto c : domain)
        data.push_back(static_cast<std::byte>(c));
    data.push_back(std::byte{0x01});
    data.push_back(std::byte{0xBB});

    const auto req = parse_sing_request(data);
    ASSERT_TRUE(req.has_value());
    EXPECT_FALSE(req->udp);
    EXPECT_FALSE(req->packet_addr);
    EXPECT_EQ(req->host, "example.com");
    EXPECT_EQ(req->port, 443);
    EXPECT_EQ(req->consumed, data.size());
}

TEST(SingmuxRequest, UdpIpv4)
{
    // flags=0x0001 (UDP)，addrType=0x01 IPv4，port 53
    auto data = bytes_of({0x00, 0x01, 0x01, 8, 8, 8, 8, 0x00, 0x35});

    const auto req = parse_sing_request(data);
    ASSERT_TRUE(req.has_value());
    EXPECT_TRUE(req->udp);
    EXPECT_FALSE(req->packet_addr);
    EXPECT_EQ(req->host, "8.8.8.8");
    EXPECT_EQ(req->port, 53);
    EXPECT_EQ(req->consumed, 9);
}

TEST(SingmuxRequest, UdpPacketAddrDomain)
{
    // flags=0x0003 (UDP + PacketAddr)，无目标地址（仅端口字段缺失时也成立：
    // PacketAddr 模式下客户端可省略地址，仍保留 flags + atyp）
    auto data = bytes_of({0x00, 0x03, 0x03, 7});
    const std::string domain = "dns.com";
    for (const auto c : domain)
        data.push_back(static_cast<std::byte>(c));
    data.push_back(std::byte{0x01});
    data.push_back(std::byte{0x35});

    const auto req = parse_sing_request(data);
    ASSERT_TRUE(req.has_value());
    EXPECT_TRUE(req->udp);
    EXPECT_TRUE(req->packet_addr);
    EXPECT_EQ(req->host, "dns.com");
    EXPECT_EQ(req->port, 309);
}

TEST(SingmuxRequest, Ipv6Address)
{
    // flags=0，addrType=0x04 IPv6（16 字节），port 8080
    auto data = bytes_of({0x00, 0x00, 0x04});
    for (int i = 0; i < 16; ++i)
        data.push_back(static_cast<std::byte>(i));
    data.push_back(std::byte{0x1F});
    data.push_back(std::byte{0x90});

    const auto req = parse_sing_request(data);
    ASSERT_TRUE(req.has_value());
    EXPECT_FALSE(req->udp);
    EXPECT_EQ(req->port, 8080);
    // IPv6 字符串化后长度 > 0
    EXPECT_FALSE(req->host.empty());
    EXPECT_EQ(req->consumed, 21);
}

TEST(SingmuxRequest, TruncatedReturnsNullopt)
{
    // 只有 flags 2 字节：不足
    auto data = bytes_of({0x00, 0x00});
    EXPECT_FALSE(parse_sing_request(data).has_value());

    // flags + atyp 但缺端口
    auto data2 = bytes_of({0x00, 0x00, 0x01, 1, 2, 3});
    EXPECT_FALSE(parse_sing_request(data2).has_value());
}

TEST(SingmuxRequest, InvalidAddrTypeFails)
{
    // atyp=0x02 非法（sing 编码无 0x02）
    auto data = bytes_of({0x00, 0x00, 0x02, 1, 2, 3, 4});
    const auto req = parse_sing_request(data);
    ASSERT_TRUE(req.has_value());
    EXPECT_EQ(req->consumed, 0);
}

TEST(SingmuxRequest, TrailingDataConsumed)
{
    // StreamRequest 后跟用户数据：consumed 应等于请求长度
    auto data = bytes_of({0x00, 0x00, 0x01, 127, 0, 0, 1, 0x01, 0xBB});
    data.push_back(std::byte{0xDE});
    data.push_back(std::byte{0xAD});

    const auto req = parse_sing_request(data);
    ASSERT_TRUE(req.has_value());
    EXPECT_EQ(req->host, "127.0.0.1");
    EXPECT_EQ(req->port, 443);
    EXPECT_EQ(req->consumed, 9);
}
