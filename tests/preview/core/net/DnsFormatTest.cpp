/**
 * @file DnsFormatTest.cpp
 * @brief DNS wire format 编解码层测试
 * @details 覆盖：查询/响应报文 Pack-Unpack 往返、域名压缩指针、
 *          压缩指针循环防护、截断输入拒绝、TCP 帧封装、
 *          NormalizeName 规范化、MinTtl 与 ExtractIps 过滤语义
 */

#include <common/Core/Net/Dns/Format.hpp>

#include <gtest/gtest.h>

namespace
{
    namespace net = boost::asio;
    using namespace Preview;
    using Preview::Network::Dns::Message;
    using Preview::Network::Dns::QType;
    using Preview::Network::Dns::Question;
    using Preview::Network::Dns::Record;

    /// 构造 A 记录 RDATA（4 字节大端 IPv4）
    auto MakeV4Rdata(std::uint8_t a, std::uint8_t b, std::uint8_t c, std::uint8_t d)
        -> std::vector<std::uint8_t>
    {
        return {a, b, c, d};
    }

    /// 构造 AAAA 记录 RDATA（16 字节，前缀 2001:db8:: 风格填充）
    auto MakeV6Rdata() -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> out(16);
        out[0] = 0x20;
        out[1] = 0x01;
        return out;
    }
} // namespace

TEST(DnsFormat, TestQueryPackUnpackRoundtrip)
{
    const auto query = Message::MakeQuery("WWW.Example.COM.", QType::A);
    EXPECT_TRUE(query.Rd);
    // 规范化：小写、去末尾点号
    EXPECT_EQ(query.Questions.size(), 1u);
    EXPECT_EQ(query.Questions[0].Name, "www.example.com");
    EXPECT_EQ(query.Questions[0].QueryType, QType::A);

    const auto bytes = query.Pack();
    EXPECT_GE(bytes.size(), 17u); // 12 头部 + 至少 1 个问题段

    const auto parsed = Message::Unpack(bytes);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->Id, query.Id);
    EXPECT_FALSE(parsed->Qr);
    EXPECT_TRUE(parsed->Rd);
    ASSERT_EQ(parsed->Questions.size(), 1u);
    EXPECT_EQ(parsed->Questions[0].Name, "www.example.com");
    EXPECT_EQ(parsed->Questions[0].QueryType, QType::A);
    EXPECT_EQ(parsed->Questions[0].QClass, 1u);
}

TEST(DnsFormat, TestResponseRoundtripAndExtractIps)
{
    Message resp;
    resp.Id = 0x1234;
    resp.Qr = true;
    resp.Ra = true;
    resp.Rcode = 0;
    resp.Questions.push_back({"example.com", QType::A, 1});

    Record aRec;
    aRec.Name = "example.com";
    aRec.Type = QType::A;
    aRec.Ttl = 300;
    aRec.Rdata = MakeV4Rdata(1, 2, 3, 4);
    resp.Answers.push_back(aRec);

    Record aaaaRec;
    aaaaRec.Name = "example.com";
    aaaaRec.Type = QType::Aaaa;
    aaaaRec.Ttl = 120;
    aaaaRec.Rdata = MakeV6Rdata();
    resp.Answers.push_back(aaaaRec);

    const auto parsed = Message::Unpack(resp.Pack());
    ASSERT_TRUE(parsed.has_value());
    EXPECT_TRUE(parsed->Qr);
    EXPECT_TRUE(parsed->Ra);
    ASSERT_EQ(parsed->Answers.size(), 2u);
    EXPECT_EQ(parsed->Answers[0].Ttl, 300u);
    EXPECT_EQ(parsed->Answers[1].Ttl, 120u);

    const auto ips = parsed->ExtractIps();
    ASSERT_EQ(ips.size(), 2u);
    EXPECT_EQ(ips[0], net::ip::make_address_v4("1.2.3.4"));
    EXPECT_TRUE(ips[1].is_v6());
    // 最小 TTL 跨三段记录取最小值
    EXPECT_EQ(parsed->MinTtl(), 120u);
}

TEST(DnsFormat, TestNameCompression)
{
    // 同名双应答：第二条 Name 应编码为 2 字节压缩指针
    Message withDup;
    withDup.Questions.push_back({"www.example.com", QType::A, 1});
    for (int i = 0; i < 2; ++i)
    {
        Record rec;
        rec.Name = "www.example.com";
        rec.Type = QType::A;
        rec.Ttl = 60;
        rec.Rdata = MakeV4Rdata(10, 0, 0, static_cast<std::uint8_t>(i + 1));
        withDup.Answers.push_back(rec);
    }

    // 同长度不同名双应答作为无压缩基线
    Message noDup;
    noDup.Questions.push_back({"www.example.com", QType::A, 1});
    const char *names[] = {"www.example.com", "www.example.org"};
    for (const auto *n : names)
    {
        Record rec;
        rec.Name = n;
        rec.Type = QType::A;
        rec.Ttl = 60;
        rec.Rdata = MakeV4Rdata(10, 0, 0, 9);
        noDup.Answers.push_back(rec);
    }

    const auto dupBytes = withDup.Pack();
    const auto baseBytes = noDup.Pack();
    // "www.example.com" 完整编码 17 字节，压缩指针仅 2 字节 → 省 15 字节
    EXPECT_EQ(baseBytes.size() - dupBytes.size(), 15u);

    // 压缩报文必须能正确往返（指针解码还原完整名字）
    const auto parsed = Message::Unpack(dupBytes);
    ASSERT_TRUE(parsed.has_value());
    ASSERT_EQ(parsed->Answers.size(), 2u);
    EXPECT_EQ(parsed->Answers[0].Name, "www.example.com");
    EXPECT_EQ(parsed->Answers[1].Name, "www.example.com");
    EXPECT_EQ(parsed->Answers[1].Rdata, MakeV4Rdata(10, 0, 0, 2));
}

TEST(DnsFormat, TestCompressionPointerLoopGuard)
{
    // 自指指针：offset 0xC00C 指向自身位置 → 必须在跳转上限内失败而非死循环
    std::vector<std::uint8_t> evil(12, 0);
    evil[4] = 0;
    evil[5] = 1; // qdcount=1
    evil.push_back(0xC0);
    evil.push_back(0x0C); // 指针指向自己所在的 offset 12
    evil.push_back(0x00);
    evil.push_back(0x01);
    evil.push_back(0x00);
    evil.push_back(0x01);

    const auto parsed = Message::Unpack(evil);
    EXPECT_FALSE(parsed.has_value());
}

TEST(DnsFormat, TestTruncatedInputRejected)
{
    const auto query = Message::MakeQuery("a.b", QType::A);
    auto bytes = query.Pack();

    // 短于头部
    EXPECT_FALSE(Message::Unpack(std::span<const std::uint8_t>(bytes.data(), 11)).has_value());
    // 头部声明的问题段被截断
    bytes.resize(14);
    EXPECT_FALSE(Message::Unpack(bytes).has_value());
    // 空输入
    EXPECT_FALSE(Message::Unpack({}).has_value());
}

TEST(DnsFormat, TestTcpFrameRoundtrip)
{
    const auto query = Message::MakeQuery("tcp.example.com", QType::Aaaa);
    const auto framed = Preview::Network::Dns::PackTcp(query);

    // 前缀长度与实际一致
    const auto Len = static_cast<std::size_t>((framed[0] << 8) | framed[1]);
    EXPECT_EQ(framed.size(), Len + 2);

    const auto parsed = Preview::Network::Dns::UnpackTcp(framed);
    ASSERT_TRUE(parsed.has_value());
    ASSERT_EQ(parsed->Questions.size(), 1u);
    EXPECT_EQ(parsed->Questions[0].Name, "tcp.example.com");
    EXPECT_EQ(parsed->Questions[0].QueryType, QType::Aaaa);

    // 长度前缀声明超出实际 → 拒绝
    auto bad = framed;
    bad[1] = 0xFF;
    EXPECT_FALSE(Preview::Network::Dns::UnpackTcp(bad).has_value());
    // 不足 2 字节
    EXPECT_FALSE(Preview::Network::Dns::UnpackTcp(std::span<const std::uint8_t>(framed.data(), 1))
                     .has_value());
}

TEST(DnsFormat, TestMinTtlSpansAllSections)
{
    Message m;
    Record ans;
    ans.Name = "x.com";
    ans.Type = QType::A;
    ans.Ttl = 500;
    ans.Rdata = MakeV4Rdata(1, 1, 1, 1);
    m.Answers.push_back(ans);

    Record auth;
    auth.Name = "x.com";
    auth.Type = QType::Ns;
    auth.Ttl = 42;
    auth.Rdata = {3, 'n', 's', 2, 'c', 'o', 'm', 0};
    m.Authority.push_back(auth);

    EXPECT_EQ(m.MinTtl(), 42u);
    // Ns 记录不参与 IP 提取
    EXPECT_TRUE(m.ExtractIps().size() == 1);
}

TEST(DnsFormat, TestExtractIpsSkipsMalformed)
{
    Message m;
    Record badLen;
    badLen.Name = "y.com";
    badLen.Type = QType::A;
    badLen.Ttl = 60;
    badLen.Rdata = {1, 2, 3}; // A 记录 RDATA 必须 4 字节
    m.Answers.push_back(badLen);

    Record cname;
    cname.Name = "y.com";
    cname.Type = QType::Cname;
    cname.Ttl = 60;
    cname.Rdata = {1, 'z', 0};
    m.Answers.push_back(cname);

    Record ok;
    ok.Name = "y.com";
    ok.Type = QType::A;
    ok.Ttl = 60;
    ok.Rdata = MakeV4Rdata(9, 9, 9, 9);
    m.Answers.push_back(ok);

    const auto ips = m.ExtractIps();
    ASSERT_EQ(ips.size(), 1u);
    EXPECT_EQ(ips[0], net::ip::make_address_v4("9.9.9.9"));
}
