/**
 * @file DnsAnswerTest.cpp
 * @brief DNS 应答热路径扫描器（AnswerScan）测试
 * @details 覆盖：手写 golden wire 字节（A/AAAA/压缩指针/三段 TTL）、
 *          NXDOMAIN 与 TC 标志上浮、非匹配类型与非法 rdata 跳过、
 *          截断/畸形输入拒绝（含压缩指针循环）、与 Message::Unpack 语义对齐
 * @note 全部离线字节操作，无网络
 */

#include <preview/Net/Dns/Answer.hpp>
#include <preview/Net/Dns/Format.hpp>

#include <boost/asio/ip/address.hpp>

#include <cstdint>
#include <span>
#include <vector>

#include <gtest/gtest.h>

namespace
{
    namespace net = boost::asio;
    using Preview::Network::Dns::AnswerSet;
    using Preview::Network::Dns::Message;
    using Preview::Network::Dns::QType;
    using Preview::Network::Dns::ScanAnswers;

    void PutU16(std::vector<std::uint8_t> &out, const std::uint16_t v)
    {
        out.push_back(static_cast<std::uint8_t>(v >> 8));
        out.push_back(static_cast<std::uint8_t>(v & 0xFF));
    }

    void PutU32(std::vector<std::uint8_t> &out, const std::uint32_t v)
    {
        out.push_back(static_cast<std::uint8_t>(v >> 24));
        out.push_back(static_cast<std::uint8_t>((v >> 16) & 0xFF));
        out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
        out.push_back(static_cast<std::uint8_t>(v & 0xFF));
    }

    /// 追加 "www.example.com" 的标签编码（16 字节，末尾不含根零）
    void PutQuestionName(std::vector<std::uint8_t> &out)
    {
        out.push_back(3);
        out.insert(out.end(), {'w', 'w', 'w'});
        out.push_back(7);
        out.insert(out.end(), {'e', 'x', 'a', 'm', 'p', 'l', 'e'});
        out.push_back(3);
        out.insert(out.end(), {'c', 'o', 'm'});
    }

    /// 构造 golden 应答：Id=0x1234，问题段 www.example.com/A，
    /// Answer 段以压缩指针回指问题名，rdata 1.2.3.4，TTL=60
    auto MakeGoldenAnswer(const std::uint8_t rcode = 0, const bool truncated = false,
                          const std::uint16_t anCount = 1) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> out;
        PutU16(out, 0x1234);                                    // id
        PutU16(out, 0x8180u | (rcode ? rcode : 0u) |
                        (truncated ? 0x0200u : 0u));            // QR|RD|RA|TC|rcode
        PutU16(out, 1);                                         // qdcount
        PutU16(out, anCount);                                   // ancount
        PutU16(out, 0);                                         // nscount
        PutU16(out, 0);                                         // arcount
        PutQuestionName(out);
        out.push_back(0);                                       // 根零
        PutU16(out, 1);                                         // qtype A
        PutU16(out, 1);                                         // qclass IN
        for (std::uint16_t i = 0; i < anCount; ++i)
        {
            PutU16(out, 0xC00Cu);                               // 压缩指针 → 问题名（偏移 12）
            PutU16(out, 1);                                     // type A
            PutU16(out, 1);                                     // class IN
            PutU32(out, 60);                                    // ttl
            PutU16(out, 4);                                     // rdlength
            out.insert(out.end(), {1, 2, 3, 4});                // 1.2.3.4
        }
        return out;
    }
} // namespace

TEST(DnsAnswer, TestGoldenWireNormalAnswer)
{
    const auto Wire = MakeGoldenAnswer();
    const auto Scan = ScanAnswers(Wire, 1);
    ASSERT_TRUE(Scan.has_value());
    EXPECT_EQ(Scan->Id, 0x1234u);
    EXPECT_FALSE(Scan->Truncated);
    EXPECT_EQ(Scan->Rcode, 0u);
    ASSERT_EQ(Scan->Ips.size(), 1u);
    EXPECT_EQ(Scan->Ips[0], net::ip::make_address_v4("1.2.3.4"));
    EXPECT_EQ(Scan->MinTtl, 60u);
}

TEST(DnsAnswer, TestGoldenWireNxDomain)
{
    const auto Wire = MakeGoldenAnswer(3, false, 0);
    const auto Scan = ScanAnswers(Wire, 1);
    ASSERT_TRUE(Scan.has_value());
    EXPECT_EQ(Scan->Rcode, 3u);
    EXPECT_TRUE(Scan->Ips.empty());
}

TEST(DnsAnswer, TestTruncatedFlagRaised)
{
    const auto Wire = MakeGoldenAnswer(0, true, 0);
    const auto Scan = ScanAnswers(Wire, 1);
    ASSERT_TRUE(Scan.has_value());
    EXPECT_TRUE(Scan->Truncated);
}

TEST(DnsAnswer, TestQtypeFilterCollectsMatchingOnly)
{
    // Answer 段两条记录：CNAME（压缩指针名 + target "a.example.com"）+ A
    std::vector<std::uint8_t> wire = MakeGoldenAnswer();
    // 追加一条 CNAME 记录（rdata 指针指向自身 question 名，len 2）
    PutU16(wire, 0xC00Cu);
    PutU16(wire, 5);  // type CNAME
    PutU16(wire, 1);
    PutU32(wire, 30);
    PutU16(wire, 2);
    PutU16(wire, 0xC00Cu);
    // 修正 ancount: 1 → 2
    wire[7] = 2;

    const auto ScanA = ScanAnswers(wire, 1);
    ASSERT_TRUE(ScanA.has_value());
    ASSERT_EQ(ScanA->Ips.size(), 1u); // 仅 A 记录
    EXPECT_EQ(ScanA->MinTtl, 30u);    // CNAME 的 TTL=30 参与最小值

    // qtype=CNAME：A 不收集（Scan 仅按传入 qtype 收集）
    const auto ScanCname = ScanAnswers(wire, 5);
    ASSERT_TRUE(ScanCname.has_value());
    EXPECT_TRUE(ScanCname->Ips.empty());
}

TEST(DnsAnswer, TestMinTtlSpansAllSections)
{
    // Answer TTL=120、Authority TTL=30（NS, rdlen 0）、Additional TTL=300（A, rdlen 0）
    // → 三段最小 30
    auto wire = MakeGoldenAnswer();
    wire[39] = 0;
    wire[40] = 0;
    wire[41] = 0;
    wire[42] = 120; // answer 记录的 TTL 60 → 120

    auto AppendRecord = [&](std::uint16_t type, std::uint32_t ttl) {
        PutU16(wire, 0xC00Cu);
        PutU16(wire, type);
        PutU16(wire, 1);
        PutU32(wire, ttl);
        PutU16(wire, 0); // rdlength 0
    };
    AppendRecord(2, 30);  // NS in authority
    AppendRecord(1, 300); // A in additional（rdlength 0 → 不收集地址）
    wire[8] = 0;
    wire[9] = 1;  // nscount=1
    wire[10] = 0;
    wire[11] = 1; // arcount=1

    const auto Scan = ScanAnswers(wire, 1);
    ASSERT_TRUE(Scan.has_value());
    EXPECT_EQ(Scan->MinTtl, 30u);
}

TEST(DnsAnswer, TestWrongRdataLengthSkipped)
{
    // A 记录 rdlength=3（≠4）→ 与 ExtractIps 语义一致：跳过不收集
    auto wire = MakeGoldenAnswer();
    wire[43] = 0;
    wire[44] = 3; // rdlength 4 → 3（多出的尾字节被忽略）
    const auto Scan = ScanAnswers(wire, 1);
    ASSERT_TRUE(Scan.has_value());
    EXPECT_TRUE(Scan->Ips.empty());
}

TEST(DnsAnswer, TestTruncatedInputRejected)
{
    // <12 字节
    const std::vector<std::uint8_t> tiny{1, 2, 3};
    EXPECT_FALSE(ScanAnswers(tiny, 1).has_value());
    // 头部声明 1 个问题但无数据
    const std::vector<std::uint8_t> headerOnly = {0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0};
    EXPECT_FALSE(ScanAnswers(headerOnly, 1).has_value());
    // 记录声明 rdlength 超出报文
    auto wire = MakeGoldenAnswer();
    wire[43] = 0xFF;
    wire[44] = 0xFF;
    EXPECT_FALSE(ScanAnswers(wire, 1).has_value());
}

TEST(DnsAnswer, TestCompressionPointerLoopGuard)
{
    // 问题段名字自指（0xC00C 指向自身）→ 指针循环必须拒绝
    std::vector<std::uint8_t> wire;
    PutU16(wire, 0x1234);
    PutU16(wire, 0x8180);
    PutU16(wire, 1);
    PutU16(wire, 0);
    PutU16(wire, 0);
    PutU16(wire, 0);
    PutU16(wire, 0xC00C); // 指向自身偏移 12
    PutU16(wire, 1);
    PutU16(wire, 1);
    EXPECT_FALSE(ScanAnswers(wire, 1).has_value());
}

TEST(DnsAnswer, TestAaaaGoldenWire)
{
    // AAAA 记录：rdata 16 字节 2001:db8::1
    std::vector<std::uint8_t> wire;
    PutU16(wire, 0x0102);
    PutU16(wire, 0x8180);
    PutU16(wire, 0); // qdcount 0
    PutU16(wire, 1);
    PutU16(wire, 0);
    PutU16(wire, 0);
    wire.push_back(0);       // 根名
    PutU16(wire, 28);        // type AAAA
    PutU16(wire, 1);
    PutU32(wire, 3600);
    PutU16(wire, 16);
    // 2001:db8::1 的 16 字节 rdata
    for (const auto b : {0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01})
    {
        wire.push_back(static_cast<std::uint8_t>(b));
    }

    const auto Scan = ScanAnswers(wire, 28);
    ASSERT_TRUE(Scan.has_value());
    ASSERT_EQ(Scan->Ips.size(), 1u);
    EXPECT_EQ(Scan->Ips[0], net::ip::make_address_v6("2001:db8::1"));
    EXPECT_EQ(Scan->MinTtl, 3600u);
}

TEST(DnsAnswer, TestOptRecordExcludedFromMinTtl)
{
    // Additional 段 OPT（type 41）：TTL 字段实为扩展标志位（RFC 6891），
    // 不得污染最小 TTL；IP 收集不受影响
    std::vector<std::uint8_t> wire = MakeGoldenAnswer();
    PutU16(wire, 0);          // 根名
    PutU16(wire, 41);         // type OPT
    PutU16(wire, 4096);       // class = UDP payload size
    PutU32(wire, 0x00008000); // 扩展标志（DO 位）
    PutU16(wire, 0);          // rdlength
    wire[10] = 0;
    wire[11] = 1;             // arcount=1

    const auto Scan = ScanAnswers(wire, 1);
    ASSERT_TRUE(Scan.has_value());
    EXPECT_EQ(Scan->MinTtl, 60u); // 不被 OPT 的标志位拉成 0/32768
    ASSERT_EQ(Scan->Ips.size(), 1u);
}

TEST(DnsAnswer, TestAgreesWithMessageUnpack)
{
    // 与完整物化路径语义对齐：同一应答，ScanAnswers 与 Unpack+ExtractIps 一致
    Message m = Message::MakeQuery("www.example.com", QType::A);
    m.Id = 0x1234;
    m.Rd = true;
    m.Qr = true;
    m.Ra = true;
    Preview::Network::Dns::Record a;
    a.Name = "www.example.com";
    a.Type = QType::A;
    a.Ttl = 42;
    a.Rdata = {9, 8, 7, 6};
    m.Answers.push_back(a);
    const auto Wire = m.Pack();

    const auto Scan = ScanAnswers(Wire, 1);
    const auto Unpacked = Message::Unpack(Wire);
    ASSERT_TRUE(Scan.has_value());
    ASSERT_TRUE(Unpacked.has_value());
    EXPECT_EQ(Scan->Id, Unpacked->Id);
    EXPECT_EQ(Scan->MinTtl, Unpacked->MinTtl());
    const auto Ips = Unpacked->ExtractIps();
    ASSERT_EQ(Scan->Ips.size(), Ips.size());
    EXPECT_EQ(Scan->Ips[0], Ips[0]);
}
