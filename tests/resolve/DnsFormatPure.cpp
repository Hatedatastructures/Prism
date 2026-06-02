/**
 * @file DnsFormatPure.cpp
 * @brief DNS wire format编解码纯函数测试
 * @details 测试 extract_ipv4/extract_ipv6/message::pack/unpack/make_query/
 *          extract_ips/min_ttl/unpack_tcp 公共接口
 */

#include <prism/memory.hpp>
#include <prism/resolve/dns/detail/format.hpp>
#include <prism/trace/spdlog.hpp>


#include <gtest/gtest.h>

namespace
{
    namespace dns = psm::resolve::dns::detail;

    // ─── extract_ipv4 / extract_ipv6 ─────────────

    TEST(DnsFormatPure, ExtractIpv4)
    {
        dns::record rec;
        rec.type = dns::qtype::a;
        rec.rdata = {192, 168, 1, 1};
        auto addr = dns::extract_ipv4(rec);
        EXPECT_TRUE(addr.has_value()) << "extract_ipv4: has value";
        EXPECT_TRUE(addr->to_uint() == (192u << 24 | 168u << 16 | 1u << 8 | 1u)) << "extract_ipv4: 192.168.1.1";
    }

    TEST(DnsFormatPure, ExtractIpv4WrongType)
    {
        dns::record rec;
        rec.type = dns::qtype::aaaa;
        rec.rdata = {192, 168, 1, 1};
        auto addr = dns::extract_ipv4(rec);
        EXPECT_TRUE(!addr.has_value()) << "extract_ipv4: wrong type -> nullopt";
    }

    TEST(DnsFormatPure, ExtractIpv4WrongSize)
    {
        dns::record rec;
        rec.type = dns::qtype::a;
        rec.rdata = {192, 168, 1};
        auto addr = dns::extract_ipv4(rec);
        EXPECT_TRUE(!addr.has_value()) << "extract_ipv4: wrong size -> nullopt";
    }

    TEST(DnsFormatPure, ExtractIpv4EmptyRdata)
    {
        dns::record rec;
        rec.type = dns::qtype::a;
        auto addr = dns::extract_ipv4(rec);
        EXPECT_TRUE(!addr.has_value()) << "extract_ipv4: empty rdata -> nullopt";
    }

    TEST(DnsFormatPure, ExtractIpv6)
    {
        dns::record rec;
        rec.type = dns::qtype::aaaa;
        rec.rdata.resize(16, 0);
        rec.rdata[0] = 0x20;
        rec.rdata[1] = 0x01;
        auto addr = dns::extract_ipv6(rec);
        EXPECT_TRUE(addr.has_value()) << "extract_ipv6: has value";
        EXPECT_TRUE(addr->to_bytes()[0] == 0x20) << "extract_ipv6: first byte=0x20";
        EXPECT_TRUE(addr->to_bytes()[1] == 0x01) << "extract_ipv6: second byte=0x01";
    }

    TEST(DnsFormatPure, ExtractIpv6WrongType)
    {
        dns::record rec;
        rec.type = dns::qtype::a;
        rec.rdata.resize(16, 0);
        auto addr = dns::extract_ipv6(rec);
        EXPECT_TRUE(!addr.has_value()) << "extract_ipv6: wrong type -> nullopt";
    }

    TEST(DnsFormatPure, ExtractIpv6WrongSize)
    {
        dns::record rec;
        rec.type = dns::qtype::aaaa;
        rec.rdata.resize(15, 0);
        auto addr = dns::extract_ipv6(rec);
        EXPECT_TRUE(!addr.has_value()) << "extract_ipv6: wrong size -> nullopt";
    }

    // ─── message::make_query ─────────────────────

    TEST(DnsFormatPure, MakeQuery)
    {
        auto msg = dns::message::make_query("Example.COM.", dns::qtype::a);
        EXPECT_TRUE(msg.questions.size() == 1) << "make_query: 1 question";
        EXPECT_TRUE(msg.questions[0].name == "example.com") << "make_query: lowercased domain";
        EXPECT_TRUE(msg.questions[0].query_type == dns::qtype::a) << "make_query: type=A";
        EXPECT_TRUE(msg.questions[0].qclass == 1) << "make_query: class=IN";
        EXPECT_TRUE(msg.rd) << "make_query: rd=true";
    }

    TEST(DnsFormatPure, MakeQueryAaaa)
    {
        auto msg = dns::message::make_query("test.org", dns::qtype::aaaa);
        EXPECT_TRUE(msg.questions[0].query_type == dns::qtype::aaaa) << "make_query: AAAA type";
    }

    // ─── message::pack / unpack roundtrip ────────

    TEST(DnsFormatPure, PackUnpackRoundtrip)
    {
        auto msg = dns::message::make_query("test.example.com", dns::qtype::a);
        msg.id = 0x1234;
        auto packed = msg.pack();
        EXPECT_TRUE(packed.size() >= 12) << "pack: at least 12 bytes header";

        auto unpacked = dns::message::unpack({packed.data(), packed.size()});
        ASSERT_TRUE(unpacked.has_value()) << "unpack: success";
        EXPECT_TRUE(unpacked->id == 0x1234) << "unpack: id preserved";
        EXPECT_TRUE(unpacked->questions.size() == 1) << "unpack: 1 question";
        EXPECT_TRUE(unpacked->questions[0].name == "test.example.com") << "unpack: domain preserved";
        EXPECT_TRUE(unpacked->questions[0].query_type == dns::qtype::a) << "unpack: type preserved";
    }

    TEST(DnsFormatPure, PackUnpackWithAnswer)
    {
        dns::message msg;
        msg.id = 0xABCD;
        msg.qr = true;
        msg.rd = true;
        msg.ra = true;

        dns::question q;
        q.name = "example.com";
        q.query_type = dns::qtype::a;
        q.qclass = 1;
        msg.questions.push_back(std::move(q));

        dns::record ans;
        ans.name = "example.com";
        ans.type = dns::qtype::a;
        ans.rclass = 1;
        ans.ttl = 300;
        ans.rdata = {93, 184, 216, 34};
        msg.answers.push_back(std::move(ans));

        auto packed = msg.pack();
        auto unpacked = dns::message::unpack({packed.data(), packed.size()});
        EXPECT_TRUE(unpacked.has_value()) << "pack+unpack answer: success";
        EXPECT_TRUE(unpacked->qr) << "pack+unpack answer: qr=true";
        EXPECT_TRUE(unpacked->ra) << "pack+unpack answer: ra=true";
        EXPECT_TRUE(unpacked->answers.size() == 1) << "pack+unpack answer: 1 answer";
        EXPECT_TRUE(unpacked->answers[0].ttl == 300) << "pack+unpack answer: ttl=300";
        EXPECT_TRUE(unpacked->answers[0].rdata.size() == 4) << "pack+unpack answer: rdata size=4";
        EXPECT_TRUE(unpacked->answers[0].rdata[0] == 93) << "pack+unpack answer: rdata[0]=93";
    }

    TEST(DnsFormatPure, PackUnpackFlags)
    {
        dns::message msg;
        msg.id = 0x0001;
        msg.qr = true;
        msg.aa = true;
        msg.tc = true;
        msg.opcode = 0x0F;
        msg.rcode = 0x0E;

        auto packed = msg.pack();
        auto unpacked = dns::message::unpack({packed.data(), packed.size()});
        EXPECT_TRUE(unpacked.has_value()) << "flags: unpack ok";
        EXPECT_TRUE(unpacked->qr) << "flags: qr=true";
        EXPECT_TRUE(unpacked->aa) << "flags: aa=true";
        EXPECT_TRUE(unpacked->tc) << "flags: tc=true";
        EXPECT_TRUE(unpacked->opcode == 0x0F) << "flags: opcode=0x0F";
        EXPECT_TRUE(unpacked->rcode == 0x0E) << "flags: rcode=0x0E";
    }

    TEST(DnsFormatPure, PackUnpackMultipleRecords)
    {
        dns::message msg;
        msg.id = 0x0042;
        msg.qr = true;

        dns::record a1;
        a1.name = "a.com";
        a1.type = dns::qtype::a;
        a1.rclass = 1;
        a1.ttl = 100;
        a1.rdata = {1, 2, 3, 4};
        msg.answers.push_back(std::move(a1));

        dns::record a2;
        a2.name = "b.com";
        a2.type = dns::qtype::a;
        a2.rclass = 1;
        a2.ttl = 200;
        a2.rdata = {5, 6, 7, 8};
        msg.answers.push_back(std::move(a2));

        auto packed = msg.pack();
        auto unpacked = dns::message::unpack({packed.data(), packed.size()});
        EXPECT_TRUE(unpacked.has_value()) << "multi: unpack ok";
        EXPECT_TRUE(unpacked->answers.size() == 2) << "multi: 2 answers";
        EXPECT_TRUE(unpacked->answers[0].rdata[0] == 1) << "multi: ans[0] rdata[0]=1";
        EXPECT_TRUE(unpacked->answers[1].rdata[0] == 5) << "multi: ans[1] rdata[0]=5";
    }

    // ─── message::extract_ips ────────────────────

    TEST(DnsFormatPure, ExtractIps)
    {
        dns::message msg;
        msg.qr = true;

        dns::record ans;
        ans.name = "example.com";
        ans.type = dns::qtype::a;
        ans.rclass = 1;
        ans.ttl = 60;
        ans.rdata = {1, 2, 3, 4};
        msg.answers.push_back(std::move(ans));

        auto ips = msg.extract_ips();
        EXPECT_TRUE(ips.size() == 1) << "extract_ips: 1 IP";
    }

    TEST(DnsFormatPure, ExtractIpsEmpty)
    {
        dns::message msg;
        auto ips = msg.extract_ips();
        EXPECT_TRUE(ips.empty()) << "extract_ips: empty -> no IPs";
    }

    TEST(DnsFormatPure, ExtractIpsFromAuthority)
    {
        dns::message msg;
        msg.qr = true;

        dns::record auth;
        auth.name = "ns.example.com";
        auth.type = dns::qtype::a;
        auth.rclass = 1;
        auth.ttl = 3600;
        auth.rdata = {10, 0, 0, 1};
        msg.authority.push_back(std::move(auth));

        auto ips = msg.extract_ips();
        EXPECT_TRUE(ips.size() == 1) << "extract_ips: authority IP found";
    }

    TEST(DnsFormatPure, ExtractIpsSkipsNonIp)
    {
        dns::message msg;
        msg.qr = true;

        dns::record ns_rec;
        ns_rec.name = "example.com";
        ns_rec.type = dns::qtype::ns;
        ns_rec.rclass = 1;
        ns_rec.ttl = 300;
        ns_rec.rdata = {3, 'n', 's', '1'};
        msg.answers.push_back(std::move(ns_rec));

        auto ips = msg.extract_ips();
        EXPECT_TRUE(ips.empty()) << "extract_ips: NS record skipped";
    }

    // ─── message::min_ttl ────────────────────────

    TEST(DnsFormatPure, MinTtlBasic)
    {
        dns::message msg;

        dns::record r1;
        r1.name = "a.com";
        r1.type = dns::qtype::a;
        r1.ttl = 300;
        r1.rdata = {1, 1, 1, 1};
        msg.answers.push_back(std::move(r1));

        dns::record r2;
        r2.name = "b.com";
        r2.type = dns::qtype::a;
        r2.ttl = 60;
        r2.rdata = {2, 2, 2, 2};
        msg.answers.push_back(std::move(r2));

        EXPECT_TRUE(msg.min_ttl() == 60) << "min_ttl: 60";
    }

    TEST(DnsFormatPure, MinTtlNoRecords)
    {
        dns::message msg;
        EXPECT_TRUE(msg.min_ttl() == 0) << "min_ttl: no records -> 0";
    }

    TEST(DnsFormatPure, MinTtlAuthority)
    {
        dns::message msg;
        dns::record auth;
        auth.name = "ns.com";
        auth.type = dns::qtype::ns;
        auth.ttl = 10;
        msg.authority.push_back(std::move(auth));

        EXPECT_TRUE(msg.min_ttl() == 10) << "min_ttl: authority considered";
    }

    // ─── unpack_tcp ──────────────────────────────

    TEST(DnsFormatPure, UnpackTcpTooShort)
    {
        std::uint8_t data[] = {0x00};
        auto result = dns::unpack_tcp({data, 1});
        EXPECT_TRUE(!result.has_value()) << "unpack_tcp: too short -> nullopt";
    }

    TEST(DnsFormatPure, UnpackTcpTruncated)
    {
        std::uint8_t data[] = {0x00, 0x10};
        auto result = dns::unpack_tcp({data, 2});
        EXPECT_TRUE(!result.has_value()) << "unpack_tcp: truncated -> nullopt";
    }

    TEST(DnsFormatPure, UnpackTcpValid)
    {
        auto msg = dns::message::make_query("test.com", dns::qtype::a);
        msg.id = 0x5678;
        auto packed = msg.pack();

        psm::memory::vector<std::uint8_t> tcp_data;
        auto len = static_cast<std::uint16_t>(packed.size());
        tcp_data.push_back(static_cast<std::uint8_t>((len >> 8) & 0xFF));
        tcp_data.push_back(static_cast<std::uint8_t>(len & 0xFF));
        tcp_data.insert(tcp_data.end(), packed.begin(), packed.end());

        auto result = dns::unpack_tcp({tcp_data.data(), tcp_data.size()});
        EXPECT_TRUE(result.has_value()) << "unpack_tcp: success";
        EXPECT_TRUE(result->id == 0x5678) << "unpack_tcp: id preserved";
    }

    // ─── unpack error paths ──────────────────────

    TEST(DnsFormatPure, UnpackTooShort)
    {
        std::uint8_t data[] = {0x00, 0x01, 0x02};
        auto result = dns::message::unpack({data, 3});
        EXPECT_TRUE(!result.has_value()) << "unpack: < 12 bytes -> nullopt";
    }

    TEST(DnsFormatPure, PackUnpackDomainCompression)
    {
        dns::message msg;
        msg.id = 0x0001;

        dns::question q;
        q.name = "example.com";
        q.query_type = dns::qtype::a;
        q.qclass = 1;
        msg.questions.push_back(std::move(q));

        dns::record ans;
        ans.name = "example.com";
        ans.type = dns::qtype::a;
        ans.rclass = 1;
        ans.ttl = 60;
        ans.rdata = {1, 2, 3, 4};
        msg.answers.push_back(std::move(ans));

        auto packed = msg.pack();
        auto unpacked = dns::message::unpack({packed.data(), packed.size()});
        EXPECT_TRUE(unpacked.has_value()) << "compression: unpack ok";
        EXPECT_TRUE(unpacked->answers[0].name == "example.com") << "compression: answer name preserved";
    }

} // namespace
