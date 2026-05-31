/**
 * @file DnsFormatPure.cpp
 * @brief DNS wire format编解码纯函数测试
 * @details 测试 extract_ipv4/extract_ipv6/message::pack/unpack/make_query/
 *          extract_ips/min_ttl/unpack_tcp 公共接口
 */

#include <prism/memory.hpp>
#include <prism/resolve/dns/detail/format.hpp>
#include <prism/trace/spdlog.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

using psm::testing::TestRunner;

namespace
{
    namespace dns = psm::resolve::dns::detail;

    // ─── extract_ipv4 / extract_ipv6 ─────────────

    void TestExtractIpv4(TestRunner &runner)
    {
        dns::record rec;
        rec.type = dns::qtype::a;
        rec.rdata = {192, 168, 1, 1};
        auto addr = dns::extract_ipv4(rec);
        runner.Check(addr.has_value(), "extract_ipv4: has value");
        runner.Check(addr->to_uint() == (192u << 24 | 168u << 16 | 1u << 8 | 1u), "extract_ipv4: 192.168.1.1");
    }

    void TestExtractIpv4WrongType(TestRunner &runner)
    {
        dns::record rec;
        rec.type = dns::qtype::aaaa;
        rec.rdata = {192, 168, 1, 1};
        auto addr = dns::extract_ipv4(rec);
        runner.Check(!addr.has_value(), "extract_ipv4: wrong type -> nullopt");
    }

    void TestExtractIpv4WrongSize(TestRunner &runner)
    {
        dns::record rec;
        rec.type = dns::qtype::a;
        rec.rdata = {192, 168, 1};
        auto addr = dns::extract_ipv4(rec);
        runner.Check(!addr.has_value(), "extract_ipv4: wrong size -> nullopt");
    }

    void TestExtractIpv4EmptyRdata(TestRunner &runner)
    {
        dns::record rec;
        rec.type = dns::qtype::a;
        auto addr = dns::extract_ipv4(rec);
        runner.Check(!addr.has_value(), "extract_ipv4: empty rdata -> nullopt");
    }

    void TestExtractIpv6(TestRunner &runner)
    {
        dns::record rec;
        rec.type = dns::qtype::aaaa;
        rec.rdata.resize(16, 0);
        rec.rdata[0] = 0x20;
        rec.rdata[1] = 0x01;
        auto addr = dns::extract_ipv6(rec);
        runner.Check(addr.has_value(), "extract_ipv6: has value");
        runner.Check(addr->to_bytes()[0] == 0x20, "extract_ipv6: first byte=0x20");
        runner.Check(addr->to_bytes()[1] == 0x01, "extract_ipv6: second byte=0x01");
    }

    void TestExtractIpv6WrongType(TestRunner &runner)
    {
        dns::record rec;
        rec.type = dns::qtype::a;
        rec.rdata.resize(16, 0);
        auto addr = dns::extract_ipv6(rec);
        runner.Check(!addr.has_value(), "extract_ipv6: wrong type -> nullopt");
    }

    void TestExtractIpv6WrongSize(TestRunner &runner)
    {
        dns::record rec;
        rec.type = dns::qtype::aaaa;
        rec.rdata.resize(15, 0);
        auto addr = dns::extract_ipv6(rec);
        runner.Check(!addr.has_value(), "extract_ipv6: wrong size -> nullopt");
    }

    // ─── message::make_query ─────────────────────

    void TestMakeQuery(TestRunner &runner)
    {
        auto msg = dns::message::make_query("Example.COM.", dns::qtype::a);
        runner.Check(msg.questions.size() == 1, "make_query: 1 question");
        runner.Check(msg.questions[0].name == "example.com", "make_query: lowercased domain");
        runner.Check(msg.questions[0].query_type == dns::qtype::a, "make_query: type=A");
        runner.Check(msg.questions[0].qclass == 1, "make_query: class=IN");
        runner.Check(msg.rd, "make_query: rd=true");
    }

    void TestMakeQueryAaaa(TestRunner &runner)
    {
        auto msg = dns::message::make_query("test.org", dns::qtype::aaaa);
        runner.Check(msg.questions[0].query_type == dns::qtype::aaaa, "make_query: AAAA type");
    }

    // ─── message::pack / unpack roundtrip ────────

    void TestPackUnpackRoundtrip(TestRunner &runner)
    {
        auto msg = dns::message::make_query("test.example.com", dns::qtype::a);
        msg.id = 0x1234;
        auto packed = msg.pack();
        runner.Check(packed.size() >= 12, "pack: at least 12 bytes header");

        auto unpacked = dns::message::unpack({packed.data(), packed.size()});
        runner.Check(unpacked.has_value(), "unpack: success");
        runner.Check(unpacked->id == 0x1234, "unpack: id preserved");
        runner.Check(unpacked->questions.size() == 1, "unpack: 1 question");
        runner.Check(unpacked->questions[0].name == "test.example.com", "unpack: domain preserved");
        runner.Check(unpacked->questions[0].query_type == dns::qtype::a, "unpack: type preserved");
    }

    void TestPackUnpackWithAnswer(TestRunner &runner)
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
        runner.Check(unpacked.has_value(), "pack+unpack answer: success");
        runner.Check(unpacked->qr, "pack+unpack answer: qr=true");
        runner.Check(unpacked->ra, "pack+unpack answer: ra=true");
        runner.Check(unpacked->answers.size() == 1, "pack+unpack answer: 1 answer");
        runner.Check(unpacked->answers[0].ttl == 300, "pack+unpack answer: ttl=300");
        runner.Check(unpacked->answers[0].rdata.size() == 4, "pack+unpack answer: rdata size=4");
        runner.Check(unpacked->answers[0].rdata[0] == 93, "pack+unpack answer: rdata[0]=93");
    }

    void TestPackUnpackFlags(TestRunner &runner)
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
        runner.Check(unpacked.has_value(), "flags: unpack ok");
        runner.Check(unpacked->qr, "flags: qr=true");
        runner.Check(unpacked->aa, "flags: aa=true");
        runner.Check(unpacked->tc, "flags: tc=true");
        runner.Check(unpacked->opcode == 0x0F, "flags: opcode=0x0F");
        runner.Check(unpacked->rcode == 0x0E, "flags: rcode=0x0E");
    }

    void TestPackUnpackMultipleRecords(TestRunner &runner)
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
        runner.Check(unpacked.has_value(), "multi: unpack ok");
        runner.Check(unpacked->answers.size() == 2, "multi: 2 answers");
        runner.Check(unpacked->answers[0].rdata[0] == 1, "multi: ans[0] rdata[0]=1");
        runner.Check(unpacked->answers[1].rdata[0] == 5, "multi: ans[1] rdata[0]=5");
    }

    // ─── message::extract_ips ────────────────────

    void TestExtractIps(TestRunner &runner)
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
        runner.Check(ips.size() == 1, "extract_ips: 1 IP");
    }

    void TestExtractIpsEmpty(TestRunner &runner)
    {
        dns::message msg;
        auto ips = msg.extract_ips();
        runner.Check(ips.empty(), "extract_ips: empty -> no IPs");
    }

    void TestExtractIpsFromAuthority(TestRunner &runner)
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
        runner.Check(ips.size() == 1, "extract_ips: authority IP found");
    }

    void TestExtractIpsSkipsNonIp(TestRunner &runner)
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
        runner.Check(ips.empty(), "extract_ips: NS record skipped");
    }

    // ─── message::min_ttl ────────────────────────

    void TestMinTtlBasic(TestRunner &runner)
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

        runner.Check(msg.min_ttl() == 60, "min_ttl: 60");
    }

    void TestMinTtlNoRecords(TestRunner &runner)
    {
        dns::message msg;
        runner.Check(msg.min_ttl() == 0, "min_ttl: no records -> 0");
    }

    void TestMinTtlAuthority(TestRunner &runner)
    {
        dns::message msg;
        dns::record auth;
        auth.name = "ns.com";
        auth.type = dns::qtype::ns;
        auth.ttl = 10;
        msg.authority.push_back(std::move(auth));

        runner.Check(msg.min_ttl() == 10, "min_ttl: authority considered");
    }

    // ─── unpack_tcp ──────────────────────────────

    void TestUnpackTcpTooShort(TestRunner &runner)
    {
        std::uint8_t data[] = {0x00};
        auto result = dns::unpack_tcp({data, 1});
        runner.Check(!result.has_value(), "unpack_tcp: too short -> nullopt");
    }

    void TestUnpackTcpTruncated(TestRunner &runner)
    {
        std::uint8_t data[] = {0x00, 0x10};
        auto result = dns::unpack_tcp({data, 2});
        runner.Check(!result.has_value(), "unpack_tcp: truncated -> nullopt");
    }

    void TestUnpackTcpValid(TestRunner &runner)
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
        runner.Check(result.has_value(), "unpack_tcp: success");
        runner.Check(result->id == 0x5678, "unpack_tcp: id preserved");
    }

    // ─── unpack error paths ──────────────────────

    void TestUnpackTooShort(TestRunner &runner)
    {
        std::uint8_t data[] = {0x00, 0x01, 0x02};
        auto result = dns::message::unpack({data, 3});
        runner.Check(!result.has_value(), "unpack: < 12 bytes -> nullopt");
    }

    void TestPackUnpackDomainCompression(TestRunner &runner)
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
        runner.Check(unpacked.has_value(), "compression: unpack ok");
        runner.Check(unpacked->answers[0].name == "example.com", "compression: answer name preserved");
    }
} // namespace

auto main() -> int
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("DnsFormatPure");

    TestExtractIpv4(runner);
    TestExtractIpv4WrongType(runner);
    TestExtractIpv4WrongSize(runner);
    TestExtractIpv4EmptyRdata(runner);
    TestExtractIpv6(runner);
    TestExtractIpv6WrongType(runner);
    TestExtractIpv6WrongSize(runner);

    TestMakeQuery(runner);
    TestMakeQueryAaaa(runner);

    TestPackUnpackRoundtrip(runner);
    TestPackUnpackWithAnswer(runner);
    TestPackUnpackFlags(runner);
    TestPackUnpackMultipleRecords(runner);
    TestPackUnpackDomainCompression(runner);

    TestExtractIps(runner);
    TestExtractIpsEmpty(runner);
    TestExtractIpsFromAuthority(runner);
    TestExtractIpsSkipsNonIp(runner);

    TestMinTtlBasic(runner);
    TestMinTtlNoRecords(runner);
    TestMinTtlAuthority(runner);

    TestUnpackTcpTooShort(runner);
    TestUnpackTcpTruncated(runner);
    TestUnpackTcpValid(runner);

    TestUnpackTooShort(runner);

    return runner.Summary();
}
