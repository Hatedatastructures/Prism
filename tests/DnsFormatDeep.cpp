/**
 * @file DnsFormatDeep.cpp
 * @brief resolve/dns/detail/format 深度同步逻辑测试
 * @details 通过 #include 源文件访问 format.cpp 全部实现，
 *          测试 DNS 报文编解码、域名压缩、IP 提取、TTL 计算等纯同步逻辑。
 *          所有被测函数均为纯函数或仅操作 PMR 内存，无 I/O 和协程依赖。
 */

#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

#include <prism/resolve/dns/detail/format.hpp>

#include <array>
#include <cstring>

using psm::testing::TestRunner;
namespace dns = psm::resolve::dns::detail;
namespace net = boost::asio;

namespace
{
    // ─── 辅助：构造 A 记录 ─────────────────────

    static auto make_a_record(const char *name, std::uint8_t a, std::uint8_t b,
                              std::uint8_t c, std::uint8_t d, std::uint32_t ttl = 300,
                              psm::memory::resource_pointer mr = psm::memory::current_resource())
        -> dns::record
    {
        dns::record r{mr};
        r.name = psm::memory::string{name, mr};
        r.type = dns::qtype::a;
        r.rclass = 1;
        r.ttl = ttl;
        r.rdata = {a, b, c, d};
        return r;
    }

    // ─── 辅助：构造 AAAA 记录 ──────────────────

    static auto make_aaaa_record(const char *name,
                                 std::array<std::uint8_t, 16> addr,
                                 std::uint32_t ttl = 300,
                                 psm::memory::resource_pointer mr = psm::memory::current_resource())
        -> dns::record
    {
        dns::record r{mr};
        r.name = psm::memory::string{name, mr};
        r.type = dns::qtype::aaaa;
        r.rclass = 1;
        r.ttl = ttl;
        r.rdata.assign(addr.begin(), addr.end());
        return r;
    }

    // ─── 辅助：构造 CNAME 记录 ──────────────────

    static auto make_cname_record(const char *name, const char *cname,
                                  std::uint32_t ttl = 300,
                                  psm::memory::resource_pointer mr = psm::memory::current_resource())
        -> dns::record
    {
        dns::record r{mr};
        r.name = psm::memory::string{name, mr};
        r.type = dns::qtype::cname;
        r.rclass = 1;
        r.ttl = ttl;
        // CNAME rdata 是域名 wire format
        const std::string_view sv{cname};
        std::size_t p = 0;
        while (p < sv.size())
        {
            const auto dot = sv.find('.', p);
            std::string_view label;
            if (dot == std::string_view::npos)
            {
                label = sv.substr(p);
            }
            else
            {
                label = sv.substr(p, dot - p);
            }
            r.rdata.push_back(static_cast<std::uint8_t>(label.size()));
            for (const char c : label)
            {
                r.rdata.push_back(static_cast<std::uint8_t>(c));
            }
            if (dot == std::string_view::npos)
            {
                break;
            }
            p = dot + 1;
        }
        r.rdata.push_back(0x00);
        return r;
    }

    // ─── extract_ipv4 ──────────────────────────

    void TestExtractIpv4Valid(TestRunner &runner)
    {
        auto r = make_a_record("example.com", 192, 168, 1, 1);
        auto addr = dns::extract_ipv4(r);
        runner.Check(!!addr, "extract_ipv4: valid A record -> has value");
        runner.Check(addr->to_uint() == (192u << 24 | 168u << 16 | 1u << 8 | 1u),
                     "extract_ipv4: correct address");
    }

    void TestExtractIpv4WrongType(TestRunner &runner)
    {
        auto r = make_a_record("example.com", 1, 2, 3, 4);
        r.type = dns::qtype::aaaa;
        auto addr = dns::extract_ipv4(r);
        runner.Check(!addr, "extract_ipv4: wrong type -> nullopt");
    }

    void TestExtractIpv4WrongRdataLen(TestRunner &runner)
    {
        dns::record r{psm::memory::current_resource()};
        r.type = dns::qtype::a;
        r.rdata = {1, 2, 3}; // 3 字节，不是 4
        auto addr = dns::extract_ipv4(r);
        runner.Check(!addr, "extract_ipv4: wrong rdata len -> nullopt");
    }

    void TestExtractIpv4EmptyRdata(TestRunner &runner)
    {
        dns::record r{psm::memory::current_resource()};
        r.type = dns::qtype::a;
        auto addr = dns::extract_ipv4(r);
        runner.Check(!addr, "extract_ipv4: empty rdata -> nullopt");
    }

    // ─── extract_ipv6 ──────────────────────────

    void TestExtractIpv6Valid(TestRunner &runner)
    {
        std::array<std::uint8_t, 16> bytes{};
        bytes[0] = 0x20;
        bytes[1] = 0x01;
        bytes[15] = 0x01;
        auto r = make_aaaa_record("example.com", bytes);
        auto addr = dns::extract_ipv6(r);
        runner.Check(!!addr, "extract_ipv6: valid AAAA record -> has value");
        auto addr_bytes = addr->to_bytes();
        runner.Check(addr_bytes[0] == 0x20, "extract_ipv6: byte[0] correct");
        runner.Check(addr_bytes[1] == 0x01, "extract_ipv6: byte[1] correct");
    }

    void TestExtractIpv6WrongType(TestRunner &runner)
    {
        std::array<std::uint8_t, 16> bytes{};
        auto r = make_aaaa_record("example.com", bytes);
        r.type = dns::qtype::a;
        auto addr = dns::extract_ipv6(r);
        runner.Check(!addr, "extract_ipv6: wrong type -> nullopt");
    }

    void TestExtractIpv6WrongRdataLen(TestRunner &runner)
    {
        dns::record r{psm::memory::current_resource()};
        r.type = dns::qtype::aaaa;
        r.rdata = {0, 0, 0, 0, 0, 0, 0, 0}; // 8 字节，不是 16
        auto addr = dns::extract_ipv6(r);
        runner.Check(!addr, "extract_ipv6: wrong rdata len -> nullopt");
    }

    // ─── message 构造 ──────────────────────────

    void TestMessageDefaultConstructor(TestRunner &runner)
    {
        dns::message msg;
        runner.Check(msg.id == 0, "message: default id = 0");
        runner.Check(!msg.qr, "message: default qr = false");
        runner.Check(msg.opcode == 0, "message: default opcode = 0");
        runner.Check(msg.questions.empty(), "message: default questions empty");
        runner.Check(msg.answers.empty(), "message: default answers empty");
    }

    void TestMessageConstructorWithMr(TestRunner &runner)
    {
        psm::memory::unsynchronized_pool mr;
        dns::message msg{&mr};
        runner.Check(msg.id == 0, "message: with mr -> id = 0");
        runner.Check(msg.questions.empty(), "message: with mr -> questions empty");
    }

    void TestMessageConstructorNullMr(TestRunner &runner)
    {
        dns::message msg{nullptr};
        runner.Check(msg.questions.empty(), "message: null mr -> no crash");
    }

    // ─── make_query ─────────────────────────────

    void TestMakeQueryBasic(TestRunner &runner)
    {
        auto msg = dns::message::make_query("example.com", dns::qtype::a);
        runner.Check(msg.rd, "make_query: rd = true");
        runner.Check(msg.opcode == 0, "make_query: opcode = 0");
        runner.Check(msg.questions.size() == 1, "make_query: 1 question");
        runner.Check(msg.questions[0].name == "example.com", "make_query: domain lowercase");
        runner.Check(msg.questions[0].query_type == dns::qtype::a, "make_query: qtype = A");
        runner.Check(msg.questions[0].qclass == 1, "make_query: qclass = IN");
    }

    void TestMakeQueryUppercase(TestRunner &runner)
    {
        auto msg = dns::message::make_query("EXAMPLE.COM", dns::qtype::aaaa);
        runner.Check(msg.questions[0].name == "example.com", "make_query: uppercase -> lowercase");
    }

    void TestMakeQueryTrailingDot(TestRunner &runner)
    {
        auto msg = dns::message::make_query("example.com.", dns::qtype::a);
        runner.Check(msg.questions[0].name == "example.com", "make_query: trailing dot removed");
    }

    void TestMakeQuerySubdomain(TestRunner &runner)
    {
        auto msg = dns::message::make_query("www.example.com", dns::qtype::a);
        runner.Check(msg.questions[0].name == "www.example.com", "make_query: subdomain preserved");
    }

    void TestMakeQueryWithMr(TestRunner &runner)
    {
        psm::memory::unsynchronized_pool mr;
        auto msg = dns::message::make_query("test.com", dns::qtype::a, &mr);
        runner.Check(msg.questions.size() == 1, "make_query: with mr -> ok");
    }

    void TestMakeQueryNullMr(TestRunner &runner)
    {
        auto msg = dns::message::make_query("test.com", dns::qtype::a, nullptr);
        runner.Check(msg.questions.size() == 1, "make_query: null mr -> ok");
    }

    // ─── pack / unpack 往返 ─────────────────────

    void TestPackUnpackRoundtrip(TestRunner &runner)
    {
        auto msg = dns::message::make_query("example.com", dns::qtype::a);
        msg.id = 0x1234;
        auto packed = msg.pack();

        runner.Check(packed.size() >= 12, "pack: header present");

        auto result = dns::message::unpack(packed);
        runner.Check(!!result, "unpack: success");
        runner.Check(result->id == 0x1234, "roundtrip: id preserved");
        runner.Check(result->rd, "roundtrip: rd preserved");
        runner.Check(result->questions.size() == 1, "roundtrip: 1 question");
        runner.Check(result->questions[0].name == "example.com", "roundtrip: domain preserved");
        runner.Check(result->questions[0].query_type == dns::qtype::a, "roundtrip: qtype preserved");
    }

    void TestPackUnpackResponse(TestRunner &runner)
    {
        auto msg = dns::message::make_query("example.com", dns::qtype::a);
        msg.id = 0xABCD;
        msg.qr = true;
        msg.ra = true;
        msg.rcode = 0;
        msg.answers.push_back(make_a_record("example.com", 93, 184, 216, 34));

        auto packed = msg.pack();
        auto result = dns::message::unpack(packed);
        runner.Check(!!result, "roundtrip response: success");
        runner.Check(result->qr, "roundtrip response: qr = true");
        runner.Check(result->ra, "roundtrip response: ra = true");
        runner.Check(result->answers.size() == 1, "roundtrip response: 1 answer");
    }

    void TestPackFlags(TestRunner &runner)
    {
        dns::message msg;
        msg.id = 0x5678;
        msg.qr = true;
        msg.opcode = 0;
        msg.aa = true;
        msg.tc = false;
        msg.rd = true;
        msg.ra = true;
        msg.rcode = 3;

        auto packed = msg.pack();
        auto result = dns::message::unpack(packed);
        runner.Check(!!result, "pack flags: success");
        runner.Check(result->qr, "pack flags: qr");
        runner.Check(result->aa, "pack flags: aa");
        runner.Check(result->rd, "pack flags: rd");
        runner.Check(result->ra, "pack flags: ra");
        runner.Check(result->rcode == 3, "pack flags: rcode = 3");
        runner.Check(!result->tc, "pack flags: tc = false");
    }

    void TestPackWithRecords(TestRunner &runner)
    {
        dns::message msg;
        msg.id = 1;
        msg.qr = true;
        msg.rd = true;
        msg.ra = true;

        dns::question q{psm::memory::current_resource()};
        q.name = "example.com";
        q.query_type = dns::qtype::a;
        q.qclass = 1;
        msg.questions.push_back(std::move(q));

        msg.answers.push_back(make_a_record("example.com", 1, 2, 3, 4, 300));
        msg.answers.push_back(make_a_record("example.com", 5, 6, 7, 8, 600));

        auto packed = msg.pack();
        auto result = dns::message::unpack(packed);
        runner.Check(!!result, "pack records: success");
        runner.Check(result->answers.size() == 2, "pack records: 2 answers");

        auto ip0 = dns::extract_ipv4(result->answers[0]);
        runner.Check(!!ip0, "pack records: first answer extractable");
        runner.Check(ip0->to_uint() == (1u << 24 | 2u << 16 | 3u << 8 | 4u),
                     "pack records: first IP correct");
    }

    void TestPackCompressionReuse(TestRunner &runner)
    {
        // 两个 answer 指向同一域名，第二次应使用压缩指针
        dns::message msg;
        msg.qr = true;

        dns::question q{psm::memory::current_resource()};
        q.name = "example.com";
        q.query_type = dns::qtype::a;
        msg.questions.push_back(std::move(q));

        msg.answers.push_back(make_a_record("example.com", 1, 2, 3, 4));
        msg.answers.push_back(make_a_record("example.com", 5, 6, 7, 8));

        auto packed = msg.pack();
        auto result = dns::message::unpack(packed);
        runner.Check(!!result, "compression reuse: unpack success");
        runner.Check(result->answers.size() == 2, "compression reuse: 2 answers");
        runner.Check(result->answers[0].name == "example.com", "compression reuse: name[0]");
        runner.Check(result->answers[1].name == "example.com", "compression reuse: name[1]");
    }

    void TestPackAuthorityAndAdditional(TestRunner &runner)
    {
        dns::message msg;
        msg.qr = true;
        msg.authority.push_back(make_a_record("ns.example.com", 10, 0, 0, 1));
        msg.additional.push_back(make_a_record("ns.example.com", 10, 0, 0, 2));

        auto packed = msg.pack();
        auto result = dns::message::unpack(packed);
        runner.Check(!!result, "auth/additional: unpack success");
        runner.Check(result->authority.size() == 1, "auth/additional: 1 authority");
        runner.Check(result->additional.size() == 1, "auth/additional: 1 additional");
    }

    // ─── unpack 边界 ────────────────────────────

    void TestUnpackTooShort(TestRunner &runner)
    {
        psm::memory::vector<std::uint8_t> data{psm::memory::current_resource()};
        data = {0x00, 0x01, 0x00, 0x00, 0x00, 0x00};
        auto result = dns::message::unpack(data);
        runner.Check(!result, "unpack: < 12 bytes -> nullopt");
    }

    void TestUnpackEmpty(TestRunner &runner)
    {
        psm::memory::vector<std::uint8_t> data{psm::memory::current_resource()};
        auto result = dns::message::unpack(data);
        runner.Check(!result, "unpack: empty -> nullopt");
    }

    void TestUnpackHeaderOnly(TestRunner &runner)
    {
        // 12 字节 header，但声明有 1 个 question（实际无数据）
        psm::memory::vector<std::uint8_t> data{psm::memory::current_resource()};
        data.resize(12, 0);
        data[4] = 0x00;
        data[5] = 0x01; // qdcount = 1
        auto result = dns::message::unpack(data);
        runner.Check(!result, "unpack: header-only with qdcount=1 -> nullopt");
    }

    void TestUnpackTruncatedRecord(TestRunner &runner)
    {
        auto msg = dns::message::make_query("example.com", dns::qtype::a);
        msg.qr = true;
        msg.answers.push_back(make_a_record("example.com", 1, 2, 3, 4));
        auto packed = msg.pack();

        // 截断最后一个字节
        packed.resize(packed.size() - 1);
        auto result = dns::message::unpack(packed);
        runner.Check(!result, "unpack: truncated record -> nullopt");
    }

    void TestUnpackWithMr(TestRunner &runner)
    {
        auto msg = dns::message::make_query("test.com", dns::qtype::a);
        auto packed = msg.pack();
        psm::memory::unsynchronized_pool mr;
        auto result = dns::message::unpack(packed, &mr);
        runner.Check(!!result, "unpack: with mr -> success");
    }

    void TestUnpackNullMr(TestRunner &runner)
    {
        auto msg = dns::message::make_query("test.com", dns::qtype::a);
        auto packed = msg.pack();
        auto result = dns::message::unpack(packed, nullptr);
        runner.Check(!!result, "unpack: null mr -> success");
    }

    // ─── 域名压缩指针解码 ──────────────────────

    void TestPackSubdomainCompression(TestRunner &runner)
    {
        dns::message msg;
        msg.qr = true;

        dns::question q{psm::memory::current_resource()};
        q.name = "www.example.com";
        q.query_type = dns::qtype::a;
        msg.questions.push_back(std::move(q));

        msg.answers.push_back(make_a_record("www.example.com", 1, 2, 3, 4));
        msg.answers.push_back(make_a_record("example.com", 5, 6, 7, 8));
        msg.answers.push_back(make_a_record("com", 9, 10, 11, 12));

        auto packed = msg.pack();
        auto result = dns::message::unpack(packed);
        runner.Check(!!result, "subdomain compression: unpack success");
        runner.Check(result->questions[0].name == "www.example.com", "subdomain: qname correct");
        runner.Check(result->answers[0].name == "www.example.com", "subdomain: ans[0] correct");
        runner.Check(result->answers[1].name == "example.com", "subdomain: ans[1] correct");
        runner.Check(result->answers[2].name == "com", "subdomain: ans[2] correct");
    }

    // ─── extract_ips ───────────────────────────

    void TestExtractIpsARecords(TestRunner &runner)
    {
        dns::message msg;
        msg.answers.push_back(make_a_record("a.com", 1, 2, 3, 4));
        msg.answers.push_back(make_a_record("a.com", 5, 6, 7, 8));

        auto ips = msg.extract_ips();
        runner.Check(ips.size() == 2, "extract_ips: 2 A records -> 2 ips");
    }

    void TestExtractIpsAaaaRecords(TestRunner &runner)
    {
        std::array<std::uint8_t, 16> addr1{};
        addr1[15] = 1;
        std::array<std::uint8_t, 16> addr2{};
        addr2[15] = 2;

        dns::message msg;
        msg.answers.push_back(make_aaaa_record("a.com", addr1));
        msg.answers.push_back(make_aaaa_record("a.com", addr2));

        auto ips = msg.extract_ips();
        runner.Check(ips.size() == 2, "extract_ips: 2 AAAA records -> 2 ips");
    }

    void TestExtractIpsMixed(TestRunner &runner)
    {
        std::array<std::uint8_t, 16> v6{};
        v6[0] = 0x20;
        v6[1] = 0x01;

        dns::message msg;
        msg.answers.push_back(make_a_record("a.com", 1, 2, 3, 4));
        msg.answers.push_back(make_aaaa_record("a.com", v6));

        auto ips = msg.extract_ips();
        runner.Check(ips.size() == 2, "extract_ips: mixed A+AAAA -> 2 ips");
    }

    void TestExtractIpsFromAllSections(TestRunner &runner)
    {
        dns::message msg;
        msg.answers.push_back(make_a_record("a.com", 1, 1, 1, 1));
        msg.authority.push_back(make_a_record("b.com", 2, 2, 2, 2));
        msg.additional.push_back(make_a_record("c.com", 3, 3, 3, 3));

        auto ips = msg.extract_ips();
        runner.Check(ips.size() == 3, "extract_ips: from all 3 sections -> 3 ips");
    }

    void TestExtractIpsSkipsCname(TestRunner &runner)
    {
        dns::message msg;
        msg.answers.push_back(make_cname_record("alias.com", "target.com"));
        msg.answers.push_back(make_a_record("target.com", 1, 2, 3, 4));

        auto ips = msg.extract_ips();
        runner.Check(ips.size() == 1, "extract_ips: skips CNAME, keeps A");
    }

    void TestExtractIpsEmpty(TestRunner &runner)
    {
        dns::message msg;
        auto ips = msg.extract_ips();
        runner.Check(ips.empty(), "extract_ips: no records -> empty");
    }

    void TestExtractIpsMalformedA(TestRunner &runner)
    {
        // type=A 但 rdata 长度不是 4
        dns::record r{psm::memory::current_resource()};
        r.name = "bad.com";
        r.type = dns::qtype::a;
        r.rdata = {1, 2, 3}; // 3 字节

        dns::message msg;
        msg.answers.push_back(std::move(r));
        auto ips = msg.extract_ips();
        runner.Check(ips.empty(), "extract_ips: malformed A -> skipped");
    }

    // ─── min_ttl ───────────────────────────────

    void TestMinTtlBasic(TestRunner &runner)
    {
        dns::message msg;
        msg.answers.push_back(make_a_record("a.com", 1, 2, 3, 4, 300));
        msg.answers.push_back(make_a_record("a.com", 5, 6, 7, 8, 100));
        runner.Check(msg.min_ttl() == 100, "min_ttl: min of 300,100 = 100");
    }

    void TestMinTtlAllSections(TestRunner &runner)
    {
        dns::message msg;
        msg.answers.push_back(make_a_record("a.com", 1, 2, 3, 4, 500));
        msg.authority.push_back(make_a_record("b.com", 5, 6, 7, 8, 200));
        msg.additional.push_back(make_a_record("c.com", 9, 10, 11, 12, 50));
        runner.Check(msg.min_ttl() == 50, "min_ttl: across all sections = 50");
    }

    void TestMinTtlEmpty(TestRunner &runner)
    {
        dns::message msg;
        runner.Check(msg.min_ttl() == 0, "min_ttl: no records -> 0");
    }

    void TestMinTtlSingle(TestRunner &runner)
    {
        dns::message msg;
        msg.answers.push_back(make_a_record("a.com", 1, 2, 3, 4, 3600));
        runner.Check(msg.min_ttl() == 3600, "min_ttl: single record -> 3600");
    }

    void TestMinTtlZero(TestRunner &runner)
    {
        dns::message msg;
        msg.answers.push_back(make_a_record("a.com", 1, 2, 3, 4, 0));
        msg.answers.push_back(make_a_record("a.com", 5, 6, 7, 8, 300));
        runner.Check(msg.min_ttl() == 0, "min_ttl: includes 0 -> 0");
    }

    // ─── unpack_tcp ────────────────────────────

    void TestUnpackTcpValid(TestRunner &runner)
    {
        auto msg = dns::message::make_query("example.com", dns::qtype::a);
        auto packed = msg.pack();

        // 添加 TCP 长度前缀
        psm::memory::vector<std::uint8_t> tcp_data{psm::memory::current_resource()};
        auto len = static_cast<std::uint16_t>(packed.size());
        tcp_data.push_back(static_cast<std::uint8_t>(len >> 8));
        tcp_data.push_back(static_cast<std::uint8_t>(len & 0xFF));
        tcp_data.insert(tcp_data.end(), packed.begin(), packed.end());

        auto result = dns::unpack_tcp(tcp_data);
        runner.Check(!!result, "unpack_tcp: valid -> success");
        runner.Check(result->questions.size() == 1, "unpack_tcp: 1 question");
    }

    void TestUnpackTcpTooShort(TestRunner &runner)
    {
        psm::memory::vector<std::uint8_t> data{psm::memory::current_resource()};
        data = {0x00};
        auto result = dns::unpack_tcp(data);
        runner.Check(!result, "unpack_tcp: 1 byte -> nullopt");
    }

    void TestUnpackTcpEmpty(TestRunner &runner)
    {
        psm::memory::vector<std::uint8_t> data{psm::memory::current_resource()};
        auto result = dns::unpack_tcp(data);
        runner.Check(!result, "unpack_tcp: empty -> nullopt");
    }

    void TestUnpackTcpIncomplete(TestRunner &runner)
    {
        // 长度声明 100 字节但实际只有 4
        psm::memory::vector<std::uint8_t> data{psm::memory::current_resource()};
        data = {0x00, 0x64, 0x00, 0x00}; // len=100, 但只有 2 字节 payload
        auto result = dns::unpack_tcp(data);
        runner.Check(!result, "unpack_tcp: incomplete -> nullopt");
    }

    void TestUnpackTcpWithMr(TestRunner &runner)
    {
        auto msg = dns::message::make_query("test.com", dns::qtype::a);
        auto packed = msg.pack();

        psm::memory::vector<std::uint8_t> tcp_data{psm::memory::current_resource()};
        auto len = static_cast<std::uint16_t>(packed.size());
        tcp_data.push_back(static_cast<std::uint8_t>(len >> 8));
        tcp_data.push_back(static_cast<std::uint8_t>(len & 0xFF));
        tcp_data.insert(tcp_data.end(), packed.begin(), packed.end());

        psm::memory::unsynchronized_pool mr;
        auto result = dns::unpack_tcp(tcp_data, &mr);
        runner.Check(!!result, "unpack_tcp: with mr -> success");
    }

    // ─── pack 空 message ────────────────────────

    void TestPackEmptyMessage(TestRunner &runner)
    {
        dns::message msg;
        msg.id = 42;
        auto packed = msg.pack();
        runner.Check(packed.size() == 12, "pack: empty message -> 12 bytes header");
        auto result = dns::message::unpack(packed);
        runner.Check(!!result, "pack empty: roundtrip success");
        runner.Check(result->id == 42, "pack empty: id preserved");
    }

    // ─── pack 带各种 qtype ─────────────────────

    void TestPackQtypeAAAA(TestRunner &runner)
    {
        auto msg = dns::message::make_query("example.com", dns::qtype::aaaa);
        auto packed = msg.pack();
        auto result = dns::message::unpack(packed);
        runner.Check(!!result, "pack qtype: AAAA roundtrip success");
        runner.Check(result->questions[0].query_type == dns::qtype::aaaa,
                     "pack qtype: AAAA preserved");
    }

    void TestPackQtypeMX(TestRunner &runner)
    {
        auto msg = dns::message::make_query("example.com", dns::qtype::mx);
        auto packed = msg.pack();
        auto result = dns::message::unpack(packed);
        runner.Check(!!result, "pack qtype: MX roundtrip success");
        runner.Check(result->questions[0].query_type == dns::qtype::mx,
                     "pack qtype: MX preserved");
    }

    // ─── 大 message ────────────────────────────

    void TestPackManyQuestions(TestRunner &runner)
    {
        dns::message msg;
        for (int i = 0; i < 10; ++i)
        {
            dns::question q{psm::memory::current_resource()};
            q.name = "domain" + std::to_string(i) + ".example.com";
            q.query_type = dns::qtype::a;
            q.qclass = 1;
            msg.questions.push_back(std::move(q));
        }
        auto packed = msg.pack();
        auto result = dns::message::unpack(packed);
        runner.Check(!!result, "pack many: success");
        runner.Check(result->questions.size() == 10, "pack many: 10 questions");
    }

    void TestPackManyRecords(TestRunner &runner)
    {
        dns::message msg;
        msg.qr = true;
        for (int i = 0; i < 20; ++i)
        {
            msg.answers.push_back(
                make_a_record("example.com",
                              static_cast<std::uint8_t>(i),
                              static_cast<std::uint8_t>(i + 1),
                              static_cast<std::uint8_t>(i + 2),
                              static_cast<std::uint8_t>(i + 3)));
        }
        auto packed = msg.pack();
        auto result = dns::message::unpack(packed);
        runner.Check(!!result, "pack many records: success");
        runner.Check(result->answers.size() == 20, "pack many records: 20 answers");
    }

    // ─── 域名边界 ──────────────────────────────

    void TestPackSingleLabel(TestRunner &runner)
    {
        auto msg = dns::message::make_query("com", dns::qtype::a);
        auto packed = msg.pack();
        auto result = dns::message::unpack(packed);
        runner.Check(!!result, "single label: success");
        runner.Check(result->questions[0].name == "com", "single label: name = com");
    }

    void TestPackDeepSubdomain(TestRunner &runner)
    {
        auto msg = dns::message::make_query("a.b.c.d.e.f.example.com", dns::qtype::a);
        auto packed = msg.pack();
        auto result = dns::message::unpack(packed);
        runner.Check(!!result, "deep subdomain: success");
        runner.Check(result->questions[0].name == "a.b.c.d.e.f.example.com",
                     "deep subdomain: name preserved");
    }

} // namespace

// #include 源文件以覆盖 format.cpp 全部实现
#include "../src/prism/resolve/dns/detail/format.cpp"

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("DnsFormatDeep");

    // extract_ipv4
    TestExtractIpv4Valid(runner);
    TestExtractIpv4WrongType(runner);
    TestExtractIpv4WrongRdataLen(runner);
    TestExtractIpv4EmptyRdata(runner);

    // extract_ipv6
    TestExtractIpv6Valid(runner);
    TestExtractIpv6WrongType(runner);
    TestExtractIpv6WrongRdataLen(runner);

    // message 构造
    TestMessageDefaultConstructor(runner);
    TestMessageConstructorWithMr(runner);
    TestMessageConstructorNullMr(runner);

    // make_query
    TestMakeQueryBasic(runner);
    TestMakeQueryUppercase(runner);
    TestMakeQueryTrailingDot(runner);
    TestMakeQuerySubdomain(runner);
    TestMakeQueryWithMr(runner);
    TestMakeQueryNullMr(runner);

    // pack / unpack 往返
    TestPackUnpackRoundtrip(runner);
    TestPackUnpackResponse(runner);
    TestPackFlags(runner);
    TestPackWithRecords(runner);
    TestPackCompressionReuse(runner);
    TestPackAuthorityAndAdditional(runner);

    // unpack 边界
    TestUnpackTooShort(runner);
    TestUnpackEmpty(runner);
    TestUnpackHeaderOnly(runner);
    TestUnpackTruncatedRecord(runner);
    TestUnpackWithMr(runner);
    TestUnpackNullMr(runner);

    // 域名压缩
    TestPackSubdomainCompression(runner);

    // extract_ips
    TestExtractIpsARecords(runner);
    TestExtractIpsAaaaRecords(runner);
    TestExtractIpsMixed(runner);
    TestExtractIpsFromAllSections(runner);
    TestExtractIpsSkipsCname(runner);
    TestExtractIpsEmpty(runner);
    TestExtractIpsMalformedA(runner);

    // min_ttl
    TestMinTtlBasic(runner);
    TestMinTtlAllSections(runner);
    TestMinTtlEmpty(runner);
    TestMinTtlSingle(runner);
    TestMinTtlZero(runner);

    // unpack_tcp
    TestUnpackTcpValid(runner);
    TestUnpackTcpTooShort(runner);
    TestUnpackTcpEmpty(runner);
    TestUnpackTcpIncomplete(runner);
    TestUnpackTcpWithMr(runner);

    // 空 message
    TestPackEmptyMessage(runner);

    // 各种 qtype
    TestPackQtypeAAAA(runner);
    TestPackQtypeMX(runner);

    // 大 message
    TestPackManyQuestions(runner);
    TestPackManyRecords(runner);

    // 域名边界
    TestPackSingleLabel(runner);
    TestPackDeepSubdomain(runner);

    return runner.Summary();
}
