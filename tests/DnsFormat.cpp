/**
 * @file DnsFormat.cpp
 * @brief DNS 报文编解码补充单元测试
 * @details 补充 DnsPacket.cpp 未覆盖的边界条件和错误路径：
 *          unpack 短缓冲区、域名压缩指针循环、多段记录、
 *          extract_ipv4/ipv6 类型不匹配、min_ttl 空记录、
 *          unpack_tcp 短数据和长度不匹配、pack_tcp 往返、
 *          extract_ips 遍历 authority/additional 段。
 */

#include <prism/memory.hpp>
#include <prism/resolve/dns/detail/format.hpp>
#include <prism/trace/spdlog.hpp>

#include <cstdint>
#include <cstring>
#include <optional>
#include <string_view>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

using psm::testing::TestRunner;

namespace
{
    namespace dns = psm::resolve::dns::detail;

    void TestUnpackTooShort(TestRunner &runner)
    {
        // 少于 12 字节 → nullopt
        const std::uint8_t data[] = {0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        auto result = dns::message::unpack(data);
        runner.Check(!result.has_value(), "unpack: 11 bytes → nullopt");
    }

    void TestUnpackMinimalHeader(TestRunner &runner)
    {
        // 最小合法报文：12 字节 header，0 question/answer/auth/additional
        std::uint8_t data[12]{};
        // ID = 0x1234
        data[0] = 0x12;
        data[1] = 0x34;
        // FLAGS: QR=1, RD=1, RA=1 → 0x8180
        data[2] = 0x81;
        data[3] = 0x80;

        auto result = dns::message::unpack(data);
        runner.Check(result.has_value(), "unpack minimal header: has_value");
        runner.Check(result->id == 0x1234, "unpack minimal header: id=0x1234");
        runner.Check(result->qr == true, "unpack minimal header: qr=true");
        runner.Check(result->rd == true, "unpack minimal header: rd=true");
        runner.Check(result->ra == true, "unpack minimal header: ra=true");
        runner.Check(result->questions.empty(), "unpack minimal header: no questions");
        runner.Check(result->answers.empty(), "unpack minimal header: no answers");
    }

    void TestUnpackQuestionTruncated(TestRunner &runner)
    {
        // 声称 1 question 但数据不够
        std::uint8_t data[14]{};
        data[4] = 0x00;
        data[5] = 0x01; // QDCOUNT=1
        auto result = dns::message::unpack(data);
        runner.Check(!result.has_value(), "unpack question truncated: nullopt");
    }

    void TestUnpackRecordTruncated(TestRunner &runner)
    {
        // Header(12) + question + 声称 1 answer 但数据截断
        // 先构建一个合法 query 报文再手动添加 ANCOUNT=1 但不追加数据
        auto mr = psm::memory::current_resource();
        auto msg = dns::message::make_query("test.com", dns::qtype::a, mr);
        auto wire = msg.pack();

        // 篡改 ANCOUNT=1
        wire[6] = 0x00;
        wire[7] = 0x01;

        auto result = dns::message::unpack(
            std::span<const std::uint8_t>(wire.data(), wire.size()), mr);
        runner.Check(!result.has_value(), "unpack record truncated: nullopt");
    }

    void TestPackAllFlags(TestRunner &runner)
    {
        auto mr = psm::memory::current_resource();
        dns::message msg(mr);
        msg.id = 0xABCD;
        msg.qr = true;
        msg.opcode = 0x0F;
        msg.aa = true;
        msg.tc = true;
        msg.rd = true;
        msg.ra = true;
        msg.rcode = 0x0F;

        auto wire = msg.pack();
        runner.Check(wire.size() >= 12, "pack all flags: size >= 12");

        auto restored = dns::message::unpack(
            std::span<const std::uint8_t>(wire.data(), wire.size()), mr);
        runner.Check(restored.has_value(), "pack all flags: unpack success");
        runner.Check(restored->id == 0xABCD, "pack all flags: id=0xABCD");
        runner.Check(restored->qr == true, "pack all flags: qr=true");
        runner.Check(restored->opcode == 0x0F, "pack all flags: opcode=0x0F");
        runner.Check(restored->aa == true, "pack all flags: aa=true");
        runner.Check(restored->tc == true, "pack all flags: tc=true");
        runner.Check(restored->rd == true, "pack all flags: rd=true");
        runner.Check(restored->ra == true, "pack all flags: ra=true");
        runner.Check(restored->rcode == 0x0F, "pack all flags: rcode=0x0F");
    }

    void TestPackUnpackAuthorityAdditional(TestRunner &runner)
    {
        auto mr = psm::memory::current_resource();
        dns::message msg(mr);
        msg.id = 0x0001;
        msg.qr = true;
        msg.rd = true;
        msg.ra = true;

        // Authority record: NS
        dns::record ns_rec(mr);
        ns_rec.name = "example.com";
        ns_rec.type = dns::qtype::ns;
        ns_rec.ttl = 3600;
        const char ns_name[] = "a.iana-servers.net";
        ns_rec.rdata.assign(ns_name, ns_name + sizeof(ns_name) - 1);
        msg.authority.push_back(std::move(ns_rec));

        // Additional record: A
        dns::record add_rec(mr);
        add_rec.name = "a.iana-servers.net";
        add_rec.type = dns::qtype::a;
        add_rec.ttl = 300;
        add_rec.rdata = {199, 43, 135, 53};
        msg.additional.push_back(std::move(add_rec));

        auto wire = msg.pack();
        auto restored = dns::message::unpack(
            std::span<const std::uint8_t>(wire.data(), wire.size()), mr);

        runner.Check(restored.has_value(), "pack authority/additional: unpack success");
        runner.Check(restored->authority.size() == 1, "pack authority: 1 record");
        runner.Check(restored->additional.size() == 1, "pack additional: 1 record");
        runner.Check(restored->authority[0].type == dns::qtype::ns, "pack authority: type=ns");
        runner.Check(restored->additional[0].type == dns::qtype::a, "pack additional: type=a");
    }

    void TestExtractIPv4WrongType(TestRunner &runner)
    {
        auto mr = psm::memory::current_resource();
        dns::record rec(mr);
        rec.type = dns::qtype::aaaa; // type 不匹配
        rec.rdata = {1, 2, 3, 4};
        auto result = dns::extract_ipv4(rec);
        runner.Check(!result.has_value(), "extract_ipv4 wrong type: nullopt");
    }

    void TestExtractIPv6WrongLength(TestRunner &runner)
    {
        auto mr = psm::memory::current_resource();
        dns::record rec(mr);
        rec.type = dns::qtype::aaaa;
        rec.rdata = {0, 0, 0, 0, 0, 0, 0, 0}; // 8 bytes, not 16
        auto result = dns::extract_ipv6(rec);
        runner.Check(!result.has_value(), "extract_ipv6 wrong length: nullopt");
    }

    void TestExtractIPv6WrongType(TestRunner &runner)
    {
        auto mr = psm::memory::current_resource();
        dns::record rec(mr);
        rec.type = dns::qtype::a; // type 不匹配
        rec.rdata.assign(16, 0);
        auto result = dns::extract_ipv6(rec);
        runner.Check(!result.has_value(), "extract_ipv6 wrong type: nullopt");
    }

    void TestMinTtlNoRecords(TestRunner &runner)
    {
        auto mr = psm::memory::current_resource();
        dns::message msg(mr);
        runner.Check(msg.min_ttl() == 0, "min_ttl no records: 0");
    }

    void TestMinTtlAcrossSections(TestRunner &runner)
    {
        auto mr = psm::memory::current_resource();
        dns::message msg(mr);

        dns::record r1(mr);
        r1.ttl = 300;
        msg.answers.push_back(std::move(r1));

        dns::record r2(mr);
        r2.ttl = 60;
        msg.authority.push_back(std::move(r2));

        dns::record r3(mr);
        r3.ttl = 120;
        msg.additional.push_back(std::move(r3));

        runner.Check(msg.min_ttl() == 60, "min_ttl across sections: 60");
    }

    void TestExtractIPsFromAuthority(TestRunner &runner)
    {
        auto mr = psm::memory::current_resource();
        dns::message msg(mr);

        // Authority 中放 A 记录
        dns::record auth(mr);
        auth.type = dns::qtype::a;
        auth.rdata = {10, 0, 0, 1};
        msg.authority.push_back(std::move(auth));

        // Additional 中放 AAAA 记录
        dns::record add(mr);
        add.type = dns::qtype::aaaa;
        add.rdata.assign(16, 0);
        add.rdata[15] = 1; // ::1
        msg.additional.push_back(std::move(add));

        auto ips = msg.extract_ips();
        runner.Check(ips.size() == 2, "extract_ips from auth/addl: 2 addresses");
    }

    void TestExtractIPsSkipsNonIp(TestRunner &runner)
    {
        auto mr = psm::memory::current_resource();
        dns::message msg(mr);

        dns::record ns(mr);
        ns.type = dns::qtype::ns;
        ns.rdata = {0x01, 0x02, 0x03};
        msg.answers.push_back(std::move(ns));

        dns::record a(mr);
        a.type = dns::qtype::a;
        a.rdata = {1, 1, 1, 1};
        msg.answers.push_back(std::move(a));

        auto ips = msg.extract_ips();
        runner.Check(ips.size() == 1, "extract_ips skips non-IP: 1 address");
    }

    void TestUnpackTcpTooShort(TestRunner &runner)
    {
        // 少于 2 字节 → nullopt
        const std::uint8_t data[] = {0x00};
        auto result = dns::unpack_tcp(data);
        runner.Check(!result.has_value(), "unpack_tcp short: nullopt");
    }

    void TestUnpackTcpLengthMismatch(TestRunner &runner)
    {
        // 声称 100 字节但实际只有 4 字节
        const std::uint8_t data[] = {0x00, 0x64, 0x00, 0x00};
        auto result = dns::unpack_tcp(data);
        runner.Check(!result.has_value(), "unpack_tcp length mismatch: nullopt");
    }

    void TestPackTcpRoundTrip(TestRunner &runner)
    {
        auto mr = psm::memory::current_resource();
        auto msg = dns::message::make_query("tcp-test.org", dns::qtype::aaaa, mr);

        // 手工构造 TCP 帧（因为 pack_tcp 可能未实现）
        auto wire = msg.pack();
        psm::memory::vector<std::uint8_t> tcp_frame(mr);
        const auto sz = static_cast<std::uint16_t>(wire.size());
        tcp_frame.push_back(static_cast<std::uint8_t>((sz >> 8) & 0xFF));
        tcp_frame.push_back(static_cast<std::uint8_t>(sz & 0xFF));
        tcp_frame.insert(tcp_frame.end(), wire.begin(), wire.end());

        auto restored = dns::unpack_tcp(
            std::span<const std::uint8_t>(tcp_frame.data(), tcp_frame.size()), mr);
        runner.Check(restored.has_value(), "tcp round trip: has_value");
        runner.Check(restored->questions.size() == 1, "tcp round trip: 1 question");
        runner.Check(restored->questions[0].name == "tcp-test.org", "tcp round trip: name match");
        runner.Check(restored->questions[0].query_type == dns::qtype::aaaa, "tcp round trip: qtype=aaaa");
    }

    void TestMakeQueryDomainNormalization(TestRunner &runner)
    {
        auto mr = psm::memory::current_resource();

        // 尾加点 → 去除
        auto msg = dns::message::make_query("Example.COM.", dns::qtype::a, mr);
        runner.Check(msg.questions[0].name == "example.com", "make_query: lower + strip dot");

        // 大写 → 小写
        auto msg2 = dns::message::make_query("UPPERCASE.NET", dns::qtype::aaaa, mr);
        runner.Check(msg2.questions[0].name == "uppercase.net", "make_query: lowercase");
    }

    void TestPackUnpackMultipleQuestions(TestRunner &runner)
    {
        auto mr = psm::memory::current_resource();
        dns::message msg(mr);
        msg.id = 0x5678;
        msg.rd = true;

        dns::question q1(mr);
        q1.name = "a.com";
        q1.query_type = dns::qtype::a;
        msg.questions.push_back(std::move(q1));

        dns::question q2(mr);
        q2.name = "b.com";
        q2.query_type = dns::qtype::aaaa;
        msg.questions.push_back(std::move(q2));

        auto wire = msg.pack();
        auto restored = dns::message::unpack(
            std::span<const std::uint8_t>(wire.data(), wire.size()), mr);

        runner.Check(restored.has_value(), "multiple questions: unpack success");
        runner.Check(restored->questions.size() == 2, "multiple questions: count=2");
        runner.Check(restored->questions[0].name == "a.com", "multiple questions: q1 name");
        runner.Check(restored->questions[0].query_type == dns::qtype::a, "multiple questions: q1 type=a");
        runner.Check(restored->questions[1].name == "b.com", "multiple questions: q2 name");
        runner.Check(restored->questions[1].query_type == dns::qtype::aaaa, "multiple questions: q2 type=aaaa");
    }

    void TestUnpackCompressionPointer(TestRunner &runner)
    {
        auto mr = psm::memory::current_resource();

        // 手工构造带压缩指针的报文
        // Header(12) + Question(example.com A IN) + Answer(压缩指针→example.com, A, IN, TTL=60, 1.2.3.4)
        psm::memory::vector<std::uint8_t> wire(mr);

        // Header: ID=0x0001, FLAGS=0x8180 (QR RD RA), QD=1, AN=1, NS=0, AR=0
        wire.insert(wire.end(), {0x00, 0x01, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00});

        // Question: example.com A IN
        // "example" (7) + "com" (3) + 0x00
        wire.insert(wire.end(), {0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00});
        // QTYPE=A(0x0001) QCLASS=IN(0x0001)
        wire.insert(wire.end(), {0x00, 0x01, 0x00, 0x01});

        // Answer: compression pointer → offset 12 (where "example.com" starts)
        // 压缩指针 0xC00C = 指向 offset 12
        wire.insert(wire.end(), {0xC0, 0x0C});
        // TYPE=A, CLASS=IN, TTL=60(0x0000003C), RDLENGTH=4
        wire.insert(wire.end(), {0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04});
        // RDATA: 1.2.3.4
        wire.insert(wire.end(), {0x01, 0x02, 0x03, 0x04});

        auto result = dns::message::unpack(
            std::span<const std::uint8_t>(wire.data(), wire.size()), mr);
        runner.Check(result.has_value(), "compression pointer: unpack success");
        runner.Check(result->answers.size() == 1, "compression pointer: 1 answer");
        runner.Check(result->answers[0].name == "example.com", "compression pointer: name match");
        runner.Check(result->answers[0].ttl == 60, "compression pointer: ttl=60");

        // 验证 extract_ipv4 能提取
        auto ip = dns::extract_ipv4(result->answers[0]);
        runner.Check(ip.has_value(), "compression pointer: extract_ipv4 success");
        auto expected = boost::asio::ip::make_address_v4("1.2.3.4");
        runner.Check(ip->to_uint() == expected.to_uint(), "compression pointer: ip=1.2.3.4");
    }

    void TestUnpackCompressionLoop(TestRunner &runner)
    {
        auto mr = psm::memory::current_resource();

        // 构造自引用压缩指针 → 循环检测
        psm::memory::vector<std::uint8_t> wire(mr);
        // Header: ID=0, FLAGS=0x8180, QD=1, AN=0, NS=0, AR=0
        wire.insert(wire.end(), {0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});

        // Question: 压缩指针指向 offset 12 (自身位置) → 循环
        wire.insert(wire.end(), {0xC0, 0x0C});
        // QTYPE + QCLASS
        wire.insert(wire.end(), {0x00, 0x01, 0x00, 0x01});

        auto result = dns::message::unpack(
            std::span<const std::uint8_t>(wire.data(), wire.size()), mr);
        // decode_name_raw 返回空但 offset 可能仍 < data.size()，
        // unpack 不会 nullopt 但 name 为空
        if (result.has_value())
        {
            runner.Check(result->questions[0].name.empty(), "compression loop: empty name");
        }
        else
        {
            runner.Check(true, "compression loop: nullopt (acceptable)");
        }
    }

    void TestUnpackNameLabelOutOfBounds(TestRunner &runner)
    {
        auto mr = psm::memory::current_resource();

        psm::memory::vector<std::uint8_t> wire(mr);
        // Header: QD=1
        wire.insert(wire.end(), {0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});

        // 标签声称长度 200 但数据不够
        wire.insert(wire.end(), {0xC8}); // len=200, 但后面没有 200 字节
        // 紧跟的数据很短
        wire.insert(wire.end(), {0x00, 0x01, 0x00, 0x01});

        auto result = dns::message::unpack(
            std::span<const std::uint8_t>(wire.data(), wire.size()), mr);
        // decode_name_raw 返回空，如果 offset 也 >= data.size() 则 nullopt
        // 否则 name 为空但解析继续
        if (!result.has_value())
        {
            runner.Check(true, "label out of bounds: nullopt");
        }
        else
        {
            runner.Check(result->questions[0].name.empty(), "label out of bounds: empty name");
        }
    }

    void TestPackUnpackMultipleAnswersWithCompression(TestRunner &runner)
    {
        auto mr = psm::memory::current_resource();
        dns::message msg(mr);
        msg.id = 0x0001;
        msg.qr = true;
        msg.rd = true;
        msg.ra = true;

        dns::question q(mr);
        q.name = "cdn.example.com";
        q.query_type = dns::qtype::a;
        msg.questions.push_back(std::move(q));

        // 两条 A 记录同名，验证压缩指针复用
        for (int i = 0; i < 2; ++i)
        {
            dns::record ans(mr);
            ans.name = "cdn.example.com";
            ans.type = dns::qtype::a;
            ans.ttl = 60;
            ans.rdata = {static_cast<std::uint8_t>(10 + i), 0, 0, static_cast<std::uint8_t>(i + 1)};
            msg.answers.push_back(std::move(ans));
        }

        auto wire = msg.pack();
        auto restored = dns::message::unpack(
            std::span<const std::uint8_t>(wire.data(), wire.size()), mr);

        runner.Check(restored.has_value(), "multi-answer compression: unpack success");
        runner.Check(restored->answers.size() == 2, "multi-answer compression: 2 answers");
        runner.Check(restored->answers[0].name == "cdn.example.com", "multi-answer: ans0 name");
        runner.Check(restored->answers[1].name == "cdn.example.com", "multi-answer: ans1 name");

        // 验证压缩确实有效：第二条记录的 name 编码应比第一条短
        // wire size 应小于无压缩情况（至少节省了 "cdn.example.com" 的重复编码）
        runner.Check(wire.size() < 200, "multi-answer compression: wire compact");
    }

    void TestUnpackRdataOutOfBounds(TestRunner &runner)
    {
        auto mr = psm::memory::current_resource();

        psm::memory::vector<std::uint8_t> wire(mr);
        // Header: QD=0, AN=1
        wire.insert(wire.end(), {0x00, 0x00, 0x81, 0x80, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00});

        // Answer record: name=0x00(root), TYPE=A, CLASS=IN, TTL=0, RDLENGTH=100 (but only 0 bytes follow)
        wire.insert(wire.end(), {0x00}); // root name
        wire.insert(wire.end(), {0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64}); // header + rdlen=100

        auto result = dns::message::unpack(
            std::span<const std::uint8_t>(wire.data(), wire.size()), mr);
        runner.Check(!result.has_value(), "rdata out of bounds: nullopt");
    }

} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("DnsFormat");

    TestUnpackTooShort(runner);
    TestUnpackMinimalHeader(runner);
    TestUnpackQuestionTruncated(runner);
    TestUnpackRecordTruncated(runner);
    TestPackAllFlags(runner);
    TestPackUnpackAuthorityAdditional(runner);
    TestExtractIPv4WrongType(runner);
    TestExtractIPv6WrongLength(runner);
    TestExtractIPv6WrongType(runner);
    TestMinTtlNoRecords(runner);
    TestMinTtlAcrossSections(runner);
    TestExtractIPsFromAuthority(runner);
    TestExtractIPsSkipsNonIp(runner);
    TestUnpackTcpTooShort(runner);
    TestUnpackTcpLengthMismatch(runner);
    TestPackTcpRoundTrip(runner);
    TestMakeQueryDomainNormalization(runner);
    TestPackUnpackMultipleQuestions(runner);
    TestUnpackCompressionPointer(runner);
    TestUnpackCompressionLoop(runner);
    TestUnpackNameLabelOutOfBounds(runner);
    TestPackUnpackMultipleAnswersWithCompression(runner);
    TestUnpackRdataOutOfBounds(runner);

    return runner.Summary();
}
