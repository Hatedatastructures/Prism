/**
 * @file DnsFormat.cpp
 * @brief DNS 报文编解码补充单元测试
 * @details 补充 DnsPacket.cpp 未覆盖的边界条件和错误路径：
 *          unpack 短缓冲区、域名压缩指针循环、多段记录、
 *          extract_ipv4/ipv6 类型不匹配、min_ttl 空记录、
 *          unpack_tcp 短数据和长度不匹配、pack_tcp 往返、
 *          extract_ips 遍历 authority/additional 段。
 */

#include <prism/core/core.hpp>
#include <prism/net/resolve/dns/detail/format.hpp>
#include <prism/trace/spdlog.hpp>

#include <cstdint>
#include <cstring>
#include <optional>
#include <string_view>


#include <gtest/gtest.h>

namespace
{
    namespace dns = psm::resolve::dns::detail;

    TEST(DnsFormat, UnpackTooShort)
    {
        const std::uint8_t data[] = {0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        auto result = dns::message::unpack(data);
        EXPECT_TRUE(!result.has_value()) << "unpack: 11 bytes -> nullopt";
    }

    TEST(DnsFormat, UnpackMinimalHeader)
    {
        std::uint8_t data[12]{};
        data[0] = 0x12;
        data[1] = 0x34;
        data[2] = 0x81;
        data[3] = 0x80;

        auto result = dns::message::unpack(data);
        EXPECT_TRUE(result.has_value()) << "unpack minimal header: has_value";
        EXPECT_TRUE(result->id == 0x1234) << "unpack minimal header: id=0x1234";
        EXPECT_TRUE(result->qr == true) << "unpack minimal header: qr=true";
        EXPECT_TRUE(result->rd == true) << "unpack minimal header: rd=true";
        EXPECT_TRUE(result->ra == true) << "unpack minimal header: ra=true";
        EXPECT_TRUE(result->questions.empty()) << "unpack minimal header: no questions";
        EXPECT_TRUE(result->answers.empty()) << "unpack minimal header: no answers";
    }

    TEST(DnsFormat, UnpackQuestionTruncated)
    {
        std::uint8_t data[14]{};
        data[4] = 0x00;
        data[5] = 0x01;
        auto result = dns::message::unpack(data);
        EXPECT_TRUE(!result.has_value()) << "unpack question truncated: nullopt";
    }

    TEST(DnsFormat, UnpackRecordTruncated)
    {
        auto mr = psm::memory::current_resource();
        auto msg = dns::message::make_query("test.com", dns::qtype::a, mr);
        auto wire = msg.pack();

        wire[6] = 0x00;
        wire[7] = 0x01;

        auto result = dns::message::unpack(
            std::span<const std::uint8_t>(wire.data(), wire.size()), mr);
        EXPECT_TRUE(!result.has_value()) << "unpack record truncated: nullopt";
    }

    TEST(DnsFormat, PackAllFlags)
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
        EXPECT_TRUE(wire.size() >= 12) << "pack all flags: size >= 12";

        auto restored = dns::message::unpack(
            std::span<const std::uint8_t>(wire.data(), wire.size()), mr);
        EXPECT_TRUE(restored.has_value()) << "pack all flags: unpack success";
        EXPECT_TRUE(restored->id == 0xABCD) << "pack all flags: id=0xABCD";
        EXPECT_TRUE(restored->qr == true) << "pack all flags: qr=true";
        EXPECT_TRUE(restored->opcode == 0x0F) << "pack all flags: opcode=0x0F";
        EXPECT_TRUE(restored->aa == true) << "pack all flags: aa=true";
        EXPECT_TRUE(restored->tc == true) << "pack all flags: tc=true";
        EXPECT_TRUE(restored->rd == true) << "pack all flags: rd=true";
        EXPECT_TRUE(restored->ra == true) << "pack all flags: ra=true";
        EXPECT_TRUE(restored->rcode == 0x0F) << "pack all flags: rcode=0x0F";
    }

    TEST(DnsFormat, PackUnpackAuthorityAdditional)
    {
        auto mr = psm::memory::current_resource();
        dns::message msg(mr);
        msg.id = 0x0001;
        msg.qr = true;
        msg.rd = true;
        msg.ra = true;

        dns::record ns_rec(mr);
        ns_rec.name = "example.com";
        ns_rec.type = dns::qtype::ns;
        ns_rec.ttl = 3600;
        const char ns_name[] = "a.iana-servers.net";
        ns_rec.rdata.assign(ns_name, ns_name + sizeof(ns_name) - 1);
        msg.authority.push_back(std::move(ns_rec));

        dns::record add_rec(mr);
        add_rec.name = "a.iana-servers.net";
        add_rec.type = dns::qtype::a;
        add_rec.ttl = 300;
        add_rec.rdata = {199, 43, 135, 53};
        msg.additional.push_back(std::move(add_rec));

        auto wire = msg.pack();
        auto restored = dns::message::unpack(
            std::span<const std::uint8_t>(wire.data(), wire.size()), mr);

        EXPECT_TRUE(restored.has_value()) << "pack authority/additional: unpack success";
        EXPECT_TRUE(restored->authority.size() == 1) << "pack authority: 1 record";
        EXPECT_TRUE(restored->additional.size() == 1) << "pack additional: 1 record";
        EXPECT_TRUE(restored->authority[0].type == dns::qtype::ns) << "pack authority: type=ns";
        EXPECT_TRUE(restored->additional[0].type == dns::qtype::a) << "pack additional: type=a";
    }

    TEST(DnsFormat, ExtractIPv4WrongType)
    {
        auto mr = psm::memory::current_resource();
        dns::record rec(mr);
        rec.type = dns::qtype::aaaa;
        rec.rdata = {1, 2, 3, 4};
        auto result = dns::extract_ipv4(rec);
        EXPECT_TRUE(!result.has_value()) << "extract_ipv4 wrong type: nullopt";
    }

    TEST(DnsFormat, ExtractIPv6WrongLength)
    {
        auto mr = psm::memory::current_resource();
        dns::record rec(mr);
        rec.type = dns::qtype::aaaa;
        rec.rdata = {0, 0, 0, 0, 0, 0, 0, 0};
        auto result = dns::extract_ipv6(rec);
        EXPECT_TRUE(!result.has_value()) << "extract_ipv6 wrong length: nullopt";
    }

    TEST(DnsFormat, ExtractIPv6WrongType)
    {
        auto mr = psm::memory::current_resource();
        dns::record rec(mr);
        rec.type = dns::qtype::a;
        rec.rdata.assign(16, 0);
        auto result = dns::extract_ipv6(rec);
        EXPECT_TRUE(!result.has_value()) << "extract_ipv6 wrong type: nullopt";
    }

    TEST(DnsFormat, MinTtlNoRecords)
    {
        auto mr = psm::memory::current_resource();
        dns::message msg(mr);
        EXPECT_TRUE(msg.min_ttl() == 0) << "min_ttl no records: 0";
    }

    TEST(DnsFormat, MinTtlAcrossSections)
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

        EXPECT_TRUE(msg.min_ttl() == 60) << "min_ttl across sections: 60";
    }

    TEST(DnsFormat, ExtractIPsFromAuthority)
    {
        auto mr = psm::memory::current_resource();
        dns::message msg(mr);

        dns::record auth(mr);
        auth.type = dns::qtype::a;
        auth.rdata = {10, 0, 0, 1};
        msg.authority.push_back(std::move(auth));

        dns::record add(mr);
        add.type = dns::qtype::aaaa;
        add.rdata.assign(16, 0);
        add.rdata[15] = 1;
        msg.additional.push_back(std::move(add));

        auto ips = msg.extract_ips();
        EXPECT_TRUE(ips.size() == 2) << "extract_ips from auth/addl: 2 addresses";
    }

    TEST(DnsFormat, ExtractIPsSkipsNonIp)
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
        EXPECT_TRUE(ips.size() == 1) << "extract_ips skips non-IP: 1 address";
    }

    TEST(DnsFormat, UnpackTcpTooShort)
    {
        const std::uint8_t data[] = {0x00};
        auto result = dns::unpack_tcp(data);
        EXPECT_TRUE(!result.has_value()) << "unpack_tcp short: nullopt";
    }

    TEST(DnsFormat, UnpackTcpLengthMismatch)
    {
        const std::uint8_t data[] = {0x00, 0x64, 0x00, 0x00};
        auto result = dns::unpack_tcp(data);
        EXPECT_TRUE(!result.has_value()) << "unpack_tcp length mismatch: nullopt";
    }

    TEST(DnsFormat, PackTcpRoundTrip)
    {
        auto mr = psm::memory::current_resource();
        auto msg = dns::message::make_query("tcp-test.org", dns::qtype::aaaa, mr);

        auto wire = msg.pack();
        psm::memory::vector<std::uint8_t> tcp_frame(mr);
        const auto sz = static_cast<std::uint16_t>(wire.size());
        tcp_frame.push_back(static_cast<std::uint8_t>((sz >> 8) & 0xFF));
        tcp_frame.push_back(static_cast<std::uint8_t>(sz & 0xFF));
        tcp_frame.insert(tcp_frame.end(), wire.begin(), wire.end());

        auto restored = dns::unpack_tcp(
            std::span<const std::uint8_t>(tcp_frame.data(), tcp_frame.size()), mr);
        EXPECT_TRUE(restored.has_value()) << "tcp round trip: has_value";
        EXPECT_TRUE(restored->questions.size() == 1) << "tcp round trip: 1 question";
        EXPECT_TRUE(restored->questions[0].name == "tcp-test.org") << "tcp round trip: name match";
        EXPECT_TRUE(restored->questions[0].query_type == dns::qtype::aaaa) << "tcp round trip: qtype=aaaa";
    }

    TEST(DnsFormat, MakeQueryDomainNormalization)
    {
        auto mr = psm::memory::current_resource();

        auto msg = dns::message::make_query("Example.COM.", dns::qtype::a, mr);
        EXPECT_TRUE(msg.questions[0].name == "example.com") << "make_query: lower + strip dot";

        auto msg2 = dns::message::make_query("UPPERCASE.NET", dns::qtype::aaaa, mr);
        EXPECT_TRUE(msg2.questions[0].name == "uppercase.net") << "make_query: lowercase";
    }

    TEST(DnsFormat, PackUnpackMultipleQuestions)
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

        EXPECT_TRUE(restored.has_value()) << "multiple questions: unpack success";
        EXPECT_TRUE(restored->questions.size() == 2) << "multiple questions: count=2";
        EXPECT_TRUE(restored->questions[0].name == "a.com") << "multiple questions: q1 name";
        EXPECT_TRUE(restored->questions[0].query_type == dns::qtype::a) << "multiple questions: q1 type=a";
        EXPECT_TRUE(restored->questions[1].name == "b.com") << "multiple questions: q2 name";
        EXPECT_TRUE(restored->questions[1].query_type == dns::qtype::aaaa) << "multiple questions: q2 type=aaaa";
    }

    TEST(DnsFormat, UnpackCompressionPointer)
    {
        auto mr = psm::memory::current_resource();

        psm::memory::vector<std::uint8_t> wire(mr);

        wire.insert(wire.end(), {0x00, 0x01, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00});
        wire.insert(wire.end(), {0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00});
        wire.insert(wire.end(), {0x00, 0x01, 0x00, 0x01});
        wire.insert(wire.end(), {0xC0, 0x0C});
        wire.insert(wire.end(), {0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04});
        wire.insert(wire.end(), {0x01, 0x02, 0x03, 0x04});

        auto result = dns::message::unpack(
            std::span<const std::uint8_t>(wire.data(), wire.size()), mr);
        EXPECT_TRUE(result.has_value()) << "compression pointer: unpack success";
        EXPECT_TRUE(result->answers.size() == 1) << "compression pointer: 1 answer";
        EXPECT_TRUE(result->answers[0].name == "example.com") << "compression pointer: name match";
        EXPECT_TRUE(result->answers[0].ttl == 60) << "compression pointer: ttl=60";

        auto ip = dns::extract_ipv4(result->answers[0]);
        EXPECT_TRUE(ip.has_value()) << "compression pointer: extract_ipv4 success";
        auto expected = boost::asio::ip::make_address_v4("1.2.3.4");
        EXPECT_TRUE(ip->to_uint() == expected.to_uint()) << "compression pointer: ip=1.2.3.4";
    }

    TEST(DnsFormat, UnpackCompressionLoop)
    {
        auto mr = psm::memory::current_resource();

        psm::memory::vector<std::uint8_t> wire(mr);
        wire.insert(wire.end(), {0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
        wire.insert(wire.end(), {0xC0, 0x0C});
        wire.insert(wire.end(), {0x00, 0x01, 0x00, 0x01});

        auto result = dns::message::unpack(
            std::span<const std::uint8_t>(wire.data(), wire.size()), mr);
        if (result.has_value())
        {
            EXPECT_TRUE(result->questions[0].name.empty()) << "compression loop: empty name or nullopt acceptable";
        }
    }

    TEST(DnsFormat, UnpackNameLabelOutOfBounds)
    {
        auto mr = psm::memory::current_resource();

        psm::memory::vector<std::uint8_t> wire(mr);
        wire.insert(wire.end(), {0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
        wire.insert(wire.end(), {0xC8});
        wire.insert(wire.end(), {0x00, 0x01, 0x00, 0x01});

        auto result = dns::message::unpack(
            std::span<const std::uint8_t>(wire.data(), wire.size()), mr);
        if (!result.has_value())
        {
            // unpack 返回 nullopt 表示格式错误，合理行为
        }
        else
        {
            EXPECT_TRUE(result->questions.empty() || result->questions[0].name.empty())
                << "label out of bounds: empty or missing name";
        }
    }

    TEST(DnsFormat, PackUnpackMultipleAnswersWithCompression)
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

        EXPECT_TRUE(restored.has_value()) << "multi-answer compression: unpack success";
        EXPECT_TRUE(restored->answers.size() == 2) << "multi-answer compression: 2 answers";
        EXPECT_TRUE(restored->answers[0].name == "cdn.example.com") << "multi-answer: ans0 name";
        EXPECT_TRUE(restored->answers[1].name == "cdn.example.com") << "multi-answer: ans1 name";
        EXPECT_TRUE(wire.size() < 200) << "multi-answer compression: wire compact";
    }

    TEST(DnsFormat, UnpackRdataOutOfBounds)
    {
        auto mr = psm::memory::current_resource();

        psm::memory::vector<std::uint8_t> wire(mr);
        wire.insert(wire.end(), {0x00, 0x00, 0x81, 0x80, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00});
        wire.insert(wire.end(), {0x00});
        wire.insert(wire.end(), {0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64});

        auto result = dns::message::unpack(
            std::span<const std::uint8_t>(wire.data(), wire.size()), mr);
        EXPECT_TRUE(!result.has_value()) << "rdata out of bounds: nullopt";
    }

} // namespace
