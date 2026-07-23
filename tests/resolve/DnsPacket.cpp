/**
 * @file DnsPacket.cpp
 * @brief DNS 报文编解码单元测试
 * @details 测试 psm::dns::detail::message 的序列化/反序列化、
 * IPv4/IPv6 地址提取、TTL 计算以及 TCP 帧封装等功能。
 * 覆盖以下测试用例：
 * 1. 构造递归查询报文 (TestMakeQuery)
 * 2. Pack/Unpack 往返一致性 (TestPackUnpackRoundTrip)
 * 3. IPv4 地址提取 (TestExtractIPv4)
 * 4. IPv6 地址提取 (TestExtractIPv6)
 * 5. IPv4 错误长度处理 (TestExtractIPv4BadLength)
 * 6. 批量 IP 地址提取 (TestExtractIPs)
 * 7. 最小 TTL 计算 (TestMinTtl)
 * 8. TCP 帧封装与解析 (TestPackUnpackTcp)
 */

#include <prism/foundation/foundation.hpp>
#include <prism/net/dns/detail/format.hpp>
#include <prism/trace/spdlog.hpp>


#include <gtest/gtest.h>

#include <cstdint>
#include <optional>
#include <string_view>

namespace net = boost::asio;

namespace
{
    // ─── 构造递归查询报文 ─────────────────────────

    TEST(DnsPacket, MakeQuery)
    {
        psm::memory::resource_pointer mr = psm::memory::current_resource();

        auto msg = psm::dns::detail::message::make_query("example.com", psm::dns::detail::qtype::a, mr);

        EXPECT_TRUE(msg.id == 0) << "id should be 0 (unassigned)";
        EXPECT_TRUE(msg.rd) << "rd should be true (recursion desired)";
        EXPECT_TRUE(!msg.qr) << "qr should be false (query, not response)";
        EXPECT_TRUE(msg.questions.size() == 1) << "questions.size() should be 1";
        EXPECT_TRUE(msg.questions[0].name == "example.com") << "question name should be 'example.com'";
        EXPECT_TRUE(msg.questions[0].query_type == psm::dns::detail::qtype::a) << "question qtype should be A (1)";
    }

    // ─── Pack/Unpack 往返一致性 ──────────────────

    TEST(DnsPacket, PackUnpackRoundTripQuery)
    {
        psm::memory::resource_pointer mr = psm::memory::current_resource();

        auto original = psm::dns::detail::message::make_query("example.com", psm::dns::detail::qtype::a, mr);
        auto wire = original.pack();

        auto opt = psm::dns::detail::message::unpack(
            std::span<const std::uint8_t>(wire.data(), wire.size()), mr);
        ASSERT_TRUE(opt.has_value()) << "unpack query returned nullopt";

        auto &restored = *opt;

        EXPECT_TRUE(restored.id == original.id) << "query: id mismatch after round trip";
        EXPECT_TRUE(restored.rd) << "query: rd should be true after round trip";
        EXPECT_TRUE(restored.questions.size() == 1 && restored.questions[0].name == "example.com")
            << "query: question name mismatch after round trip";
        EXPECT_TRUE(restored.questions[0].query_type == psm::dns::detail::qtype::a)
            << "query: question qtype mismatch after round trip";
    }

    TEST(DnsPacket, PackUnpackRoundTripResponse)
    {
        psm::memory::resource_pointer mr = psm::memory::current_resource();

        psm::dns::detail::message msg(mr);
        msg.id = 0x1234;
        msg.qr = true;
        msg.rd = true;
        msg.ra = true;

        psm::dns::detail::question q(mr);
        q.name = "example.com";
        q.query_type = psm::dns::detail::qtype::a;
        msg.questions.push_back(std::move(q));

        psm::dns::detail::record ans(mr);
        ans.name = "example.com";
        ans.type = psm::dns::detail::qtype::a;
        ans.ttl = 300;
        ans.rdata = {8, 8, 8, 8};
        msg.answers.push_back(std::move(ans));

        auto wire = msg.pack();

        auto opt = psm::dns::detail::message::unpack(
            std::span<const std::uint8_t>(wire.data(), wire.size()), mr);
        ASSERT_TRUE(opt.has_value()) << "unpack response returned nullopt";

        auto &restored = *opt;

        EXPECT_TRUE(restored.id == 0x1234) << "response: id mismatch";
        EXPECT_TRUE(restored.qr) << "response: qr should be true";
        EXPECT_TRUE(restored.answers.size() == 1) << "response: answers count mismatch";
        EXPECT_TRUE(restored.answers[0].name == "example.com") << "response: answer name mismatch";
        EXPECT_TRUE(restored.answers[0].type == psm::dns::detail::qtype::a) << "response: answer type mismatch";
        EXPECT_TRUE(restored.answers[0].ttl == 300) << "response: answer TTL mismatch";
        EXPECT_TRUE(restored.answers[0].rdata.size() == 4 &&
                    restored.answers[0].rdata[0] == 8 &&
                    restored.answers[0].rdata[1] == 8 &&
                    restored.answers[0].rdata[2] == 8 &&
                    restored.answers[0].rdata[3] == 8)
            << "response: answer rdata mismatch";
    }

    // ─── IPv4 地址提取 ───────────────────────────

    TEST(DnsPacket, ExtractIPv4)
    {
        // 公网地址 8.8.8.8
        {
            psm::memory::resource_pointer mr = psm::memory::current_resource();
            psm::dns::detail::record rec(mr);
            rec.type = psm::dns::detail::qtype::a;
            rec.rdata = {8, 8, 8, 8};

            auto result = psm::dns::detail::extract_ipv4(rec);
            ASSERT_TRUE(result.has_value()) << "extract_ipv4 returned nullopt for 8.8.8.8";

            auto expected = net::ip::make_address_v4("8.8.8.8");
            EXPECT_TRUE(result->to_uint() == expected.to_uint()) << "extract_ipv4: 8.8.8.8 mismatch";
        }

        // 私有地址 192.168.1.1
        {
            psm::memory::resource_pointer mr = psm::memory::current_resource();
            psm::dns::detail::record rec(mr);
            rec.type = psm::dns::detail::qtype::a;
            rec.rdata = {192, 168, 1, 1};

            auto result = psm::dns::detail::extract_ipv4(rec);
            ASSERT_TRUE(result.has_value()) << "extract_ipv4 returned nullopt for 192.168.1.1";

            auto expected = net::ip::make_address_v4("192.168.1.1");
            EXPECT_TRUE(result->to_uint() == expected.to_uint()) << "extract_ipv4: 192.168.1.1 mismatch";
        }
    }

    // ─── IPv6 地址提取 ───────────────────────────

    TEST(DnsPacket, ExtractIPv6)
    {
        psm::memory::resource_pointer mr = psm::memory::current_resource();
        psm::dns::detail::record rec(mr);
        rec.type = psm::dns::detail::qtype::aaaa;
        rec.rdata = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};

        auto result = psm::dns::detail::extract_ipv6(rec);
        ASSERT_TRUE(result.has_value()) << "extract_ipv6 returned nullopt for ::1";

        auto expected = net::ip::make_address_v6("::1");
        EXPECT_TRUE(result->to_bytes() == expected.to_bytes()) << "extract_ipv6: ::1 mismatch";
    }

    // ─── IPv4 错误长度处理 ───────────────────────

    TEST(DnsPacket, ExtractIPv4BadLength)
    {
        psm::memory::resource_pointer mr = psm::memory::current_resource();

        // rdata 仅 3 字节
        {
            psm::dns::detail::record rec(mr);
            rec.rdata = {1, 2, 3};

            auto result = psm::dns::detail::extract_ipv4(rec);
            EXPECT_TRUE(!result.has_value()) << "extract_ipv4 should return nullopt for 3-byte rdata";
        }

        // rdata 有 5 字节
        {
            psm::dns::detail::record rec(mr);
            rec.rdata = {1, 2, 3, 4, 5};

            auto result = psm::dns::detail::extract_ipv4(rec);
            EXPECT_TRUE(!result.has_value()) << "extract_ipv4 should return nullopt for 5-byte rdata";
        }
    }

    // ─── 批量 IP 地址提取 ────────────────────────

    TEST(DnsPacket, ExtractIPs)
    {
        psm::memory::resource_pointer mr = psm::memory::current_resource();
        psm::dns::detail::message msg(mr);

        // A 记录：1.1.1.1
        {
            psm::dns::detail::record rec(mr);
            rec.name = "example.com";
            rec.type = psm::dns::detail::qtype::a;
            rec.ttl = 300;
            rec.rdata = {1, 1, 1, 1};
            msg.answers.push_back(std::move(rec));
        }

        // AAAA 记录：::1
        {
            psm::dns::detail::record rec(mr);
            rec.name = "example.com";
            rec.type = psm::dns::detail::qtype::aaaa;
            rec.ttl = 300;
            rec.rdata = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
            msg.answers.push_back(std::move(rec));
        }

        auto ips = msg.extract_ips();
        EXPECT_TRUE(ips.size() == 2) << "extract_ips should return 2 addresses";
    }

    // ─── 最小 TTL 计算 ──────────────────────────

    TEST(DnsPacket, MinTtl)
    {
        psm::memory::resource_pointer mr = psm::memory::current_resource();

        // 三条记录，TTL 分别为 300、600、60
        {
            psm::dns::detail::message msg(mr);

            psm::dns::detail::record r1(mr);
            r1.ttl = 300;
            msg.answers.push_back(std::move(r1));

            psm::dns::detail::record r2(mr);
            r2.ttl = 600;
            msg.answers.push_back(std::move(r2));

            psm::dns::detail::record r3(mr);
            r3.ttl = 60;
            msg.answers.push_back(std::move(r3));

            EXPECT_TRUE(msg.min_ttl() == 60) << "min_ttl should be 60";
        }

        // 单条记录，TTL=3600
        {
            psm::dns::detail::message msg(mr);

            psm::dns::detail::record r(mr);
            r.ttl = 3600;
            msg.answers.push_back(std::move(r));

            EXPECT_TRUE(msg.min_ttl() == 3600) << "min_ttl should be 3600 for single record";
        }
    }

    // ─── TCP 帧封装与解析 ────────────────────────

    TEST(DnsPacket, PackUnpackTcp)
    {
        psm::memory::resource_pointer mr = psm::memory::current_resource();

        auto original = psm::dns::detail::message::make_query("test.org", psm::dns::detail::qtype::aaaa, mr);
        auto wire = original.pack();

        psm::memory::vector<std::uint8_t> tcp_frame(mr);
        const auto wire_size = static_cast<std::uint16_t>(wire.size());
        tcp_frame.push_back(static_cast<std::uint8_t>((wire_size >> 8) & 0xFF));
        tcp_frame.push_back(static_cast<std::uint8_t>(wire_size & 0xFF));
        tcp_frame.insert(tcp_frame.end(), wire.begin(), wire.end());

        auto opt = psm::dns::detail::unpack_tcp(
            std::span<const std::uint8_t>(tcp_frame.data(), tcp_frame.size()), mr);
        ASSERT_TRUE(opt.has_value()) << "unpack_tcp returned nullopt";

        auto &restored = *opt;

        EXPECT_TRUE(restored.id == original.id) << "TCP round trip: id mismatch";
        EXPECT_TRUE(restored.questions.size() == original.questions.size())
            << "TCP round trip: question count mismatch";
        EXPECT_TRUE(restored.questions[0].name == "test.org") << "TCP round trip: question name mismatch";
        EXPECT_TRUE(restored.questions[0].query_type == psm::dns::detail::qtype::aaaa)
            << "TCP round trip: question qtype mismatch";
    }

} // namespace
