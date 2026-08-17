/**
 * @file TrojanCodecDeep.cpp
 * @brief Trojan codec 剩余分支深度测试
 * @details 覆盖 encode_address ipv6 分支、parse_request 的 ipv4/ipv6
 *          need_more 与 ipv6 成功路径，以及 parser 的 need_more /
 *          bad_magic / auth_failed 错误分支。
 */

#include <boost/asio/buffer.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

#include <common/core/error.hpp>
#include <common/protocols/trojan/codec.hpp>
#include <gtest/gtest.h>

namespace
{
    using namespace preview;

    /**
     * @brief 从初始值列表构造字节向量
     */
    auto make_bytes(std::initializer_list<std::uint8_t> list) -> std::vector<std::uint8_t>
    {
        return std::vector<std::uint8_t>(list);
    }

    TEST(TrojanCodecDeep, EncodeAddressIpv6)
    {
        trojan::address addr{};
        addr.type = trojan::address_type::ipv6;
        addr.host.assign(16, 'q');
        addr.port = 8080;
        const auto wire = trojan::encode_address(addr);
        EXPECT_EQ(wire.size(), 19u);
        EXPECT_EQ(wire[0], 0x04);
        EXPECT_EQ(wire[1], 'q');
        EXPECT_EQ(wire[17], 0x1F);
        EXPECT_EQ(wire[18], 0x90);

        // credential 输出 hex
        const auto cred = trojan::credential("pw");
        EXPECT_EQ(cred.size(), trojan::credential_len);
        for (const auto c : cred)
        {
            EXPECT_TRUE((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'));
        }
    }

    TEST(TrojanCodecDeep, ParseRequestAddressBranches)
    {
        const auto cred = trojan::credential("pw");
        std::vector<std::uint8_t> base(cred.begin(), cred.end());
        base.push_back('\r');
        base.push_back('\n');
        base.push_back(0x01); // cmd connect

        trojan::request_header hdr{};
        std::size_t consumed = 0;

        // ipv4 数据不足
        std::vector<std::uint8_t> v4 = base;
        v4.push_back(0x01);
        v4.push_back(8);
        v4.push_back(8);
        EXPECT_EQ(trojan::parse_request(v4, hdr, consumed), error::need_more);

        // ipv6 数据不足
        std::vector<std::uint8_t> v6 = base;
        v6.push_back(0x04);
        v6.insert(v6.end(), 3, 0x42);
        EXPECT_EQ(trojan::parse_request(v6, hdr, consumed), error::need_more);

        // ipv6 成功
        std::vector<std::uint8_t> v6ok = base;
        v6ok.push_back(0x04);
        v6ok.insert(v6ok.end(), 16, 0x42);
        v6ok.push_back(0x01);
        v6ok.push_back(0xBB);
        v6ok.push_back('\r');
        v6ok.push_back('\n');
        EXPECT_EQ(trojan::parse_request(v6ok, hdr, consumed), error::none);
        EXPECT_EQ(hdr.target.type, trojan::address_type::ipv6);
        EXPECT_EQ(hdr.target.host, std::string(16, '\x42'));
        EXPECT_EQ(hdr.target.port, 443u);
    }

    TEST(TrojanCodecDeep, ParserErrorBranches)
    {
        const auto cred = trojan::credential("pw");
        trojan::parser p("pw");
        std::error_code ec;

        // need_more
        EXPECT_EQ(p.put(boost::asio::buffer(make_bytes({0x01})), ec), 0u);
        EXPECT_EQ(ec, make_error_code(error::need_more));
        p.reset();

        // bad_magic（CRLF 缺失）
        std::vector<std::uint8_t> bad(cred.begin(), cred.end());
        bad.push_back('X');
        bad.push_back('\n');
        EXPECT_EQ(p.put(boost::asio::buffer(bad), ec), 0u);
        EXPECT_EQ(ec, make_error_code(error::bad_magic));
        p.reset();

        // auth_failed（CRLF 正确但凭据不匹配）
        std::vector<std::uint8_t> wrong(cred.size(), 'f');
        wrong.push_back('\r');
        wrong.push_back('\n');
        wrong.push_back(0x01);
        wrong.push_back(0x01);
        wrong.insert(wrong.end(), 4, 8);
        wrong.push_back(0x00);
        wrong.push_back(0x35);
        wrong.push_back('\r');
        wrong.push_back('\n');
        EXPECT_EQ(p.put(boost::asio::buffer(wrong), ec), 0u);
        EXPECT_EQ(ec, make_error_code(error::auth_failed));
        p.reset();

        // 成功（正确凭据 + ipv4 + CRLF 结尾）
        std::vector<std::uint8_t> ok(cred.begin(), cred.end());
        ok.push_back('\r');
        ok.push_back('\n');
        ok.push_back(0x01);
        ok.push_back(0x01);
        ok.insert(ok.end(), 4, 8);
        ok.push_back(0x00);
        ok.push_back(0x35);
        ok.push_back('\r');
        ok.push_back('\n');
        EXPECT_EQ(p.put(boost::asio::buffer(ok), ec), ok.size());
        EXPECT_TRUE(p.is_done());
        EXPECT_TRUE(p.get().valid);
        EXPECT_FALSE(p.get().udp);
        EXPECT_EQ(p.get().dst.host, "8.8.8.8");

        // UDP 命令 → udp 标志
        p.reset();
        ok[57 + 1] = 0x03; // cmd = udp_associate
        EXPECT_EQ(p.put(boost::asio::buffer(ok), ec), ok.size());
        EXPECT_TRUE(p.get().udp);
    }

} // namespace
