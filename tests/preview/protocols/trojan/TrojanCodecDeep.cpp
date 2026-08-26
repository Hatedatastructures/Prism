/**
 * @file TrojanCodecDeep.cpp
 * @brief Trojan Codec 剩余分支深度测试
 * @details 覆盖 EncodeAddress ipv6 分支、ParseRequest 的 ipv4/ipv6
 *          need_more 与 ipv6 成功路径，以及 Parser 的 need_more /
 *          bad_magic / auth_failed 错误分支。
 */

#include <boost/asio/buffer.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

#include <common/Core/Error.hpp>
#include <common/Protocols/Trojan/Codec.hpp>
#include <gtest/gtest.h>

namespace
{
    using namespace Preview;

    /**
     * @brief 从初始值列表构造字节向量
     */
    auto make_bytes(std::initializer_list<std::uint8_t> List) -> std::vector<std::uint8_t>
    {
        return std::vector<std::uint8_t>(List);
    }

    TEST(TrojanCodecDeep, EncodeAddressIpv6)
    {
        Trojan::Address addr{};
        addr.Type = Trojan::AddressType::Ipv6;
        addr.Host.assign(16, 'q');
        addr.Port = 8080;
        const auto wire = Trojan::EncodeAddress(addr);
        EXPECT_EQ(wire.size(), 19u);
        EXPECT_EQ(wire[0], 0x04);
        EXPECT_EQ(wire[1], 'q');
        EXPECT_EQ(wire[17], 0x1F);
        EXPECT_EQ(wire[18], 0x90);

        // Credential 输出 hex
        const auto cred = Trojan::Credential("pw");
        EXPECT_EQ(cred.size(), Trojan::CredentialLen);
        for (const auto c : cred)
        {
            EXPECT_TRUE((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'));
        }
    }

    TEST(TrojanCodecDeep, ParseRequestAddressBranches)
    {
        const auto cred = Trojan::Credential("pw");
        std::vector<std::uint8_t> base(cred.begin(), cred.end());
        base.push_back('\r');
        base.push_back('\n');
        base.push_back(0x01); // cmd Connect

        Trojan::RequestHeader hdr{};
        std::size_t consumed = 0;

        // ipv4 数据不足
        std::vector<std::uint8_t> v4 = base;
        v4.push_back(0x01);
        v4.push_back(8);
        v4.push_back(8);
        EXPECT_EQ(Trojan::ParseRequest(v4, hdr, consumed), Error::NeedMore);

        // ipv6 数据不足
        std::vector<std::uint8_t> v6 = base;
        v6.push_back(0x04);
        v6.insert(v6.end(), 3, 0x42);
        EXPECT_EQ(Trojan::ParseRequest(v6, hdr, consumed), Error::NeedMore);

        // ipv6 成功
        std::vector<std::uint8_t> v6ok = base;
        v6ok.push_back(0x04);
        v6ok.insert(v6ok.end(), 16, 0x42);
        v6ok.push_back(0x01);
        v6ok.push_back(0xBB);
        v6ok.push_back('\r');
        v6ok.push_back('\n');
        EXPECT_EQ(Trojan::ParseRequest(v6ok, hdr, consumed), Error::None);
        EXPECT_EQ(hdr.Target.Type, Trojan::AddressType::Ipv6);
        EXPECT_EQ(hdr.Target.Host, std::string(16, '\x42'));
        EXPECT_EQ(hdr.Target.Port, 443u);
    }

    TEST(TrojanCodecDeep, ParserErrorBranches)
    {
        const auto cred = Trojan::Credential("pw");
        Trojan::Parser p("pw");
        std::error_code ec;

        // need_more
        EXPECT_EQ(p.Put(boost::asio::buffer(make_bytes({0x01})), ec), 0u);
        EXPECT_EQ(ec, make_error_code(Error::NeedMore));
        p.Reset();

        // bad_magic（CRLF 缺失）
        std::vector<std::uint8_t> bad(cred.begin(), cred.end());
        bad.push_back('X');
        bad.push_back('\n');
        EXPECT_EQ(p.Put(boost::asio::buffer(bad), ec), 0u);
        EXPECT_EQ(ec, make_error_code(Error::BadMagic));
        p.Reset();

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
        EXPECT_EQ(p.Put(boost::asio::buffer(wrong), ec), 0u);
        EXPECT_EQ(ec, make_error_code(Error::AuthFailed));
        p.Reset();

        // 成功（正确凭据 + ipv4 + CRLF 结尾）
        std::vector<std::uint8_t> Ok(cred.begin(), cred.end());
        Ok.push_back('\r');
        Ok.push_back('\n');
        Ok.push_back(0x01);
        Ok.push_back(0x01);
        Ok.insert(Ok.end(), 4, 8);
        Ok.push_back(0x00);
        Ok.push_back(0x35);
        Ok.push_back('\r');
        Ok.push_back('\n');
        EXPECT_EQ(p.Put(boost::asio::buffer(Ok), ec), Ok.size());
        EXPECT_TRUE(p.IsDone());
        EXPECT_TRUE(p.Get().valid);
        EXPECT_FALSE(p.Get().udp);
        EXPECT_EQ(p.Get().dst.Host, "8.8.8.8");

        // UDP 命令 → udp 标志
        p.Reset();
        Ok[57 + 1] = 0x03; // cmd = udp_associate
        EXPECT_EQ(p.Put(boost::asio::buffer(Ok), ec), Ok.size());
        EXPECT_TRUE(p.Get().udp);
    }

} // namespace
