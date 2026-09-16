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

#include <Preview/Foundation/Error.hpp>
#include <Preview/Protocols/Trojan/Codec.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    namespace Trojan = Preview::Trojan;
    using Preview::Error;
    using Preview::make_error_code;

    /**
     * @brief 从初始值列表构造字节向量
     */
    auto MakeBytes(std::initializer_list<std::uint8_t> List) -> std::vector<std::uint8_t>
    {
        return std::vector<std::uint8_t>(List);
    }

    TEST(TrojanCodecDeep, EncodeAddressIpv6)
    {
        Trojan::Address Address{};
        Address.Type = Trojan::AddressType::Ipv6;
        Address.Host.assign(16, 'q');
        Address.Port = 8080;
        const auto Wire = Trojan::EncodeAddress(Address);
        EXPECT_EQ(Wire.size(), 19u);
        EXPECT_EQ(Wire[0], 0x04);
        EXPECT_EQ(Wire[1], 'q');
        EXPECT_EQ(Wire[17], 0x1F);
        EXPECT_EQ(Wire[18], 0x90);

        // Credential 输出 hex
        const auto Credential = Trojan::Credential("pw");
        EXPECT_EQ(Credential.size(), Trojan::CredentialLen);
        for (const auto Char : Credential)
        {
            EXPECT_TRUE((Char >= '0' && Char <= '9') || (Char >= 'a' && Char <= 'f'));
        }
    }

    TEST(TrojanCodecDeep, ParseRequestAddressBranches)
    {
        const auto Credential = Trojan::Credential("pw");
        std::vector<std::uint8_t> Base(Credential.begin(), Credential.end());
        Base.push_back('\r');
        Base.push_back('\n');
        Base.push_back(0x01); // cmd Connect

        Trojan::RequestHeader Header{};
        std::size_t Consumed = 0;

        // ipv4 数据不足
        std::vector<std::uint8_t> V4 = Base;
        V4.push_back(0x01);
        V4.push_back(8);
        V4.push_back(8);
        EXPECT_EQ(Trojan::ParseRequest(V4, Header, Consumed), Error::NeedMore);

        // ipv6 数据不足
        std::vector<std::uint8_t> V6 = Base;
        V6.push_back(0x04);
        V6.insert(V6.end(), 3, 0x42);
        EXPECT_EQ(Trojan::ParseRequest(V6, Header, Consumed), Error::NeedMore);

        // ipv6 成功
        std::vector<std::uint8_t> V6Ok = Base;
        V6Ok.push_back(0x04);
        V6Ok.insert(V6Ok.end(), 16, 0x42);
        V6Ok.push_back(0x01);
        V6Ok.push_back(0xBB);
        V6Ok.push_back('\r');
        V6Ok.push_back('\n');
        EXPECT_EQ(Trojan::ParseRequest(V6Ok, Header, Consumed), Error::None);
        EXPECT_EQ(Header.Target.Type, Trojan::AddressType::Ipv6);
        EXPECT_EQ(Header.Target.Host, std::string(16, '\x42'));
        EXPECT_EQ(Header.Target.Port, 443u);
    }

    TEST(TrojanCodecDeep, ParserErrorBranches)
    {
        const auto Credential = Trojan::Credential("pw");
        Trojan::Parser Parser("pw");
        std::error_code ErrorCode;

        // need_more
        EXPECT_EQ(Parser.Put(Net::buffer(MakeBytes({0x01})), ErrorCode), 0u);
        EXPECT_EQ(ErrorCode, make_error_code(Error::NeedMore));
        Parser.Reset();

        // bad_magic（CRLF 缺失）
        std::vector<std::uint8_t> Bad(Credential.begin(), Credential.end());
        Bad.push_back('X');
        Bad.push_back('\n');
        EXPECT_EQ(Parser.Put(Net::buffer(Bad), ErrorCode), 0u);
        EXPECT_EQ(ErrorCode, make_error_code(Error::BadMagic));
        Parser.Reset();

        // auth_failed（CRLF 正确但凭据不匹配）
        std::vector<std::uint8_t> Wrong(Credential.size(), 'f');
        Wrong.push_back('\r');
        Wrong.push_back('\n');
        Wrong.push_back(0x01);
        Wrong.push_back(0x01);
        Wrong.insert(Wrong.end(), 4, 8);
        Wrong.push_back(0x00);
        Wrong.push_back(0x35);
        Wrong.push_back('\r');
        Wrong.push_back('\n');
        EXPECT_EQ(Parser.Put(Net::buffer(Wrong), ErrorCode), 0u);
        EXPECT_EQ(ErrorCode, make_error_code(Error::AuthFailed));
        Parser.Reset();

        // 成功（正确凭据 + ipv4 + CRLF 结尾）
        std::vector<std::uint8_t> Ok(Credential.begin(), Credential.end());
        Ok.push_back('\r');
        Ok.push_back('\n');
        Ok.push_back(0x01);
        Ok.push_back(0x01);
        Ok.insert(Ok.end(), 4, 8);
        Ok.push_back(0x00);
        Ok.push_back(0x35);
        Ok.push_back('\r');
        Ok.push_back('\n');
        EXPECT_EQ(Parser.Put(Net::buffer(Ok), ErrorCode), Ok.size());
        EXPECT_TRUE(Parser.IsDone());
        EXPECT_TRUE(Parser.Get().valid);
        EXPECT_FALSE(Parser.Get().udp);
        EXPECT_EQ(Parser.Get().dst.Host, "8.8.8.8");

        // UDP 命令 → udp 标志
        Parser.Reset();
        Ok[57 + 1] = 0x03; // cmd = udp_associate
        EXPECT_EQ(Parser.Put(Net::buffer(Ok), ErrorCode), Ok.size());
        EXPECT_TRUE(Parser.Get().udp);
    }

} // namespace
