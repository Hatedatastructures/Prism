/**
 * @file TestCommonCodecDeep2.cpp
 * @brief 测试库 Codec 第二轮剩余分支深度测试
 * @details 覆盖 hysteria2（地址 ipv4/ipv6 解析截断与成功、BuildUdp
 *          空目标、Parser need_more）、anytls（认证帧长度不足）、
 *          reality（base64url 2 字节余数编码、非法字符解码、大写
 *          hex 分支）、socks5（Remaining / TakeRemaining 空返回）。
 */

#include <boost/asio/buffer.hpp>

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include <common/Core/Error.hpp>
#include <common/Protocols/Hysteria2/Codec.hpp>
#include <common/Protocols/Socks5/Codec.hpp>
#include <common/Protocols/Anytls/Codec.hpp>
#include <common/Protocols/Reality/Codec.hpp>
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

    TEST(Hysteria2CodecDeep, ParseAddressBranches)
    {
        Hysteria2::Address addr{};
        std::size_t consumed = 0;

        // ipv4 数据不足
        EXPECT_EQ(Hysteria2::ParseAddress(std::span<const std::uint8_t>(make_bytes({0x01, 8, 8})), addr,
                                           consumed),
                  Error::need_more);
        // ipv6 数据不足
        EXPECT_EQ(Hysteria2::ParseAddress(std::span<const std::uint8_t>(make_bytes({0x03, 1})), addr,
                                           consumed),
                  Error::need_more);
        // ipv6 成功
        std::vector<std::uint8_t> v6{0x03};
        v6.insert(v6.end(), 16, 0x42);
        v6.push_back(0x00);
        v6.push_back(0x50);
        EXPECT_EQ(Hysteria2::ParseAddress(v6, addr, consumed), Error::none);
        EXPECT_EQ(addr.Type, Hysteria2::AddressType::Ipv6);
        EXPECT_EQ(addr.Host, std::string(16, '\x42'));
        EXPECT_EQ(addr.Port, 80u);
    }

    TEST(Hysteria2CodecDeep, BuildUdpNullDst)
    {
        Hysteria2::UdpFrameInput in{};
        in.payload = std::span<const std::uint8_t>{};
        EXPECT_TRUE(Hysteria2::BuildUdp(in).empty());
    }

    TEST(Hysteria2CodecDeep, ParserNeedMore)
    {
        Hysteria2::Parser p;
        std::error_code ec;
        EXPECT_EQ(p.Put(boost::asio::buffer(make_bytes({0x01, 0x01, 8})), ec), 0u);
        EXPECT_EQ(ec, make_error_code(Error::need_more));
        p.Reset();
        // 成功解析（ipv4）
        std::vector<std::uint8_t> Ok{0x01, 0x01, 8, 8, 8, 8, 0x00, 0x35, 'x'};
        EXPECT_EQ(p.Put(boost::asio::buffer(Ok), ec), 9u);
        EXPECT_TRUE(p.IsDone());
        EXPECT_EQ(p.Get().dst.Host, "8.8.8.8");
    }

    TEST(AnyTlsCodecDeep, ParseAuthFrameShort)
    {
        std::array<std::uint8_t, 32> Hash{};
        std::uint16_t pad_len = 0;
        // 帧头不足
        EXPECT_EQ(Anytls::ParseAuthFrame(std::span<const std::uint8_t>(make_bytes({0x01})), Hash, pad_len),
                  Error::bad_length);
        // 头长足够但 padding 不足
        std::vector<std::uint8_t> short_pad(34, 0);
        short_pad[32] = 0x01; // pad_len = 256
        EXPECT_EQ(Anytls::ParseAuthFrame(short_pad, Hash, pad_len), Error::bad_length);
        // 成功
        std::vector<std::uint8_t> Ok(34 + 5, 0);
        EXPECT_EQ(Anytls::ParseAuthFrame(Ok, Hash, pad_len), Error::none);
    }

    TEST(RealityCodecDeep, Base64UrlBranches)
    {
        // 1 字节余数编码（i + 1 == Size 分支）
        const std::array<std::uint8_t, 4> four{1, 2, 3, 4};
        const auto enc4 = Reality::Base64urlEncode(four);
        EXPECT_EQ(enc4.size(), 6u);
        // 2 字节余数编码
        const std::array<std::uint8_t, 2> two{'a', 'b'};
        const auto enc2 = Reality::Base64urlEncode(two);
        EXPECT_EQ(enc2.size(), 3u);
        // 3 字节整块 + 2 余数
        const std::array<std::uint8_t, 5> five{1, 2, 3, 4, 5};
        const auto enc5 = Reality::Base64urlEncode(five);
        EXPECT_EQ(enc5.size(), 7u);
        // 3 字节余数分支（i + 2 == Size）
        std::array<std::uint8_t, 8> eight{};
        eight.fill(0x55);
        EXPECT_EQ(Reality::Base64urlEncode(eight).size(), 11u);
        // 往返一致性
        const auto dec = Reality::Base64urlDecode(enc5);
        EXPECT_EQ(dec.size(), 5u);
        EXPECT_EQ(dec[0], 1u);

        // 非法字符解码 → 空
        EXPECT_TRUE(Reality::Base64urlDecode("a!b").empty());
        // 大写字母解码分支
        const auto up = Reality::Base64urlDecode("QUJD");
        EXPECT_EQ(up.size(), 3u);
        EXPECT_EQ(up[0], 'A');
        // 数字与小写分支
        const auto dn = Reality::Base64urlDecode("YWJj");
        EXPECT_EQ(dn.size(), 3u);
        EXPECT_EQ(dn[0], 'a');

        // ParseShortId：大写 hex 分支 + 非法长度 + 成功
        std::array<std::uint8_t, Reality::MaxShortIdLen> sid{};
        EXPECT_FALSE(Reality::ParseShortId("ABCD1234", sid));
        EXPECT_EQ(sid[0], 0xAB);
        EXPECT_TRUE(Reality::ParseShortId("ABC", sid));
        EXPECT_TRUE(Reality::ParseShortId("ZZ", sid));
    }

    TEST(Socks5CodecDeep, RemainingEmpty)
    {
        Socks5::Parser p;
        std::error_code ec;
        // 未完成解析时 Remaining / TakeRemaining 返回空
        EXPECT_TRUE(p.Remaining().empty());
        EXPECT_TRUE(p.TakeRemaining().empty());
        // 完成后无剩余
        p.Expect(Socks5::Message::Kind::Greeting);
        EXPECT_EQ(p.Put(boost::asio::buffer(make_bytes({0x05, 0x01, 0x00})), ec), 3u);
        EXPECT_TRUE(p.IsDone());
        EXPECT_TRUE(p.Remaining().empty());
        EXPECT_TRUE(p.TakeRemaining().empty());
    }

} // namespace
