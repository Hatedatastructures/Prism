/**
 * @file TestCommonCodecDeep2.cpp
 * @brief 测试库 codec 第二轮剩余分支深度测试
 * @details 覆盖 hysteria2（地址 ipv4/ipv6 解析截断与成功、build_udp
 *          空目标、parser need_more）、anytls（认证帧长度不足）、
 *          reality（base64url 2 字节余数编码、非法字符解码、大写
 *          hex 分支）、socks5（remaining / take_remaining 空返回）。
 */

#include <boost/asio/buffer.hpp>

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include <common/core/error.hpp>
#include <common/protocols/hysteria2/codec.hpp>
#include <common/protocols/socks5/codec.hpp>
#include <common/protocols/anytls/codec.hpp>
#include <common/protocols/reality/codec.hpp>
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

    TEST(Hysteria2CodecDeep, ParseAddressBranches)
    {
        hysteria2::address addr{};
        std::size_t consumed = 0;

        // ipv4 数据不足
        EXPECT_EQ(hysteria2::parse_address(std::span<const std::uint8_t>(make_bytes({0x01, 8, 8})), addr,
                                           consumed),
                  error::need_more);
        // ipv6 数据不足
        EXPECT_EQ(hysteria2::parse_address(std::span<const std::uint8_t>(make_bytes({0x03, 1})), addr,
                                           consumed),
                  error::need_more);
        // ipv6 成功
        std::vector<std::uint8_t> v6{0x03};
        v6.insert(v6.end(), 16, 0x42);
        v6.push_back(0x00);
        v6.push_back(0x50);
        EXPECT_EQ(hysteria2::parse_address(v6, addr, consumed), error::none);
        EXPECT_EQ(addr.type, hysteria2::address_type::ipv6);
        EXPECT_EQ(addr.host, std::string(16, '\x42'));
        EXPECT_EQ(addr.port, 80u);
    }

    TEST(Hysteria2CodecDeep, BuildUdpNullDst)
    {
        hysteria2::udp_frame_input in{};
        in.payload = std::span<const std::uint8_t>{};
        EXPECT_TRUE(hysteria2::build_udp(in).empty());
    }

    TEST(Hysteria2CodecDeep, ParserNeedMore)
    {
        hysteria2::parser p;
        std::error_code ec;
        EXPECT_EQ(p.put(boost::asio::buffer(make_bytes({0x01, 0x01, 8})), ec), 0u);
        EXPECT_EQ(ec, make_error_code(error::need_more));
        p.reset();
        // 成功解析（ipv4）
        std::vector<std::uint8_t> ok{0x01, 0x01, 8, 8, 8, 8, 0x00, 0x35, 'x'};
        EXPECT_EQ(p.put(boost::asio::buffer(ok), ec), 9u);
        EXPECT_TRUE(p.is_done());
        EXPECT_EQ(p.get().dst.host, "8.8.8.8");
    }

    TEST(AnyTlsCodecDeep, ParseAuthFrameShort)
    {
        std::array<std::uint8_t, 32> hash{};
        std::uint16_t pad_len = 0;
        // 帧头不足
        EXPECT_EQ(anytls::parse_auth_frame(std::span<const std::uint8_t>(make_bytes({0x01})), hash, pad_len),
                  error::bad_length);
        // 头长足够但 padding 不足
        std::vector<std::uint8_t> short_pad(34, 0);
        short_pad[32] = 0x01; // pad_len = 256
        EXPECT_EQ(anytls::parse_auth_frame(short_pad, hash, pad_len), error::bad_length);
        // 成功
        std::vector<std::uint8_t> ok(34 + 5, 0);
        EXPECT_EQ(anytls::parse_auth_frame(ok, hash, pad_len), error::none);
    }

    TEST(RealityCodecDeep, Base64UrlBranches)
    {
        // 1 字节余数编码（i + 1 == size 分支）
        const std::array<std::uint8_t, 4> four{1, 2, 3, 4};
        const auto enc4 = reality::base64url_encode(four);
        EXPECT_EQ(enc4.size(), 6u);
        // 2 字节余数编码
        const std::array<std::uint8_t, 2> two{'a', 'b'};
        const auto enc2 = reality::base64url_encode(two);
        EXPECT_EQ(enc2.size(), 3u);
        // 3 字节整块 + 2 余数
        const std::array<std::uint8_t, 5> five{1, 2, 3, 4, 5};
        const auto enc5 = reality::base64url_encode(five);
        EXPECT_EQ(enc5.size(), 7u);
        // 3 字节余数分支（i + 2 == size）
        std::array<std::uint8_t, 8> eight{};
        eight.fill(0x55);
        EXPECT_EQ(reality::base64url_encode(eight).size(), 11u);
        // 往返一致性
        const auto dec = reality::base64url_decode(enc5);
        EXPECT_EQ(dec.size(), 5u);
        EXPECT_EQ(dec[0], 1u);

        // 非法字符解码 → 空
        EXPECT_TRUE(reality::base64url_decode("a!b").empty());
        // 大写字母解码分支
        const auto up = reality::base64url_decode("QUJD");
        EXPECT_EQ(up.size(), 3u);
        EXPECT_EQ(up[0], 'A');
        // 数字与小写分支
        const auto dn = reality::base64url_decode("YWJj");
        EXPECT_EQ(dn.size(), 3u);
        EXPECT_EQ(dn[0], 'a');

        // parse_short_id：大写 hex 分支 + 非法长度 + 成功
        std::array<std::uint8_t, reality::max_short_id_len> sid{};
        EXPECT_FALSE(reality::parse_short_id("ABCD1234", sid));
        EXPECT_EQ(sid[0], 0xAB);
        EXPECT_TRUE(reality::parse_short_id("ABC", sid));
        EXPECT_TRUE(reality::parse_short_id("ZZ", sid));
    }

    TEST(Socks5CodecDeep, RemainingEmpty)
    {
        socks5::parser p;
        std::error_code ec;
        // 未完成解析时 remaining / take_remaining 返回空
        EXPECT_TRUE(p.remaining().empty());
        EXPECT_TRUE(p.take_remaining().empty());
        // 完成后无剩余
        p.expect(socks5::message::kind::greeting);
        EXPECT_EQ(p.put(boost::asio::buffer(make_bytes({0x05, 0x01, 0x00})), ec), 3u);
        EXPECT_TRUE(p.is_done());
        EXPECT_TRUE(p.remaining().empty());
        EXPECT_TRUE(p.take_remaining().empty());
    }

} // namespace
