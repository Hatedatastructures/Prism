/**
 * @file TuicCodecDeepTest.cpp
 * @brief TUIC 地址和解析器边界测试。
 */

#include <boost/asio/buffer.hpp>
#include <gtest/gtest.h>
#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>
#include <Prism/Foundation/ByteSpan.hpp>
#include <Prism/Foundation/Error.hpp>
#include <Prism/Protocols/Tuic/Codec.hpp>

namespace
{
    namespace Net = boost::asio;
    namespace Tuic = Prism::Tuic;
    using Prism::As;
    using Prism::AsBytes;
    using Prism::AsBytesSpan;
    using Prism::AsStrView;
    using Prism::AsU8;
    using Prism::AsU8Span;
    using Prism::Error;
    using Prism::make_error_code;

auto MakeBytes(std::initializer_list<std::uint8_t> List) -> std::vector<std::uint8_t>
    {
        return std::vector<std::uint8_t>(List);
    }
} // namespace

TEST(TuicCodecDeep, ParseAddressBranches)
    {
        Tuic::Address Address{};
        std::size_t Consumed = 0;
        // ipv4 不足
        EXPECT_EQ(Tuic::ParseAddress(std::span<const std::uint8_t>(MakeBytes({0x01, 1, 2})), Address, Consumed),
                  Error::NeedMore);
        // ipv6 不足
        EXPECT_EQ(Tuic::ParseAddress(std::span<const std::uint8_t>(MakeBytes({0x02, 1})), Address, Consumed),
                  Error::NeedMore);
        // ipv6 成功
        std::vector<std::uint8_t> V6{0x02};
        V6.insert(V6.end(), 16, 0x42);
        V6.push_back(0x00);
        V6.push_back(0x50);
        EXPECT_EQ(Tuic::ParseAddress(V6, Address, Consumed), Error::None);
        EXPECT_EQ(Address.Host, std::string(16, '\x42'));
        EXPECT_EQ(Address.Port, 80u);
        // domain 缺长度
        EXPECT_EQ(Tuic::ParseAddress(std::span<const std::uint8_t>(MakeBytes({0x00})), Address, Consumed),
                  Error::NeedMore);
        // domain 不足
        EXPECT_EQ(Tuic::ParseAddress(std::span<const std::uint8_t>(MakeBytes({0x00, 3, 'a'})), Address, Consumed),
                  Error::NeedMore);
        // domain 成功
        std::vector<std::uint8_t> Domain{0x00, 3};
        const std::string_view Name = "abc";
        Domain.insert(Domain.end(), Name.begin(), Name.end());
        Domain.push_back(0x01);
        Domain.push_back(0xBB);
        EXPECT_EQ(Tuic::ParseAddress(Domain, Address, Consumed), Error::None);
        EXPECT_EQ(Address.Host, "abc");
        EXPECT_EQ(Address.Port, 443u);
    }

TEST(TuicCodecDeep, ParseErrorAndParser)
    {
        // Parse：地址解析失败（domain 长度截断）→ need_more 经 Parse 传播
        Tuic::Message Message{};
        std::size_t Consumed = 0;
        std::vector<std::uint8_t> Bad{0x05, 0x02, 0, 0, 0, 0, 1, 0, 0, 0, 0x00, 0x0A, 'a', 'b'};
        EXPECT_EQ(Tuic::Parse(Bad, Message, Consumed), Error::NeedMore);

        // Parser：need_more（设置 ErrorCode）/ 错误传播
        Tuic::Parser Parser;
        std::error_code ErrorCode;
        EXPECT_EQ(Parser.Put(Net::buffer(MakeBytes({0x05})), ErrorCode), 0u);
        EXPECT_TRUE(ErrorCode);
        EXPECT_EQ(ErrorCode, make_error_code(Error::NeedMore));
        EXPECT_EQ(ErrorCode, make_error_code(Error::NeedMore));
        Parser.Reset();
        EXPECT_EQ(Parser.Put(Net::buffer(MakeBytes({0x03, 0x02, 0, 0, 0, 0, 1, 0, 0, 0})), ErrorCode), 0u);
        EXPECT_EQ(ErrorCode, make_error_code(Error::BadMagic));
        Parser.Reset();
        // 成功解析
        std::vector<std::uint8_t> Ok{0x05, 0x02, 0, 0, 0, 1, 1, 0, 0, 1, 0x01, 8, 8, 8, 8, 0x00, 0x35, 'x'};
        EXPECT_EQ(Parser.Put(Net::buffer(Ok), ErrorCode), 18u);
        EXPECT_TRUE(Parser.IsDone());
        EXPECT_EQ(Parser.Get().Cmd, Tuic::CmdPacket);
        EXPECT_EQ(Parser.Get().PktId, 1u);
        EXPECT_EQ(Parser.Get().dst.Host, "8.8.8.8");
    }

    // ───────────────────────── TUIC Codec ─────────────────────────
