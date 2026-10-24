/**
 * @file VmessGoldenVectorTest.cpp
 * @brief VMess golden vector 解析和构造测试。
 */

#include <gtest/gtest.h>
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>
#include <Prism/Foundation/Error.hpp>
#include <cstring>
#include <Prism/Protocols/Vmess/AuthCrypto.hpp>
#include <Prism/Protocols/Vmess/AuthHeader.hpp>
#include <Prism/Protocols/Vmess/AuthId.hpp>
#include <Prism/Protocols/Vmess/AuthKdf.hpp>
#include <Prism/Protocols/Vmess/ChunkCodec.hpp>
#include <Prism/Protocols/Vmess/RequestCodec.hpp>
#include <Prism/Protocols/Vmess/ResponseCodec.hpp>
#include <Prism/Protocols/Vmess/Types.hpp>

namespace
{
    namespace Vmess = Prism::Vmess;
    using Prism::Error;
    using Prism::make_error_code;

} // namespace

TEST(GoldenVector, VmessRequestHeaderRoundtrip)
{
    Vmess::RequestHeader hdr;
    hdr.Version = Vmess::ProtocolVersion;
    hdr.Cmd = static_cast<std::uint8_t>(static_cast<std::uint8_t>(Vmess::Command::Tcp));
    hdr.Target.Type = Vmess::AddressType::Domain;
    hdr.Target.Host = "example.com";
    hdr.Target.Port = 443;
    std::array<std::uint8_t, 16> iv{}, key{};
    for (size_t i=0;i<16;++i){ iv[i]=static_cast<uint8_t>(i); key[i]=static_cast<uint8_t>(i+16); }
    const auto wire = Vmess::BuildRequestHeader(hdr, Vmess::RequestMeta{iv, key, 0x5A, 0});
    ASSERT_FALSE(wire.empty());
    Vmess::RequestHeader Parsed;
    Vmess::RequestMetaOut meta;
    const auto err = Vmess::ParseRequestHeader(std::span<const std::uint8_t>(wire), Parsed, meta);
    EXPECT_EQ(err, Error::None);
    EXPECT_EQ(Parsed.Target.Host, "example.com");
    EXPECT_EQ(Parsed.Target.Port, 443u);
    EXPECT_EQ(Parsed.Cmd, static_cast<std::uint8_t>(Vmess::Command::Tcp));
}

TEST(GoldenVector, VmessChunkRoundtrip)
{
    std::array<std::uint8_t, 16> key{};
    std::array<std::uint8_t, 12> Nonce{};
    for (size_t i=0;i<16;++i) key[i]=static_cast<uint8_t>(i);
    for (size_t i=0;i<12;++i) Nonce[i]=static_cast<uint8_t>(i+1);
    Vmess::ChunkEncryptor enc{std::span<const std::uint8_t,16>(key), std::span<const std::uint8_t,12>(Nonce)};
    Vmess::ChunkDecryptor dec{std::span<const std::uint8_t,16>(key), std::span<const std::uint8_t,12>(Nonce)};
    const std::vector<std::uint8_t> plain = {0x01,0x02,0x03,0x04};
    std::vector<std::uint8_t> enc_buf(plain.size() + Vmess::ChunkEncryptor::Overhead);
    const auto n = enc.Seal(plain, enc_buf);
    ASSERT_GT(n, 0u);
    std::vector<std::uint8_t> dec_buf(n);
    std::size_t consumed=0;
    const auto err = dec.Open(std::span<const std::uint8_t>(enc_buf.data(), n), dec_buf, consumed);
    EXPECT_EQ(err, Error::None);
    EXPECT_EQ(consumed, n);
    // Open() 写入定长 span（不 resize），比对解密出的明文内容
    ASSERT_GE(dec_buf.size(), plain.size());
    EXPECT_EQ(std::memcmp(dec_buf.data(), plain.data(), plain.size()), 0);
}

