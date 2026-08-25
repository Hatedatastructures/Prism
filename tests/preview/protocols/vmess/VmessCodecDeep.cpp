/**
 * @file VmessCodecDeep.cpp
 * @brief VMess Codec 剩余分支深度测试
 * @details 覆盖 BuildRequestHeader 的 ipv4 非法输入 / ipv6 分支、
 *          ParseRequestHeader 的地址截断与 FNV1a 校验失败、
 *          ChunkDecryptor 的错误路径（头部不足 / 坏密文 / 超长）、
 *          Parser 的 need_more / 认证失败 / 头解析失败传播、
 *          ChunkStream::Decrypt 错误路径，以及 AesGcmOpen 的
 *          密文过短分支。
 */

#include <boost/asio/buffer.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

#include <common/Core/Error.hpp>
#include <common/Protocols/Vmess/Codec.hpp>
#include <gtest/gtest.h>

namespace
{
    using namespace Preview;

    /**
     * @brief 构造 16 字节 UUID
     */
    auto make_uuid() -> std::array<std::uint8_t, 16>
    {
        std::array<std::uint8_t, 16> u{};
        u.fill(0x33);
        return u;
    }

    TEST(VmessCodecDeep, AesGcmOpenShortCipher)
    {
        std::array<std::uint8_t, 16> key{};
        std::array<std::uint8_t, 12> Nonce{};
        std::array<std::uint8_t, 8> cipher{};
        const auto plain = Vmess::detail::AesGcmOpen(
            Vmess::detail::OpenInput{std::span<const std::uint8_t, 16>(key), std::span<const std::uint8_t, 12>(Nonce), cipher, std::span<const std::uint8_t>{}});
        EXPECT_TRUE(plain.empty());
    }

    TEST(VmessCodecDeep, BuildHeaderAddressBranches)
    {
        Vmess::RequestHeader hdr{};
        std::array<std::uint8_t, 16> iv{};
        std::array<std::uint8_t, 16> key{};
        Vmess::RequestMeta meta{std::span<const std::uint8_t, 16>(iv), std::span<const std::uint8_t, 16>(key)};
        meta.v = 0x42;
        meta.p = 3;

        // ipv4 正常
        hdr.Target.Type = Vmess::AddressType::Ipv4;
        hdr.Target.Host = "10.0.0.1";
        hdr.Target.Port = 443;
        const auto Ok = Vmess::BuildRequestHeader(hdr, meta);
        EXPECT_GT(Ok.size(), 40u);

        // ipv4 段过多
        hdr.Target.Host = "1.2.3.4.5";
        EXPECT_TRUE(Vmess::BuildRequestHeader(hdr, meta).empty());

        // ipv4 段超 255
        hdr.Target.Host = "300.1.1.1";
        EXPECT_TRUE(Vmess::BuildRequestHeader(hdr, meta).empty());

        // ipv4 段数不足
        hdr.Target.Host = "1.2.3";
        EXPECT_TRUE(Vmess::BuildRequestHeader(hdr, meta).empty());

        // ipv6 编码
        hdr.Target.Type = Vmess::AddressType::Ipv6;
        hdr.Target.Host.assign(16, 'w');
        const auto v6 = Vmess::BuildRequestHeader(hdr, meta);
        EXPECT_EQ(v6.size(), 41u + 16u + meta.p + 4u);
    }

    TEST(VmessCodecDeep, ParseHeaderBranches)
    {
        Vmess::RequestHeader hdr{};
        Vmess::RequestMetaOut meta{};
        std::array<std::uint8_t, 16> iv{};
        std::array<std::uint8_t, 16> key{};
        std::array<std::uint8_t, 16> iv2{};
        std::array<std::uint8_t, 16> key2{};

        // ipv4 截断
        std::vector<std::uint8_t> v4(41, 0);
        v4[0] = 0x01;
        v4[40] = 0x01; // ipv4
        EXPECT_EQ(Vmess::ParseRequestHeader(v4, hdr, meta), Error::need_more);

        // ipv6 截断
        std::vector<std::uint8_t> v6(41, 0);
        v6[0] = 0x01;
        v6[40] = 0x04; // ipv6
        EXPECT_EQ(Vmess::ParseRequestHeader(v6, hdr, meta), Error::need_more);

        // ipv6 成功（Build 后回解析）
        Vmess::RequestHeader src{};
        src.Cmd = static_cast<std::uint8_t>(Vmess::Command::Udp);
        src.Target.Type = Vmess::AddressType::Ipv6;
        src.Target.Host.assign(16, 'z');
        src.Target.Port = 53;
        Vmess::RequestMeta m{std::span<const std::uint8_t, 16>(iv), std::span<const std::uint8_t, 16>(key)};
        const auto wire = Vmess::BuildRequestHeader(src, m);
        EXPECT_EQ(Vmess::ParseRequestHeader(wire, hdr, meta), Error::none);
        EXPECT_EQ(hdr.Target.Type, Vmess::AddressType::Ipv6);
        EXPECT_EQ(hdr.Target.Host, std::string(16, 'z'));
        EXPECT_EQ(hdr.Target.Port, 53u);

        // FNV1a 校验失败
        auto tampered = wire;
        tampered.back() ^= 0x01;
        EXPECT_EQ(Vmess::ParseRequestHeader(tampered, hdr, meta), Error::bad_auth);
    }

    TEST(VmessCodecDeep, ChunkDecryptorErrors)
    {
        std::array<std::uint8_t, 16> key{};
        std::array<std::uint8_t, 12> Nonce{};
        Vmess::ChunkDecryptor dec{std::span<const std::uint8_t, 16>(key), std::span<const std::uint8_t, 12>(Nonce)};

        // 头部不足
        std::array<std::uint8_t, 10> short_head{};
        const auto r1 = dec.OpenLen(std::span<const std::uint8_t>(short_head));
        EXPECT_FALSE(r1);
        EXPECT_EQ(r1.error(), Error::need_more);

        // 坏密文（tag 篡改）
        std::array<std::uint8_t, 18> bad_head{};
        bad_head[17] = 0xFF;
        const auto r2 = dec.OpenLen(std::span<const std::uint8_t>(bad_head));
        EXPECT_FALSE(r2);
        EXPECT_EQ(r2.error(), Error::bad_auth);

        // 超长（> max_chunk_len）
        Vmess::ChunkEncryptor enc{std::span<const std::uint8_t, 16>(key), std::span<const std::uint8_t, 12>(Nonce)};
        std::array<std::uint8_t, 34> len_enc{};
        const auto n1 = enc.Seal({}, len_enc); // 空块：长度 0
        (void)n1;
        const auto r3 = dec.OpenLen(std::span<const std::uint8_t>(len_enc).first(18));
        ASSERT_TRUE(r3);
        EXPECT_EQ(*r3, 0u);

        // 超长长度字段（> max_chunk_len → bad_length）
        Vmess::ChunkEncryptor enc2{std::span<const std::uint8_t, 16>(key), std::span<const std::uint8_t, 12>(Nonce)};
        std::vector<std::uint8_t> big_payload(20000, 0xAB);
        std::vector<std::uint8_t> big_wire(big_payload.size() + 34);
        const auto nb = enc2.Seal(big_payload, big_wire);
        EXPECT_EQ(nb, big_payload.size() + 34);
        Vmess::ChunkDecryptor dec2{std::span<const std::uint8_t, 16>(key), std::span<const std::uint8_t, 12>(Nonce)};
        const auto r4 = dec2.OpenLen(std::span<const std::uint8_t>(big_wire).first(18));
        EXPECT_FALSE(r4);
        EXPECT_EQ(r4, Error::bad_length);
    }

    TEST(VmessCodecDeep, ChunkOpenEndAndErrors)
    {
        std::array<std::uint8_t, 16> key{};
        std::array<std::uint8_t, 12> Nonce{};

        // 结束块（len==0）
        Vmess::ChunkEncryptor enc{std::span<const std::uint8_t, 16>(key), std::span<const std::uint8_t, 12>(Nonce)};
        std::array<std::uint8_t, 34> fin{};
        const auto nf = enc.Finish(fin);
        EXPECT_EQ(nf, 34u);
        Vmess::ChunkDecryptor dec{std::span<const std::uint8_t, 16>(key), std::span<const std::uint8_t, 12>(Nonce)};
        std::array<std::uint8_t, 64> out{};
        std::size_t consumed = 0;
        EXPECT_EQ(dec.Open(std::span<const std::uint8_t>(fin), out, consumed), Error::none);
        EXPECT_EQ(consumed, 18u);

        // 错误传播（OpenLen 失败 → Open 返回错误）
        std::array<std::uint8_t, 18> bad{};
        bad[17] = 0x01;
        const auto ec = dec.Open(std::span<const std::uint8_t>(bad), out, consumed);
        EXPECT_EQ(ec, Error::bad_auth);
    }

    TEST(VmessCodecDeep, ParserErrorPropagation)
    {
        const auto uuid = make_uuid();
        const auto cmd_key = Vmess::CmdKeyFromUuid(uuid);
        std::array<std::uint8_t, 4> random{0x11, 0x22, 0x33, 0x44};

        // 合法 body（ipv4）
        Vmess::RequestHeader hdr{};
        hdr.Cmd = Vmess::CmdTcp;
        hdr.Target.Type = Vmess::AddressType::Ipv4;
        hdr.Target.Host = "8.8.8.8";
        hdr.Target.Port = 53;
        std::array<std::uint8_t, 16> iv{};
        std::array<std::uint8_t, 16> key{};
        Vmess::RequestMeta m{std::span<const std::uint8_t, 16>(iv), std::span<const std::uint8_t, 16>(key)};
        const auto body = Vmess::BuildRequestHeader(hdr, m);
        const auto wire =
            Vmess::SealAuthHeader(cmd_key, Vmess::AuthHeaderInput{body, 1000, random});

        Vmess::Parser p(uuid);
        std::error_code ec;

        // 数据不足
        EXPECT_EQ(p.Put(boost::asio::buffer(std::array<std::uint8_t, 30>{}), ec), 0u);
        EXPECT_EQ(ec, make_error_code(Error::need_more));
        p.Reset();

        // 总长不足（截断 wire 尾部）
        const auto truncated = std::vector<std::uint8_t>(wire.begin(), wire.end() - 20);
        EXPECT_EQ(p.Put(boost::asio::buffer(truncated), ec), 0u);
        EXPECT_EQ(ec, make_error_code(Error::need_more));
        p.Reset();

        // 认证头解密失败（篡改 hdr_enc 区）
        auto tampered = wire;
        tampered.back() ^= 0x01;
        EXPECT_EQ(p.Put(boost::asio::buffer(tampered), ec), 0u);
        EXPECT_EQ(ec, make_error_code(Error::bad_auth));
        p.Reset();

        // 头解析失败（版本错误 body）
        Vmess::RequestHeader bad_hdr{};
        bad_hdr.Version = 0x02;
        bad_hdr.Target.Type = Vmess::AddressType::Domain;
        bad_hdr.Target.Host = "x.com";
        const auto bad_body = Vmess::BuildRequestHeader(bad_hdr, m);
        const auto bad_wire =
            Vmess::SealAuthHeader(cmd_key, Vmess::AuthHeaderInput{bad_body, 1000, random});
        EXPECT_EQ(p.Put(boost::asio::buffer(bad_wire), ec), 0u);
        EXPECT_EQ(ec, make_error_code(Error::bad_magic));
        p.Reset();

        // 成功解析
        EXPECT_EQ(p.Put(boost::asio::buffer(wire), ec), wire.size());
        EXPECT_TRUE(p.IsDone());
        EXPECT_EQ(p.Get().dst.Host, "8.8.8.8");
        EXPECT_EQ(p.Get().Cmd, 0x01u);
        // Done 后再 Put → 返回累积字节数
        std::error_code ec2;
        EXPECT_EQ(p.Put(boost::asio::buffer(std::array<std::uint8_t, 4>{}), ec2), wire.size());
        EXPECT_FALSE(ec2);
    }

    TEST(VmessCodecDeep, ChunkStreamDecryptErrors)
    {
        std::array<std::uint8_t, 16> key{};
        std::array<std::uint8_t, 16> iv{};
        Vmess::ChunkStream cs;
        cs.Init(std::span<const std::uint8_t, 16>(key), std::span<const std::uint8_t, 16>(iv));

        // wire 不足 18 字节
        std::string plain;
        std::array<std::uint8_t, 10> short_wire{};
        auto r1 = cs.Decrypt(std::span<const std::uint8_t>(short_wire), plain);
        EXPECT_TRUE(r1.ec);
        EXPECT_EQ(r1.ec, make_error_code(Error::need_more));

        // 坏密文
        std::array<std::uint8_t, 18> bad{};
        bad[17] = 0x01;
        auto r2 = cs.Decrypt(std::span<const std::uint8_t>(bad), plain);
        EXPECT_TRUE(r2.ec);
        EXPECT_EQ(r2.ec, make_error_code(Error::bad_auth));
    }

} // namespace
