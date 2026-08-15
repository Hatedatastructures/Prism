/**
 * @file VmessCodecDeep.cpp
 * @brief VMess codec 剩余分支深度测试
 * @details 覆盖 build_request_header 的 ipv4 非法输入 / ipv6 分支、
 *          parse_request_header 的地址截断与 FNV1a 校验失败、
 *          chunk_decryptor 的错误路径（头部不足 / 坏密文 / 超长）、
 *          parser 的 need_more / 认证失败 / 头解析失败传播、
 *          chunk_stream::decrypt 错误路径，以及 aes_gcm_open 的
 *          密文过短分支。
 */

#include <boost/asio/buffer.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

#include <common/core/error.hpp>
#include <common/proxy/vmess/codec.hpp>
#include <gtest/gtest.h>

namespace
{
    using namespace psmtest;

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
        std::array<std::uint8_t, 12> nonce{};
        std::array<std::uint8_t, 8> cipher{};
        const auto plain = vmess::detail::aes_gcm_open(
            vmess::detail::open_input{std::span<const std::uint8_t, 16>(key), std::span<const std::uint8_t, 12>(nonce), cipher, std::span<const std::uint8_t>{}});
        EXPECT_TRUE(plain.empty());
    }

    TEST(VmessCodecDeep, BuildHeaderAddressBranches)
    {
        vmess::request_header hdr{};
        std::array<std::uint8_t, 16> iv{};
        std::array<std::uint8_t, 16> key{};
        vmess::request_meta meta{std::span<const std::uint8_t, 16>(iv), std::span<const std::uint8_t, 16>(key)};
        meta.v = 0x42;
        meta.p = 3;

        // ipv4 正常
        hdr.target.type = vmess::address_type::ipv4;
        hdr.target.host = "10.0.0.1";
        hdr.target.port = 443;
        const auto ok = vmess::build_request_header(hdr, meta);
        EXPECT_GT(ok.size(), 40u);

        // ipv4 段过多
        hdr.target.host = "1.2.3.4.5";
        EXPECT_TRUE(vmess::build_request_header(hdr, meta).empty());

        // ipv4 段超 255
        hdr.target.host = "300.1.1.1";
        EXPECT_TRUE(vmess::build_request_header(hdr, meta).empty());

        // ipv4 段数不足
        hdr.target.host = "1.2.3";
        EXPECT_TRUE(vmess::build_request_header(hdr, meta).empty());

        // ipv6 编码
        hdr.target.type = vmess::address_type::ipv6;
        hdr.target.host.assign(16, 'w');
        const auto v6 = vmess::build_request_header(hdr, meta);
        EXPECT_EQ(v6.size(), 41u + 16u + meta.p + 4u);
    }

    TEST(VmessCodecDeep, ParseHeaderBranches)
    {
        vmess::request_header hdr{};
        vmess::request_meta_out meta{};
        std::array<std::uint8_t, 16> iv{};
        std::array<std::uint8_t, 16> key{};
        std::array<std::uint8_t, 16> iv2{};
        std::array<std::uint8_t, 16> key2{};

        // ipv4 截断
        std::vector<std::uint8_t> v4(41, 0);
        v4[0] = 0x01;
        v4[40] = 0x01; // ipv4
        EXPECT_EQ(vmess::parse_request_header(v4, hdr, meta), error::need_more);

        // ipv6 截断
        std::vector<std::uint8_t> v6(41, 0);
        v6[0] = 0x01;
        v6[40] = 0x04; // ipv6
        EXPECT_EQ(vmess::parse_request_header(v6, hdr, meta), error::need_more);

        // ipv6 成功（build 后回解析）
        vmess::request_header src{};
        src.cmd = vmess::command::udp;
        src.target.type = vmess::address_type::ipv6;
        src.target.host.assign(16, 'z');
        src.target.port = 53;
        vmess::request_meta m{std::span<const std::uint8_t, 16>(iv), std::span<const std::uint8_t, 16>(key)};
        const auto wire = vmess::build_request_header(src, m);
        EXPECT_EQ(vmess::parse_request_header(wire, hdr, meta), error::none);
        EXPECT_EQ(hdr.target.type, vmess::address_type::ipv6);
        EXPECT_EQ(hdr.target.host, std::string(16, 'z'));
        EXPECT_EQ(hdr.target.port, 53u);

        // FNV1a 校验失败
        auto tampered = wire;
        tampered.back() ^= 0x01;
        EXPECT_EQ(vmess::parse_request_header(tampered, hdr, meta), error::bad_auth);
    }

    TEST(VmessCodecDeep, ChunkDecryptorErrors)
    {
        std::array<std::uint8_t, 16> key{};
        std::array<std::uint8_t, 12> nonce{};
        vmess::chunk_decryptor dec{std::span<const std::uint8_t, 16>(key), std::span<const std::uint8_t, 12>(nonce)};

        // 头部不足
        std::array<std::uint8_t, 10> short_head{};
        const auto r1 = dec.open_len(std::span<const std::uint8_t>(short_head));
        EXPECT_FALSE(r1);
        EXPECT_EQ(r1.error(), error::need_more);

        // 坏密文（tag 篡改）
        std::array<std::uint8_t, 18> bad_head{};
        bad_head[17] = 0xFF;
        const auto r2 = dec.open_len(std::span<const std::uint8_t>(bad_head));
        EXPECT_FALSE(r2);
        EXPECT_EQ(r2.error(), error::bad_auth);

        // 超长（> max_chunk_len）
        vmess::chunk_encryptor enc{std::span<const std::uint8_t, 16>(key), std::span<const std::uint8_t, 12>(nonce)};
        std::array<std::uint8_t, 34> len_enc{};
        const auto n1 = enc.seal({}, len_enc); // 空块：长度 0
        (void)n1;
        const auto r3 = dec.open_len(std::span<const std::uint8_t>(len_enc).first(18));
        ASSERT_TRUE(r3);
        EXPECT_EQ(*r3, 0u);

        // 超长长度字段（> max_chunk_len → bad_length）
        vmess::chunk_encryptor enc2{std::span<const std::uint8_t, 16>(key), std::span<const std::uint8_t, 12>(nonce)};
        std::vector<std::uint8_t> big_payload(20000, 0xAB);
        std::vector<std::uint8_t> big_wire(big_payload.size() + 34);
        const auto nb = enc2.seal(big_payload, big_wire);
        EXPECT_EQ(nb, big_payload.size() + 34);
        vmess::chunk_decryptor dec2{std::span<const std::uint8_t, 16>(key), std::span<const std::uint8_t, 12>(nonce)};
        const auto r4 = dec2.open_len(std::span<const std::uint8_t>(big_wire).first(18));
        EXPECT_FALSE(r4);
        EXPECT_EQ(r4.error(), error::bad_length);
    }

    TEST(VmessCodecDeep, ChunkOpenEndAndErrors)
    {
        std::array<std::uint8_t, 16> key{};
        std::array<std::uint8_t, 12> nonce{};

        // 结束块（len==0）
        vmess::chunk_encryptor enc{std::span<const std::uint8_t, 16>(key), std::span<const std::uint8_t, 12>(nonce)};
        std::array<std::uint8_t, 34> fin{};
        const auto nf = enc.finish(fin);
        EXPECT_EQ(nf, 34u);
        vmess::chunk_decryptor dec{std::span<const std::uint8_t, 16>(key), std::span<const std::uint8_t, 12>(nonce)};
        std::array<std::uint8_t, 64> out{};
        std::size_t consumed = 0;
        EXPECT_EQ(dec.open(std::span<const std::uint8_t>(fin), out, consumed), error::none);
        EXPECT_EQ(consumed, 18u);

        // 错误传播（open_len 失败 → open 返回错误）
        std::array<std::uint8_t, 18> bad{};
        bad[17] = 0x01;
        const auto ec = dec.open(std::span<const std::uint8_t>(bad), out, consumed);
        EXPECT_EQ(ec, error::bad_auth);
    }

    TEST(VmessCodecDeep, ParserErrorPropagation)
    {
        const auto uuid = make_uuid();
        const auto cmd_key = vmess::cmd_key_from_uuid(uuid);
        std::array<std::uint8_t, 4> random{0x11, 0x22, 0x33, 0x44};

        // 合法 body（ipv4）
        vmess::request_header hdr{};
        hdr.cmd = vmess::command::tcp;
        hdr.target.type = vmess::address_type::ipv4;
        hdr.target.host = "8.8.8.8";
        hdr.target.port = 53;
        std::array<std::uint8_t, 16> iv{};
        std::array<std::uint8_t, 16> key{};
        vmess::request_meta m{std::span<const std::uint8_t, 16>(iv), std::span<const std::uint8_t, 16>(key)};
        const auto body = vmess::build_request_header(hdr, m);
        const auto wire =
            vmess::seal_auth_header(cmd_key, vmess::auth_header_input{body, 1000, random});

        vmess::parser p(uuid);
        std::error_code ec;

        // 数据不足
        EXPECT_EQ(p.put(boost::asio::buffer(std::array<std::uint8_t, 30>{}), ec), 0u);
        EXPECT_EQ(ec, make_error_code(error::need_more));
        p.reset();

        // 总长不足（截断 wire 尾部）
        const auto truncated = std::vector<std::uint8_t>(wire.begin(), wire.end() - 20);
        EXPECT_EQ(p.put(boost::asio::buffer(truncated), ec), 0u);
        EXPECT_EQ(ec, make_error_code(error::need_more));
        p.reset();

        // 认证头解密失败（篡改 hdr_enc 区）
        auto tampered = wire;
        tampered.back() ^= 0x01;
        EXPECT_EQ(p.put(boost::asio::buffer(tampered), ec), 0u);
        EXPECT_EQ(ec, make_error_code(error::bad_auth));
        p.reset();

        // 头解析失败（版本错误 body）
        vmess::request_header bad_hdr{};
        bad_hdr.version = 0x02;
        bad_hdr.target.type = vmess::address_type::domain;
        bad_hdr.target.host = "x.com";
        const auto bad_body = vmess::build_request_header(bad_hdr, m);
        const auto bad_wire =
            vmess::seal_auth_header(cmd_key, vmess::auth_header_input{bad_body, 1000, random});
        EXPECT_EQ(p.put(boost::asio::buffer(bad_wire), ec), 0u);
        EXPECT_EQ(ec, make_error_code(error::bad_magic));
        p.reset();

        // 成功解析
        EXPECT_EQ(p.put(boost::asio::buffer(wire), ec), wire.size());
        EXPECT_TRUE(p.is_done());
        EXPECT_EQ(p.get().dst.host, "8.8.8.8");
        EXPECT_EQ(p.get().cmd, 0x01u);
        // done 后再 put → 返回累积字节数
        std::error_code ec2;
        EXPECT_EQ(p.put(boost::asio::buffer(std::array<std::uint8_t, 4>{}), ec2), wire.size());
        EXPECT_FALSE(ec2);
    }

    TEST(VmessCodecDeep, ChunkStreamDecryptErrors)
    {
        std::array<std::uint8_t, 16> key{};
        std::array<std::uint8_t, 16> iv{};
        vmess::chunk_stream cs;
        cs.init(std::span<const std::uint8_t, 16>(key), std::span<const std::uint8_t, 16>(iv));

        // wire 不足 18 字节
        std::string plain;
        std::array<std::uint8_t, 10> short_wire{};
        auto r1 = cs.decrypt(std::span<const std::uint8_t>(short_wire), plain);
        EXPECT_TRUE(r1.ec);
        EXPECT_EQ(r1.ec, make_error_code(error::need_more));

        // 坏密文
        std::array<std::uint8_t, 18> bad{};
        bad[17] = 0x01;
        auto r2 = cs.decrypt(std::span<const std::uint8_t>(bad), plain);
        EXPECT_TRUE(r2.ec);
        EXPECT_EQ(r2.ec, make_error_code(error::bad_auth));
    }

} // namespace
