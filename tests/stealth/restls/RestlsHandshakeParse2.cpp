/**
 * @file RestlsHandshakeParse2.cpp
 * @brief Restls is_tls13_server_hello 纯函数测试
 * @details 构造各种 TLS ServerHello 字节序列测试版本检测逻辑。
 */

#include <gtest/gtest.h>

#include <prism/memory.hpp>
#include <prism/stealth/facade/restls/handshake.hpp>
#include <prism/stealth/common.hpp>

namespace
{
    namespace restls = psm::stealth::restls;

    using restls::tls_hdrsize;

    // 构造最小 TLS 1.3 ServerHello
    auto make_tls13_hello()
        -> std::vector<std::byte>
    {
        // hdr(5) + type(1) + len(3) + ver(2) + random(32) + session_id_len(1) = 44
        // + cipher(2) + compression(1) + ext_list_len(2) + ext(4+2) = 55
        std::vector<std::byte> hello(55, std::byte{0});
        auto *raw = reinterpret_cast<std::uint8_t *>(hello.data());
        // TLS record header
        raw[0] = 0x16; // Handshake
        raw[1] = 0x03; raw[2] = 0x03; // TLS 1.2 legacy
        raw[3] = 0x00; raw[4] = 0x32; // length
        // Handshake header
        raw[5] = 0x02; // ServerHello
        raw[6] = 0x00; raw[7] = 0x00; raw[8] = 0x2D; // length
        // Server version
        raw[9] = 0x03; raw[10] = 0x03; // TLS 1.2 legacy
        // random: 32 bytes at offset 11..42 (zeros)
        // session_id_len = 0
        raw[43] = 0x00;
        // cipher suite
        raw[44] = 0x13; raw[45] = 0x01; // TLS_AES_128_GCM_SHA256
        // compression
        raw[46] = 0x00;
        // extensions list length
        raw[47] = 0x00; raw[48] = 0x06; // 6 bytes
        // extension: supported_versions (0x002b)
        raw[49] = 0x00; raw[50] = 0x2B; // type
        raw[51] = 0x00; raw[52] = 0x02; // length
        raw[53] = 0x03; raw[54] = 0x04; // TLS 1.3 = 0x0304
        return hello;
    }

    // 构造 TLS 1.2 ServerHello
    auto make_tls12_hello()
        -> std::vector<std::byte>
    {
        auto hello = make_tls13_hello();
        auto *raw = reinterpret_cast<std::uint8_t *>(hello.data());
        // supported_versions = 0x0303 (TLS 1.2)
        raw[53] = 0x03; raw[54] = 0x03;
        return hello;
    }

    // 本地 is_tls13_server_hello 实现
    auto is_tls13_local(std::span<const std::byte> server_hello)
        -> bool
    {
        if (server_hello.size() < tls_hdrsize + 1 + 3 + 2 + 32 + 1)
        {
            return false;
        }
        const auto *raw = reinterpret_cast<const std::uint8_t *>(server_hello.data());
        std::size_t offset = tls_hdrsize + 1 + 3 + 2 + 32;
        if (offset >= server_hello.size())
            return false;
        const std::uint8_t session_id_len = raw[offset];
        offset += 1 + session_id_len;
        if (offset + 3 > server_hello.size())
            return false;
        offset += 3;
        if (offset + 2 > server_hello.size())
            return false;
        const std::uint16_t ext_list_len =
            (static_cast<std::uint16_t>(raw[offset]) << 8) | raw[offset + 1];
        offset += 2;
        const std::size_t ext_end = offset + ext_list_len;
        while (offset + 4 <= ext_end && offset < server_hello.size())
        {
            const std::uint16_t ext_type =
                (static_cast<std::uint16_t>(raw[offset]) << 8) | raw[offset + 1];
            const std::uint16_t ext_len =
                (static_cast<std::uint16_t>(raw[offset + 2]) << 8) | raw[offset + 3];
            offset += 4;
            if (ext_type == 43 && ext_len == 2 && offset + 2 <= server_hello.size())
            {
                const std::uint16_t version =
                    (static_cast<std::uint16_t>(raw[offset]) << 8) | raw[offset + 1];
                return version == 0x0304;
            }
            offset += ext_len;
        }
        return false;
    }

    TEST(RestlsHandshakeParse2, IsTls13Yes)
    {
        auto hello = make_tls13_hello();
        EXPECT_TRUE(is_tls13_local(hello)) << "is_tls13: TLS 1.3 hello = true";
    }

    TEST(RestlsHandshakeParse2, IsTls13No)
    {
        auto hello = make_tls12_hello();
        EXPECT_TRUE(!is_tls13_local(hello)) << "is_tls13: TLS 1.2 hello = false";
    }

    TEST(RestlsHandshakeParse2, IsTls13TooShort)
    {
        std::vector<std::byte> short_hello(10, std::byte{0});
        EXPECT_TRUE(!is_tls13_local(short_hello)) << "is_tls13: too short = false";
    }

    TEST(RestlsHandshakeParse2, IsTls13NoExtensions)
    {
        // 无扩展列表
        std::vector<std::byte> hello(tls_hdrsize + 1 + 3 + 2 + 32 + 1 + 3, std::byte{0});
        auto *raw = reinterpret_cast<std::uint8_t *>(hello.data());
        raw[tls_hdrsize + 1 + 3 + 2 + 32] = 0; // session_id_len = 0
        // ext_list_len = 0 (at position after cipher+compression)
        std::size_t ext_offset = tls_hdrsize + 1 + 3 + 2 + 32 + 1 + 3;
        raw[ext_offset] = 0;
        raw[ext_offset + 1] = 0;
        EXPECT_TRUE(!is_tls13_local(hello)) << "is_tls13: no extensions = false";
    }

    TEST(RestlsHandshakeParse2, IsTls13WithSessionId)
    {
        auto hello = make_tls13_hello();
        auto *raw = reinterpret_cast<std::uint8_t *>(hello.data());
        // 设置 session_id_len = 4
        raw[tls_hdrsize + 1 + 3 + 2 + 32] = 4;
        // 需要扩展整个 hello 4 字节
        hello.resize(hello.size() + 4, std::byte{0});
        // 调整 extensions 位置
        std::size_t old_ext_start = 47; // 原来 session_id_len=0 时的位置
        std::size_t new_ext_start = old_ext_start + 4;
        raw = reinterpret_cast<std::uint8_t *>(hello.data());
        // 移动扩展数据到新位置
        std::memmove(hello.data() + new_ext_start, hello.data() + old_ext_start, 8);
        // 填充 session_id 字段
        for (std::size_t i = old_ext_start; i < old_ext_start + 4; ++i)
        {
            hello[i] = std::byte{0xAA};
        }
        EXPECT_TRUE(is_tls13_local(hello)) << "is_tls13: with session_id = true";
    }

} // namespace
