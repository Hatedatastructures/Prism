/**
 * @file Shadowtls.cpp
 * @brief ShadowTLS v3 测试
 */

#include <gtest/gtest.h>

#include <prism/stealth/facade/shadowtls/util/auth.hpp>
#include <prism/memory.hpp>

#include <openssl/hmac.h>

#include <sstream>
#include <cstring>
#include <iomanip>
#include <span>
#include <vector>

namespace
{
    template<typename T>
    auto BytesToHex(const std::span<T> bytes) -> std::string
    {
        std::ostringstream oss;
        for (auto b : bytes)
            oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(b);
        return oss.str();
    }

    TEST(Shadowtls, HMACComputation)
    {
        using namespace psm::stealth::shadowtls;

        const std::string password = "test_password";
        std::array<std::byte, 64> data{};
        for (std::size_t i = 0; i < data.size(); ++i)
            data[i] = static_cast<std::byte>(i);

        const auto hmac1 = compute_hmac(password, data.data(), data.size());
        const auto hmac2 = compute_hmac(password, data.data(), data.size());

        EXPECT_TRUE(hmac1 == hmac2) << "HMAC deterministic output";

        const auto hmac3 = compute_hmac("different_password", data.data(), data.size());
        EXPECT_TRUE(hmac1 != hmac3) << "HMAC differs with different password";
    }

    TEST(Shadowtls, WriteKeyGeneration)
    {
        using namespace psm::stealth::shadowtls;

        const std::string password = "test_password";
        std::array<std::byte, 32> server_random{};
        for (std::size_t i = 0; i < server_random.size(); ++i)
            server_random[i] = static_cast<std::byte>(0xA0 + i);

        const auto write_key = compute_write_key(password, server_random);

        EXPECT_TRUE(write_key.size() == 32) << "WriteKey is 32 bytes (SHA256 output)";
        EXPECT_TRUE(!write_key.empty()) << "WriteKey is non-empty";

        const auto write_key2 = compute_write_key(password, server_random);
        EXPECT_TRUE(write_key == write_key2) << "WriteKey deterministic";

        const auto write_key3 = compute_write_key("other_password", server_random);
        EXPECT_TRUE(write_key != write_key3) << "WriteKey differs with different password";
    }

    TEST(Shadowtls, FrameHMACVerification)
    {
        using namespace psm::stealth::shadowtls;

        const std::string password = "test_password";
        std::array<std::byte, 32> server_random{};
        for (std::size_t i = 0; i < server_random.size(); ++i)
            server_random[i] = static_cast<std::byte>(i);

        std::array<std::byte, 16> payload{};
        for (std::size_t i = 0; i < payload.size(); ++i)
            payload[i] = static_cast<std::byte>(0x10 + i);

        // compute_write_hmac：服务端→客户端方向，不含后缀
        const auto write_hmac = compute_write_hmac(password, server_random, payload);

        // compute_write_hmac 使用 "S" 标签（服务端→客户端方向）
        // verify_frame_hmac 使用 "C" 标签（客户端→服务端方向）
        // 两者标签不同，write_hmac 不应该通过 verify
        EXPECT_TRUE(!verify_frame_hmac(verify_input{password, server_random, payload, write_hmac}))
              << "Write HMAC ('S' tag) should fail against verify ('C' tag)";

        // 手动构建含 "C" 标签的客户端 HMAC（参照 sing-shadowtls hmacVerify）
        // HMAC-SHA1(password, serverRandom + "C" + payload)[:4]
        HMAC_CTX *ctx = HMAC_CTX_new();
        HMAC_Init_ex(ctx, password.data(), static_cast<int>(password.size()), EVP_sha1(), nullptr);
        HMAC_Update(ctx, reinterpret_cast<const unsigned char *>(server_random.data()), server_random.size());
        constexpr unsigned char tag_c = 'C';
        HMAC_Update(ctx, &tag_c, 1);
        HMAC_Update(ctx, reinterpret_cast<const unsigned char *>(payload.data()), payload.size());
        std::array<std::uint8_t, 20> md{}; // SHA1 输出 20 字节
        unsigned int md_len = 0;
        HMAC_Final(ctx, md.data(), &md_len);
        HMAC_CTX_free(ctx);

        std::array<std::uint8_t, 4> read_hmac{};
        std::memcpy(read_hmac.data(), md.data(), 4);

        EXPECT_TRUE(verify_frame_hmac(verify_input{password, server_random, payload, read_hmac}))
              << "Frame HMAC verification with correct client HMAC ('C' tag)";
    }

    TEST(Shadowtls, ClientHelloVerification)
    {
        using namespace psm::stealth::shadowtls;

        const std::string password = "test_password";

        std::array<std::byte, 10> short_data{};
        EXPECT_TRUE(!verify_client_hello(short_data, password))
              << "ClientHello rejects short data";

        std::array<std::byte, 80> fake_hello{};
        fake_hello[0] = std::byte{0x00};
        EXPECT_TRUE(!verify_client_hello(fake_hello, password))
              << "ClientHello rejects wrong record type";
    }

    TEST(Shadowtls, VerifyClientHelloTooShort)
    {
        std::vector<std::byte> short_buf(50, std::byte{0x16});
        EXPECT_TRUE(!psm::stealth::shadowtls::verify_client_hello(
                  std::span<const std::byte>{short_buf.data(), short_buf.size()}, "password"))
              << "verify_client_hello: too short -> false";
    }

    TEST(Shadowtls, VerifyClientHelloWrongContentType)
    {
        std::vector<std::byte> buf(100, std::byte{0x00});
        buf[0] = std::byte{0x17}; // not 0x16
        buf[5] = std::byte{0x01};
        buf[43] = std::byte{32};
        EXPECT_TRUE(!psm::stealth::shadowtls::verify_client_hello(
                  std::span<const std::byte>{buf.data(), buf.size()}, "password"))
              << "verify_client_hello: wrong content type -> false";
    }

    TEST(Shadowtls, VerifyClientHelloWrongHandshakeType)
    {
        std::vector<std::byte> buf(100, std::byte{0x00});
        buf[0] = std::byte{0x16};
        buf[5] = std::byte{0x02}; // ServerHello, not ClientHello
        buf[43] = std::byte{32};
        EXPECT_TRUE(!psm::stealth::shadowtls::verify_client_hello(
                  std::span<const std::byte>{buf.data(), buf.size()}, "password"))
              << "verify_client_hello: wrong handshake type -> false";
    }

    TEST(Shadowtls, VerifyClientHelloWrongSessionIdLen)
    {
        std::vector<std::byte> buf(100, std::byte{0x00});
        buf[0] = std::byte{0x16};
        buf[5] = std::byte{0x01};
        buf[43] = std::byte{16}; // not 32
        EXPECT_TRUE(!psm::stealth::shadowtls::verify_client_hello(
                  std::span<const std::byte>{buf.data(), buf.size()}, "password"))
              << "verify_client_hello: wrong session_id_len -> false";
    }

} // namespace
