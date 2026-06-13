/**
 * @file ShadowtlsAuthDeep.cpp
 * @brief ShadowTLS auth 深度测试
 * @details 测试 auth.cpp 中所有同步纯函数：
 *          compute_hmac、verify_client_hello、verify_frame_hmac、
 *          compute_write_hmac、compute_write_key。
 *          通过 #include 源文件覆盖编译行。
 */

#include <gtest/gtest.h>

#include <prism/core/core.hpp>

// #include 源文件增加覆盖率计数
#include "../../src/prism/stealth/facade/shadowtls/util/auth.cpp"

namespace
{
    using namespace psm::stealth::shadowtls;

    // ─── compute_hmac ──────────────────────────────

    TEST(ShadowtlsAuthDeep, ComputeHmacBasic)
    {
        const char *key = "password";
        std::array<std::byte, 4> data{std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04}};

        auto result = compute_hmac(key, data.data(), data.size());
        EXPECT_TRUE(result.size() == 4) << "compute_hmac: size=4";
        // 确定性：相同输入产生相同输出
        auto result2 = compute_hmac(key, data.data(), data.size());
        EXPECT_TRUE(result == result2) << "compute_hmac: deterministic";
    }

    TEST(ShadowtlsAuthDeep, ComputeHmacEmptyData)
    {
        const char *key = "password";
        auto result = compute_hmac(key, nullptr, 0);
        EXPECT_TRUE(result.size() == 4) << "compute_hmac: empty data -> size=4";
    }

    TEST(ShadowtlsAuthDeep, ComputeHmacDifferentKey)
    {
        std::array<std::byte, 4> data{std::byte{0xAA}};

        auto r1 = compute_hmac("key1", data.data(), data.size());
        auto r2 = compute_hmac("key2", data.data(), data.size());
        EXPECT_TRUE(r1 != r2) << "compute_hmac: different key -> different result";
    }

    TEST(ShadowtlsAuthDeep, ComputeHmacDifferentData)
    {
        const char *key = "password";
        std::array<std::byte, 4> d1{std::byte{0x01}};
        std::array<std::byte, 4> d2{std::byte{0x02}};

        auto r1 = compute_hmac(key, d1.data(), d1.size());
        auto r2 = compute_hmac(key, d2.data(), d2.size());
        EXPECT_TRUE(r1 != r2) << "compute_hmac: different data -> different result";
    }

    // ─── verify_client_hello ───────────────────────

    // 构造合法的 ClientHello 帧（含 TLS 记录头）
    auto make_valid_client_hello(std::string_view password)
        -> psm::memory::vector<std::byte>
    {
        // TLS Header(5) + Handshake Header(4) + Version(2) + Random(32) +
        // SessionID Length(1) + SessionID(32) = 76 bytes minimum
        psm::memory::vector<std::byte> buf(76, std::byte{}, psm::memory::current_resource());

        auto *raw = reinterpret_cast<std::uint8_t *>(buf.data());

        // TLS Record Header
        raw[0] = content_handshake; // Content Type: Handshake
        raw[1] = 0x03; raw[2] = 0x01; // Version TLS 1.0
        raw[3] = 0x00; raw[4] = 0x47; // Length = 71

        // Handshake Header
        raw[5] = hs_type_clienthello; // Handshake Type: ClientHello
        raw[6] = 0x00; raw[7] = 0x00; raw[8] = 0x43; // Length = 67

        // ClientHello Version
        raw[9] = 0x03; raw[10] = 0x03; // TLS 1.2

        // Random: 32 bytes (offset 11..42)
        for (int i = 0; i < 32; ++i) raw[11 + i] = static_cast<std::uint8_t>(i);

        // Session ID Length
        raw[43] = tls_session_id_sz; // 32

        // Session ID: 28 bytes filler + 4 bytes HMAC
        for (int i = 0; i < 28; ++i) raw[44 + i] = static_cast<std::uint8_t>(i + 0x10);

        // 计算 HMAC 并填充到 SessionID 最后 4 字节
        // data = ClientHello[5:]，SessionID HMAC 部分（偏移 40..43 相对 data）置零
        const std::size_t data_size = buf.size() - tls_hdrsize;
        psm::memory::vector<std::uint8_t> hmac_data(data_size, psm::memory::current_resource());
        for (std::size_t i = 0; i < data_size; ++i)
            hmac_data[i] = static_cast<std::uint8_t>(buf[tls_hdrsize + i]);

        // hmac_offset_in_data = session_id_len_idx + 1 + tls_session_id_sz - hmac_size - tls_hdrsize
        // = 43 + 1 + 32 - 4 - 5 = 67
        constexpr std::size_t hmac_offset_in_data = session_id_len_idx + 1 + tls_session_id_sz - hmac_size - tls_hdrsize;
        std::memset(hmac_data.data() + hmac_offset_in_data, 0, hmac_size);

        auto expected = compute_hmac(password, reinterpret_cast<const std::byte *>(hmac_data.data()), hmac_data.size());

        // 写入 HMAC 到 SessionID 最后 4 字节
        constexpr std::size_t client_hmac_offset = session_id_len_idx + 1 + tls_session_id_sz - hmac_size;
        raw[client_hmac_offset + 0] = expected[0];
        raw[client_hmac_offset + 1] = expected[1];
        raw[client_hmac_offset + 2] = expected[2];
        raw[client_hmac_offset + 3] = expected[3];

        return buf;
    }

    TEST(ShadowtlsAuthDeep, VerifyClientHelloValid)
    {
        auto buf = make_valid_client_hello("mypassword");
        auto span = std::span<const std::byte>(buf.data(), buf.size());
        EXPECT_TRUE(verify_client_hello(span, "mypassword")) << "verify_client_hello: valid -> true";
    }

    TEST(ShadowtlsAuthDeep, VerifyClientHelloWrongPassword)
    {
        auto buf = make_valid_client_hello("mypassword");
        auto span = std::span<const std::byte>(buf.data(), buf.size());
        EXPECT_TRUE(!verify_client_hello(span, "wrongpassword")) << "verify_client_hello: wrong password -> false";
    }

    TEST(ShadowtlsAuthDeep, VerifyClientHelloTooShort)
    {
        psm::memory::vector<std::byte> buf(10, std::byte{}, psm::memory::current_resource());
        auto span = std::span<const std::byte>(buf.data(), buf.size());
        EXPECT_TRUE(!verify_client_hello(span, "password")) << "verify_client_hello: too short -> false";
    }

    TEST(ShadowtlsAuthDeep, VerifyClientHelloBadContentType)
    {
        auto buf = make_valid_client_hello("password");
        // 修改 content type 为非 handshake
        buf[0] = std::byte{0x17}; // Application Data
        auto span = std::span<const std::byte>(buf.data(), buf.size());
        EXPECT_TRUE(!verify_client_hello(span, "password")) << "verify_client_hello: bad content type -> false";
    }

    TEST(ShadowtlsAuthDeep, VerifyClientHelloBadHandshakeType)
    {
        auto buf = make_valid_client_hello("password");
        buf[5] = std::byte{0x02}; // ServerHello
        auto span = std::span<const std::byte>(buf.data(), buf.size());
        EXPECT_TRUE(!verify_client_hello(span, "password")) << "verify_client_hello: bad handshake type -> false";
    }

    TEST(ShadowtlsAuthDeep, VerifyClientHelloBadSessionIdLen)
    {
        auto buf = make_valid_client_hello("password");
        auto *raw = reinterpret_cast<std::uint8_t *>(buf.data());
        raw[session_id_len_idx] = 16; // 非 32
        auto span = std::span<const std::byte>(buf.data(), buf.size());
        EXPECT_TRUE(!verify_client_hello(span, "password")) << "verify_client_hello: bad session_id len -> false";
    }

    // ─── verify_frame_hmac ─────────────────────────

    TEST(ShadowtlsAuthDeep, VerifyFrameHmacValid)
    {
        const char *password = "password";
        std::array<std::byte, 32> server_random{};
        for (std::size_t i = 0; i < 32; ++i) server_random[i] = std::byte{i};

        std::array<std::byte, 16> payload{};
        for (std::size_t i = 0; i < 16; ++i) payload[i] = std::byte{i + 0x40};

        // 计算 HMAC-SHA1(password, serverRandom + "C" + payload)[:4]
        HMAC_CTX *ctx = HMAC_CTX_new();
        HMAC_Init_ex(ctx, password, static_cast<int>(std::strlen(password)), EVP_sha1(), nullptr);
        HMAC_Update(ctx, reinterpret_cast<const std::uint8_t *>(server_random.data()), server_random.size());
        constexpr std::uint8_t tag_c = 'C';
        HMAC_Update(ctx, &tag_c, 1);
        HMAC_Update(ctx, reinterpret_cast<const std::uint8_t *>(payload.data()), payload.size());
        std::array<std::uint8_t, EVP_MAX_MD_SIZE> md{};
        std::uint32_t md_len = 0;
        HMAC_Final(ctx, md.data(), &md_len);
        HMAC_CTX_free(ctx);

        std::array<std::uint8_t, 4> client_hmac{};
        std::memcpy(client_hmac.data(), md.data(), hmac_size);

        verify_input in{
            password,
            server_random,
            payload,
            client_hmac};
        EXPECT_TRUE(verify_frame_hmac(in)) << "verify_frame_hmac: valid -> true";

        // 篡改一个字节应失败
        std::array<std::uint8_t, 4> bad_hmac = client_hmac;
        bad_hmac[0] ^= 0xFF;
        verify_input in_bad{password, server_random, payload, bad_hmac};
        EXPECT_TRUE(!verify_frame_hmac(in_bad)) << "verify_frame_hmac: tampered -> false";
    }

    // ─── compute_write_hmac ────────────────────────

    TEST(ShadowtlsAuthDeep, ComputeWriteHmacBasic)
    {
        const char *password = "password";
        std::array<std::byte, 32> server_random{};
        std::array<std::byte, 16> payload{};

        auto result = compute_write_hmac(password, server_random, payload);
        EXPECT_TRUE(result.size() == 4) << "compute_write_hmac: size=4";

        // 确定性
        auto result2 = compute_write_hmac(password, server_random, payload);
        EXPECT_TRUE(result == result2) << "compute_write_hmac: deterministic";
    }

    TEST(ShadowtlsAuthDeep, ComputeWriteHmacDifferentPayload)
    {
        const char *password = "password";
        std::array<std::byte, 32> server_random{};
        std::array<std::byte, 4> p1{std::byte{0x01}};
        std::array<std::byte, 4> p2{std::byte{0x02}};

        auto r1 = compute_write_hmac(password, server_random, p1);
        auto r2 = compute_write_hmac(password, server_random, p2);
        EXPECT_TRUE(r1 != r2) << "compute_write_hmac: different payload -> different";
    }

    // ─── compute_write_key ─────────────────────────

    TEST(ShadowtlsAuthDeep, ComputeWriteKeyBasic)
    {
        const char *password = "password";
        std::array<std::byte, 32> server_random{};
        for (std::size_t i = 0; i < 32; ++i) server_random[i] = std::byte{i};

        auto key = compute_write_key(password, server_random);
        EXPECT_TRUE(key.size() == SHA256_DIGEST_LENGTH) << "compute_write_key: size=32";
    }

    TEST(ShadowtlsAuthDeep, ComputeWriteKeyDeterministic)
    {
        const char *password = "password";
        std::array<std::byte, 32> server_random{};

        auto k1 = compute_write_key(password, server_random);
        auto k2 = compute_write_key(password, server_random);
        EXPECT_TRUE(k1 == k2) << "compute_write_key: deterministic";
    }

    TEST(ShadowtlsAuthDeep, ComputeWriteKeyDifferentInputs)
    {
        std::array<std::byte, 32> rnd1{};
        std::array<std::byte, 32> rnd2{};
        rnd2[0] = std::byte{0x01};

        auto k1 = compute_write_key("password", rnd1);
        auto k2 = compute_write_key("password", rnd2);
        EXPECT_TRUE(k1 != k2) << "compute_write_key: different random -> different key";
    }

} // namespace
