/**
 * @file ShadowtlsHandshakeDeep.cpp
 * @brief ShadowTLS handshake.cpp 深度测试
 * @details 测试 handshake.cpp 中 anonymous namespace 的 verify_client 函数。
 *          verify_client 根据 config.version 选择 v3 多用户或 v1/v2 单密码认证，
 *          通过 verify_client_hello 验证 ClientHello HMAC。
 */

#include <gtest/gtest.h>

#include <prism/foundation/foundation.hpp>
#include <prism/stealth/facade/shadowtls/config.hpp>
#include <prism/stealth/facade/shadowtls/util/auth.hpp>
#include <prism/stealth/facade/shadowtls/util/constants.hpp>

#include <cstdint>
#include <cstring>

#include "../../src/prism/stealth/facade/shadowtls/handshake.cpp"

namespace
{
    using namespace psm::stealth::shadowtls;
    using stls_config = psm::stealth::shadowtls::config;

    /**
     * @brief 构造带合法 HMAC 的 ClientHello 帧数据
     * @details TLS 记录头(5) + 握手头(4) + 版本(2) + 随机数(32) +
     *          SessionID 长度(1) + SessionID(32) = 76 字节。
     *          SessionID 最后 4 字节放置 HMAC 标签。
     */
    auto make_client_hello(std::string_view password)
        -> psm::memory::vector<std::byte>
    {
        constexpr std::size_t buf_size = tls_hdrsize + 1 + 3 + 2 + tls_rndsize + 1 + tls_session_id_sz;
        psm::memory::vector<std::byte> buf(buf_size, std::byte{}, psm::memory::current_resource());

        auto *raw = reinterpret_cast<std::uint8_t *>(buf.data());
        raw[0] = content_handshake;
        raw[1] = 0x03; raw[2] = 0x01;
        raw[3] = static_cast<std::uint8_t>((buf_size - tls_hdrsize) >> 8);
        raw[4] = static_cast<std::uint8_t>((buf_size - tls_hdrsize) & 0xFF);
        raw[5] = hs_type_clienthello;
        raw[6] = 0x00; raw[7] = 0x00;
        raw[8] = static_cast<std::uint8_t>((buf_size - tls_hdrsize - 4) & 0xFF);
        raw[9] = 0x03; raw[10] = 0x03;

        for (int i = 0; i < 32; ++i)
            raw[11 + i] = static_cast<std::uint8_t>(i);

        raw[43] = tls_session_id_sz;

        for (int i = 0; i < 28; ++i)
            raw[44 + i] = static_cast<std::uint8_t>(i + 0x10);

        constexpr std::size_t data_size = buf_size - tls_hdrsize;
        psm::memory::vector<std::uint8_t> hmac_data(data_size, psm::memory::current_resource());
        for (std::size_t i = 0; i < data_size; ++i)
            hmac_data[i] = static_cast<std::uint8_t>(buf[tls_hdrsize + i]);

        constexpr std::size_t hmac_offset_in_data =
            session_id_len_idx + 1 + tls_session_id_sz - hmac_size - tls_hdrsize;
        std::memset(hmac_data.data() + hmac_offset_in_data, 0, hmac_size);

        auto expected = compute_hmac(
            password,
            reinterpret_cast<const std::byte *>(hmac_data.data()),
            hmac_data.size());

        constexpr std::size_t client_hmac_offset =
            session_id_len_idx + 1 + tls_session_id_sz - hmac_size;
        raw[client_hmac_offset + 0] = expected[0];
        raw[client_hmac_offset + 1] = expected[1];
        raw[client_hmac_offset + 2] = expected[2];
        raw[client_hmac_offset + 3] = expected[3];

        return buf;
    }

    // ─── verify_client v3 多用户 ──────────────────────

    TEST(ShadowtlsHandshakeDeep, VerifyClientV3MatchFirstUser)
    {
        stls_config cfg;
        cfg.version = 3;
        cfg.users.push_back(user{psm::memory::string("alice"), psm::memory::string("pass_alice")});
        cfg.users.push_back(user{psm::memory::string("bob"), psm::memory::string("pass_bob")});

        auto hello = make_client_hello("pass_alice");
        auto span = std::span<const std::byte>(hello.data(), hello.size());

        auto result = verify_client(cfg, span, nullptr);
        EXPECT_TRUE(result.has_value()) << "verify_client v3: first user match";
        if (result)
        {
            EXPECT_TRUE(result->matched_user == "alice") << "verify_client v3: matched_user=alice";
            EXPECT_TRUE(result->password == "pass_alice") << "verify_client v3: password=pass_alice";
        }
    }

    TEST(ShadowtlsHandshakeDeep, VerifyClientV3MatchSecondUser)
    {
        stls_config cfg;
        cfg.version = 3;
        cfg.users.push_back(user{psm::memory::string("alice"), psm::memory::string("pass_alice")});
        cfg.users.push_back(user{psm::memory::string("bob"), psm::memory::string("pass_bob")});

        auto hello = make_client_hello("pass_bob");
        auto span = std::span<const std::byte>(hello.data(), hello.size());

        auto result = verify_client(cfg, span, nullptr);
        EXPECT_TRUE(result.has_value()) << "verify_client v3: second user match";
        if (result)
        {
            EXPECT_TRUE(result->matched_user == "bob") << "verify_client v3: matched_user=bob";
            EXPECT_TRUE(result->password == "pass_bob") << "verify_client v3: password=pass_bob";
        }
    }

    TEST(ShadowtlsHandshakeDeep, VerifyClientV3NoMatch)
    {
        stls_config cfg;
        cfg.version = 3;
        cfg.users.push_back(user{psm::memory::string("alice"), psm::memory::string("pass_alice")});

        auto hello = make_client_hello("unknown_password");
        auto span = std::span<const std::byte>(hello.data(), hello.size());

        auto result = verify_client(cfg, span, nullptr);
        EXPECT_TRUE(!result.has_value()) << "verify_client v3: no match -> nullopt";
    }

    TEST(ShadowtlsHandshakeDeep, VerifyClientV3EmptyPasswordSkipped)
    {
        stls_config cfg;
        cfg.version = 3;
        cfg.users.push_back(user{psm::memory::string("empty"), psm::memory::string("")});
        cfg.users.push_back(user{psm::memory::string("alice"), psm::memory::string("pass_alice")});

        auto hello = make_client_hello("pass_alice");
        auto span = std::span<const std::byte>(hello.data(), hello.size());

        auto result = verify_client(cfg, span, nullptr);
        EXPECT_TRUE(result.has_value()) << "verify_client v3: skip empty password user";
        if (result)
        {
            EXPECT_TRUE(result->matched_user == "alice") << "verify_client v3: skipped empty user";
        }
    }

    TEST(ShadowtlsHandshakeDeep, VerifyClientV3AllEmptyPasswords)
    {
        stls_config cfg;
        cfg.version = 3;
        cfg.users.push_back(user{psm::memory::string("a"), psm::memory::string("")});
        cfg.users.push_back(user{psm::memory::string("b"), psm::memory::string("")});

        auto hello = make_client_hello("any_password");
        auto span = std::span<const std::byte>(hello.data(), hello.size());

        auto result = verify_client(cfg, span, nullptr);
        EXPECT_TRUE(!result.has_value()) << "verify_client v3: all empty passwords -> nullopt";
    }

    TEST(ShadowtlsHandshakeDeep, VerifyClientV3EmptyUsers)
    {
        stls_config cfg;
        cfg.version = 3;

        auto hello = make_client_hello("some_pass");
        auto span = std::span<const std::byte>(hello.data(), hello.size());

        auto result = verify_client(cfg, span, nullptr);
        EXPECT_TRUE(!result.has_value()) << "verify_client v3: empty user list -> nullopt";
    }

    // ─── verify_client v1/v2 单密码 ────────────────────

    TEST(ShadowtlsHandshakeDeep, VerifyClientV2Match)
    {
        stls_config cfg;
        cfg.version = 2;
        cfg.password = psm::memory::string("shared_secret");

        auto hello = make_client_hello("shared_secret");
        auto span = std::span<const std::byte>(hello.data(), hello.size());

        auto result = verify_client(cfg, span, nullptr);
        EXPECT_TRUE(result.has_value()) << "verify_client v2: password match";
        if (result)
        {
            EXPECT_TRUE(result->matched_user == "default") << "verify_client v2: matched_user=default";
            EXPECT_TRUE(result->password == "shared_secret") << "verify_client v2: password=shared_secret";
        }
    }

    TEST(ShadowtlsHandshakeDeep, VerifyClientV2NoMatch)
    {
        stls_config cfg;
        cfg.version = 2;
        cfg.password = psm::memory::string("shared_secret");

        auto hello = make_client_hello("wrong_password");
        auto span = std::span<const std::byte>(hello.data(), hello.size());

        auto result = verify_client(cfg, span, nullptr);
        EXPECT_TRUE(!result.has_value()) << "verify_client v2: wrong password -> nullopt";
    }

    TEST(ShadowtlsHandshakeDeep, VerifyClientV2EmptyPassword)
    {
        stls_config cfg;
        cfg.version = 2;
        cfg.password = psm::memory::string("");

        auto hello = make_client_hello("any_password");
        auto span = std::span<const std::byte>(hello.data(), hello.size());

        auto result = verify_client(cfg, span, nullptr);
        EXPECT_TRUE(!result.has_value()) << "verify_client v2: empty password -> nullopt";
    }

    TEST(ShadowtlsHandshakeDeep, VerifyClientV1Match)
    {
        stls_config cfg;
        cfg.version = 1;
        cfg.password = psm::memory::string("v1_pass");

        auto hello = make_client_hello("v1_pass");
        auto span = std::span<const std::byte>(hello.data(), hello.size());

        auto result = verify_client(cfg, span, nullptr);
        EXPECT_TRUE(result.has_value()) << "verify_client v1: password match";
        if (result)
        {
            EXPECT_TRUE(result->matched_user == "default") << "verify_client v1: matched_user=default";
        }
    }

} // namespace
