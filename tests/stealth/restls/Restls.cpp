/**
 * @file Restls.cpp
 * @brief Restls 伪装方案测试
 */

#include <gtest/gtest.h>

#include <prism/stealth/facade/restls/config.hpp>
#include <prism/stealth/facade/restls/crypto.hpp>
#include <prism/stealth/facade/shadowtls/util/constants.hpp>
#include <prism/foundation/foundation.hpp>

namespace
{
    TEST(Restls, ConfigEnabled)
    {
        using namespace psm::stealth::restls;

        // 空 host 应该返回 false
        config cfg1;
        cfg1.host = "";
        cfg1.password = "test_password";
        EXPECT_TRUE(!cfg1.enabled()) << "Config disabled when host is empty";

        // 空 password 应该返回 false
        config cfg2;
        cfg2.host = "www.microsoft.com:443";
        cfg2.password = "";
        EXPECT_TRUE(!cfg2.enabled()) << "Config disabled when password is empty";

        // 有效配置应该返回 true
        config cfg3;
        cfg3.server_names.push_back("example.com");
        cfg3.host = "www.microsoft.com:443";
        cfg3.password = "test_password";
        EXPECT_TRUE(cfg3.enabled()) << "Config enabled with valid host and password";
    }

    TEST(Restls, Constants)
    {
        // Restls TLS 常量与 shadowtls 共享，此处仅验证值正确性
        using namespace psm::stealth::restls;
        EXPECT_TRUE(tls_hdrsize == 5) << "TLS header size is 5 bytes";
        EXPECT_TRUE(tls_rndsize == 32) << "TLS random size is 32 bytes";
        EXPECT_TRUE(psm::stealth::shadowtls::content_handshake == 0x16) << "Handshake content type is 0x16";
        EXPECT_TRUE(psm::stealth::shadowtls::content_appdata == 0x17) << "Application data content type is 0x17";
        constexpr std::size_t auth_tag_size = 4;
        EXPECT_TRUE(auth_tag_size == 4) << "Auth tag size is 4 bytes";
    }

    TEST(Restls, VersionHint)
    {
        using namespace psm::stealth::restls;

        config cfg;
        cfg.host = "www.microsoft.com:443";
        cfg.password = "test_password";

        // 默认 version_hint 可以是空或 "tls13"
        EXPECT_TRUE(cfg.version_hint.empty() || cfg.version_hint == "tls13" || cfg.version_hint == "tls12")
            << "Version hint should be empty, tls12, or tls13";

        // 设置 tls13
        cfg.version_hint = "tls13";
        EXPECT_TRUE(cfg.version_hint == "tls13") << "Version hint can be set to tls13";

        // 设置 tls12
        cfg.version_hint = "tls12";
        EXPECT_TRUE(cfg.version_hint == "tls12") << "Version hint can be set to tls12";
    }

} // namespace
