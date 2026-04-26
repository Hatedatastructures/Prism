/**
 * @file Restls.cpp
 * @brief Restls 伪装方案测试
 */

#include <prism/stealth/restls/config.hpp>
#include <prism/stealth/restls/constants.hpp>
#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>
#include <iostream>

#ifdef _WIN32
#include <windows.h>
#endif

namespace
{
    int passed = 0;
    int failed = 0;

    auto LogPass(const std::string_view msg) -> void
    {
        ++passed;
        psm::trace::info("[Restls] PASS: {}", std::string{msg});
    }

    auto LogFail(const std::string_view msg) -> void
    {
        ++failed;
        psm::trace::error("[Restls] FAIL: {}", std::string{msg});
    }

    auto Check(const bool condition, const std::string_view message) -> void
    {
        if (condition) LogPass(message); else LogFail(message);
    }
}

void TestConfigEnabled()
{
    using namespace psm::stealth::restls;

    // 空 host 应该返回 false
    config cfg1;
    cfg1.host = "";
    cfg1.password = "test_password";
    Check(!cfg1.enabled(), "Config disabled when host is empty");

    // 空 password 应该返回 false
    config cfg2;
    cfg2.host = "www.microsoft.com:443";
    cfg2.password = "";
    Check(!cfg2.enabled(), "Config disabled when password is empty");

    // 有效配置应该返回 true
    config cfg3;
    cfg3.host = "www.microsoft.com:443";
    cfg3.password = "test_password";
    Check(cfg3.enabled(), "Config enabled with valid host and password");
}

void TestConstants()
{
    using namespace psm::stealth::restls;

    Check(tls_header_size == 5, "TLS header size is 5 bytes");
    Check(tls_random_size == 32, "TLS random size is 32 bytes");
    Check(content_type_handshake == 0x16, "Handshake content type is 0x16");
    Check(content_type_application_data == 0x17, "Application data content type is 0x17");
    Check(auth_tag_size == 4, "Auth tag size is 4 bytes");
}

void TestVersionHint()
{
    using namespace psm::stealth::restls;

    config cfg;
    cfg.host = "www.microsoft.com:443";
    cfg.password = "test_password";

    // 默认 version_hint 可以是空或 "tls13"
    Check(cfg.version_hint.empty() || cfg.version_hint == "tls13" || cfg.version_hint == "tls12",
          "Version hint should be empty, tls12, or tls13");

    // 设置 tls13
    cfg.version_hint = "tls13";
    Check(cfg.version_hint == "tls13", "Version hint can be set to tls13");

    // 设置 tls12
    cfg.version_hint = "tls12";
    Check(cfg.version_hint == "tls12", "Version hint can be set to tls12");
}

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_global_pooling();
    psm::trace::init({});

    TestConfigEnabled();
    TestConstants();
    TestVersionHint();

    psm::trace::info("[Restls] =============================");
    psm::trace::info("[Restls] Passed: {}, Failed: {}", passed, failed);
    psm::trace::info("[Restls] =============================");
    psm::trace::shutdown();

    return failed == 0 ? 0 : 1;
}