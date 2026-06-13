/**
 * @file NativeSchemePure.cpp
 * @brief Native TLS 伪装方案纯函数单元测试
 * @details 测试 native scheme 的 name()、active()、guess() 同步方法。
 *          handshake() 是异步协程，此处仅覆盖同步可测路径。
 */

#include <gtest/gtest.h>

#include <prism/core/core.hpp>
#include <prism/stealth/stealth.hpp>
#include <prism/config/config.hpp>

namespace
{
    TEST(NativeSchemePure, NativeName)
    {
        psm::stealth::native::native scheme;
        EXPECT_TRUE(scheme.name() == std::string_view("native"))
            << "native: name() == 'native'";
    }

    TEST(NativeSchemePure, NativeActiveDisabled)
    {
        psm::config cfg;
        cfg.stealth.native_tls.enabled = false;

        psm::stealth::native::native scheme;
        EXPECT_TRUE(!scheme.active(cfg)) << "native: active=false when disabled";
    }

    TEST(NativeSchemePure, NativeActiveEnabled)
    {
        psm::config cfg;
        cfg.stealth.native_tls.enabled = true;

        psm::stealth::native::native scheme;
        EXPECT_TRUE(scheme.active(cfg)) << "native: active=true when enabled";
    }

    TEST(NativeSchemePure, NativeGuess)
    {
        psm::config cfg;
        psm::stealth::native::native scheme;
        auto result = scheme.guess(cfg);

        EXPECT_TRUE(result.score == 50) << "native: guess score=50";
        EXPECT_TRUE(result.solo_flag == 0) << "native: guess solo_flag=0";
        EXPECT_TRUE(result.note == std::string_view("native TLS fallback"))
            << "native: guess note='native TLS fallback'";
    }

    TEST(NativeSchemePure, NativeTier)
    {
        psm::stealth::native::native scheme;
        EXPECT_TRUE(scheme.tier() == 2) << "native: tier=2";
    }

    TEST(NativeSchemePure, NativeCategory)
    {
        psm::stealth::native::native scheme;
        EXPECT_TRUE(scheme.category() == psm::stealth::scheme_category::facade)
            << "native: category=facade";
    }

    TEST(NativeSchemePure, NativeUnique)
    {
        psm::stealth::native::native scheme;
        EXPECT_TRUE(!scheme.unique()) << "native: unique=false";
    }

    TEST(NativeSchemePure, NativeSniff)
    {
        psm::stealth::native::native scheme;
        psm::stealth::hello_features feat;
        auto result = scheme.sniff(0, feat);
        EXPECT_TRUE(!result.hit) << "native: sniff hit=false";
        EXPECT_TRUE(!result.solo) << "native: sniff solo=false";
    }

    TEST(NativeSchemePure, NativeVerify)
    {
        psm::stealth::native::native scheme;
        psm::stealth::hello_features feat;
        psm::config cfg;
        auto result = scheme.verify(feat, {}, cfg);
        EXPECT_TRUE(result.score == 0) << "native: verify score=0";
    }

    TEST(NativeSchemePure, NativeGuessDefault)
    {
        // guess() 应调用 weight() 返回 50
        psm::stealth::native::native scheme;
        psm::config cfg;
        auto result = scheme.guess(cfg);
        EXPECT_TRUE(result.score == 50) << "native: guess score=50 (from weight)";
        EXPECT_TRUE(result.solo_flag == 0) << "native: guess solo_flag=0";
    }

} // namespace
