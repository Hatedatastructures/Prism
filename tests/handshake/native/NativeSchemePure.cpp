/**
 * @file NativeSchemePure.cpp
 * @brief Native TLS 伪装方案纯函数单元测试
 * @details 测试 native scheme 的 name()、active()、guess() 同步方法。
 *          handshake() 是异步协程，此处仅覆盖同步可测路径。
 */

#include <prism/foundation/foundation.hpp>
#include <prism/handshake/handshake.hpp>
#include <prism/settings/settings.hpp>

#include <gtest/gtest.h>

namespace
{
    TEST(NativeSchemePure, NativeName)
    {
        psm::handshake::native::native scheme;
        EXPECT_EQ(scheme.name(), std::string_view("native")) << "native: name() == 'native'";
    }

    TEST(NativeSchemePure, NativeActiveDisabled)
    {
        psm::settings cfg;
        cfg.stealth.native_tls.enabled = false;

        psm::handshake::native::native scheme;
        EXPECT_TRUE(!scheme.active(cfg)) << "native: active=false when disabled";
    }

    TEST(NativeSchemePure, NativeActiveEnabled)
    {
        psm::settings cfg;
        cfg.stealth.native_tls.enabled = true;

        psm::handshake::native::native scheme;
        EXPECT_TRUE(scheme.active(cfg)) << "native: active=true when enabled";
    }

    TEST(NativeSchemePure, NativeGuess)
    {
        psm::settings cfg;
        psm::handshake::native::native scheme;
        auto result = scheme.guess(cfg);

        EXPECT_EQ(result.score, 50) << "native: guess score=50";
        EXPECT_EQ(result.solo_flag, 0) << "native: guess solo_flag=0";
        EXPECT_EQ(result.note, std::string_view("native TLS fallback"))
            << "native: guess note='native TLS fallback'";
    }

    TEST(NativeSchemePure, NativeTier)
    {
        psm::handshake::native::native scheme;
        EXPECT_EQ(scheme.tier(), 2) << "native: tier=2";
    }

    TEST(NativeSchemePure, NativeCategory)
    {
        psm::handshake::native::native scheme;
        EXPECT_EQ(scheme.category(), psm::handshake::scheme_category::facade) << "native: category=facade";
    }

    TEST(NativeSchemePure, NativeUnique)
    {
        psm::handshake::native::native scheme;
        EXPECT_TRUE(!scheme.unique()) << "native: unique=false";
    }

    TEST(NativeSchemePure, NativeSniff)
    {
        psm::handshake::native::native scheme;
        psm::handshake::hello_features feat;
        auto result = scheme.sniff(0, feat);
        EXPECT_TRUE(!result.hit) << "native: sniff hit=false";
        EXPECT_TRUE(!result.solo) << "native: sniff solo=false";
    }

    TEST(NativeSchemePure, NativeVerify)
    {
        psm::handshake::native::native scheme;
        psm::handshake::hello_features feat;
        psm::settings cfg;
        auto result = scheme.verify(feat, {}, cfg);
        EXPECT_EQ(result.score, 0) << "native: verify score=0";
    }

    TEST(NativeSchemePure, NativeGuessDefault)
    {
        // guess() 应调用 weight() 返回 50
        psm::handshake::native::native scheme;
        psm::settings cfg;
        auto result = scheme.guess(cfg);
        EXPECT_EQ(result.score, 50) << "native: guess score=50 (from weight)";
        EXPECT_EQ(result.solo_flag, 0) << "native: guess solo_flag=0";
    }

} // namespace
