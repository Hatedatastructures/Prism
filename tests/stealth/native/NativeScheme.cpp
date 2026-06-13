/**
 * @file NativeScheme.cpp
 * @brief 原生 TLS 伪装方案单元测试
 * @details 覆盖 native scheme 的 name/active/guess/tier/unique/weight 方法。
 */

#include <gtest/gtest.h>

#include <prism/stealth/facade/native.hpp>
#include <prism/config/config.hpp>

#include <string_view>

namespace
{
    TEST(NativeScheme, Name)
    {
        psm::stealth::native::native scheme;
        EXPECT_TRUE(scheme.name() == std::string_view{"native"})
            << "native: name == 'native'";
    }

    TEST(NativeScheme, Tier)
    {
        psm::stealth::native::native scheme;
        EXPECT_TRUE(scheme.tier() == 2) << "native: tier == 2";
    }

    TEST(NativeScheme, Unique)
    {
        psm::stealth::native::native scheme;
        EXPECT_TRUE(scheme.unique() == false) << "native: unique == false";
    }

    TEST(NativeScheme, ActiveEnabled)
    {
        psm::stealth::native::native scheme;
        psm::config cfg;
        cfg.stealth.native_tls.enabled = true;
        EXPECT_TRUE(scheme.active(cfg) == true) << "native: active when enabled=true";
    }

    TEST(NativeScheme, ActiveDisabled)
    {
        psm::stealth::native::native scheme;
        psm::config cfg;
        cfg.stealth.native_tls.enabled = false;
        EXPECT_TRUE(scheme.active(cfg) == false) << "native: inactive when enabled=false";
    }

    TEST(NativeScheme, ActiveDefault)
    {
        psm::stealth::native::native scheme;
        psm::config cfg; // 默认 enabled=true
        EXPECT_TRUE(scheme.active(cfg) == true) << "native: active by default";
    }

    TEST(NativeScheme, Guess)
    {
        psm::stealth::native::native scheme;
        psm::config cfg;
        auto result = scheme.guess(cfg);
        EXPECT_TRUE(result.score == 50) << "native guess: score=50";
        EXPECT_TRUE(result.solo_flag == 0) << "native guess: solo_flag=0";
    }

} // namespace
