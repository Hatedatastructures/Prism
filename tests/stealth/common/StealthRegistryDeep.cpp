/**
 * @file StealthRegistryDeep.cpp
 * @brief stealth/registry 深度纯函数测试
 * @details 通过 #include 源文件访问 registry.cpp 中所有同步函数，
 *          覆盖 register_schemes、scheme_registry 单例/add/all/find。
 */

#include <gtest/gtest.h>

#include <prism/foundation/foundation.hpp>

#include "../../src/prism/stealth/registry.cpp"

namespace
{
    namespace stealth = psm::stealth;

    TEST(StealthRegistryDeep, RegistryInstance)
    {
        auto &a = stealth::scheme_registry::instance();
        auto &b = stealth::scheme_registry::instance();
        EXPECT_TRUE(&a == &b) << "registry: same instance";
    }

    TEST(StealthRegistryDeep, RegisterSchemes)
    {
        stealth::register_schemes();
        auto &reg = stealth::scheme_registry::instance();
        auto &all = reg.all();
        EXPECT_TRUE(!all.empty()) << "register_schemes: schemes not empty";
        // register_schemes 注册 6 个方案
        EXPECT_TRUE(all.size() >= 6) << "register_schemes: >= 6 schemes";
    }

    TEST(StealthRegistryDeep, FindExisting)
    {
        stealth::register_schemes();
        auto &reg = stealth::scheme_registry::instance();
        auto reality = reg.find("reality");
        EXPECT_TRUE(reality != nullptr) << "find: reality found";
        EXPECT_TRUE(reality->name() == "reality") << "find: reality name match";

        auto shadowtls = reg.find("shadowtls");
        EXPECT_TRUE(shadowtls != nullptr) << "find: shadowtls found";

        auto native = reg.find("native");
        EXPECT_TRUE(native != nullptr) << "find: native found";
    }

    TEST(StealthRegistryDeep, FindAnytls)
    {
        stealth::register_schemes();
        auto &reg = stealth::scheme_registry::instance();
        auto s = reg.find("anytls");
        EXPECT_TRUE(s != nullptr) << "find: anytls found";
        EXPECT_TRUE(s->name() == "anytls") << "find: anytls name match";
    }

    TEST(StealthRegistryDeep, FindTrustTunnel)
    {
        stealth::register_schemes();
        auto &reg = stealth::scheme_registry::instance();
        auto s = reg.find("trusttunnel");
        EXPECT_TRUE(s != nullptr) << "find: trusttunnel found";
    }

    TEST(StealthRegistryDeep, FindRestls)
    {
        stealth::register_schemes();
        auto &reg = stealth::scheme_registry::instance();
        auto s = reg.find("restls");
        EXPECT_TRUE(s != nullptr) << "find: restls found";
    }

    TEST(StealthRegistryDeep, FindNonexistent)
    {
        stealth::register_schemes();
        auto &reg = stealth::scheme_registry::instance();
        auto s = reg.find("nonexistent_scheme");
        EXPECT_TRUE(s == nullptr) << "find: nonexistent -> nullptr";
    }

    TEST(StealthRegistryDeep, FindEmptyName)
    {
        stealth::register_schemes();
        auto &reg = stealth::scheme_registry::instance();
        auto s = reg.find("");
        EXPECT_TRUE(s == nullptr) << "find: empty name -> nullptr";
    }

    TEST(StealthRegistryDeep, AllReturnsVector)
    {
        stealth::register_schemes();
        auto &reg = stealth::scheme_registry::instance();
        auto &all = reg.all();
        for (const auto &s : all)
        {
            EXPECT_TRUE(s != nullptr) << "all: scheme is not null";
            EXPECT_TRUE(!s->name().empty()) << "all: scheme has non-empty name";
        }
    }

} // namespace
