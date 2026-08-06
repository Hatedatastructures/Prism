/**
 * @file StealthRegistryPure.cpp
 * @brief Stealth 方案注册表测试
 * @details 测试 scheme_registry 的 find/all/instance 方法
 */

#include <gtest/gtest.h>

#include <prism/foundation/foundation.hpp>
#include <prism/handshake/registry.hpp>

namespace
{
    TEST(StealthRegistryPure, InstanceSingleton)
    {
        auto &a = psm::handshake::scheme_registry::instance();
        auto &b = psm::handshake::scheme_registry::instance();
        EXPECT_TRUE(&a == &b) << "instance: same reference";
    }

    TEST(StealthRegistryPure, RegisterAndAll)
    {
        psm::handshake::register_schemes();
        auto &reg = psm::handshake::scheme_registry::instance();
        EXPECT_TRUE(reg.all().size() >= 6) << "register: >= 6 schemes";
    }

    TEST(StealthRegistryPure, FindReality)
    {
        psm::handshake::register_schemes();
        auto s = psm::handshake::scheme_registry::instance().find("reality");
        EXPECT_TRUE(s != nullptr) << "find: reality found";
    }

    TEST(StealthRegistryPure, FindShadowtls)
    {
        psm::handshake::register_schemes();
        auto s = psm::handshake::scheme_registry::instance().find("shadowtls");
        EXPECT_TRUE(s != nullptr) << "find: shadowtls found";
    }

    TEST(StealthRegistryPure, FindRestls)
    {
        psm::handshake::register_schemes();
        auto s = psm::handshake::scheme_registry::instance().find("restls");
        EXPECT_TRUE(s != nullptr) << "find: restls found";
    }

    TEST(StealthRegistryPure, FindAnytls)
    {
        psm::handshake::register_schemes();
        auto s = psm::handshake::scheme_registry::instance().find("anytls");
        EXPECT_TRUE(s != nullptr) << "find: anytls found";
    }

    TEST(StealthRegistryPure, FindTrusttunnel)
    {
        psm::handshake::register_schemes();
        auto s = psm::handshake::scheme_registry::instance().find("trusttunnel");
        EXPECT_TRUE(s != nullptr) << "find: trusttunnel found";
    }

    TEST(StealthRegistryPure, FindNonexistent)
    {
        psm::handshake::register_schemes();
        auto s = psm::handshake::scheme_registry::instance().find("no_such_scheme");
        EXPECT_TRUE(s == nullptr) << "find: nonexistent returns null";
    }

    TEST(StealthRegistryPure, AllHaveNames)
    {
        psm::handshake::register_schemes();
        bool all_named = true;
        for (const auto &s : psm::handshake::scheme_registry::instance().all())
        {
            if (s->name().empty())
                all_named = false;
        }
        EXPECT_TRUE(all_named) << "all: every scheme has a name";
    }

    TEST(StealthRegistryPure, AllReturnsSameRef)
    {
        auto &v1 = psm::handshake::scheme_registry::instance().all();
        auto &v2 = psm::handshake::scheme_registry::instance().all();
        EXPECT_TRUE(&v1 == &v2) << "all: same reference";
    }

} // namespace
