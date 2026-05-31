/**
 * @file StealthRegistryPure.cpp
 * @brief Stealth 方案注册表测试
 * @details 测试 scheme_registry 的 find/all/instance 方法
 */

#include <prism/memory.hpp>
#include <prism/stealth/registry.hpp>
#include <prism/trace/spdlog.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

using psm::testing::TestRunner;

namespace
{
    void TestInstanceSingleton(TestRunner &runner)
    {
        auto &a = psm::stealth::scheme_registry::instance();
        auto &b = psm::stealth::scheme_registry::instance();
        runner.Check(&a == &b, "instance: same reference");
    }

    void TestRegisterAndAll(TestRunner &runner)
    {
        psm::stealth::register_schemes();
        auto &reg = psm::stealth::scheme_registry::instance();
        runner.Check(reg.all().size() >= 6, "register: >= 6 schemes");
    }

    void TestFindReality(TestRunner &runner)
    {
        auto s = psm::stealth::scheme_registry::instance().find("reality");
        runner.Check(s != nullptr, "find: reality found");
    }

    void TestFindShadowtls(TestRunner &runner)
    {
        auto s = psm::stealth::scheme_registry::instance().find("shadowtls");
        runner.Check(s != nullptr, "find: shadowtls found");
    }

    void TestFindRestls(TestRunner &runner)
    {
        auto s = psm::stealth::scheme_registry::instance().find("restls");
        runner.Check(s != nullptr, "find: restls found");
    }

    void TestFindAnytls(TestRunner &runner)
    {
        auto s = psm::stealth::scheme_registry::instance().find("anytls");
        runner.Check(s != nullptr, "find: anytls found");
    }

    void TestFindTrusttunnel(TestRunner &runner)
    {
        auto s = psm::stealth::scheme_registry::instance().find("trusttunnel");
        runner.Check(s != nullptr, "find: trusttunnel found");
    }

    void TestFindNonexistent(TestRunner &runner)
    {
        auto s = psm::stealth::scheme_registry::instance().find("no_such_scheme");
        runner.Check(s == nullptr, "find: nonexistent returns null");
    }

    void TestAllHaveNames(TestRunner &runner)
    {
        bool all_named = true;
        for (const auto &s : psm::stealth::scheme_registry::instance().all())
        {
            if (s->name().empty())
                all_named = false;
        }
        runner.Check(all_named, "all: every scheme has a name");
    }

    void TestAllReturnsSameRef(TestRunner &runner)
    {
        auto &v1 = psm::stealth::scheme_registry::instance().all();
        auto &v2 = psm::stealth::scheme_registry::instance().all();
        runner.Check(&v1 == &v2, "all: same reference");
    }
} // namespace

auto main() -> int
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("StealthRegistryPure");

    TestInstanceSingleton(runner);
    TestRegisterAndAll(runner);
    TestFindReality(runner);
    TestFindShadowtls(runner);
    TestFindRestls(runner);
    TestFindAnytls(runner);
    TestFindTrusttunnel(runner);
    TestFindNonexistent(runner);
    TestAllHaveNames(runner);
    TestAllReturnsSameRef(runner);

    return runner.Summary();
}
