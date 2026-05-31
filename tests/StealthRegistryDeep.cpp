/**
 * @file StealthRegistryDeep.cpp
 * @brief stealth/registry 深度纯函数测试
 * @details 通过 #include 源文件访问 registry.cpp 中所有同步函数，
 *          覆盖 register_schemes、scheme_registry 单例/add/all/find。
 */

#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

#include "../src/prism/stealth/registry.cpp"

using psm::testing::TestRunner;

namespace
{
    namespace stealth = psm::stealth;

    void TestRegistryInstance(TestRunner &runner)
    {
        auto &a = stealth::scheme_registry::instance();
        auto &b = stealth::scheme_registry::instance();
        runner.Check(&a == &b, "registry: same instance");
    }

    void TestRegisterSchemes(TestRunner &runner)
    {
        stealth::register_schemes();
        auto &reg = stealth::scheme_registry::instance();
        auto &all = reg.all();
        runner.Check(!all.empty(), "register_schemes: schemes not empty");
        // register_schemes 注册 6 个方案
        runner.Check(all.size() >= 6, "register_schemes: >= 6 schemes");
    }

    void TestFindExisting(TestRunner &runner)
    {
        auto &reg = stealth::scheme_registry::instance();
        auto reality = reg.find("reality");
        runner.Check(reality != nullptr, "find: reality found");
        runner.Check(reality->name() == "reality", "find: reality name match");

        auto shadowtls = reg.find("shadowtls");
        runner.Check(shadowtls != nullptr, "find: shadowtls found");

        auto native = reg.find("native");
        runner.Check(native != nullptr, "find: native found");
    }

    void TestFindAnytls(TestRunner &runner)
    {
        auto &reg = stealth::scheme_registry::instance();
        auto s = reg.find("anytls");
        runner.Check(s != nullptr, "find: anytls found");
        runner.Check(s->name() == "anytls", "find: anytls name match");
    }

    void TestFindTrustTunnel(TestRunner &runner)
    {
        auto &reg = stealth::scheme_registry::instance();
        auto s = reg.find("trusttunnel");
        runner.Check(s != nullptr, "find: trusttunnel found");
    }

    void TestFindRestls(TestRunner &runner)
    {
        auto &reg = stealth::scheme_registry::instance();
        auto s = reg.find("restls");
        runner.Check(s != nullptr, "find: restls found");
    }

    void TestFindNonexistent(TestRunner &runner)
    {
        auto &reg = stealth::scheme_registry::instance();
        auto s = reg.find("nonexistent_scheme");
        runner.Check(s == nullptr, "find: nonexistent -> nullptr");
    }

    void TestFindEmptyName(TestRunner &runner)
    {
        auto &reg = stealth::scheme_registry::instance();
        auto s = reg.find("");
        runner.Check(s == nullptr, "find: empty name -> nullptr");
    }

    void TestAllReturnsVector(TestRunner &runner)
    {
        auto &reg = stealth::scheme_registry::instance();
        auto &all = reg.all();
        for (const auto &s : all)
        {
            runner.Check(s != nullptr, "all: scheme is not null");
            runner.Check(!s->name().empty(), "all: scheme has non-empty name");
        }
    }

} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("StealthRegistryDeep");

    TestRegistryInstance(runner);
    TestRegisterSchemes(runner);
    TestFindExisting(runner);
    TestFindAnytls(runner);
    TestFindTrustTunnel(runner);
    TestFindRestls(runner);
    TestFindNonexistent(runner);
    TestFindEmptyName(runner);
    TestAllReturnsVector(runner);

    return runner.Summary();
}
