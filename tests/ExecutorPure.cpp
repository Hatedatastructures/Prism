/**
 * @file ExecutorPure.cpp
 * @brief Stealth 方案执行器纯函数单元测试
 * @details 通过 #include 源文件访问匿名命名空间中的 secondary_probe 辅助函数，
 *          测试其空预读和非空预读的协议检测逻辑。
 *          find_scheme 测试通过 registry::find 间接验证。
 */

#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>
#include <prism/stealth.hpp>
#include <prism/config.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

// #include 源文件以访问匿名命名空间中的 secondary_probe
#include "../src/prism/stealth/executor.cpp"

using psm::testing::TestRunner;

namespace
{
    /**
     * @brief secondary_probe 空预读返回 unknown
     */
    void TestSecondaryProbeEmpty(TestRunner &runner)
    {
        psm::memory::vector<std::byte> empty_preread;
        auto result = psm::stealth::secondary_probe(empty_preread);
        runner.Check(result == psm::protocol::protocol_type::unknown,
                     "secondary_probe: empty preread → unknown");
    }

    /**
     * @brief secondary_probe HTTP GET 请求检测
     */
    void TestSecondaryProbeHttpGet(TestRunner &runner)
    {
        const char *http_get = "GET / HTTP/1.1\r\nHost: example.com\r\n";
        const auto *ptr = reinterpret_cast<const std::byte *>(http_get);
        psm::memory::vector<std::byte> preread(ptr, ptr + std::strlen(http_get));
        auto result = psm::stealth::secondary_probe(preread);
        runner.Check(result == psm::protocol::protocol_type::http,
                     "secondary_probe: HTTP GET → http");
    }

    /**
     * @brief secondary_probe 非 HTTP 非 SOCKS5 字节视为 shadowsocks
     */
    void TestSecondaryProbeShadowsocks(TestRunner &runner)
    {
        const char *random = "\x17\x03\x03\x00\x05hello";
        const auto *ptr = reinterpret_cast<const std::byte *>(random);
        psm::memory::vector<std::byte> preread(ptr, ptr + std::strlen(random));
        auto result = psm::stealth::secondary_probe(preread);
        runner.Check(result == psm::protocol::protocol_type::shadowsocks,
                     "secondary_probe: random bytes → shadowsocks");
    }

    /**
     * @brief secondary_probe SOCKS5 握手检测
     */
    void TestSecondaryProbeSocks5(TestRunner &runner)
    {
        const unsigned char socks5_data[] = {0x05, 0x01, 0x00};
        const auto *ptr = reinterpret_cast<const std::byte *>(socks5_data);
        psm::memory::vector<std::byte> preread(ptr, ptr + sizeof(socks5_data));
        auto result = psm::stealth::secondary_probe(preread);
        runner.Check(result == psm::protocol::protocol_type::socks5,
                     "secondary_probe: SOCKS5 → socks5");
    }

    /**
     * @brief scheme_registry::find 在空注册表中查找返回 nullptr
     */
    void TestRegistryFindEmpty(TestRunner &runner)
    {
        psm::stealth::scheme_registry registry;
        auto found = registry.find("native");
        runner.Check(!found, "registry::find: empty → nullptr");
    }

    /**
     * @brief scheme_registry::find 在有 native 的注册表中查找命中
     */
    void TestRegistryFindHit(TestRunner &runner)
    {
        psm::stealth::scheme_registry registry;
        auto scheme = std::make_shared<psm::stealth::native::native>();
        registry.add(scheme);
        auto found = registry.find("native");
        runner.Check(found != nullptr, "registry::find: native registered → found");
        runner.Check(found->name() == std::string_view("native"),
                     "registry::find: found name == 'native'");
    }

    /**
     * @brief scheme_registry::find 查找不存在的方案返回 nullptr
     */
    void TestRegistryFindMiss(TestRunner &runner)
    {
        psm::stealth::scheme_registry registry;
        auto scheme = std::make_shared<psm::stealth::native::native>();
        registry.add(scheme);
        auto found = registry.find("nonexistent");
        runner.Check(!found, "registry::find: nonexistent → nullptr");
    }

    /**
     * @brief scheme_executor 从注册表初始化
     */
    void TestExecutorFromRegistry(TestRunner &runner)
    {
        psm::stealth::scheme_registry registry;
        auto scheme = std::make_shared<psm::stealth::native::native>();
        registry.add(scheme);
        psm::stealth::scheme_executor executor(registry);
        // 验证构造不崩溃即可
        runner.Check(true, "executor: constructed from registry");
    }

} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("ExecutorPure");

    TestSecondaryProbeEmpty(runner);
    TestSecondaryProbeHttpGet(runner);
    TestSecondaryProbeShadowsocks(runner);
    TestSecondaryProbeSocks5(runner);
    TestRegistryFindEmpty(runner);
    TestRegistryFindHit(runner);
    TestRegistryFindMiss(runner);
    TestExecutorFromRegistry(runner);

    return runner.Summary();
}
