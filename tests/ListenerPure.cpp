/**
 * @file ListenerPure.cpp
 * @brief listener::make_affinity 纯逻辑单元测试
 * @details 通过 #include 源文件访问 private static 方法 make_affinity，
 *          测试 IPv4/IPv6/loopback/zero 地址的亲和性哈希计算。
 */

#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>

#include <boost/asio.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

namespace net = boost::asio;

// 通过预处理器 hack 访问 private static 方法（仅限测试翻译单元）
#define private public
#include "../src/prism/instance/front/listener.cpp"
#undef private

using psm::testing::TestRunner;

namespace
{
    void TestMakeAffinityIPv4(TestRunner &runner)
    {
        net::ip::tcp::endpoint ep(net::ip::make_address_v4("192.168.1.1"), 80);
        auto result = psm::instance::front::listener::make_affinity(ep);
        runner.Check(result == 0xC0A80101ULL, "make_affinity IPv4: 192.168.1.1");
    }

    void TestMakeAffinityIPv4Loopback(TestRunner &runner)
    {
        net::ip::tcp::endpoint ep(net::ip::make_address_v4("127.0.0.1"), 443);
        auto result = psm::instance::front::listener::make_affinity(ep);
        runner.Check(result == 0x7F000001ULL, "make_affinity IPv4: 127.0.0.1");
    }

    void TestMakeAffinityIPv6Loopback(TestRunner &runner)
    {
        net::ip::tcp::endpoint ep(net::ip::make_address_v6("::1"), 443);
        auto result = psm::instance::front::listener::make_affinity(ep);
        // ::1 = 00..01, high=0, low=1, high^low = 1
        runner.Check(result == 1ULL, "make_affinity IPv6: ::1");
    }

    void TestMakeAffinityZeroAddress(TestRunner &runner)
    {
        net::ip::tcp::endpoint ep(net::ip::make_address_v4("0.0.0.0"), 0);
        auto result = psm::instance::front::listener::make_affinity(ep);
        runner.Check(result == 0ULL, "make_affinity IPv4: 0.0.0.0");
    }
}

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("ListenerPure");

    TestMakeAffinityIPv4(runner);
    TestMakeAffinityIPv4Loopback(runner);
    TestMakeAffinityIPv6Loopback(runner);
    TestMakeAffinityZeroAddress(runner);

    return runner.Summary();
}
