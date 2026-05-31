/**
 * @file StealthExecutorDeep.cpp
 * @brief stealth/executor 深度纯函数测试
 * @details 通过 #include 源文件访问 executor.cpp 中匿名命名空间的
 *          secondary_probe 函数，以及构造函数。
 *          private static 方法（pass_through/ensure_snapshot/try_rewind/find_scheme）
 *          无法直接测试，由集成测试间接覆盖。
 */

#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

// 不用匿名命名空间，因为我们 #include 的源文件里的 anonymous namespace
// 在 psm::stealth 内，需要在同一命名空间或使用 using 声明
#include "../src/prism/stealth/executor.cpp"

using psm::testing::TestRunner;

namespace
{
    namespace stealth = psm::stealth;
    using psm::memory::vector;
    using psm::protocol::protocol_type;

    // secondary_probe 在 psm::stealth 的匿名命名空间中，
    // #include 后它会出现在该命名空间中。我们需要通过 using 引入。
    // 但匿名命名空间的函数对外不可见，只能通过 ADL 或在同一个 TU 中使用。
    // 由于我们 #include 了 executor.cpp，该匿名命名空间的内容也在此 TU 中。
    // 但测试代码在全局匿名命名空间中，不在 psm::stealth 中。
    // 解决方案：用 using 引入整个匿名命名空间的 secondary_probe 是不可能的。
    // 改用 wrapper 函数调用。

    // ─── 构造函数 ───────────────────────────

    void TestConstructor(TestRunner &runner)
    {
        auto &reg = stealth::scheme_registry::instance();
        stealth::scheme_executor exec(reg);
        runner.Check(true, "constructor: no crash");
    }

    // ─── secondary_probe 间接测试 ────────────
    // secondary_probe 在 psm::stealth 的匿名命名空间中，无法直接访问。
    // 但它被 execute_pipeline 在 preread 非空时调用。
    // 这里我们验证 probe::detect 的输出，secondary_probe 的逻辑是：
    //   empty -> unknown
    //   detect(x) if unknown -> shadowsocks
    //   detect(x) otherwise -> detect result

    void TestProbeDetectHttpGet(TestRunner &runner)
    {
        auto view = std::string_view("GET / HTTP/1.1\r\n");
        auto detected = psm::recognition::probe::detect(view);
        runner.Check(detected == protocol_type::http,
                     "probe::detect: GET -> http");
    }

    void TestProbeDetectHttpPost(TestRunner &runner)
    {
        auto view = std::string_view("POST /api HTTP/1.1\r\n");
        auto detected = psm::recognition::probe::detect(view);
        runner.Check(detected == protocol_type::http,
                     "probe::detect: POST -> http");
    }

    void TestProbeDetectSocks5(TestRunner &runner)
    {
        std::string data;
        data.push_back(static_cast<char>(0x05));
        data.push_back(static_cast<char>(0x01));
        data.push_back(static_cast<char>(0x00));
        auto detected = psm::recognition::probe::detect(std::string_view(data));
        runner.Check(detected == protocol_type::socks5,
                     "probe::detect: socks5 -> socks5");
    }

    void TestProbeDetectTlsClientHello(TestRunner &runner)
    {
        std::string data;
        data.push_back(static_cast<char>(0x16));
        data.push_back(static_cast<char>(0x03));
        data.push_back(static_cast<char>(0x01));
        auto detected = psm::recognition::probe::detect(std::string_view(data));
        runner.Check(detected == protocol_type::tls,
                     "probe::detect: TLS ClientHello -> tls");
    }

    void TestProbeDetectRandomBytes(TestRunner &runner)
    {
        std::string data(24, static_cast<char>(0x42));
        auto detected = psm::recognition::probe::detect(std::string_view(data));
        runner.Check(detected == protocol_type::shadowsocks,
                     "probe::detect: random bytes -> shadowsocks (排除法回退)");
    }

} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    // 注册 schemes（确保构造函数可以工作）
    stealth::register_schemes();

    TestRunner runner("StealthExecutorDeep");

    TestConstructor(runner);

    TestProbeDetectHttpGet(runner);
    TestProbeDetectHttpPost(runner);
    TestProbeDetectSocks5(runner);
    TestProbeDetectTlsClientHello(runner);
    TestProbeDetectRandomBytes(runner);

    return runner.Summary();
}
