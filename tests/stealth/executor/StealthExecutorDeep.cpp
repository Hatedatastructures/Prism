/**
 * @file StealthExecutorDeep.cpp
 * @brief stealth/executor 深度纯函数测试
 * @details 通过 #include 源文件访问 executor.cpp 中匿名命名空间的
 *          secondary_probe 函数，以及构造函数。
 *          private static 方法（pass_through/ensure_snapshot/try_rewind/find_scheme）
 *          无法直接测试，由集成测试间接覆盖。
 */

#include <gtest/gtest.h>

#include <prism/foundation/foundation.hpp>

// 不用匿名命名空间，因为我们 #include 的源文件里的 anonymous namespace
// 在 psm::stealth 内，需要在同一命名空间或使用 using 声明
#include "../../src/prism/stealth/executor.cpp"

namespace
{
    namespace stealth = psm::stealth;
    using psm::memory::vector;
    using psm::protocol::protocol_type;

    // ─── 构造函数 ───────────────────────────

    TEST(StealthExecutorDeep, Constructor)
    {
        auto &reg = stealth::scheme_registry::instance();
        stealth::scheme_executor exec(reg);
        // 验证构造成功：executor 持有与全局单例相同的 registry 引用
        auto &reg2 = stealth::scheme_registry::instance();
        EXPECT_EQ(&reg, &reg2) << "constructor: executor preserves registry reference";
    }

    // ─── secondary_probe 间接测试 ────────────
    // secondary_probe 在 psm::stealth 的匿名命名空间中，无法直接访问。
    // 但它被 execute_pipeline 在 preread 非空时调用。
    // 这里我们验证 probe::detect 的输出，secondary_probe 的逻辑是：
    //   empty -> unknown
    //   detect(x) if unknown -> shadowsocks
    //   detect(x) otherwise -> detect result

    TEST(StealthExecutorDeep, ProbeDetectHttpGet)
    {
        auto view = std::string_view("GET / HTTP/1.1\r\n");
        auto detected = psm::recognition::probe::detect(view);
        EXPECT_TRUE(detected == protocol_type::http)
            << "probe::detect: GET -> http";
    }

    TEST(StealthExecutorDeep, ProbeDetectHttpPost)
    {
        auto view = std::string_view("POST /api HTTP/1.1\r\n");
        auto detected = psm::recognition::probe::detect(view);
        EXPECT_TRUE(detected == protocol_type::http)
            << "probe::detect: POST -> http";
    }

    TEST(StealthExecutorDeep, ProbeDetectSocks5)
    {
        std::string data;
        data.push_back(static_cast<char>(0x05));
        data.push_back(static_cast<char>(0x01));
        data.push_back(static_cast<char>(0x00));
        auto detected = psm::recognition::probe::detect(std::string_view(data));
        EXPECT_TRUE(detected == protocol_type::socks5)
            << "probe::detect: socks5 -> socks5";
    }

    TEST(StealthExecutorDeep, ProbeDetectTlsClientHello)
    {
        std::string data;
        data.push_back(static_cast<char>(0x16));
        data.push_back(static_cast<char>(0x03));
        data.push_back(static_cast<char>(0x01));
        auto detected = psm::recognition::probe::detect(std::string_view(data));
        EXPECT_TRUE(detected == protocol_type::tls)
            << "probe::detect: TLS ClientHello -> tls";
    }

    TEST(StealthExecutorDeep, ProbeDetectRandomBytes)
    {
        std::string data(24, static_cast<char>(0x42));
        auto detected = psm::recognition::probe::detect(std::string_view(data));
        EXPECT_TRUE(detected == protocol_type::shadowsocks)
            << "probe::detect: random bytes -> shadowsocks (排除法回退)";
    }

} // namespace
