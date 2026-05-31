/**
 * @file MuxCorePure.cpp
 * @brief 多路复用核心基类纯函数单元测试
 * @details 通过 #include 源文件访问匿名命名空间中的 resolve_mr 辅助函数，
 *          测试其空指针/非空指针分支；同时验证 config 默认值和 protocol_type
 *          枚举值，确认 core.hpp 头文件可正确 include。
 */

#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

// #include 源文件以访问匿名命名空间中的 resolve_mr 纯辅助函数
#include "../src/prism/multiplex/core.cpp"

using psm::testing::TestRunner;

namespace
{
    /**
     * @brief resolve_mr 传入空指针时应返回 current_resource
     */
    void TestResolveMrNull(TestRunner &runner)
    {
        auto *expected = psm::memory::current_resource();
        auto *result = resolve_mr(nullptr);
        runner.Check(result == expected, "resolve_mr: nullptr → current_resource()");
    }

    /**
     * @brief resolve_mr 传入非空指针时应返回原指针
     */
    void TestResolveMrNonNull(TestRunner &runner)
    {
        psm::memory::unsynchronized_pool pool;
        auto *result = resolve_mr(&pool);
        runner.Check(result == &pool, "resolve_mr: 非空指针 → 返回原指针");
    }

    /**
     * @brief resolve_mr 传入同步池时应返回同步池指针
     */
    void TestResolveMrSyncPool(TestRunner &runner)
    {
        psm::memory::synchronized_pool pool;
        auto *result = resolve_mr(&pool);
        runner.Check(result == &pool, "resolve_mr: 同步池指针 → 返回同步池指针");
    }

    /**
     * @brief 验证 resolve_mr 返回值可用于 PMR 容器分配
     */
    void TestResolveMrUsable(TestRunner &runner)
    {
        auto *mr = resolve_mr(nullptr);
        runner.Check(mr != nullptr, "resolve_mr: 返回值非空");
        // 用返回的 mr 创建 PMR 容器验证可用性
        psm::memory::vector<int> vec(mr);
        vec.push_back(42);
        runner.Check(!vec.empty(), "resolve_mr: 返回的 mr 可创建 PMR 容器");
        runner.Check(vec[0] == 42, "resolve_mr: PMR 容器读写正确");
    }

    /**
     * @brief 验证 multiplex::config 默认值
     */
    void TestConfigDefaults(TestRunner &runner)
    {
        psm::multiplex::config cfg;
        runner.Check(!cfg.enabled, "config: 默认 enabled=false");
        runner.Check(cfg.smux.max_streams == 32, "config: smux.max_streams=32");
        runner.Check(cfg.smux.buffer_size == 4096, "config: smux.buffer_size=4096");
        runner.Check(cfg.yamux.max_streams == 32, "config: yamux.max_streams=32");
        runner.Check(cfg.h2mux.max_streams == 256, "config: h2mux.max_streams=256");
    }

    /**
     * @brief 验证 protocol_type 枚举值
     */
    void TestProtocolTypeEnumValues(TestRunner &runner)
    {
        using pt = psm::multiplex::protocol_type;
        runner.Check(static_cast<std::uint8_t>(pt::smux) == 0, "protocol_type: smux=0");
        runner.Check(static_cast<std::uint8_t>(pt::yamux) == 1, "protocol_type: yamux=1");
        runner.Check(static_cast<std::uint8_t>(pt::h2mux) == 2, "protocol_type: h2mux=2");
    }

    /**
     * @brief 验证 smux::config 默认值
     */
    void TestSmuxConfigDefaults(TestRunner &runner)
    {
        psm::multiplex::smux::config cfg;
        runner.Check(cfg.max_streams == 32, "smux: max_streams=32");
        runner.Check(cfg.buffer_size == 4096, "smux: buffer_size=4096");
        runner.Check(cfg.keepalive_interval == 30000, "smux: keepalive_interval=30000");
        runner.Check(cfg.idle_timeout == 60000, "smux: idle_timeout=60000");
        runner.Check(cfg.max_dgram == 65535, "smux: max_dgram=65535");
    }

    /**
     * @brief 验证 yamux::config 默认值
     */
    void TestYamuxConfigDefaults(TestRunner &runner)
    {
        psm::multiplex::yamux::config cfg;
        runner.Check(cfg.max_streams == 32, "yamux: max_streams=32");
        runner.Check(cfg.buffer_size == 4096, "yamux: buffer_size=4096");
        runner.Check(cfg.initial_window == 256 * 1024, "yamux: initial_window=256KB");
        runner.Check(cfg.enable_ping == true, "yamux: enable_ping=true");
        runner.Check(cfg.ping_interval == 30000, "yamux: ping_interval=30000");
        runner.Check(cfg.open_timeout == 30000, "yamux: open_timeout=30000");
        runner.Check(cfg.close_timeout == 30000, "yamux: close_timeout=30000");
        runner.Check(cfg.udp_idle == 60000, "yamux: udp_idle=60000");
    }

    /**
     * @brief 验证 h2mux::config 默认值
     */
    void TestH2muxConfigDefaults(TestRunner &runner)
    {
        psm::multiplex::h2mux::config cfg;
        runner.Check(cfg.max_streams == 256, "h2mux: max_streams=256");
        runner.Check(cfg.buffer_size == 4096, "h2mux: buffer_size=4096");
        runner.Check(cfg.max_frame_size == 16384, "h2mux: max_frame_size=16384");
        runner.Check(cfg.idle_timeout == 30000, "h2mux: idle_timeout=30000");
        runner.Check(cfg.udp_idle == 60000, "h2mux: udp_idle=60000");
        runner.Check(cfg.max_dgram == 65535, "h2mux: max_dgram=65535");
    }

} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("MuxCorePure");

    TestResolveMrNull(runner);
    TestResolveMrNonNull(runner);
    TestResolveMrSyncPool(runner);
    TestResolveMrUsable(runner);
    TestConfigDefaults(runner);
    TestProtocolTypeEnumValues(runner);
    TestSmuxConfigDefaults(runner);
    TestYamuxConfigDefaults(runner);
    TestH2muxConfigDefaults(runner);

    return runner.Summary();
}
