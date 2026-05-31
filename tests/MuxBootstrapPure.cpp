/**
 * @file MuxBootstrapPure.cpp
 * @brief 多路复用引导模块纯函数单元测试
 * @details 验证 bootstrap.hpp 头文件正确 include、protocol_type 枚举值、
 *          各协议 config 默认值和可修改性。bootstrap 和 negotiate 均为异步协程，
 *          bootstrap_context / core_options 包含引用成员无法默认构造，
 *          此处仅验证同步可测的纯逻辑。
 */

#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>
#include <prism/multiplex/bootstrap.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

using psm::testing::TestRunner;

namespace
{
    /**
     * @brief 验证 config enabled 字段可修改
     */
    void TestConfigEnabledMutable(TestRunner &runner)
    {
        psm::multiplex::config cfg;
        runner.Check(!cfg.enabled, "config: 初始 enabled=false");
        cfg.enabled = true;
        runner.Check(cfg.enabled, "config: enabled 可设为 true");
    }

    /**
     * @brief 验证 protocol_type 可用于 switch 分支
     */
    void TestProtocolTypeSwitch(TestRunner &runner)
    {
        using pt = psm::multiplex::protocol_type;
        auto classify = [](pt p) -> int
        {
            switch (p)
            {
            case pt::smux:
                return 0;
            case pt::yamux:
                return 1;
            case pt::h2mux:
                return 2;
            default:
                return -1;
            }
        };
        runner.Check(classify(pt::smux) == 0, "protocol_type: switch smux → 0");
        runner.Check(classify(pt::yamux) == 1, "protocol_type: switch yamux → 1");
        runner.Check(classify(pt::h2mux) == 2, "protocol_type: switch h2mux → 2");
        runner.Check(classify(static_cast<pt>(99)) == -1, "protocol_type: switch 未知值 → -1");
    }

    /**
     * @brief 验证各协议 config 的 max_dgram 默认一致
     */
    void TestMaxDgramConsistency(TestRunner &runner)
    {
        psm::multiplex::smux::config sc;
        psm::multiplex::yamux::config yc;
        psm::multiplex::h2mux::config hc;
        runner.Check(sc.max_dgram == yc.max_dgram, "max_dgram: smux == yamux");
        runner.Check(yc.max_dgram == hc.max_dgram, "max_dgram: yamux == h2mux");
        runner.Check(sc.max_dgram == 65535, "max_dgram: 全部为 65535");
    }

    /**
     * @brief 验证 multiplex::config 聚合配置修改
     */
    void TestConfigSubConfigMutable(TestRunner &runner)
    {
        psm::multiplex::config cfg;
        cfg.smux.max_streams = 64;
        cfg.yamux.initial_window = 512 * 1024;
        cfg.h2mux.max_frame_size = 32768;
        runner.Check(cfg.smux.max_streams == 64, "config: smux.max_streams 可修改");
        runner.Check(cfg.yamux.initial_window == 512 * 1024, "config: yamux.initial_window 可修改");
        runner.Check(cfg.h2mux.max_frame_size == 32768, "config: h2mux.max_frame_size 可修改");
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
    }

    /**
     * @brief 验证 yamux::config 默认值
     */
    void TestYamuxConfigDefaults(TestRunner &runner)
    {
        psm::multiplex::yamux::config cfg;
        runner.Check(cfg.max_streams == 32, "yamux: max_streams=32");
        runner.Check(cfg.initial_window == 256 * 1024, "yamux: initial_window=256KB");
        runner.Check(cfg.enable_ping == true, "yamux: enable_ping=true");
        runner.Check(cfg.ping_interval == 30000, "yamux: ping_interval=30000");
        runner.Check(cfg.open_timeout == 30000, "yamux: open_timeout=30000");
        runner.Check(cfg.close_timeout == 30000, "yamux: close_timeout=30000");
    }

    /**
     * @brief 验证 h2mux::config 默认值
     */
    void TestH2muxConfigDefaults(TestRunner &runner)
    {
        psm::multiplex::h2mux::config cfg;
        runner.Check(cfg.max_streams == 256, "h2mux: max_streams=256");
        runner.Check(cfg.max_frame_size == 16384, "h2mux: max_frame_size=16384");
        runner.Check(cfg.idle_timeout == 30000, "h2mux: idle_timeout=30000");
        runner.Check(cfg.udp_idle == 60000, "h2mux: udp_idle=60000");
    }

} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("MuxBootstrapPure");

    TestConfigEnabledMutable(runner);
    TestProtocolTypeSwitch(runner);
    TestMaxDgramConsistency(runner);
    TestConfigSubConfigMutable(runner);
    TestSmuxConfigDefaults(runner);
    TestYamuxConfigDefaults(runner);
    TestH2muxConfigDefaults(runner);

    return runner.Summary();
}
