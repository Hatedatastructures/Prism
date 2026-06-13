/**
 * @file MuxBootstrapPure.cpp
 * @brief 多路复用引导模块纯函数单元测试
 * @details 验证 bootstrap.hpp 头文件正确 include、protocol_type 枚举值、
 *          各协议 config 默认值和可修改性。bootstrap 和 negotiate 均为异步协程，
 *          bootstrap_context / core_options 包含引用成员无法默认构造，
 *          此处仅验证同步可测的纯逻辑。
 */

#include <prism/core/core.hpp>
#include <prism/trace/spdlog.hpp>
#include <prism/proto/multiplex/bootstrap.hpp>

#include <gtest/gtest.h>

namespace
{
    /**
     * @brief 验证 config enabled 字段可修改
     */
    TEST(MuxBootstrapPure, ConfigEnabledMutable)
    {
        psm::multiplex::config cfg;
        EXPECT_TRUE(!cfg.enabled) << "config: 初始 enabled=false";
        cfg.enabled = true;
        EXPECT_TRUE(cfg.enabled) << "config: enabled 可设为 true";
    }

    /**
     * @brief 验证 protocol_type 可用于 switch 分支
     */
    TEST(MuxBootstrapPure, ProtocolTypeSwitch)
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
        EXPECT_TRUE(classify(pt::smux) == 0) << "protocol_type: switch smux -> 0";
        EXPECT_TRUE(classify(pt::yamux) == 1) << "protocol_type: switch yamux -> 1";
        EXPECT_TRUE(classify(pt::h2mux) == 2) << "protocol_type: switch h2mux -> 2";
        EXPECT_TRUE(classify(static_cast<pt>(99)) == -1) << "protocol_type: switch 未知值 -> -1";
    }

    /**
     * @brief 验证各协议 config 的 max_dgram 默认一致
     */
    TEST(MuxBootstrapPure, MaxDgramConsistency)
    {
        psm::multiplex::smux::config sc;
        psm::multiplex::yamux::config yc;
        psm::multiplex::h2mux::config hc;
        EXPECT_TRUE(sc.max_dgram == yc.max_dgram) << "max_dgram: smux == yamux";
        EXPECT_TRUE(yc.max_dgram == hc.max_dgram) << "max_dgram: yamux == h2mux";
        EXPECT_TRUE(sc.max_dgram == 65535) << "max_dgram: 全部为 65535";
    }

    /**
     * @brief 验证 multiplex::config 聚合配置修改
     */
    TEST(MuxBootstrapPure, ConfigSubConfigMutable)
    {
        psm::multiplex::config cfg;
        cfg.smux.max_streams = 64;
        cfg.yamux.initial_window = 512 * 1024;
        cfg.h2mux.max_frame_size = 32768;
        EXPECT_TRUE(cfg.smux.max_streams == 64) << "config: smux.max_streams 可修改";
        EXPECT_TRUE(cfg.yamux.initial_window == 512 * 1024) << "config: yamux.initial_window 可修改";
        EXPECT_TRUE(cfg.h2mux.max_frame_size == 32768) << "config: h2mux.max_frame_size 可修改";
    }

    /**
     * @brief 验证 smux::config 默认值
     */
    TEST(MuxBootstrapPure, SmuxConfigDefaults)
    {
        psm::multiplex::smux::config cfg;
        EXPECT_TRUE(cfg.max_streams == 32) << "smux: max_streams=32";
        EXPECT_TRUE(cfg.buffer_size == 4096) << "smux: buffer_size=4096";
        EXPECT_TRUE(cfg.keepalive_interval == 30000) << "smux: keepalive_interval=30000";
        EXPECT_TRUE(cfg.idle_timeout == 60000) << "smux: idle_timeout=60000";
    }

    /**
     * @brief 验证 yamux::config 默认值
     */
    TEST(MuxBootstrapPure, YamuxConfigDefaults)
    {
        psm::multiplex::yamux::config cfg;
        EXPECT_TRUE(cfg.max_streams == 32) << "yamux: max_streams=32";
        EXPECT_TRUE(cfg.initial_window == 256 * 1024) << "yamux: initial_window=256KB";
        EXPECT_TRUE(cfg.enable_ping == true) << "yamux: enable_ping=true";
        EXPECT_TRUE(cfg.ping_interval == 30000) << "yamux: ping_interval=30000";
        EXPECT_TRUE(cfg.open_timeout == 30000) << "yamux: open_timeout=30000";
        EXPECT_TRUE(cfg.close_timeout == 30000) << "yamux: close_timeout=30000";
    }

    /**
     * @brief 验证 h2mux::config 默认值
     */
    TEST(MuxBootstrapPure, H2muxConfigDefaults)
    {
        psm::multiplex::h2mux::config cfg;
        EXPECT_TRUE(cfg.max_streams == 256) << "h2mux: max_streams=256";
        EXPECT_TRUE(cfg.max_frame_size == 16384) << "h2mux: max_frame_size=16384";
        EXPECT_TRUE(cfg.idle_timeout == 30000) << "h2mux: idle_timeout=30000";
        EXPECT_TRUE(cfg.udp_idle == 60000) << "h2mux: udp_idle=60000";
    }

} // namespace
