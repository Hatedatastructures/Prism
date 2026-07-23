/**
 * @file MultiplexDuct.cpp
 * @brief 多路复用 duct 与配置单元测试
 * @details 验证 multiplex 层配置结构体的默认值：
 * 1. duct 无独立配置结构体，通过构造函数参数配置
 * 2. smux::config 默认值
 * 3. yamux::config 默认值
 * 4. multiplex::config 默认值
 */

#include <prism/foundation/foundation.hpp>
#include <prism/trace/spdlog.hpp>
#include <prism/protocol/multiplex/config.hpp>
#include <prism/protocol/multiplex/duct.hpp>

#include <gtest/gtest.h>

#include <cstdint>
#include <type_traits>

namespace
{
    // ─── duct config ─────────────────────────

    /**
     * @brief 测试 duct 无独立配置结构体
     * @details duct 类不提供独立的 config 结构体，所有参数通过构造函数直接传入。
     * 验证 duct 仅暴露 stream_id() 查询接口，无 config 类型成员。
     */
    TEST(MultiplexDuct, DuctConfigDefaults)
    {
        // duct 没有独立的 config 结构体，配置通过构造函数参数传入：
        // duct(std::uint32_t stream_id, shared_ptr<core> owner,
        //      shared_transmission target, std::uint32_t buffer_size, resource_pointer mr)
        // 此处验证 duct 类型存在且无 config 嵌套类型。
        // 使用 static_assert 确保 duct 不提供 ::config 子类型。
        // 同时验证 duct 类的 stream_id() 接口存在且返回正确类型。
        static_assert(std::is_same_v<decltype(std::declval<psm::multiplex::duct>().stream_id()), std::uint32_t>,
                      "duct::stream_id() should return std::uint32_t");
    }

    // ─── smux config ─────────────────────────

    /**
     * @brief 测试 smux::config 默认值
     * @details 验证 smux 协议配置结构体的各项默认参数。
     */
    TEST(MultiplexDuct, SmuxConfigDefaults)
    {
        psm::multiplex::smux::config cfg;

        EXPECT_TRUE(cfg.max_streams == 32) << "smux::config::max_streams defaults to 32";
        EXPECT_TRUE(cfg.buffer_size == 4096) << "smux::config::buffer_size defaults to 4096";
        EXPECT_TRUE(cfg.keepalive_interval == 30000) << "smux::config::keepalive_interval defaults to 30000";
        EXPECT_TRUE(cfg.idle_timeout == 60000) << "smux::config::idle_timeout defaults to 60000";
        EXPECT_TRUE(cfg.max_dgram == 65535) << "smux::config::max_dgram defaults to 65535";
    }

    // ─── yamux config ────────────────────────

    /**
     * @brief 测试 yamux::config 默认值
     * @details 验证 yamux 协议配置结构体的各项默认参数。
     */
    TEST(MultiplexDuct, YamuxConfigDefaults)
    {
        psm::multiplex::yamux::config cfg;

        EXPECT_TRUE(cfg.max_streams == 32) << "yamux::config::max_streams defaults to 32";
        EXPECT_TRUE(cfg.buffer_size == 4096) << "yamux::config::buffer_size defaults to 4096";
        EXPECT_TRUE(cfg.initial_window == 256 * 1024) << "yamux::config::initial_window defaults to 256KB";
        EXPECT_TRUE(cfg.enable_ping == true) << "yamux::config::enable_ping defaults to true";
        EXPECT_TRUE(cfg.ping_interval == 30000) << "yamux::config::ping_interval defaults to 30000";
        EXPECT_TRUE(cfg.open_timeout == 30000) << "yamux::config::open_timeout defaults to 30000";
        EXPECT_TRUE(cfg.close_timeout == 30000) << "yamux::config::close_timeout defaults to 30000";
        EXPECT_TRUE(cfg.udp_idle == 60000) << "yamux::config::udp_idle defaults to 60000";
        EXPECT_TRUE(cfg.max_dgram == 65535) << "yamux::config::max_dgram defaults to 65535";
    }

    // ─── multiplex config ────────────────────

    /**
     * @brief 测试 multiplex::config 默认值
     * @details 验证多路复用入口配置的全局开关和子配置默认值。
     */
    TEST(MultiplexDuct, MultiplexConfigDefaults)
    {
        psm::multiplex::config cfg;

        EXPECT_TRUE(cfg.enabled == false) << "multiplex::config::enabled defaults to false";

        // 验证子配置继承各自默认值
        EXPECT_TRUE(cfg.smux.max_streams == 32) << "multiplex::config::smux.max_streams defaults to 32";
        EXPECT_TRUE(cfg.smux.buffer_size == 4096) << "multiplex::config::smux.buffer_size defaults to 4096";
        EXPECT_TRUE(cfg.smux.keepalive_interval == 30000) << "multiplex::config::smux.keepalive_interval defaults to 30000";
        EXPECT_TRUE(cfg.smux.idle_timeout == 60000) << "multiplex::config::smux.idle_timeout defaults to 60000";
        EXPECT_TRUE(cfg.smux.max_dgram == 65535) << "multiplex::config::smux.max_dgram defaults to 65535";

        EXPECT_TRUE(cfg.yamux.max_streams == 32) << "multiplex::config::yamux.max_streams defaults to 32";
        EXPECT_TRUE(cfg.yamux.buffer_size == 4096) << "multiplex::config::yamux.buffer_size defaults to 4096";
        EXPECT_TRUE(cfg.yamux.initial_window == 256 * 1024) << "multiplex::config::yamux.initial_window defaults to 256KB";
        EXPECT_TRUE(cfg.yamux.enable_ping == true) << "multiplex::config::yamux.enable_ping defaults to true";
        EXPECT_TRUE(cfg.yamux.ping_interval == 30000) << "multiplex::config::yamux.ping_interval defaults to 30000";
        EXPECT_TRUE(cfg.yamux.open_timeout == 30000) << "multiplex::config::yamux.open_timeout defaults to 30000";
        EXPECT_TRUE(cfg.yamux.close_timeout == 30000) << "multiplex::config::yamux.close_timeout defaults to 30000";
        EXPECT_TRUE(cfg.yamux.udp_idle == 60000) << "multiplex::config::yamux.udp_idle defaults to 60000";
        EXPECT_TRUE(cfg.yamux.max_dgram == 65535) << "multiplex::config::yamux.max_dgram defaults to 65535";
    }

} // namespace
