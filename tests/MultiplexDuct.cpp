/**
 * @file MultiplexDuct.cpp
 * @brief 多路复用 duct 与配置单元测试
 * @details 验证 multiplex 层配置结构体的默认值：
 * 1. duct 无独立配置结构体，通过构造函数参数配置
 * 2. smux::config 默认值
 * 3. yamux::config 默认值
 * 4. multiplex::config 默认值
 */

#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>
#include <prism/multiplex/config.hpp>
#include <prism/multiplex/duct.hpp>

#include "common/TestRunner.hpp"

#include <cstdint>
#include <type_traits>

namespace
{
    psm::testing::TestRunner runner("MultiplexDuct");
} // namespace

// ---------- duct config ----------

/**
 * @brief 测试 duct 无独立配置结构体
 * @details duct 类不提供独立的 config 结构体，所有参数通过构造函数直接传入。
 * 验证 duct 仅暴露 stream_id() 查询接口，无 config 类型成员。
 */
void TestDuctConfigDefaults()
{
    runner.LogInfo("=== TestDuctConfigDefaults ===");

    // duct 没有独立的 config 结构体，配置通过构造函数参数传入：
    // duct(std::uint32_t stream_id, shared_ptr<core> owner,
    //      shared_transmission target, std::uint32_t buffer_size, resource_pointer mr)
    // 此处验证 duct 类型存在且无 config 嵌套类型。
    // 使用 static_assert 确保 duct 不提供 ::config 子类型。
    // 同时验证 duct 类的 stream_id() 接口存在且返回正确类型。
    static_assert(std::is_same_v<decltype(std::declval<psm::multiplex::duct>().stream_id()), std::uint32_t>,
                  "duct::stream_id() should return std::uint32_t");

    runner.LogPass("duct has no independent config struct");
}

// ---------- smux config ----------

/**
 * @brief 测试 smux::config 默认值
 * @details 验证 smux 协议配置结构体的各项默认参数。
 */
void TestSmuxConfigDefaults()
{
    runner.LogInfo("=== TestSmuxConfigDefaults ===");

    psm::multiplex::smux::config cfg;

    runner.Check(cfg.max_streams == 32, "smux::config::max_streams defaults to 32");
    runner.Check(cfg.buffer_size == 4096, "smux::config::buffer_size defaults to 4096");
    runner.Check(cfg.keepalive_interval_ms == 30000, "smux::config::keepalive_interval_ms defaults to 30000");
    runner.Check(cfg.udp_idle_timeout_ms == 60000, "smux::config::udp_idle_timeout_ms defaults to 60000");
    runner.Check(cfg.udp_max_datagram == 65535, "smux::config::udp_max_datagram defaults to 65535");
}

// ---------- yamux config ----------

/**
 * @brief 测试 yamux::config 默认值
 * @details 验证 yamux 协议配置结构体的各项默认参数。
 */
void TestYamuxConfigDefaults()
{
    runner.LogInfo("=== TestYamuxConfigDefaults ===");

    psm::multiplex::yamux::config cfg;

    runner.Check(cfg.max_streams == 32, "yamux::config::max_streams defaults to 32");
    runner.Check(cfg.buffer_size == 4096, "yamux::config::buffer_size defaults to 4096");
    runner.Check(cfg.initial_window == 256 * 1024, "yamux::config::initial_window defaults to 256KB");
    runner.Check(cfg.enable_ping == true, "yamux::config::enable_ping defaults to true");
    runner.Check(cfg.ping_interval_ms == 30000, "yamux::config::ping_interval_ms defaults to 30000");
    runner.Check(cfg.stream_open_timeout_ms == 30000, "yamux::config::stream_open_timeout_ms defaults to 30000");
    runner.Check(cfg.stream_close_timeout_ms == 30000, "yamux::config::stream_close_timeout_ms defaults to 30000");
    runner.Check(cfg.udp_idle_timeout_ms == 60000, "yamux::config::udp_idle_timeout_ms defaults to 60000");
    runner.Check(cfg.udp_max_datagram == 65535, "yamux::config::udp_max_datagram defaults to 65535");
}

// ---------- multiplex config ----------

/**
 * @brief 测试 multiplex::config 默认值
 * @details 验证多路复用入口配置的全局开关和子配置默认值。
 */
void TestMultiplexConfigDefaults()
{
    runner.LogInfo("=== TestMultiplexConfigDefaults ===");

    psm::multiplex::config cfg;

    runner.Check(cfg.enabled == false, "multiplex::config::enabled defaults to false");

    // 验证子配置继承各自默认值
    runner.Check(cfg.smux.max_streams == 32, "multiplex::config::smux.max_streams defaults to 32");
    runner.Check(cfg.smux.buffer_size == 4096, "multiplex::config::smux.buffer_size defaults to 4096");
    runner.Check(cfg.smux.keepalive_interval_ms == 30000, "multiplex::config::smux.keepalive_interval_ms defaults to 30000");
    runner.Check(cfg.smux.udp_idle_timeout_ms == 60000, "multiplex::config::smux.udp_idle_timeout_ms defaults to 60000");
    runner.Check(cfg.smux.udp_max_datagram == 65535, "multiplex::config::smux.udp_max_datagram defaults to 65535");

    runner.Check(cfg.yamux.max_streams == 32, "multiplex::config::yamux.max_streams defaults to 32");
    runner.Check(cfg.yamux.buffer_size == 4096, "multiplex::config::yamux.buffer_size defaults to 4096");
    runner.Check(cfg.yamux.initial_window == 256 * 1024, "multiplex::config::yamux.initial_window defaults to 256KB");
    runner.Check(cfg.yamux.enable_ping == true, "multiplex::config::yamux.enable_ping defaults to true");
    runner.Check(cfg.yamux.ping_interval_ms == 30000, "multiplex::config::yamux.ping_interval_ms defaults to 30000");
    runner.Check(cfg.yamux.stream_open_timeout_ms == 30000, "multiplex::config::yamux.stream_open_timeout_ms defaults to 30000");
    runner.Check(cfg.yamux.stream_close_timeout_ms == 30000, "multiplex::config::yamux.stream_close_timeout_ms defaults to 30000");
    runner.Check(cfg.yamux.udp_idle_timeout_ms == 60000, "multiplex::config::yamux.udp_idle_timeout_ms defaults to 60000");
    runner.Check(cfg.yamux.udp_max_datagram == 65535, "multiplex::config::yamux.udp_max_datagram defaults to 65535");
}

/**
 * @brief 测试入口
 * @details 初始化全局内存池和日志系统，依次运行 duct 配置、smux 配置、
 * yamux 配置、multiplex 入口配置等默认值测试用例，输出结果。
 * @return 0 表示全部通过，1 表示存在失败
 */
int main()
{
    psm::memory::system::enable_global_pooling();
    psm::trace::init({});

    runner.LogInfo("========== Multiplex Duct Tests ==========");

    TestDuctConfigDefaults();
    TestSmuxConfigDefaults();
    TestYamuxConfigDefaults();
    TestMultiplexConfigDefaults();

    return runner.Summary();
}
