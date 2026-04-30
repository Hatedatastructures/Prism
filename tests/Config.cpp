/**
 * @file Config.cpp
 * @brief 协议与伪装配置结构体单元测试
 * @details 验证各协议和伪装方案配置结构体的默认值与有效性逻辑，包括：
 * 1. SOCKS5 配置默认值（TCP/UDP 开关、UDP 参数、认证开关）
 * 2. SOCKS5 配置有效性（有认证用户时应启用认证）
 * 3. Trojan 配置默认值（TCP/UDP 开关、UDP 参数）
 * 4. Trojan 配置有效性（字段可正确设置）
 * 5. VLESS 配置默认值（UDP 开关、UDP 参数）
 * 6. VLESS 配置有效性（字段可正确设置）
 * 7. Shadowsocks 配置默认值（TCP/UDP 开关、时间戳窗口、Salt TTL）
 * 8. Shadowsocks 配置有效性（PSK + method 可正确设置）
 * 9. ShadowTLS 配置默认值（version、strict_mode、timeout）
 * 10. ShadowTLS 配置有效性（version=2 时用 password，version=3 时用 users）
 * 11. Reality 配置默认值（dest、private_key、server_names、short_ids 为空）
 * 12. Reality enabled() 逻辑（缺少 key/server_names/dest 时返回 false）
 */

#include <prism/protocol/socks5/config.hpp>
#include <prism/protocol/trojan/config.hpp>
#include <prism/protocol/vless/config.hpp>
#include <prism/protocol/shadowsocks/config.hpp>
#include <prism/stealth/shadowtls/config.hpp>
#include <prism/stealth/reality/config.hpp>
#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>

#include "common/TestRunner.hpp"

#ifdef WIN32
#include <windows.h>
#endif

#include <string>
#include <string_view>

namespace
{
    psm::testing::TestRunner runner("Config");
}

namespace socks5 = psm::protocol::socks5;
namespace trojan = psm::protocol::trojan;
namespace vless = psm::protocol::vless;
namespace shadowsocks = psm::protocol::shadowsocks;
namespace shadowtls = psm::stealth::shadowtls;
namespace reality = psm::stealth::reality;

/**
 * @brief 测试 SOCKS5 配置默认值
 */
void TestSocks5ConfigDefaults()
{
    runner.LogInfo("=== Testing SOCKS5 config defaults ===");

    socks5::config cfg;

    runner.Check(cfg.enable_tcp == true, "enable_tcp defaults to true");
    runner.Check(cfg.enable_udp == true, "enable_udp defaults to true");
    runner.Check(cfg.enable_bind == false, "enable_bind defaults to false");
    runner.Check(cfg.udp_bind_port == 0, "udp_bind_port defaults to 0");
    runner.Check(cfg.udp_idle_timeout == 60, "udp_idle_timeout defaults to 60");
    runner.Check(cfg.udp_max_datagram == 65535, "udp_max_datagram defaults to 65535");
    runner.Check(cfg.enable_auth == false, "enable_auth defaults to false");

    runner.LogPass("SOCKS5 config defaults");
}

/**
 * @brief 测试 SOCKS5 配置有效性
 */
void TestSocks5ConfigValidate()
{
    runner.LogInfo("=== Testing SOCKS5 config validation ===");

    // 启用认证且设置合理参数的配置
    socks5::config cfg;
    cfg.enable_auth = true;
    cfg.enable_tcp = true;
    cfg.enable_udp = true;
    cfg.udp_idle_timeout = 120;
    cfg.udp_max_datagram = 32768;
    cfg.udp_bind_port = 9000;

    runner.Check(cfg.enable_auth == true, "enable_auth can be set to true");
    runner.Check(cfg.enable_tcp == true, "enable_tcp remains true");
    runner.Check(cfg.udp_idle_timeout == 120, "udp_idle_timeout can be customized");
    runner.Check(cfg.udp_max_datagram == 32768, "udp_max_datagram can be customized");
    runner.Check(cfg.udp_bind_port == 9000, "udp_bind_port can be customized");

    runner.LogPass("SOCKS5 config validation");
}

/**
 * @brief 测试 Trojan 配置默认值
 */
void TestTrojanConfigDefaults()
{
    runner.LogInfo("=== Testing Trojan config defaults ===");

    trojan::config cfg;

    runner.Check(cfg.enable_tcp == true, "enable_tcp defaults to true");
    runner.Check(cfg.enable_udp == false, "enable_udp defaults to false");
    runner.Check(cfg.udp_idle_timeout == 60, "udp_idle_timeout defaults to 60");
    runner.Check(cfg.udp_max_datagram == 65535, "udp_max_datagram defaults to 65535");

    runner.LogPass("Trojan config defaults");
}

/**
 * @brief 测试 Trojan 配置有效性
 */
void TestTrojanConfigValidate()
{
    runner.LogInfo("=== Testing Trojan config validation ===");

    trojan::config cfg;
    cfg.enable_tcp = true;
    cfg.enable_udp = true;
    cfg.udp_idle_timeout = 90;
    cfg.udp_max_datagram = 32768;

    runner.Check(cfg.enable_tcp == true, "enable_tcp can remain true");
    runner.Check(cfg.enable_udp == true, "enable_udp can be set to true");
    runner.Check(cfg.udp_idle_timeout == 90, "udp_idle_timeout can be customized");
    runner.Check(cfg.udp_max_datagram == 32768, "udp_max_datagram can be customized");

    runner.LogPass("Trojan config validation");
}

/**
 * @brief 测试 VLESS 配置默认值
 */
void TestVlessConfigDefaults()
{
    runner.LogInfo("=== Testing VLESS config defaults ===");

    vless::config cfg;

    runner.Check(cfg.enable_udp == false, "enable_udp defaults to false");
    runner.Check(cfg.udp_idle_timeout == 60, "udp_idle_timeout defaults to 60");
    runner.Check(cfg.udp_max_datagram == 65535, "udp_max_datagram defaults to 65535");

    runner.LogPass("VLESS config defaults");
}

/**
 * @brief 测试 VLESS 配置有效性
 */
void TestVlessConfigValidate()
{
    runner.LogInfo("=== Testing VLESS config validation ===");

    vless::config cfg;
    cfg.enable_udp = true;
    cfg.udp_idle_timeout = 30;
    cfg.udp_max_datagram = 16384;

    runner.Check(cfg.enable_udp == true, "enable_udp can be set to true");
    runner.Check(cfg.udp_idle_timeout == 30, "udp_idle_timeout can be customized");
    runner.Check(cfg.udp_max_datagram == 16384, "udp_max_datagram can be customized");

    runner.LogPass("VLESS config validation");
}

/**
 * @brief 测试 Shadowsocks 配置默认值
 */
void TestShadowsocksConfigDefaults()
{
    runner.LogInfo("=== Testing Shadowsocks config defaults ===");

    shadowsocks::config cfg;

    runner.Check(cfg.enable_tcp == true, "enable_tcp defaults to true");
    runner.Check(cfg.enable_udp == false, "enable_udp defaults to false");
    runner.Check(cfg.timestamp_window == 30, "timestamp_window defaults to 30");
    runner.Check(cfg.salt_pool_ttl == 60, "salt_pool_ttl defaults to 60");
    runner.Check(cfg.udp_idle_timeout == 60, "udp_idle_timeout defaults to 60");
    runner.Check(cfg.psk.empty(), "psk defaults to empty");
    runner.Check(cfg.method.empty(), "method defaults to empty");

    runner.LogPass("Shadowsocks config defaults");
}

/**
 * @brief 测试 Shadowsocks 配置有效性
 */
void TestShadowsocksConfigValidate()
{
    runner.LogInfo("=== Testing Shadowsocks config validation ===");

    shadowsocks::config cfg;
    cfg.psk = "dGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVy"; // base64 测试 PSK
    cfg.method = "2022-blake3-aes-256-gcm";
    cfg.enable_tcp = true;
    cfg.enable_udp = true;
    cfg.timestamp_window = 45;
    cfg.salt_pool_ttl = 90;

    runner.Check(!cfg.psk.empty(), "psk can be set");
    runner.Check(cfg.method == "2022-blake3-aes-256-gcm", "method can be set explicitly");
    runner.Check(cfg.enable_udp == true, "enable_udp can be set to true");
    runner.Check(cfg.timestamp_window == 45, "timestamp_window can be customized");
    runner.Check(cfg.salt_pool_ttl == 90, "salt_pool_ttl can be customized");

    runner.LogPass("Shadowsocks config validation");
}

/**
 * @brief 测试 ShadowTLS 配置默认值
 */
void TestShadowtlsConfigDefaults()
{
    runner.LogInfo("=== Testing ShadowTLS config defaults ===");

    shadowtls::config cfg;

    runner.Check(cfg.version == 3, "version defaults to 3");
    runner.Check(cfg.password.empty(), "password defaults to empty");
    runner.Check(cfg.users.empty(), "users defaults to empty");
    runner.Check(cfg.handshake_dest.empty(), "handshake_dest defaults to empty");
    runner.Check(cfg.strict_mode == true, "strict_mode defaults to true");
    runner.Check(cfg.handshake_timeout_ms == 5000, "handshake_timeout_ms defaults to 5000");

    runner.LogPass("ShadowTLS config defaults");
}

/**
 * @brief 测试 ShadowTLS 配置有效性
 */
void TestShadowtlsConfigValidate()
{
    runner.LogInfo("=== Testing ShadowTLS config validation ===");

    // v2 模式：使用单一 password
    shadowtls::config cfg_v2;
    cfg_v2.version = 2;
    cfg_v2.password = "test_password_v2";
    cfg_v2.handshake_dest = "www.example.com:443";
    cfg_v2.strict_mode = false;

    runner.Check(cfg_v2.version == 2, "version can be set to 2");
    runner.Check(!cfg_v2.password.empty(), "v2 password can be set");
    runner.Check(cfg_v2.handshake_dest == "www.example.com:443", "handshake_dest can be set");
    runner.Check(cfg_v2.strict_mode == false, "strict_mode can be disabled");

    // v3 模式：使用多用户
    shadowtls::config cfg_v3;
    cfg_v3.version = 3;
    cfg_v3.users.push_back({"user1", "pass1"});
    cfg_v3.users.push_back({"user2", "pass2"});
    cfg_v3.handshake_dest = "www.cloudflare.com:443";

    runner.Check(cfg_v3.version == 3, "version defaults to 3");
    runner.Check(cfg_v3.users.size() == 2, "v3 can have multiple users");
    runner.Check(cfg_v3.users[0].name == "user1", "v3 user name can be set");
    runner.Check(cfg_v3.users[0].password == "pass1", "v3 user password can be set");
    runner.Check(cfg_v3.users[1].name == "user2", "second v3 user name can be set");
    runner.Check(!cfg_v3.handshake_dest.empty(), "v3 handshake_dest can be set");

    runner.LogPass("ShadowTLS config validation");
}

/**
 * @brief 测试 Reality 配置默认值
 */
void TestRealityConfigDefaults()
{
    runner.LogInfo("=== Testing Reality config defaults ===");

    reality::config cfg;

    runner.Check(cfg.dest.empty(), "dest defaults to empty");
    runner.Check(cfg.private_key.empty(), "private_key defaults to empty");
    runner.Check(cfg.server_names.empty(), "server_names defaults to empty");
    runner.Check(cfg.short_ids.empty(), "short_ids defaults to empty");
    runner.Check(cfg.enabled() == false, "enabled() returns false when unconfigured");

    runner.LogPass("Reality config defaults");
}

/**
 * @brief 测试 Reality 配置有效性
 */
void TestRealityConfigValidate()
{
    runner.LogInfo("=== Testing Reality config validation ===");

    // 完整配置应启用
    reality::config cfg_full;
    cfg_full.dest = "www.microsoft.com:443";
    cfg_full.private_key = "iIdwLBfO6L5E5n7nX7rG6r6H6g6f6e6d6c6b6a69";
    cfg_full.server_names.push_back("www.microsoft.com");
    cfg_full.server_names.push_back("www.apple.com");
    cfg_full.short_ids.push_back("");

    runner.Check(!cfg_full.dest.empty(), "dest can be set");
    runner.Check(!cfg_full.private_key.empty(), "private_key can be set");
    runner.Check(cfg_full.server_names.size() == 2, "server_names can have multiple entries");
    runner.Check(cfg_full.enabled() == true, "enabled() returns true with full config");

    // 缺少 private_key 时应禁用
    reality::config cfg_no_key;
    cfg_no_key.dest = "www.microsoft.com:443";
    cfg_no_key.server_names.push_back("www.microsoft.com");

    runner.Check(cfg_no_key.enabled() == false, "enabled() returns false when private_key is empty");

    // 缺少 server_names 时应禁用
    reality::config cfg_no_names;
    cfg_no_names.dest = "www.microsoft.com:443";
    cfg_no_names.private_key = "iIdwLBfO6L5E5n7nX7rG6r6H6g6f6e6d6c6b6a69";

    runner.Check(cfg_no_names.enabled() == false, "enabled() returns false when server_names is empty");

    // 缺少 dest 时应禁用
    reality::config cfg_no_dest;
    cfg_no_dest.private_key = "iIdwLBfO6L5E5n7nX7rG6r6H6g6f6e6d6c6b6a69";
    cfg_no_dest.server_names.push_back("www.microsoft.com");

    runner.Check(cfg_no_dest.enabled() == false, "enabled() returns false when dest is empty");

    runner.LogPass("Reality config validation");
}

/**
 * @brief 测试入口
 * @details 初始化全局 PMR 内存池和日志系统，依次运行各协议与伪装方案
 * 配置结构体的默认值和有效性测试，输出结果汇总。
 * @return 0 表示全部通过，1 表示存在失败
 */
int main()
{
#ifdef WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_global_pooling();
    psm::trace::init({});

    runner.LogInfo("Starting Config tests...");

    TestSocks5ConfigDefaults();
    TestSocks5ConfigValidate();
    TestTrojanConfigDefaults();
    TestTrojanConfigValidate();
    TestVlessConfigDefaults();
    TestVlessConfigValidate();
    TestShadowsocksConfigDefaults();
    TestShadowsocksConfigValidate();
    TestShadowtlsConfigDefaults();
    TestShadowtlsConfigValidate();
    TestRealityConfigDefaults();
    TestRealityConfigValidate();

    runner.LogInfo("Config tests completed.");

    return runner.Summary();
}
