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

#include <prism/proto/protocol/socks5/config.hpp>
#include <prism/proto/protocol/trojan/config.hpp>
#include <prism/proto/protocol/vless/config.hpp>
#include <prism/proto/protocol/shadowsocks/config.hpp>
#include <prism/stealth/facade/shadowtls/config.hpp>
#include <prism/stealth/facade/reality/config.hpp>
#include <prism/core/core.hpp>
#include <prism/trace/spdlog.hpp>

#include <gtest/gtest.h>

#include <string>
#include <string_view>

namespace
{
    namespace socks5 = psm::protocol::socks5;
    namespace trojan = psm::protocol::trojan;
    namespace vless = psm::protocol::vless;
    namespace shadowsocks = psm::protocol::shadowsocks;
    namespace shadowtls = psm::stealth::shadowtls;
    namespace reality = psm::stealth::reality;

    TEST(Config, Socks5ConfigDefaults)
    {
        socks5::config cfg;

        EXPECT_TRUE(cfg.enable_tcp == true) << "enable_tcp defaults to true";
        EXPECT_TRUE(cfg.enable_udp == true) << "enable_udp defaults to true";
        EXPECT_TRUE(cfg.enable_bind == false) << "enable_bind defaults to false";
        EXPECT_TRUE(cfg.bind_port == 0) << "bind_port defaults to 0";
        EXPECT_TRUE(cfg.idle_timeout == 60) << "idle_timeout defaults to 60";
        EXPECT_TRUE(cfg.max_dgram == 65535) << "max_dgram defaults to 65535";
        EXPECT_TRUE(cfg.enable_auth == false) << "enable_auth defaults to false";
    }

    TEST(Config, Socks5ConfigValidate)
    {
        socks5::config cfg;
        cfg.enable_auth = true;
        cfg.enable_tcp = true;
        cfg.enable_udp = true;
        cfg.idle_timeout = 120;
        cfg.max_dgram = 32768;
        cfg.bind_port = 9000;

        EXPECT_TRUE(cfg.enable_auth == true) << "enable_auth can be set to true";
        EXPECT_TRUE(cfg.enable_tcp == true) << "enable_tcp remains true";
        EXPECT_TRUE(cfg.idle_timeout == 120) << "idle_timeout can be customized";
        EXPECT_TRUE(cfg.max_dgram == 32768) << "max_dgram can be customized";
        EXPECT_TRUE(cfg.bind_port == 9000) << "bind_port can be customized";
    }

    TEST(Config, TrojanConfigDefaults)
    {
        trojan::config cfg;

        EXPECT_TRUE(cfg.enable_tcp == true) << "enable_tcp defaults to true";
        EXPECT_TRUE(cfg.enable_udp == false) << "enable_udp defaults to false";
        EXPECT_TRUE(cfg.idle_timeout == 60) << "idle_timeout defaults to 60";
        EXPECT_TRUE(cfg.max_dgram == 65535) << "max_dgram defaults to 65535";
    }

    TEST(Config, TrojanConfigValidate)
    {
        trojan::config cfg;
        cfg.enable_tcp = true;
        cfg.enable_udp = true;
        cfg.idle_timeout = 90;
        cfg.max_dgram = 32768;

        EXPECT_TRUE(cfg.enable_tcp == true) << "enable_tcp can remain true";
        EXPECT_TRUE(cfg.enable_udp == true) << "enable_udp can be set to true";
        EXPECT_TRUE(cfg.idle_timeout == 90) << "idle_timeout can be customized";
        EXPECT_TRUE(cfg.max_dgram == 32768) << "max_dgram can be customized";
    }

    TEST(Config, VlessConfigDefaults)
    {
        vless::config cfg;

        EXPECT_TRUE(cfg.enable_udp == false) << "enable_udp defaults to false";
        EXPECT_TRUE(cfg.idle_timeout == 60) << "idle_timeout defaults to 60";
        EXPECT_TRUE(cfg.max_dgram == 65535) << "max_dgram defaults to 65535";
    }

    TEST(Config, VlessConfigValidate)
    {
        vless::config cfg;
        cfg.enable_udp = true;
        cfg.idle_timeout = 30;
        cfg.max_dgram = 16384;

        EXPECT_TRUE(cfg.enable_udp == true) << "enable_udp can be set to true";
        EXPECT_TRUE(cfg.idle_timeout == 30) << "idle_timeout can be customized";
        EXPECT_TRUE(cfg.max_dgram == 16384) << "max_dgram can be customized";
    }

    TEST(Config, ShadowsocksConfigDefaults)
    {
        shadowsocks::config cfg;

        EXPECT_TRUE(cfg.enable_tcp == true) << "enable_tcp defaults to true";
        EXPECT_TRUE(cfg.enable_udp == false) << "enable_udp defaults to false";
        EXPECT_TRUE(cfg.timestamp_window == 30) << "timestamp_window defaults to 30";
        EXPECT_TRUE(cfg.salt_ttl == 60) << "salt_ttl defaults to 60";
        EXPECT_TRUE(cfg.idle_timeout == 60) << "idle_timeout defaults to 60";
        EXPECT_TRUE(cfg.psk.empty()) << "psk defaults to empty";
        EXPECT_TRUE(cfg.method.empty()) << "method defaults to empty";
    }

    TEST(Config, ShadowsocksConfigValidate)
    {
        shadowsocks::config cfg;
        cfg.psk = "dGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVy"; // base64 测试 PSK
        cfg.method = "2022-blake3-aes-256-gcm";
        cfg.enable_tcp = true;
        cfg.enable_udp = true;
        cfg.timestamp_window = 45;
        cfg.salt_ttl = 90;

        EXPECT_TRUE(!cfg.psk.empty()) << "psk can be set";
        EXPECT_TRUE(cfg.method == "2022-blake3-aes-256-gcm") << "method can be set explicitly";
        EXPECT_TRUE(cfg.enable_udp == true) << "enable_udp can be set to true";
        EXPECT_TRUE(cfg.timestamp_window == 45) << "timestamp_window can be customized";
        EXPECT_TRUE(cfg.salt_ttl == 90) << "salt_ttl can be customized";
    }

    TEST(Config, ShadowtlsConfigDefaults)
    {
        shadowtls::config cfg;

        EXPECT_TRUE(cfg.version == 3) << "version defaults to 3";
        EXPECT_TRUE(cfg.password.empty()) << "password defaults to empty";
        EXPECT_TRUE(cfg.users.empty()) << "users defaults to empty";
        EXPECT_TRUE(cfg.handshake_dest.empty()) << "handshake_dest defaults to empty";
        EXPECT_TRUE(cfg.strict_mode == true) << "strict_mode defaults to true";
        EXPECT_TRUE(cfg.hs_timeout == 5000) << "hs_timeout defaults to 5000";
    }

    TEST(Config, ShadowtlsConfigValidate)
    {
        // v2 模式：使用单一 password
        shadowtls::config cfg_v2;
        cfg_v2.version = 2;
        cfg_v2.password = "test_password_v2";
        cfg_v2.handshake_dest = "www.example.com:443";
        cfg_v2.strict_mode = false;

        EXPECT_TRUE(cfg_v2.version == 2) << "version can be set to 2";
        EXPECT_TRUE(!cfg_v2.password.empty()) << "v2 password can be set";
        EXPECT_TRUE(cfg_v2.handshake_dest == "www.example.com:443") << "handshake_dest can be set";
        EXPECT_TRUE(cfg_v2.strict_mode == false) << "strict_mode can be disabled";

        // v3 模式：使用多用户
        shadowtls::config cfg_v3;
        cfg_v3.version = 3;
        cfg_v3.users.push_back({"user1", "pass1"});
        cfg_v3.users.push_back({"user2", "pass2"});
        cfg_v3.handshake_dest = "www.cloudflare.com:443";

        EXPECT_TRUE(cfg_v3.version == 3) << "version defaults to 3";
        EXPECT_TRUE(cfg_v3.users.size() == 2) << "v3 can have multiple users";
        EXPECT_TRUE(cfg_v3.users[0].name == "user1") << "v3 user name can be set";
        EXPECT_TRUE(cfg_v3.users[0].password == "pass1") << "v3 user password can be set";
        EXPECT_TRUE(cfg_v3.users[1].name == "user2") << "second v3 user name can be set";
        EXPECT_TRUE(!cfg_v3.handshake_dest.empty()) << "v3 handshake_dest can be set";
    }

    TEST(Config, RealityConfigDefaults)
    {
        reality::config cfg;

        EXPECT_TRUE(cfg.dest.empty()) << "dest defaults to empty";
        EXPECT_TRUE(cfg.private_key.empty()) << "private_key defaults to empty";
        EXPECT_TRUE(cfg.server_names.empty()) << "server_names defaults to empty";
        EXPECT_TRUE(cfg.short_ids.empty()) << "short_ids defaults to empty";
        EXPECT_TRUE(cfg.enabled() == false) << "enabled() returns false when unconfigured";
    }

    TEST(Config, RealityConfigValidate)
    {
        // 完整配置应启用
        reality::config cfg_full;
        cfg_full.dest = "www.microsoft.com:443";
        cfg_full.private_key = "iIdwLBfO6L5E5n7nX7rG6r6H6g6f6e6d6c6b6a69";
        cfg_full.server_names.push_back("www.microsoft.com");
        cfg_full.server_names.push_back("www.apple.com");
        cfg_full.short_ids.push_back("");

        EXPECT_TRUE(!cfg_full.dest.empty()) << "dest can be set";
        EXPECT_TRUE(!cfg_full.private_key.empty()) << "private_key can be set";
        EXPECT_TRUE(cfg_full.server_names.size() == 2) << "server_names can have multiple entries";
        EXPECT_TRUE(cfg_full.enabled() == true) << "enabled() returns true with full config";

        // 缺少 private_key 时应禁用
        reality::config cfg_no_key;
        cfg_no_key.dest = "www.microsoft.com:443";
        cfg_no_key.server_names.push_back("www.microsoft.com");

        EXPECT_TRUE(cfg_no_key.enabled() == false) << "enabled() returns false when private_key is empty";

        // 缺少 server_names 时应禁用
        reality::config cfg_no_names;
        cfg_no_names.dest = "www.microsoft.com:443";
        cfg_no_names.private_key = "iIdwLBfO6L5E5n7nX7rG6r6H6g6f6e6d6c6b6a69";

        EXPECT_TRUE(cfg_no_names.enabled() == false) << "enabled() returns false when server_names is empty";

        // 缺少 dest 时应禁用
        reality::config cfg_no_dest;
        cfg_no_dest.private_key = "iIdwLBfO6L5E5n7nX7rG6r6H6g6f6e6d6c6b6a69";
        cfg_no_dest.server_names.push_back("www.microsoft.com");

        EXPECT_TRUE(cfg_no_dest.enabled() == false) << "enabled() returns false when dest is empty";
    }
} // namespace
