/**
 * @file validator.cpp
 * @brief config validator 单元测试
 * @details 验证 validate() 的各项检查：buffer.size、addressable.port、dns.servers、
 * protocol 配置、reverse_map 端点格式。
 */

#include <prism/config/config.hpp>
#include <prism/config/validator.hpp>
#include <prism/foundation/exception/security.hpp>
#include <prism/foundation/memory/container.hpp>

#include <gtest/gtest.h>

namespace
{
    /**
     * @brief 构造合法配置（含必要字段填充）
     */
    auto make_valid_config() -> psm::config
    {
        psm::config cfg;
        cfg.buffer.size = 262144;
        cfg.instance.addressable.port = 443;
        cfg.protocol.socks5.enable_tcp = true;
        cfg.protocol.trojan.enable_tcp = true;
        cfg.protocol.vless.enable_udp = true;
        cfg.protocol.shadowsocks.enable_udp = true;
        // 测试环境无真实 DNS 服务器，禁用 cache 避免 servers 非空检查
        cfg.dns.cache_enabled = false;
        return cfg;
    }
} // namespace

TEST(ConfigValidator, ValidConfigPasses)
{
    auto cfg = make_valid_config();
    const auto result = psm::config_validator::validate(cfg);
    EXPECT_TRUE(result.valid);
    EXPECT_TRUE(result.errors.empty());
}

TEST(ConfigValidator, InvalidBuffer)
{
    auto cfg = make_valid_config();
    cfg.buffer.size = 0;
    const auto result = psm::config_validator::validate(cfg);
    EXPECT_FALSE(result.valid);
    ASSERT_FALSE(result.errors.empty());
    EXPECT_NE(result.errors[0].find("buffer.size"), psm::memory::string::npos);
}

TEST(ConfigValidator, InvalidPort)
{
    auto cfg = make_valid_config();
    cfg.instance.addressable.port = 0;
    const auto result = psm::config_validator::validate(cfg);
    EXPECT_FALSE(result.valid);
    ASSERT_FALSE(result.errors.empty());
    EXPECT_NE(result.errors[0].find("addressable.port"), psm::memory::string::npos);
}

TEST(ConfigValidator, EmptyDnsServersWhenCacheEnabled)
{
    auto cfg = make_valid_config();
    cfg.dns.cache_enabled = true;
    cfg.dns.servers.clear();
    const auto result = psm::config_validator::validate(cfg);
    EXPECT_FALSE(result.valid);
}

TEST(ConfigValidator, EmptyDnsServersOkWhenCacheDisabled)
{
    auto cfg = make_valid_config();
    cfg.dns.cache_enabled = false;
    cfg.dns.servers.clear();
    const auto result = psm::config_validator::validate(cfg);
    EXPECT_TRUE(result.valid);
}

TEST(ConfigValidator, UnsupportedProtocol)
{
    auto cfg = make_valid_config();
    cfg.protocol.trojan.enable_tcp = false;
    cfg.protocol.trojan.enable_udp = false;
    const auto result = psm::config_validator::validate(cfg);
    EXPECT_FALSE(result.valid);
    ASSERT_FALSE(result.errors.empty());
    bool found = false;
    for (const auto &err : result.errors)
    {
        if (err.find("protocol.trojan") != psm::memory::string::npos)
        {
            found = true;
            break;
        }
    }
    EXPECT_TRUE(found);
}

TEST(ConfigValidator, ReverseMapIpLiteralCheck)
{
    auto cfg = make_valid_config();
    cfg.instance.reverse_map.clear();
    cfg.instance.reverse_map.emplace(
        psm::memory::string{"example.com"},
        psm::runtime::endpoint{psm::memory::string{"not.an.ip", cfg.instance.reverse_map.get_allocator()}, 8443});
    const auto result = psm::config_validator::validate(cfg);
    EXPECT_FALSE(result.valid);
}

TEST(ConfigValidator, ReverseMapValidIpLiteralOk)
{
    auto cfg = make_valid_config();
    cfg.instance.reverse_map.clear();
    cfg.instance.reverse_map.emplace(
        psm::memory::string{"backend.com"},
        psm::runtime::endpoint{psm::memory::string{"127.0.0.1", cfg.instance.reverse_map.get_allocator()}, 8443});
    const auto result = psm::config_validator::validate(cfg);
    EXPECT_TRUE(result.valid);
}

TEST(ConfigValidator, ValidateOrThrowThrowsOnInvalid)
{
    auto cfg = make_valid_config();
    cfg.buffer.size = 0;
    EXPECT_THROW(psm::config_validator::validate_or_throw(cfg), psm::exception::security);
}

TEST(ConfigValidator, ValidateOrThrowNoThrowOnValid)
{
    auto cfg = make_valid_config();
    EXPECT_NO_THROW(psm::config_validator::validate_or_throw(cfg));
}
