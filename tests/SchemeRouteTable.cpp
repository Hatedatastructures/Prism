/**
 * @file SchemeRouteTable.cpp
 * @brief SNI 路由表单元测试
 */

#include <prism/recognition/routes.hpp>
#include <prism/config.hpp>
#include "common/TestRunner.hpp"

namespace
{
    auto BuildTestConfig() -> psm::config
    {
        psm::config cfg;

        // Reality 配置
        cfg.stealth.reality.server_names.push_back("reality.example.com");
        cfg.stealth.reality.dest = "www.microsoft.com:443";
        cfg.stealth.reality.private_key = "test_key_base64";

        // ShadowTLS 配置
        cfg.stealth.shadowtls.server_names.push_back("shadowtls.example.com");
        cfg.stealth.shadowtls.handshake_dest = "www.microsoft.com:443";
        cfg.stealth.shadowtls.users.push_back({"user1", "password1"});

        // Restls 配置
        cfg.stealth.restls.server_names.push_back("restls.example.com");
        cfg.stealth.restls.host = "www.microsoft.com:443";
        cfg.stealth.restls.password = "restls_password";

        // AnyTLS 配置
        cfg.stealth.anytls.server_names.push_back("anytls.example.com");
        cfg.stealth.anytls.certificate = "cert.pem";
        cfg.stealth.anytls.private_key = "key.pem";
        cfg.stealth.anytls.users.push_back({"user1", "password1"});

        // TrustTunnel 配置
        cfg.stealth.trusttunnel.server_names.push_back("trusttunnel.example.com");
        cfg.stealth.trusttunnel.certificate = "cert.pem";
        cfg.stealth.trusttunnel.private_key = "key.pem";
        cfg.stealth.trusttunnel.users.push_back({"user1", "password1"});

        return cfg;
    }
}

void TestSchemeRouteTableBuild()
{
    psm::testing::TestRunner runner("SchemeRouteTable::build");

    auto cfg = BuildTestConfig();
    auto table = psm::recognition::route_table::build(cfg);

    runner.Check(!table.empty(), "Route table should not be empty");
    runner.Check(table.registered_snis().size() == 5, "Should have 5 registered SNIs");

    runner.Summary();
}

void TestSchemeRouteTableLookup()
{
    psm::testing::TestRunner runner("SchemeRouteTable::lookup");

    auto cfg = BuildTestConfig();
    auto table = psm::recognition::route_table::build(cfg);

    // 测试 Reality SNI
    auto schemes = table.lookup("reality.example.com");
    runner.Check(schemes.size() == 1, "Reality SNI should match 1 scheme");
    runner.Check(schemes[0] == "reality", "Should be reality");

    // 测试 ShadowTLS SNI
    schemes = table.lookup("shadowtls.example.com");
    runner.Check(schemes.size() == 1, "ShadowTLS SNI should match 1 scheme");
    runner.Check(schemes[0] == "shadowtls", "Should be shadowtls");

    // 测试未知 SNI
    schemes = table.lookup("unknown.example.com");
    runner.Check(schemes.empty(), "Unknown SNI should match none");

    // 测试空 SNI
    schemes = table.lookup("");
    runner.Check(schemes.empty(), "Empty SNI should match none");

    runner.Summary();
}

void TestSchemeRouteTableMatchesAny()
{
    psm::testing::TestRunner runner("SchemeRouteTable::matches_any");

    auto cfg = BuildTestConfig();
    auto table = psm::recognition::route_table::build(cfg);

    runner.Check(table.matches_any("reality.example.com"), "Reality SNI should match");
    runner.Check(table.matches_any("shadowtls.example.com"), "ShadowTLS SNI should match");
    runner.Check(!table.matches_any("unknown.example.com"), "Unknown SNI should not match");
    runner.Check(!table.matches_any(""), "Empty SNI should not match");

    runner.Summary();
}

int main()
{
    TestSchemeRouteTableBuild();
    TestSchemeRouteTableLookup();
    TestSchemeRouteTableMatchesAny();

    return 0;
}