/**
 * @file SettingsApiTest.cpp
 * @brief 配置加载与管理 API 测试（T5-8 O7 / T5-9）
 * @details 覆盖：
 *          - JSON 解析：object/array/嵌套/转义/错误输入
 *          - 配置加载：合法 / 缺失必填 / 范围非法 / 类型错误 / 未知字段忽略
 *          - 管理 API：会话列表快照 / 流量摘要 / 配置快照
 */

#include <gtest/gtest.h>

#include <cstdint>
#include <string>

#include <common/core/api/api_manager.hpp>
#include <common/core/settings/json.hpp>
#include <common/core/settings/loader.hpp>

namespace
{

    TEST(JsonParser, BasicValues)
    {
        psmtest::settings::json_value v;
        EXPECT_TRUE(psmtest::settings::parse_json("null", v).message.empty());
        EXPECT_EQ(v.data.index(), 0);

        EXPECT_TRUE(psmtest::settings::parse_json("true", v).message.empty());
        EXPECT_EQ(std::get<bool>(v.data), true);

        EXPECT_TRUE(psmtest::settings::parse_json("42", v).message.empty());
        EXPECT_EQ(std::get<double>(v.data), 42);

        EXPECT_TRUE(psmtest::settings::parse_json("-3.5", v).message.empty());
        EXPECT_EQ(std::get<double>(v.data), -3.5);

        EXPECT_TRUE(psmtest::settings::parse_json("\"hi\\n\"", v).message.empty());
        EXPECT_EQ(std::get<std::string>(v.data), "hi\n");
    }

    TEST(JsonParser, NestedStructures)
    {
        psmtest::settings::json_value v;
        const std::string text = R"({"a": {"b": [1, 2, {"c": "x"}]}, "d": []})";
        EXPECT_TRUE(psmtest::settings::parse_json(text, v).message.empty());

        const auto *b = psmtest::settings::lookup(v, "a.b");
        ASSERT_NE(b, nullptr);
        ASSERT_EQ(b->data.index(), 4);
        EXPECT_EQ(std::get<psmtest::settings::json_array>(b->data).items.size(), 3);

        const auto *c = psmtest::settings::lookup(v, "a.b.2.c");
        ASSERT_NE(c, nullptr);
        EXPECT_EQ(std::get<std::string>(c->data), "x");

        EXPECT_EQ(psmtest::settings::lookup(v, "a.b.2.z"), nullptr);
        EXPECT_EQ(psmtest::settings::lookup(v, "missing"), nullptr);
    }

    TEST(JsonParser, ErrorInputs)
    {
        psmtest::settings::json_value v;
        EXPECT_FALSE(psmtest::settings::parse_json("", v).message.empty());
        EXPECT_FALSE(psmtest::settings::parse_json("{", v).message.empty());
        EXPECT_FALSE(psmtest::settings::parse_json("[1,2", v).message.empty());
        EXPECT_FALSE(psmtest::settings::parse_json("{\"a\":}", v).message.empty());
        EXPECT_FALSE(psmtest::settings::parse_json("{\"a\":1} extra", v).message.empty());
        EXPECT_FALSE(psmtest::settings::parse_json("tru", v).message.empty());
        EXPECT_FALSE(psmtest::settings::parse_json("\"unterminated", v).message.empty());
    }

    TEST(ConfigLoader, ValidConfig)
    {
        psmtest::settings::proxy_config cfg;
        const std::string text = R"({
            "listen_addr": "0.0.0.0",
            "listen_port": 1080,
            "protocol": "socks5",
            "max_connections": 2048,
            "auth_required": true,
            "idle_timeout_ms": 120000
        })";
        const auto err = psmtest::settings::load_config(text, cfg);
        EXPECT_TRUE(err.message.empty());
        EXPECT_EQ(cfg.listen_addr, "0.0.0.0");
        EXPECT_EQ(cfg.listen_port, 1080);
        EXPECT_EQ(cfg.protocol, "socks5");
        EXPECT_EQ(cfg.max_connections, 2048);
        EXPECT_TRUE(cfg.auth_required);
        EXPECT_EQ(cfg.idle_timeout_ms, 120000);
    }

    TEST(ConfigLoader, DefaultsAndUnknownFields)
    {
        psmtest::settings::proxy_config cfg;
        // 未知字段忽略 + 缺省值生效
        const std::string text = R"({"listen_port": 8080, "future_field": 123})";
        const auto err = psmtest::settings::load_config(text, cfg);
        EXPECT_TRUE(err.message.empty());
        EXPECT_EQ(cfg.listen_addr, "127.0.0.1");
        EXPECT_EQ(cfg.listen_port, 8080);
        EXPECT_EQ(cfg.protocol, "socks5");
        EXPECT_FALSE(cfg.auth_required);
    }

    TEST(ConfigLoader, MissingRequired)
    {
        psmtest::settings::proxy_config cfg;
        const auto err = psmtest::settings::load_config("{}", cfg);
        EXPECT_FALSE(err.message.empty());
        EXPECT_EQ(err.field, "listen_port");
    }

    TEST(ConfigLoader, RangeAndTypeErrors)
    {
        psmtest::settings::proxy_config cfg;
        // 端口越界
        auto err = psmtest::settings::load_config(R"({"listen_port": 70000})", cfg);
        EXPECT_FALSE(err.message.empty());
        EXPECT_EQ(err.field, "listen_port");

        // 端口非数字
        err = psmtest::settings::load_config(R"({"listen_port": "1080"})", cfg);
        EXPECT_FALSE(err.message.empty());
        EXPECT_EQ(err.field, "listen_port");

        // 协议不支持
        err = psmtest::settings::load_config(R"({"listen_port": 1, "protocol": "quic"})", cfg);
        EXPECT_FALSE(err.message.empty());
        EXPECT_EQ(err.field, "protocol");

        // 布尔类型错误
        err = psmtest::settings::load_config(R"({"listen_port": 1, "auth_required": "yes"})", cfg);
        EXPECT_FALSE(err.message.empty());
        EXPECT_EQ(err.field, "auth_required");
    }

    TEST(ApiManager, SessionListSnapshot)
    {
        psmtest::runtime::session_registry registry;
        psmtest::runtime::session_info info;
        info.id = 7;
        info.identity = "alice";
        info.peer = "10.0.0.1";
        info.target = "example.com:443";
        registry.put(info);

        psmtest::runtime::per_worker_traffic traffic(2);
        traffic.add(0, 100, 200);

        psmtest::api::registry_api_manager api(&registry, &traffic);

        const auto sessions = api.list_sessions();
        ASSERT_EQ(sessions.size(), 1);
        EXPECT_EQ(sessions[0].id, 7);
        EXPECT_TRUE(sessions[0].detail.find("alice") != std::string::npos);

        const auto sum = api.traffic_summary();
        EXPECT_EQ(sum.up, 100);
        EXPECT_EQ(sum.down, 200);

        const auto snap = api.config_snapshot();
        EXPECT_TRUE(snap.find("\"sessions\":1") != std::string::npos);
    }

    TEST(ApiManager, EmptySnapshot)
    {
        psmtest::runtime::session_registry registry;
        psmtest::runtime::per_worker_traffic traffic(1);

        psmtest::api::registry_api_manager api(&registry, &traffic);
        EXPECT_TRUE(api.list_sessions().empty());
        EXPECT_EQ(api.traffic_summary().up, 0);
        EXPECT_TRUE(api.config_snapshot().find("\"sessions\":0") != std::string::npos);
    }

} // namespace
