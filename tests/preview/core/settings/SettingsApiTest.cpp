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

#include <preview/Composition/Api/ApiManager.hpp>
#include <preview/Composition/Settings/Json.hpp>
#include <preview/Composition/Settings/Loader.hpp>

namespace
{

    TEST(JsonParser, BasicValues)
    {
        Preview::Settings::JsonValue v;
        EXPECT_TRUE(Preview::Settings::ParseJson("null", v).Message.empty());
        EXPECT_EQ(v.Data.index(), 0);

        EXPECT_TRUE(Preview::Settings::ParseJson("true", v).Message.empty());
        EXPECT_EQ(std::get<bool>(v.Data), true);

        EXPECT_TRUE(Preview::Settings::ParseJson("42", v).Message.empty());
        EXPECT_EQ(std::get<double>(v.Data), 42);

        EXPECT_TRUE(Preview::Settings::ParseJson("-3.5", v).Message.empty());
        EXPECT_EQ(std::get<double>(v.Data), -3.5);

        EXPECT_TRUE(Preview::Settings::ParseJson("\"hi\\n\"", v).Message.empty());
        EXPECT_EQ(std::get<std::string>(v.Data), "hi\n");
    }

    TEST(JsonParser, NestedStructures)
    {
        Preview::Settings::JsonValue v;
        const std::string text = R"({"a": {"b": [1, 2, {"c": "x"}]}, "d": []})";
        EXPECT_TRUE(Preview::Settings::ParseJson(text, v).Message.empty());

        const auto *b = Preview::Settings::Lookup(v, "a.b");
        ASSERT_NE(b, nullptr);
        ASSERT_EQ(b->Data.index(), 4);
        EXPECT_EQ(std::get<Preview::Settings::JsonArray>(b->Data).items.size(), 3);

        const auto *c = Preview::Settings::Lookup(v, "a.b.2.c");
        ASSERT_NE(c, nullptr);
        EXPECT_EQ(std::get<std::string>(c->Data), "x");

        EXPECT_EQ(Preview::Settings::Lookup(v, "a.b.2.z"), nullptr);
        EXPECT_EQ(Preview::Settings::Lookup(v, "missing"), nullptr);
    }

    TEST(JsonParser, ErrorInputs)
    {
        Preview::Settings::JsonValue v;
        EXPECT_FALSE(Preview::Settings::ParseJson("", v).Message.empty());
        EXPECT_FALSE(Preview::Settings::ParseJson("{", v).Message.empty());
        EXPECT_FALSE(Preview::Settings::ParseJson("[1,2", v).Message.empty());
        EXPECT_FALSE(Preview::Settings::ParseJson("{\"a\":}", v).Message.empty());
        EXPECT_FALSE(Preview::Settings::ParseJson("{\"a\":1} extra", v).Message.empty());
        EXPECT_FALSE(Preview::Settings::ParseJson("tru", v).Message.empty());
        EXPECT_FALSE(Preview::Settings::ParseJson("\"unterminated", v).Message.empty());
    }

    TEST(ConfigLoader, ValidConfig)
    {
        Preview::Settings::ProxyConfig cfg;
        const std::string text = R"({
            "ListenAddr": "0.0.0.0",
            "ListenPort": 1080,
            "Protocol": "socks5",
            "MaxConnections": 2048,
            "AuthRequired": true,
            "IdleTimeoutMs": 120000
        })";
        const auto err = Preview::Settings::LoadConfig(text, cfg);
        EXPECT_TRUE(err.Message.empty());
        EXPECT_EQ(cfg.ListenAddr, "0.0.0.0");
        EXPECT_EQ(cfg.ListenPort, 1080);
        EXPECT_EQ(cfg.Protocol, "socks5");
        EXPECT_EQ(cfg.MaxConnections, 2048);
        EXPECT_TRUE(cfg.AuthRequired);
        EXPECT_EQ(cfg.IdleTimeoutMs, 120000);
    }

    TEST(ConfigLoader, DefaultsAndUnknownFields)
    {
        Preview::Settings::ProxyConfig cfg;
        // 未知字段忽略 + 缺省值生效
        const std::string text = R"({"ListenPort": 8080, "future_field": 123})";
        const auto err = Preview::Settings::LoadConfig(text, cfg);
        EXPECT_TRUE(err.Message.empty());
        EXPECT_EQ(cfg.ListenAddr, "127.0.0.1");
        EXPECT_EQ(cfg.ListenPort, 8080);
        EXPECT_EQ(cfg.Protocol, "socks5");
        EXPECT_FALSE(cfg.AuthRequired);
    }

    TEST(ConfigLoader, MissingRequired)
    {
        Preview::Settings::ProxyConfig cfg;
        const auto err = Preview::Settings::LoadConfig("{}", cfg);
        EXPECT_FALSE(err.Message.empty());
        EXPECT_EQ(err.field, "ListenPort");
    }

    TEST(ConfigLoader, RangeAndTypeErrors)
    {
        Preview::Settings::ProxyConfig cfg;
        // 端口越界
        auto err = Preview::Settings::LoadConfig(R"({"ListenPort": 70000})", cfg);
        EXPECT_FALSE(err.Message.empty());
        EXPECT_EQ(err.field, "ListenPort");

        // 端口非数字
        err = Preview::Settings::LoadConfig(R"({"ListenPort": "1080"})", cfg);
        EXPECT_FALSE(err.Message.empty());
        EXPECT_EQ(err.field, "ListenPort");

        // 协议不支持
        err = Preview::Settings::LoadConfig(R"({"ListenPort": 1, "Protocol": "quic"})", cfg);
        EXPECT_FALSE(err.Message.empty());
        EXPECT_EQ(err.field, "Protocol");

        // 布尔类型错误
        err = Preview::Settings::LoadConfig(R"({"ListenPort": 1, "AuthRequired": "yes"})", cfg);
        EXPECT_FALSE(err.Message.empty());
        EXPECT_EQ(err.field, "AuthRequired");
    }

    TEST(ApiManager, SessionListSnapshot)
    {
        Preview::Runtime::SessionRegistry registry;
        Preview::Runtime::SessionInfo Info;
        Info.Id = 7;
        Info.identity = "alice";
        Info.peer = "10.0.0.1";
        Info.Target = "example.com:443";
        registry.Put(Info);

        Preview::Runtime::PerWorkerTraffic traffic(2);
        traffic.Add(0, 100, 200);

        Preview::Api::RegistryApiManager api(&registry, &traffic);

        const auto sessions = api.ListSessions();
        ASSERT_EQ(sessions.size(), 1);
        EXPECT_EQ(sessions[0].Id, 7);
        EXPECT_TRUE(sessions[0].detail.find("alice") != std::string::npos);

        const auto sum = api.TrafficSummary();
        EXPECT_EQ(sum.Up, 100);
        EXPECT_EQ(sum.Down, 200);

        const auto snap = api.ConfigSnapshot();
        EXPECT_TRUE(snap.find("\"sessions\":1") != std::string::npos);
    }

    TEST(ApiManager, EmptySnapshot)
    {
        Preview::Runtime::SessionRegistry registry;
        Preview::Runtime::PerWorkerTraffic traffic(1);

        Preview::Api::RegistryApiManager api(&registry, &traffic);
        EXPECT_TRUE(api.ListSessions().empty());
        EXPECT_EQ(api.TrafficSummary().Up, 0);
        EXPECT_TRUE(api.ConfigSnapshot().find("\"sessions\":0") != std::string::npos);
    }

    TEST(ApiManager, IdentityTrafficCompatibility)
    {
        Preview::Runtime::SessionRegistry registry;
        Preview::Runtime::PerWorkerTraffic traffic(1);
        Preview::Runtime::IdentityTraffic identity;
        identity.Add("alice", 10, 20);
        identity.Add("bob", 30, 40);

        Preview::Api::RegistryApiManager api(&registry, &traffic, &identity);
        EXPECT_TRUE(api.ConfigSnapshot().find("\"identities\":2") != std::string::npos);

        identity.Add("carol", 1, 2);
        EXPECT_TRUE(api.ConfigSnapshot().find("\"identities\":3") != std::string::npos);
    }

} // namespace
