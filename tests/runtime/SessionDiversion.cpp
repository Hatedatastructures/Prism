/**
 * @file SessionDiversion.cpp
 * @brief 工厂 8 分支 + 回落树状覆盖（仅验证工厂分发，不触发 handler::run）
 */

#include <gtest/gtest.h>

#include <prism/foundation/memory/pool.hpp>
#include <prism/net/connection/types.hpp>
#include <prism/protocol/handler.hpp>
#include <prism/resource/session.hpp>
#include <prism/settings/settings.hpp>

#include <memory>

namespace {

    /// 构造真实会话资源（handler 构造保存引用，禁止伪造未构造对象）
    auto make_session(std::uint32_t buf = 4096) -> std::shared_ptr<psm::resource::session>
    {
        auto cfg = std::make_shared<psm::settings>();
        auto proc = std::make_shared<psm::resource::process>(
            psm::resource::process::options{cfg, nullptr, nullptr});
        auto wrk = std::make_shared<psm::resource::worker>(
            psm::resource::worker::options{proc, psm::memory::system::global_pool()});
        return std::make_shared<psm::resource::session>(
            psm::resource::session::options{wrk, 1, buf, nullptr, {}, nullptr, nullptr});
    }

    /// 全局环境：启用内存池（session/PMR 依赖）
    class MemoryEnv final : public ::testing::Environment
    {
    public:
        void SetUp() override { psm::memory::system::enable_pooling(); }
    };

    [[maybe_unused]] const auto* g_env = ::testing::AddGlobalTestEnvironment(new MemoryEnv());
}

TEST(SessionDiversionFactory, Http)
{
    auto res = make_session();
    std::array<std::byte,1> dummy{};
    psm::protocol::handler_params params{*res, dummy};
    EXPECT_NE(psm::protocol::make_protocol_handler(psm::connect::protocol_type::http, std::move(params)), nullptr);
}
TEST(SessionDiversionFactory, Socks5)
{
    auto res = make_session();
    std::array<std::byte,1> dummy{};
    psm::protocol::handler_params params{*res, dummy};
    EXPECT_NE(psm::protocol::make_protocol_handler(psm::connect::protocol_type::socks5, std::move(params)), nullptr);
}
TEST(SessionDiversionFactory, Trojan)
{
    auto res = make_session();
    std::array<std::byte,1> dummy{};
    psm::protocol::handler_params params{*res, dummy};
    EXPECT_NE(psm::protocol::make_protocol_handler(psm::connect::protocol_type::trojan, std::move(params)), nullptr);
}
TEST(SessionDiversionFactory, Vless)
{
    auto res = make_session();
    std::array<std::byte,1> dummy{};
    psm::protocol::handler_params params{*res, dummy};
    EXPECT_NE(psm::protocol::make_protocol_handler(psm::connect::protocol_type::vless, std::move(params)), nullptr);
}
TEST(SessionDiversionFactory, Shadowsocks)
{
    auto res = make_session();
    std::array<std::byte,1> dummy{};
    psm::protocol::handler_params params{*res, dummy};
    EXPECT_NE(psm::protocol::make_protocol_handler(psm::connect::protocol_type::shadowsocks, std::move(params)), nullptr);
}
TEST(SessionDiversionFactory, Vmess)
{
    auto res = make_session();
    std::array<std::byte,1> dummy{};
    psm::protocol::handler_params params{*res, dummy};
    EXPECT_NE(psm::protocol::make_protocol_handler(psm::connect::protocol_type::vmess, std::move(params)), nullptr);
}
TEST(SessionDiversionFactory, Hysteria2)
{
    auto res = make_session();
    std::array<std::byte,1> dummy{};
    psm::protocol::handler_params params{*res, dummy};
    EXPECT_NE(psm::protocol::make_protocol_handler(psm::connect::protocol_type::hysteria2, std::move(params)), nullptr);
}
TEST(SessionDiversionFactory, Tuic)
{
    auto res = make_session();
    std::array<std::byte,1> dummy{};
    psm::protocol::handler_params params{*res, dummy};
    EXPECT_NE(psm::protocol::make_protocol_handler(psm::connect::protocol_type::tuic, std::move(params)), nullptr);
}
TEST(SessionDiversionFactory, UnknownReturnsNull)
{
    auto res = make_session();
    std::array<std::byte,1> dummy{};
    psm::protocol::handler_params p1{*res, dummy};
    EXPECT_EQ(psm::protocol::make_protocol_handler(psm::connect::protocol_type::unknown, std::move(p1)), nullptr);
    psm::protocol::handler_params p2{*res, dummy};
    EXPECT_EQ(psm::protocol::make_protocol_handler(static_cast<psm::connect::protocol_type>(99), std::move(p2)), nullptr);
    psm::protocol::handler_params p3{*res, dummy};
    EXPECT_EQ(psm::protocol::make_protocol_handler(psm::connect::protocol_type::tls, std::move(p3)), nullptr);
}
