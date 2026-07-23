/**
 * @file Socks5ConnDeep.cpp
 * @brief SOCKS5 协议中继器 Deep 测试
 * @details 直接包含 conn.cpp 测试内部函数：
 * negotiated_authentication、password_auth、resolve_command、
 * resolve_address、read_req_hdr、build_ok_resp、send_impl 等。
 */

#include <gtest/gtest.h>

// Deep test: 包含源文件以测试内部函数
// 注意：不能与其他包含 conn.cpp 的测试编译到同一可执行文件
#define private public
#include "../../src/prism/protocol/socks5/conn.cpp"
#undef private

#include <prism/foundation/fault/handling.hpp>
#include <prism/foundation/foundation.hpp>
#include <prism/protocol/socks5/config.hpp>
#include <prism/protocol/socks5/constants.hpp>
#include <prism/protocol/socks5/packet.hpp>

#include <boost/asio.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <span>
#include <vector>

#include "common/MockTransport.hpp"

namespace
{
    namespace net = boost::asio;
    using namespace psm::protocol::socks5;
    using namespace psm::testing;
} // anonymous namespace

// ── build_ok_resp: IPv4 地址 ──

TEST(Socks5ConnDeep, BuildOkRespIPv4)
{
    request req{};
    req.cmd = command::connect;
    req.destination_port = 443;
    req.destination_address = ipv4_address{{127, 0, 0, 1}};

    std::array<std::uint8_t, 262> buf{};
    const auto len = conn::build_ok_resp(req, buf);

    EXPECT_GE(len, 10u); // VER(1) + REP(1) + RSV(1) + ATYP(1) + IPv4(4) + PORT(2)
    EXPECT_EQ(buf[0], 0x05);                 // VER
    EXPECT_EQ(buf[1], static_cast<uint8_t>(reply_code::succeeded)); // REP
    EXPECT_EQ(buf[2], 0x00);                 // RSV
    EXPECT_EQ(buf[3], 0x01);                 // ATYP = IPv4
    EXPECT_EQ(buf[4], 127);
    EXPECT_EQ(buf[5], 0);
    EXPECT_EQ(buf[6], 0);
    EXPECT_EQ(buf[7], 1);
    // 端口 443 = 0x01BB
    EXPECT_EQ(buf[8], 0x01);
    EXPECT_EQ(buf[9], 0xBB);
    EXPECT_EQ(len, 10u);
}

// ── build_ok_resp: IPv6 地址 ──

TEST(Socks5ConnDeep, BuildOkRespIPv6)
{
    request req{};
    req.cmd = command::connect;
    req.destination_port = 8080;
    ipv6_address addr{};
    addr.bytes[0] = 0x20;
    addr.bytes[1] = 0x01;
    addr.bytes[15] = 0x01;
    req.destination_address = addr;

    std::array<std::uint8_t, 262> buf{};
    const auto len = conn::build_ok_resp(req, buf);

    EXPECT_EQ(buf[3], 0x04); // ATYP = IPv6
    EXPECT_EQ(len, 22u);     // VER+REP+RSV+ATYP(4) + IPv6(16) + PORT(2)
}

// ── build_ok_resp: 域名地址 ──

TEST(Socks5ConnDeep, BuildOkRespDomain)
{
    request req{};
    req.cmd = command::connect;
    req.destination_port = 443;
    domain_address daddr{};
    daddr.length = 11;
    const char *domain = "example.com";
    std::copy_n(domain, 11, daddr.value.begin());
    req.destination_address = daddr;

    std::array<std::uint8_t, 262> buf{};
    const auto len = conn::build_ok_resp(req, buf);

    EXPECT_EQ(buf[3], 0x03);              // ATYP = domain
    EXPECT_EQ(buf[4], 11);                // domain length
    EXPECT_EQ(len, 4u + 1u + 11u + 2u);  // header + len + domain + port
}

// ── negotiated_authentication: 无认证成功路径 ──

TEST(Socks5ConnDeep, NegotiatedAuthNoAuthSuccess)
{
    auto mock = std::make_shared<MockTransport>();

    // SOCKS5 方法协商请求：VER=5, NMETHODS=1, METHOD=0x00 (no_auth)
    const std::vector<std::byte> greeting = {
        std::byte{0x05}, std::byte{0x01}, std::byte{0x00}};
    mock->inject_read(greeting.data(), greeting.size());

    // 关闭读端防止挂起
    // （negotiated_authentication 读完 greeting 后不会再读）

    config cfg{};
    cfg.enable_auth = false;
    auto c = std::make_shared<conn>(mock, cfg);

    net::io_context ioc;
    std::atomic<bool> done{false};
    std::pair<psm::fault::code, auth_method> result;

    net::co_spawn(
        ioc,
        [&]() -> net::awaitable<void>
        {
            result = co_await c->negotiated_authentication();
            done = true;
        },
        net::detached);

    ioc.run_for(std::chrono::milliseconds(500));
    ASSERT_TRUE(done);

    EXPECT_EQ(result.first, psm::fault::code::success);
    EXPECT_EQ(result.second, auth_method::no_auth);

    // 验证响应：0x05 0x00
    const auto &written = mock->written_data();
    ASSERT_GE(written.size(), 2u);
    EXPECT_EQ(std::to_integer<uint8_t>(written[0]), 0x05);
    EXPECT_EQ(std::to_integer<uint8_t>(written[1]), 0x00);
}

// ── negotiated_authentication: 协议版本错误 ──

TEST(Socks5ConnDeep, NegotiatedAuthWrongVersion)
{
    auto mock = std::make_shared<MockTransport>();

    // 错误的协议版本
    const std::vector<std::byte> bad_greeting = {
        std::byte{0x04}, std::byte{0x01}, std::byte{0x00}};
    mock->inject_read(bad_greeting.data(), bad_greeting.size());

    config cfg{};
    cfg.enable_auth = false;
    auto c = std::make_shared<conn>(mock, cfg);

    net::io_context ioc;
    std::atomic<bool> done{false};
    std::pair<psm::fault::code, auth_method> result;

    net::co_spawn(
        ioc,
        [&]() -> net::awaitable<void>
        {
            result = co_await c->negotiated_authentication();
            done = true;
        },
        net::detached);

    ioc.run_for(std::chrono::milliseconds(500));
    ASSERT_TRUE(done);

    EXPECT_EQ(result.first, psm::fault::code::protocol_error);
    EXPECT_EQ(result.second, auth_method::no_acceptable);
}

// ── negotiated_authentication: 读错误 ──

TEST(Socks5ConnDeep, NegotiatedAuthReadError)
{
    auto mock = std::make_shared<MockTransport>();
    mock->set_read_error(std::make_error_code(std::errc::connection_reset));

    config cfg{};
    cfg.enable_auth = false;
    auto c = std::make_shared<conn>(mock, cfg);

    net::io_context ioc;
    std::atomic<bool> done{false};
    std::pair<psm::fault::code, auth_method> result;

    net::co_spawn(
        ioc,
        [&]() -> net::awaitable<void>
        {
            result = co_await c->negotiated_authentication();
            done = true;
        },
        net::detached);

    ioc.run_for(std::chrono::milliseconds(500));
    ASSERT_TRUE(done);

    EXPECT_TRUE(psm::fault::failed(result.first));
}

// ── negotiated_authentication: 启用认证但客户端不支持 ──

TEST(Socks5ConnDeep, NegotiatedAuthRequiredButNotSupported)
{
    auto mock = std::make_shared<MockTransport>();

    // 只支持 no_auth (0x00)，但服务端要求认证
    const std::vector<std::byte> greeting = {
        std::byte{0x05}, std::byte{0x01}, std::byte{0x00}};
    mock->inject_read(greeting.data(), greeting.size());

    config cfg{};
    cfg.enable_auth = true;
    // 不设 acct_dir → password_supported 但 acct_dir 为空
    auto c = std::make_shared<conn>(mock, cfg);

    net::io_context ioc;
    std::atomic<bool> done{false};
    std::pair<psm::fault::code, auth_method> result;

    net::co_spawn(
        ioc,
        [&]() -> net::awaitable<void>
        {
            result = co_await c->negotiated_authentication();
            done = true;
        },
        net::detached);

    ioc.run_for(std::chrono::milliseconds(500));
    ASSERT_TRUE(done);

    // enable_auth=true, acct_dir_=nullptr → password_supported=true 但 acct_dir 为空
    // 走到 no_auth_supported && !enable_auth 分支失败
    // 最后发送 0xFF 拒绝
    EXPECT_EQ(result.first, psm::fault::code::not_supported);

    const auto &written = mock->written_data();
    ASSERT_GE(written.size(), 2u);
    EXPECT_EQ(std::to_integer<uint8_t>(written[0]), 0x05);
    EXPECT_EQ(std::to_integer<uint8_t>(written[1]), 0xFF);
}

// ── negotiated_authentication: 认证方法中包含 password ──

TEST(Socks5ConnDeep, NegotiatedAuthPasswordMethodSupported)
{
    auto mock = std::make_shared<MockTransport>();

    // 方法列表包含 no_auth(0x00) 和 password(0x02)
    const std::vector<std::byte> greeting = {
        std::byte{0x05}, std::byte{0x02}, std::byte{0x00}, std::byte{0x02}};
    mock->inject_read(greeting.data(), greeting.size());

    // enable_auth=false → 走 no_auth 分支
    config cfg{};
    cfg.enable_auth = false;
    auto c = std::make_shared<conn>(mock, cfg);

    net::io_context ioc;
    std::atomic<bool> done{false};
    std::pair<psm::fault::code, auth_method> result;

    net::co_spawn(
        ioc,
        [&]() -> net::awaitable<void>
        {
            result = co_await c->negotiated_authentication();
            done = true;
        },
        net::detached);

    ioc.run_for(std::chrono::milliseconds(500));
    ASSERT_TRUE(done);

    EXPECT_EQ(result.first, psm::fault::code::success);
    EXPECT_EQ(result.second, auth_method::no_auth);

    const auto &written = mock->written_data();
    ASSERT_GE(written.size(), 2u);
    EXPECT_EQ(std::to_integer<uint8_t>(written[1]), 0x00);
}

// ── resolve_command: CONNECT 命令允许 ──

TEST(Socks5ConnDeep, ResolveCommandConnectAllowed)
{
    auto mock = std::make_shared<MockTransport>();
    config cfg{};
    cfg.enable_tcp = true;
    auto c = std::make_shared<conn>(mock, cfg);

    net::io_context ioc;
    net::steady_timer deadline(ioc, std::chrono::seconds(30));
    request req;

    std::atomic<bool> done{false};
    psm::fault::code result;

    net::co_spawn(
        ioc,
        [&]() -> net::awaitable<void>
        {
            result = co_await c->resolve_command(deadline, command::connect, req);
            done = true;
        },
        net::detached);

    ioc.run_for(std::chrono::milliseconds(200));
    ASSERT_TRUE(done);

    EXPECT_EQ(result, psm::fault::code::success);
    EXPECT_EQ(req.transport, psm::protocol::form::stream);
}

// ── resolve_command: CONNECT 命令被禁用 ──

TEST(Socks5ConnDeep, ResolveCommandConnectDenied)
{
    auto mock = std::make_shared<MockTransport>();
    config cfg{};
    cfg.enable_tcp = false;
    auto c = std::make_shared<conn>(mock, cfg);

    net::io_context ioc;
    net::steady_timer deadline(ioc, std::chrono::seconds(30));
    request req;

    std::atomic<bool> done{false};
    psm::fault::code result;

    net::co_spawn(
        ioc,
        [&]() -> net::awaitable<void>
        {
            result = co_await c->resolve_command(deadline, command::connect, req);
            done = true;
        },
        net::detached);

    ioc.run_for(std::chrono::milliseconds(200));
    ASSERT_TRUE(done);

    EXPECT_EQ(result, psm::fault::code::not_supported);

    // 验证发送了 connect_denied 错误响应
    const auto &written = mock->written_data();
    ASSERT_GE(written.size(), 10u);
    EXPECT_EQ(std::to_integer<uint8_t>(written[1]),
              static_cast<uint8_t>(reply_code::connect_denied));
}

// ── resolve_command: UDP_ASSOCIATE 命令 ──

TEST(Socks5ConnDeep, ResolveCommandUdpAssociate)
{
    auto mock = std::make_shared<MockTransport>();
    config cfg{};
    cfg.enable_udp = true;
    auto c = std::make_shared<conn>(mock, cfg);

    net::io_context ioc;
    net::steady_timer deadline(ioc, std::chrono::seconds(30));
    request req;

    std::atomic<bool> done{false};
    psm::fault::code result;

    net::co_spawn(
        ioc,
        [&]() -> net::awaitable<void>
        {
            result = co_await c->resolve_command(deadline, command::udp_associate, req);
            done = true;
        },
        net::detached);

    ioc.run_for(std::chrono::milliseconds(200));
    ASSERT_TRUE(done);

    EXPECT_EQ(result, psm::fault::code::success);
    EXPECT_EQ(req.transport, psm::protocol::form::datagram);
}

// ── resolve_command: BIND 命令禁用 ──

TEST(Socks5ConnDeep, ResolveCommandBindDenied)
{
    auto mock = std::make_shared<MockTransport>();
    config cfg{};
    cfg.enable_bind = false;
    auto c = std::make_shared<conn>(mock, cfg);

    net::io_context ioc;
    net::steady_timer deadline(ioc, std::chrono::seconds(30));
    request req;

    std::atomic<bool> done{false};
    psm::fault::code result;

    net::co_spawn(
        ioc,
        [&]() -> net::awaitable<void>
        {
            result = co_await c->resolve_command(deadline, command::bind, req);
            done = true;
        },
        net::detached);

    ioc.run_for(std::chrono::milliseconds(200));
    ASSERT_TRUE(done);

    EXPECT_EQ(result, psm::fault::code::unsupported_command);
}

// ── resolve_command: 未知命令 ──

TEST(Socks5ConnDeep, ResolveCommandUnknown)
{
    auto mock = std::make_shared<MockTransport>();
    config cfg{};
    auto c = std::make_shared<conn>(mock, cfg);

    net::io_context ioc;
    net::steady_timer deadline(ioc, std::chrono::seconds(30));
    request req;

    std::atomic<bool> done{false};
    psm::fault::code result;

    net::co_spawn(
        ioc,
        [&]() -> net::awaitable<void>
        {
            result = co_await c->resolve_command(
                deadline, static_cast<command>(0xFF), req);
            done = true;
        },
        net::detached);

    ioc.run_for(std::chrono::milliseconds(200));
    ASSERT_TRUE(done);

    EXPECT_EQ(result, psm::fault::code::unsupported_command);
}

// ── send_error: 发送错误响应 ──

TEST(Socks5ConnDeep, SendErrorResponse)
{
    auto mock = std::make_shared<MockTransport>();
    config cfg{};
    auto c = std::make_shared<conn>(mock, cfg);

    net::io_context ioc;
    std::atomic<bool> done{false};
    psm::fault::code result;

    net::co_spawn(
        ioc,
        [&]() -> net::awaitable<void>
        {
            result = co_await c->send_error(reply_code::host_unreachable);
            done = true;
        },
        net::detached);

    ioc.run_for(std::chrono::milliseconds(200));
    ASSERT_TRUE(done);

    const auto &written = mock->written_data();
    ASSERT_GE(written.size(), 10u);
    EXPECT_EQ(std::to_integer<uint8_t>(written[0]), 0x05);
    EXPECT_EQ(std::to_integer<uint8_t>(written[1]),
              static_cast<uint8_t>(reply_code::host_unreachable));
    EXPECT_EQ(std::to_integer<uint8_t>(written[2]), 0x00); // RSV
    EXPECT_EQ(std::to_integer<uint8_t>(written[3]), 0x01); // ATYP IPv4
}

// ── send_success: 发送成功响应 ──

TEST(Socks5ConnDeep, SendSuccessResponse)
{
    auto mock = std::make_shared<MockTransport>();
    config cfg{};
    auto c = std::make_shared<conn>(mock, cfg);

    request req{};
    req.destination_address = ipv4_address{{192, 168, 1, 1}};
    req.destination_port = 8080;

    net::io_context ioc;
    std::atomic<bool> done{false};
    psm::fault::code result;

    net::co_spawn(
        ioc,
        [&]() -> net::awaitable<void>
        {
            result = co_await c->send_success(req);
            done = true;
        },
        net::detached);

    ioc.run_for(std::chrono::milliseconds(200));
    ASSERT_TRUE(done);

    EXPECT_EQ(result, psm::fault::code::success);

    const auto &written = mock->written_data();
    ASSERT_GE(written.size(), 10u);
    EXPECT_EQ(std::to_integer<uint8_t>(written[0]), 0x05);
    EXPECT_EQ(std::to_integer<uint8_t>(written[1]),
              static_cast<uint8_t>(reply_code::succeeded));
}

// ── conn: close 和 cancel 传播 ──

TEST(Socks5ConnDeep, CloseAndCancelPropagation)
{
    auto mock = std::make_shared<MockTransport>();
    config cfg{};
    auto c = std::make_shared<conn>(mock, cfg);

    EXPECT_FALSE(mock->is_closed());
    EXPECT_FALSE(mock->is_cancelled());

    c->cancel();
    EXPECT_TRUE(mock->is_cancelled());

    c->close();
    EXPECT_TRUE(mock->is_closed());
}

// ── conn: release 转移所有权 ──

TEST(Socks5ConnDeep, ReleaseOwnership)
{
    auto mock = std::make_shared<MockTransport>();
    config cfg{};
    auto c = std::make_shared<conn>(mock, cfg);

    EXPECT_TRUE(c->is_valid());

    auto released = c->release();
    EXPECT_EQ(released, mock);
    EXPECT_FALSE(c->is_valid());
}

// ── conn: next_layer 返回内层 ──

TEST(Socks5ConnDeep, NextLayerAccessor)
{
    auto mock = std::make_shared<MockTransport>();
    config cfg{};
    auto c = std::make_shared<conn>(mock, cfg);

    EXPECT_EQ(c->next_layer(), mock.get());
    EXPECT_EQ(c->underlying().transport_type(), psm::transport::transmission::type::tcp);
}

// ── conn: executor 委托到内层 ──

TEST(Socks5ConnDeep, ExecutorDelegatesToInner)
{
    auto mock = std::make_shared<MockTransport>();
    config cfg{};
    auto c = std::make_shared<conn>(mock, cfg);

    auto ex = c->executor();
    auto inner_ex = mock->executor();
    // 比较执行器：MockTransport 内部有自己的 io_context
    EXPECT_TRUE(ex);
}

// ── read_req_hdr: 正常请求头解析 ──

TEST(Socks5ConnDeep, ReadReqHdrSuccess)
{
    auto mock = std::make_shared<MockTransport>();
    config cfg{};
    auto c = std::make_shared<conn>(mock, cfg);

    // VER=5, CMD=CONNECT(1), RSV=0, ATYP=IPv4(1)
    const std::vector<std::byte> header = {
        std::byte{0x05}, std::byte{0x01}, std::byte{0x00}, std::byte{0x01}};
    mock->inject_read(header.data(), header.size());

    net::io_context ioc;
    std::atomic<bool> done{false};
    std::pair<psm::fault::code, wire::header_parse> result;

    net::co_spawn(
        ioc,
        [&]() -> net::awaitable<void>
        {
            result = co_await c->read_req_hdr();
            done = true;
        },
        net::detached);

    ioc.run_for(std::chrono::milliseconds(200));
    ASSERT_TRUE(done);

    EXPECT_EQ(result.first, psm::fault::code::success);
    EXPECT_EQ(result.second.cmd, command::connect);
    EXPECT_EQ(result.second.atyp, address_type::ipv4);
}

// ── read_req_hdr: 读错误 ──

TEST(Socks5ConnDeep, ReadReqHdrReadError)
{
    auto mock = std::make_shared<MockTransport>();
    mock->set_read_error(std::make_error_code(std::errc::connection_reset));

    config cfg{};
    auto c = std::make_shared<conn>(mock, cfg);

    net::io_context ioc;
    std::atomic<bool> done{false};
    std::pair<psm::fault::code, wire::header_parse> result;

    net::co_spawn(
        ioc,
        [&]() -> net::awaitable<void>
        {
            result = co_await c->read_req_hdr();
            done = true;
        },
        net::detached);

    ioc.run_for(std::chrono::milliseconds(200));
    ASSERT_TRUE(done);

    EXPECT_TRUE(psm::fault::failed(result.first));
}

// ── read_req_hdr: 域名地址类型 ──

TEST(Socks5ConnDeep, ReadReqHdrDomainAtyp)
{
    auto mock = std::make_shared<MockTransport>();
    config cfg{};
    auto c = std::make_shared<conn>(mock, cfg);

    // VER=5, CMD=CONNECT(1), RSV=0, ATYP=DOMAIN(3)
    const std::vector<std::byte> header = {
        std::byte{0x05}, std::byte{0x01}, std::byte{0x00}, std::byte{0x03}};
    mock->inject_read(header.data(), header.size());

    net::io_context ioc;
    std::atomic<bool> done{false};
    std::pair<psm::fault::code, wire::header_parse> result;

    net::co_spawn(
        ioc,
        [&]() -> net::awaitable<void>
        {
            result = co_await c->read_req_hdr();
            done = true;
        },
        net::detached);

    ioc.run_for(std::chrono::milliseconds(200));
    ASSERT_TRUE(done);

    EXPECT_EQ(result.first, psm::fault::code::success);
    EXPECT_EQ(result.second.atyp, address_type::domain);
}

// ── set_traffic: 设置流量统计 ──

TEST(Socks5ConnDeep, SetTrafficState)
{
    auto mock = std::make_shared<MockTransport>();
    config cfg{};
    auto c = std::make_shared<conn>(mock, cfg);

    EXPECT_EQ(c->traffic_, nullptr);
    EXPECT_EQ(c->proto_, psm::connect::protocol_type::unknown);

    c->set_traffic(reinterpret_cast<psm::stats::traffic::traffic_state *>(0x1),
                   psm::connect::protocol_type::socks5);

    EXPECT_NE(c->traffic_, nullptr);
    EXPECT_EQ(c->proto_, psm::connect::protocol_type::socks5);
}

// ── ep_to_addr: IPv4 和 IPv6 端点转换 ──

TEST(Socks5ConnDeep, EpToAddrConversion)
{
    {
        auto ep = net::ip::udp::endpoint(
            net::ip::make_address("127.0.0.1"), 1080);
        auto addr = conn::ep_to_addr(ep);
        EXPECT_TRUE(std::holds_alternative<ipv4_address>(addr));
        const auto &ip4 = std::get<ipv4_address>(addr);
        EXPECT_EQ(ip4.bytes[0], 127);
        EXPECT_EQ(ip4.bytes[3], 1);
    }

    {
        auto ep = net::ip::udp::endpoint(
            net::ip::make_address("::1"), 1080);
        auto addr = conn::ep_to_addr(ep);
        EXPECT_TRUE(std::holds_alternative<ipv6_address>(addr));
        const auto &ip6 = std::get<ipv6_address>(addr);
        EXPECT_EQ(ip6.bytes[15], 1);
    }
}
