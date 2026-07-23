/**
 * @file H2muxCraftAsync.cpp
 * @brief h2mux craft 异步端到端路径测试
 * @details 测试 craft 的 send_data/send_fin/send_loop/wait_first_connect/
 *          frame_loop/activate_stream(handle_connect 第二次触发)等异步路径。
 *          所有测试使用 co_spawn + ioc.run() 模式。
 * @note close() 后必须 transport->close() 解除 MockTransport 轮询循环
 *       对 frame_loop 的阻塞，否则 ioc.run() 不会返回。
 */

#include <prism/foundation/foundation.hpp>
#include <prism/trace/spdlog.hpp>

#include "common/MockTransport.hpp"

#define private public
#define protected public
#include <prism/net/connect/pool/pool.hpp>
#include <prism/net/connect/dial/router.hpp>
#include <prism/net/dns/resolver.hpp>
#include <prism/protocol/multiplex/h2mux/craft.hpp>
#include <prism/account/stats/traffic.hpp>
#undef protected
#undef private

#include <nghttp2/nghttp2.h>

using MockTransport = psm::testing::MockTransport;
namespace multiplex = psm::multiplex;
namespace h2mux = psm::multiplex::h2mux;
namespace net = boost::asio;

#include <gtest/gtest.h>

namespace
{
    static multiplex::config g_cfg{};

    static auto make_check_resolver() -> h2mux::address_resolver
    {
        return [](std::int32_t, const h2mux::h2_headers &) -> h2mux::stream_info
        {
            h2mux::stream_info info;
            info.type = h2mux::stream_type::check;
            info.valid = true;
            return info;
        };
    }

    static auto make_invalid_resolver() -> h2mux::address_resolver
    {
        return [](std::int32_t, const h2mux::h2_headers &) -> h2mux::stream_info
        {
            h2mux::stream_info info;
            info.valid = false;
            return info;
        };
    }

    // ─── 测试夹具 ────────────────────────────────

    struct AsyncFixture
    {
        std::shared_ptr<MockTransport> transport;
        std::unique_ptr<net::io_context> ioc;
        std::unique_ptr<psm::connect::connection_pool> pool;
        std::unique_ptr<psm::connect::router> router_ptr;
        std::shared_ptr<h2mux::craft> craft_obj;

        explicit AsyncFixture(h2mux::address_resolver resolver = make_check_resolver())
        {
            transport = std::make_shared<MockTransport>();
            ioc = std::make_unique<net::io_context>(1);
            pool = std::make_unique<psm::connect::connection_pool>(*ioc);
            psm::dns::config dns_cfg;
            psm::connect::router_options ropts{*pool, *ioc, dns_cfg};
            router_ptr = std::make_unique<psm::connect::router>(std::move(ropts));
            multiplex::core_options opts{transport, nullptr, g_cfg, nullptr};
            h2mux::craft_init init{nullptr, g_cfg, std::move(resolver)};
            craft_obj = std::make_shared<h2mux::craft>(std::move(opts), std::move(init));
        }
    };

    // ─── send_data 通过 send_loop 写入 transport ──

    TEST(H2muxCraftAsync, SendDataWritesToTransport)
    {
        AsyncFixture fx;

        std::exception_ptr ep;
        bool wrote_data = false;

        auto coro = [&]() -> net::awaitable<void>
        {
            fx.craft_obj->start();

            net::steady_timer timer(co_await net::this_coro::executor);
            timer.expires_after(std::chrono::milliseconds(200));
            boost::system::error_code ec;
            co_await timer.async_wait(net::redirect_error(net::use_awaitable, ec));

            psm::memory::vector<std::byte> payload(psm::memory::current_resource());
            payload.push_back(std::byte{0xDE});
            payload.push_back(std::byte{0xAD});

            co_await fx.craft_obj->send_data(1, std::move(payload));

            timer.expires_after(std::chrono::milliseconds(200));
            co_await timer.async_wait(net::redirect_error(net::use_awaitable, ec));

            wrote_data = !fx.transport->written_data().empty();

            fx.transport->close();
            fx.craft_obj->close();
        };

        auto &mock_ioc = fx.transport->get_io_context();
        net::co_spawn(mock_ioc.get_executor(), coro(), [&](std::exception_ptr e)
                      { ep = e; mock_ioc.stop(); });
        mock_ioc.run();

        if (ep)
        {
            try { std::rethrow_exception(ep); }
            catch (const std::exception &e) { FAIL() << e.what(); }
        }

        EXPECT_TRUE(wrote_data) << "send_data: bytes written to transport";
    }

    // ─── send_fin 不崩溃 ─────────────────────────

    TEST(H2muxCraftAsync, SendFinNoCrash)
    {
        AsyncFixture fx;

        std::exception_ptr ep;
        bool fin_ok = false;

        auto coro = [&]() -> net::awaitable<void>
        {
            fx.craft_obj->start();

            net::steady_timer timer(co_await net::this_coro::executor);
            timer.expires_after(std::chrono::milliseconds(200));
            boost::system::error_code ec;
            co_await timer.async_wait(net::redirect_error(net::use_awaitable, ec));

            fx.craft_obj->send_fin(1);

            timer.expires_after(std::chrono::milliseconds(200));
            co_await timer.async_wait(net::redirect_error(net::use_awaitable, ec));

            fin_ok = true;

            fx.transport->close();
            fx.craft_obj->close();
        };

        auto &mock_ioc = fx.transport->get_io_context();
        net::co_spawn(mock_ioc.get_executor(), coro(), [&](std::exception_ptr e)
                      { ep = e; mock_ioc.stop(); });
        mock_ioc.run();

        if (ep)
        {
            try { std::rethrow_exception(ep); }
            catch (const std::exception &e) { FAIL() << e.what(); }
        }

        EXPECT_TRUE(fin_ok) << "send_fin: completed without crash";
    }

    // ─── send_data 空 payload 被跳过 ────────────

    TEST(H2muxCraftAsync, SendDataEmptyPayload)
    {
        AsyncFixture fx;

        std::exception_ptr ep;
        bool empty_ok = false;

        auto coro = [&]() -> net::awaitable<void>
        {
            fx.craft_obj->start();

            net::steady_timer timer(co_await net::this_coro::executor);
            timer.expires_after(std::chrono::milliseconds(200));
            boost::system::error_code ec;
            co_await timer.async_wait(net::redirect_error(net::use_awaitable, ec));

            psm::memory::vector<std::byte> empty_payload(psm::memory::current_resource());
            co_await fx.craft_obj->send_data(1, std::move(empty_payload));

            empty_ok = true;

            fx.transport->close();
            fx.craft_obj->close();
        };

        auto &mock_ioc = fx.transport->get_io_context();
        net::co_spawn(mock_ioc.get_executor(), coro(), [&](std::exception_ptr e)
                      { ep = e; mock_ioc.stop(); });
        mock_ioc.run();

        if (ep)
        {
            try { std::rethrow_exception(ep); }
            catch (const std::exception &e) { FAIL() << e.what(); }
        }

        EXPECT_TRUE(empty_ok) << "send_data: empty payload handled";
    }

    // ─── frame_loop 读错误正常退出 ──────────────

    TEST(H2muxCraftAsync, FrameLoopReadError)
    {
        AsyncFixture fx;
        fx.transport->set_read_error(std::make_error_code(std::errc::connection_reset));

        std::exception_ptr ep;
        bool closed_ok = false;

        auto coro = [&]() -> net::awaitable<void>
        {
            fx.craft_obj->start();

            net::steady_timer timer(co_await net::this_coro::executor);
            timer.expires_after(std::chrono::milliseconds(300));
            boost::system::error_code ec;
            co_await timer.async_wait(net::redirect_error(net::use_awaitable, ec));

            closed_ok = !fx.craft_obj->is_active();
        };

        auto &mock_ioc = fx.transport->get_io_context();
        net::co_spawn(mock_ioc.get_executor(), coro(), [&](std::exception_ptr e)
                      { ep = e; mock_ioc.stop(); });
        mock_ioc.run();

        if (ep)
        {
            try { std::rethrow_exception(ep); }
            catch (const std::exception &e) { FAIL() << e.what(); }
        }

        EXPECT_TRUE(closed_ok) << "frame_loop: read error -> graceful shutdown";
    }

    // ─── wait_first_connect（无 CONNECT，关闭）──

    TEST(H2muxCraftAsync, WaitFirstConnectNone)
    {
        AsyncFixture fx;

        std::exception_ptr ep;
        std::optional<h2mux::h2_headers> result;

        auto coro = [&]() -> net::awaitable<void>
        {
            fx.craft_obj->start();

            net::steady_timer timer(co_await net::this_coro::executor);
            timer.expires_after(std::chrono::milliseconds(100));
            boost::system::error_code ec;
            co_await timer.async_wait(net::redirect_error(net::use_awaitable, ec));

            fx.transport->close();
            result = co_await fx.craft_obj->wait_first_connect();
        };

        auto &mock_ioc = fx.transport->get_io_context();
        net::co_spawn(mock_ioc.get_executor(), coro(), [&](std::exception_ptr e)
                      { ep = e; mock_ioc.stop(); });
        mock_ioc.run();

        if (ep)
        {
            try { std::rethrow_exception(ep); }
            catch (const std::exception &e) { FAIL() << e.what(); }
        }

        EXPECT_TRUE(!result.has_value()) << "wait_first_connect: no CONNECT -> nullopt";
    }

    // ─── wait_first_connect 立即返回（connect_resolved_ 已为 true）──

    TEST(H2muxCraftAsync, WaitFirstConnectImmediateReturn)
    {
        AsyncFixture fx;

        std::exception_ptr ep;
        std::optional<h2mux::h2_headers> result;

        auto coro = [&]() -> net::awaitable<void>
        {
            fx.craft_obj->start();

            net::steady_timer timer(co_await net::this_coro::executor);
            timer.expires_after(std::chrono::milliseconds(100));
            boost::system::error_code ec;
            co_await timer.async_wait(net::redirect_error(net::use_awaitable, ec));

            // 模拟 handle_connect 已设置 connect_resolved_
            fx.craft_obj->connect_resolved_ = true;
            fx.craft_obj->first_connect_.authority = "test.local:443";
            fx.craft_obj->first_connect_.host = "test.local";
            fx.craft_obj->first_connect_.stream_id = 1;

            result = co_await fx.craft_obj->wait_first_connect();

            fx.transport->close();
            fx.craft_obj->close();
        };

        auto &mock_ioc = fx.transport->get_io_context();
        net::co_spawn(mock_ioc.get_executor(), coro(), [&](std::exception_ptr e)
                      { ep = e; mock_ioc.stop(); });
        mock_ioc.run();

        if (ep)
        {
            try { std::rethrow_exception(ep); }
            catch (const std::exception &e) { FAIL() << e.what(); }
        }

        ASSERT_TRUE(result.has_value()) << "wait_first_connect: immediate result";
        EXPECT_TRUE(result->authority == "test.local:443")
            << "wait_first_connect: authority preserved";
    }

    // ─── wait_first_connect 立即返回空（resolved 但 authority 为空）──

    TEST(H2muxCraftAsync, WaitFirstConnectImmediateEmpty)
    {
        AsyncFixture fx;

        std::exception_ptr ep;
        std::optional<h2mux::h2_headers> result;

        auto coro = [&]() -> net::awaitable<void>
        {
            fx.craft_obj->start();

            net::steady_timer timer(co_await net::this_coro::executor);
            timer.expires_after(std::chrono::milliseconds(100));
            boost::system::error_code ec;
            co_await timer.async_wait(net::redirect_error(net::use_awaitable, ec));

            // resolved 但 authority 为空 → nullopt
            fx.craft_obj->connect_resolved_ = true;

            result = co_await fx.craft_obj->wait_first_connect();

            fx.transport->close();
            fx.craft_obj->close();
        };

        auto &mock_ioc = fx.transport->get_io_context();
        net::co_spawn(mock_ioc.get_executor(), coro(), [&](std::exception_ptr e)
                      { ep = e; mock_ioc.stop(); });
        mock_ioc.run();

        if (ep)
        {
            try { std::rethrow_exception(ep); }
            catch (const std::exception &e) { FAIL() << e.what(); }
        }

        EXPECT_TRUE(!result.has_value()) << "wait_first_connect: resolved but empty -> nullopt";
    }

    // ─── activate_stream(check) 通过 handle_connect 第二次调用触发 ──

    TEST(H2muxCraftAsync, ActivateStreamCheckViaHandleConnect)
    {
        AsyncFixture fx{make_check_resolver()};

        std::exception_ptr ep;
        bool second_resolved = false;
        bool second_connecting = false;

        auto coro = [&]() -> net::awaitable<void>
        {
            fx.craft_obj->start();

            net::steady_timer timer(co_await net::this_coro::executor);
            timer.expires_after(std::chrono::milliseconds(200));
            boost::system::error_code ec;
            co_await timer.async_wait(net::redirect_error(net::use_awaitable, ec));

            // 模拟第一个 CONNECT 已被 handle_connect 处理
            h2mux::h2_pending_entry entry1;
            entry1.headers.authority = "first.local:443";
            entry1.headers.stream_id = 1;
            fx.craft_obj->h2_pending_[1] = std::move(entry1);
            fx.craft_obj->handle_connect(1);
            EXPECT_TRUE(fx.craft_obj->connect_resolved_) << "first connect resolved";

            // 第二个 CONNECT 触发 activate_stream（check 类型）
            h2mux::h2_pending_entry entry2;
            entry2.headers.authority = "health.local:443";
            entry2.headers.host = "_check";
            entry2.headers.stream_id = 3;
            fx.craft_obj->h2_pending_[3] = std::move(entry2);
            fx.craft_obj->handle_connect(3);

            // 等待 activate_stream 完成
            timer.expires_after(std::chrono::milliseconds(300));
            co_await timer.async_wait(net::redirect_error(net::use_awaitable, ec));

            second_resolved = fx.craft_obj->connect_resolved_;
            second_connecting = fx.craft_obj->h2_pending_.count(3) == 0;

            fx.transport->close();
            fx.craft_obj->close();
        };

        auto &mock_ioc = fx.transport->get_io_context();
        net::co_spawn(mock_ioc.get_executor(), coro(), [&](std::exception_ptr e)
                      { ep = e; mock_ioc.stop(); });
        mock_ioc.run();

        if (ep)
        {
            try { std::rethrow_exception(ep); }
            catch (const std::exception &e) { FAIL() << e.what(); }
        }

        EXPECT_TRUE(second_resolved) << "activate_stream(check): resolved";
        EXPECT_TRUE(second_connecting) << "activate_stream(check): pending erased";
    }

    // ─── handle_connect 第二次调用 invalid resolver 不 spawn ──

    TEST(H2muxCraftAsync, HandleConnectSecondInvalid)
    {
        AsyncFixture fx{make_invalid_resolver()};

        std::exception_ptr ep;
        bool not_connecting = false;

        auto coro = [&]() -> net::awaitable<void>
        {
            fx.craft_obj->start();

            net::steady_timer timer(co_await net::this_coro::executor);
            timer.expires_after(std::chrono::milliseconds(200));
            boost::system::error_code ec;
            co_await timer.async_wait(net::redirect_error(net::use_awaitable, ec));

            // 第一个 CONNECT 也返回 invalid，不会设置 connect_resolved_
            h2mux::h2_pending_entry entry1;
            entry1.headers.authority = "first.local:443";
            fx.craft_obj->h2_pending_[1] = std::move(entry1);
            fx.craft_obj->handle_connect(1);

            // 第二个 CONNECT，同样 invalid → 不 spawn
            h2mux::h2_pending_entry entry2;
            entry2.headers.authority = "bad.local:443";
            fx.craft_obj->h2_pending_[3] = std::move(entry2);
            fx.craft_obj->handle_connect(3);

            not_connecting = !fx.craft_obj->h2_pending_[3].connecting;

            fx.transport->close();
            fx.craft_obj->close();
        };

        auto &mock_ioc = fx.transport->get_io_context();
        net::co_spawn(mock_ioc.get_executor(), coro(), [&](std::exception_ptr e)
                      { ep = e; mock_ioc.stop(); });
        mock_ioc.run();

        if (ep)
        {
            try { std::rethrow_exception(ep); }
            catch (const std::exception &e) { FAIL() << e.what(); }
        }

        EXPECT_TRUE(not_connecting) << "handle_connect: invalid -> not connecting";
    }

    // ─── respond_connect 异步路径 ────────────────

    TEST(H2muxCraftAsync, RespondConnectAsync)
    {
        AsyncFixture fx;

        std::exception_ptr ep;
        bool respond_200_ok = false;
        bool respond_407_ok = false;

        auto coro = [&]() -> net::awaitable<void>
        {
            fx.craft_obj->start();

            net::steady_timer timer(co_await net::this_coro::executor);
            timer.expires_after(std::chrono::milliseconds(200));
            boost::system::error_code ec;
            co_await timer.async_wait(net::redirect_error(net::use_awaitable, ec));

            respond_200_ok = (fx.craft_obj->respond_connect(1, 200) == 0);
            respond_407_ok = (fx.craft_obj->respond_connect(3, 407) == 0);

            fx.transport->close();
            fx.craft_obj->close();
        };

        auto &mock_ioc = fx.transport->get_io_context();
        net::co_spawn(mock_ioc.get_executor(), coro(), [&](std::exception_ptr e)
                      { ep = e; mock_ioc.stop(); });
        mock_ioc.run();

        if (ep)
        {
            try { std::rethrow_exception(ep); }
            catch (const std::exception &e) { FAIL() << e.what(); }
        }

        EXPECT_TRUE(respond_200_ok) << "respond_connect(200): success";
        EXPECT_TRUE(respond_407_ok) << "respond_connect(407): success";
    }

} // namespace
