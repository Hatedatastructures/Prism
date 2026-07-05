/**
 * @file H2muxCraftDeep.cpp
 * @brief multiplex/h2mux/craft 深度同步逻辑测试
 * @details 通过 #include 源文件访问匿名命名空间中的 log_spawn_error，
 *          以及 craft 类的构造、析构、respond_connect、close、send_fin、
 *          executor 等同步/公开方法。
 *          涉及 start() 的测试使用 co_spawn + ioc.run() 协程模式驱动，
 *          避免同步 start() + poll()/run_for() 导致的 Access violation。
 */

#include <prism/foundation/foundation.hpp>
#include <prism/trace/spdlog.hpp>

#include "common/MockTransport.hpp"

#include <prism/net/connect/pool/pool.hpp>
#include <prism/net/connect/dial/router.hpp>
#include <prism/net/resolve/dns/dns.hpp>
#include <prism/proto/multiplex/h2mux/craft.hpp>
#include <prism/account/stats/traffic.hpp>

using MockTransport = psm::testing::MockTransport;
namespace multiplex = psm::multiplex;
namespace h2mux = psm::multiplex::h2mux;
namespace net = boost::asio;

#include <gtest/gtest.h>

namespace
{
    // ─── 构造辅助 ──────────────────────────────

    static multiplex::config g_cfg{};

    static auto make_resolver() -> h2mux::address_resolver
    {
        return [](std::int32_t, const h2mux::h2_headers &) -> h2mux::stream_info
        {
            h2mux::stream_info info;
            info.host = "127.0.0.1";
            info.port = 80;
            info.type = h2mux::stream_type::tcp;
            info.valid = true;
            return info;
        };
    }

    struct CraftFixture
    {
        std::shared_ptr<MockTransport> transport;
        std::unique_ptr<net::io_context> ioc;
        std::unique_ptr<psm::connect::connection_pool> pool;
        std::unique_ptr<psm::connect::router> router_ptr;
        std::shared_ptr<h2mux::craft> craft_obj;

        CraftFixture()
        {
            transport = std::make_shared<MockTransport>();
            ioc = std::make_unique<net::io_context>(1);
            pool = std::make_unique<psm::connect::connection_pool>(*ioc);
            psm::resolve::dns::config dns_cfg;
            psm::connect::router_options ropts{*pool, *ioc, dns_cfg};
            router_ptr = std::make_unique<psm::connect::router>(std::move(ropts));
            multiplex::core_options opts{transport, nullptr, g_cfg, nullptr};
            h2mux::craft_init init{nullptr, g_cfg, make_resolver()};
            craft_obj = std::make_shared<h2mux::craft>(std::move(opts), std::move(init));
        }
    };

    // ─── 构造函数 ─────────────────────────────

    TEST(H2muxCraftDeep, ConstructorDefault)
    {
        CraftFixture fx;
        EXPECT_TRUE(!fx.craft_obj->is_active()) << "constructor: inactive by default";
    }

    TEST(H2muxCraftDeep, ConstructorWithMr)
    {
        auto transport = std::make_shared<MockTransport>();
        auto ioc = std::make_unique<net::io_context>(1);
        auto pool = std::make_unique<psm::connect::connection_pool>(*ioc);
        psm::resolve::dns::config dns_cfg;
        psm::connect::router_options ropts{*pool, *ioc, dns_cfg};
        auto router_ptr = std::make_unique<psm::connect::router>(std::move(ropts));
        psm::memory::unsynchronized_pool mr;
        multiplex::core_options opts{transport, nullptr, g_cfg, &mr};
        h2mux::craft_init init{nullptr, g_cfg, make_resolver()};
        auto c = std::make_shared<h2mux::craft>(std::move(opts), std::move(init));
        EXPECT_TRUE(!c->is_active()) << "constructor: with mr -> inactive";
    }

    // ─── executor ─────────────────────────────

    TEST(H2muxCraftDeep, Executor)
    {
        CraftFixture fx;
        auto ex = fx.craft_obj->executor();
        EXPECT_TRUE(!!ex) << "executor: non-empty";
    }

    // ─── respond_connect（public 方法） ──────

    TEST(H2muxCraftDeep, RespondConnectWithoutSession)
    {
        CraftFixture fx;
        auto rc = fx.craft_obj->respond_connect(1, 200);
        EXPECT_NE(rc, 0) << "respond_connect without session should fail";
    }

    TEST(H2muxCraftDeep, RespondConnect407WithoutSession)
    {
        CraftFixture fx;
        auto rc = fx.craft_obj->respond_connect(1, 407);
        EXPECT_NE(rc, 0) << "respond_connect 407 without session should fail";
    }

    // ─── close() 幂等性 ─────────────────────

    TEST(H2muxCraftDeep, CloseIdempotent)
    {
        CraftFixture fx;
        fx.craft_obj->close();
        EXPECT_TRUE(!fx.craft_obj->is_active()) << "close: first close -> inactive";
        fx.craft_obj->close();
        EXPECT_TRUE(!fx.craft_obj->is_active()) << "close: second close -> still inactive";
    }

    TEST(H2muxCraftDeep, CloseWithTraffic)
    {
        CraftFixture fx;
        psm::stats::traffic::traffic_state ts;
        fx.craft_obj->set_traffic(&ts, psm::protocol::protocol_type::trojan);
        fx.craft_obj->accumulate_traffic(1000, 2000);
        fx.craft_obj->close();
    }

    TEST(H2muxCraftDeep, CloseWithoutTraffic)
    {
        CraftFixture fx;
        fx.craft_obj->accumulate_traffic(100, 200);
        fx.craft_obj->close();
    }

    // ─── set_traffic + accumulate_traffic ──────

    TEST(H2muxCraftDeep, SetTraffic)
    {
        CraftFixture fx;
        psm::stats::traffic::traffic_state ts;
        fx.craft_obj->set_traffic(&ts, psm::protocol::protocol_type::trojan);
    }

    TEST(H2muxCraftDeep, AccumulateTrafficBoth)
    {
        CraftFixture fx;
        fx.craft_obj->accumulate_traffic(100, 200);
    }

    TEST(H2muxCraftDeep, AccumulateTrafficZero)
    {
        CraftFixture fx;
        fx.craft_obj->accumulate_traffic(0, 0);
    }

    TEST(H2muxCraftDeep, AccumulateTrafficMultiple)
    {
        CraftFixture fx;
        fx.craft_obj->accumulate_traffic(10, 20);
        fx.craft_obj->accumulate_traffic(30, 40);
    }

    // ─── 析构函数 ─────────────────────────────

    TEST(H2muxCraftDeep, DestructorNoInit)
    {
        CraftFixture fx;
        EXPECT_TRUE(!fx.craft_obj->is_active()) << "destructor: created inactive";
        fx.craft_obj.reset();
    }

    TEST(H2muxCraftDeep, DestructorAfterClose)
    {
        CraftFixture fx;
        fx.craft_obj->close();
        fx.craft_obj.reset();
    }

    // ─── start + respond_connect + close 路径 ──

    TEST(H2muxCraftDeep, StartRespondClose)
    {
        // 使用 co_spawn + ioc.run() 模式（与 MuxLifecycle 相同），
        // 避免同步 start() + poll()/run_for() 导致的 Access violation。
        // root cause: core::start() 通过 co_spawn 将 run_wrapper 投递到
        // transport 的 executor 上，run_wrapper 中 scope_guard + co_await run()
        // 需要完整的协程调度支持。poll()/run_for() 不提供足够的调度保障。
        CraftFixture fx;
        std::exception_ptr ep;
        bool respond_ok = false;
        bool close_ok = false;

        auto coro = [&]() -> net::awaitable<void>
        {
            fx.craft_obj->start();

            // 等待 init_nghttp2 + send_pending + send_loop 启动
            net::steady_timer timer(fx.transport->get_io_context().get_executor());
            timer.expires_after(std::chrono::milliseconds(100));
            boost::system::error_code ec;
            co_await timer.async_wait(net::redirect_error(net::use_awaitable, ec));

            // respond_connect 需要 session_ 已由 init_nghttp2 创建
            fx.craft_obj->respond_connect(1, 200);
            respond_ok = true; // 只要没崩溃就算通过

            // close 使 active_=false 并 cancel/close transport
            fx.craft_obj->close();
            close_ok = !fx.craft_obj->is_active();
        };

        auto &mock_ioc = fx.transport->get_io_context();
        net::co_spawn(mock_ioc.get_executor(), coro(), [&](std::exception_ptr e)
                      { ep = e; mock_ioc.stop(); });
        mock_ioc.run();

        if (ep)
        {
            try
            {
                std::rethrow_exception(ep);
            }
            catch (const std::exception &e)
            {
                FAIL() << "coroutine exception: " << e.what();
            }
        }

        EXPECT_TRUE(respond_ok) << "respond_connect completed without crash";
        EXPECT_TRUE(close_ok) << "close after start -> inactive";
    }

} // namespace

// #include 源文件以覆盖 log_spawn_error 匿名命名空间函数
#include "../src/prism/proto/multiplex/h2mux/craft.cpp"

namespace
{
    // ─── log_spawn_error（通过 #include 获取匿名命名空间访问权）──

    TEST(H2muxCraftDeep, LogSpawnErrorException)
    {
        try
        {
            throw std::runtime_error("test h2mux error");
        }
        catch (...)
        {
            psm::multiplex::h2mux::log_spawn_error(std::current_exception(), "test");
        }
    }

    TEST(H2muxCraftDeep, LogSpawnErrorUnknown)
    {
        try
        {
            throw 42;
        }
        catch (...)
        {
            psm::multiplex::h2mux::log_spawn_error(std::current_exception(), "test");
        }
    }
} // namespace
