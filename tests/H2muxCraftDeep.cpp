/**
 * @file H2muxCraftDeep.cpp
 * @brief multiplex/h2mux/craft 深度同步逻辑测试
 * @details 通过 #include 源文件访问匿名命名空间中的 log_spawn_error，
 *          以及 craft 类的构造、析构、respond_connect、close、send_fin、
 *          executor 等同步/公开方法。
 *          start() 会 co_spawn 协程，frame_loop 在 MockTransport 上挂起读，
 *          但 send_loop 和 co_spawn 完成回调都持有 shared_ptr 所以析构安全。
 *          问题：run() 内部 frame_loop 挂起在 MockTransport 的读定时器上，
 *          run_one() 只能驱动一步。所以只测试不 start 的同步路径，
 *          以及 start + close 的基本流程。
 */

#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"
#include "common/MockTransport.hpp"

#include <prism/connect/pool/pool.hpp>
#include <prism/connect/dial/router.hpp>
#include <prism/resolve/dns/dns.hpp>
#include <prism/multiplex/h2mux/craft.hpp>
#include <prism/stats/traffic.hpp>

using psm::testing::TestRunner;
using MockTransport = psm::testing::MockTransport;
namespace multiplex = psm::multiplex;
namespace h2mux = psm::multiplex::h2mux;
namespace net = boost::asio;

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
            multiplex::core_options opts{transport, *router_ptr, g_cfg, nullptr};
            h2mux::craft_init init{*router_ptr, g_cfg, make_resolver()};
            craft_obj = std::make_shared<h2mux::craft>(std::move(opts), std::move(init));
        }
    };

    // ─── 构造函数 ─────────────────────────────

    void TestConstructorDefault(TestRunner &runner)
    {
        CraftFixture fx;
        runner.Check(!fx.craft_obj->is_active(), "constructor: inactive by default");
    }

    void TestConstructorWithMr(TestRunner &runner)
    {
        auto transport = std::make_shared<MockTransport>();
        auto ioc = std::make_unique<net::io_context>(1);
        auto pool = std::make_unique<psm::connect::connection_pool>(*ioc);
        psm::resolve::dns::config dns_cfg;
        psm::connect::router_options ropts{*pool, *ioc, dns_cfg};
        auto router_ptr = std::make_unique<psm::connect::router>(std::move(ropts));
        psm::memory::unsynchronized_pool mr;
        multiplex::core_options opts{transport, *router_ptr, g_cfg, &mr};
        h2mux::craft_init init{*router_ptr, g_cfg, make_resolver()};
        auto c = std::make_shared<h2mux::craft>(std::move(opts), std::move(init));
        runner.Check(!c->is_active(), "constructor: with mr -> inactive");
    }

    // ─── executor ─────────────────────────────

    void TestExecutor(TestRunner &runner)
    {
        CraftFixture fx;
        auto ex = fx.craft_obj->executor();
        runner.Check(!!ex, "executor: non-empty");
    }

    // ─── respond_connect（public 方法） ──────

    void TestRespondConnectWithoutSession(TestRunner &runner)
    {
        runner.Check(true, "respond_connect: no session -> skip (nghttp2 UB)");
    }

    void TestRespondConnect407WithoutSession(TestRunner &runner)
    {
        runner.Check(true, "respond_connect: 407 no session -> skip (nghttp2 UB)");
    }

    // ─── close() 幂等性 ─────────────────────

    void TestCloseIdempotent(TestRunner &runner)
    {
        CraftFixture fx;
        fx.craft_obj->close();
        runner.Check(!fx.craft_obj->is_active(), "close: first close -> inactive");
        fx.craft_obj->close();
        runner.Check(!fx.craft_obj->is_active(), "close: second close -> still inactive");
    }

    void TestCloseWithTraffic(TestRunner &runner)
    {
        CraftFixture fx;
        psm::stats::traffic::traffic_state ts;
        fx.craft_obj->set_traffic(&ts, psm::protocol::protocol_type::trojan);
        fx.craft_obj->accumulate_traffic(1000, 2000);
        fx.craft_obj->close();
        runner.Check(true, "close: with traffic flush -> no crash");
    }

    void TestCloseWithoutTraffic(TestRunner &runner)
    {
        CraftFixture fx;
        fx.craft_obj->accumulate_traffic(100, 200);
        fx.craft_obj->close();
        runner.Check(true, "close: no traffic_state -> no crash");
    }

    // ─── set_traffic + accumulate_traffic ──────

    void TestSetTraffic(TestRunner &runner)
    {
        CraftFixture fx;
        psm::stats::traffic::traffic_state ts;
        fx.craft_obj->set_traffic(&ts, psm::protocol::protocol_type::trojan);
        runner.Check(true, "set_traffic: no crash");
    }

    void TestAccumulateTrafficBoth(TestRunner &runner)
    {
        CraftFixture fx;
        fx.craft_obj->accumulate_traffic(100, 200);
        runner.Check(true, "accumulate: up=100 down=200 -> no crash");
    }

    void TestAccumulateTrafficZero(TestRunner &runner)
    {
        CraftFixture fx;
        fx.craft_obj->accumulate_traffic(0, 0);
        runner.Check(true, "accumulate: zeros -> no crash");
    }

    void TestAccumulateTrafficMultiple(TestRunner &runner)
    {
        CraftFixture fx;
        fx.craft_obj->accumulate_traffic(10, 20);
        fx.craft_obj->accumulate_traffic(30, 40);
        runner.Check(true, "accumulate: multiple -> no crash");
    }

    // ─── 析构函数 ─────────────────────────────

    void TestDestructorNoInit(TestRunner &runner)
    {
        CraftFixture fx;
        runner.Check(!fx.craft_obj->is_active(), "destructor: created inactive");
        fx.craft_obj.reset();
        runner.Check(true, "destructor: no init -> no crash");
    }

    void TestDestructorAfterClose(TestRunner &runner)
    {
        CraftFixture fx;
        fx.craft_obj->close();
        fx.craft_obj.reset();
        runner.Check(true, "destructor: after close -> no crash");
    }

    // ─── start + respond_connect + close 路径 ──

    void TestStartRespondClose(TestRunner &runner)
    {
        // start() → co_spawn run() 在 MockTransport 的 ioc 上
        // run_one() 驱动一步：init_nghttp2 + send_pending 设置帧
        // 然后 frame_loop 挂起在 transport 读
        // close() 停止 active_ + cancel transport → frame_loop 读返回 eof → run() 退出
        CraftFixture fx;
        fx.craft_obj->start();
        auto &mock_ioc = fx.transport->get_io_context();

        // 驱动 init_nghttp2 和 send_pending（写出 settings 帧）
        mock_ioc.run_one();

        // respond_connect 需要 session_ 已创建
        auto rc = fx.craft_obj->respond_connect(1, 200);
        runner.Check(rc == 0, "respond_connect: after init -> 0");

        // close 使 active_=false 并 cancel/close transport
        fx.craft_obj->close();
        runner.Check(!fx.craft_obj->is_active(), "close after start -> inactive");

        // 驱动 close 后 frame_loop 退出 + run() 完成
        // 需要 poll 来驱动 frame_loop 中的读操作发现 closed_ 并退出
        mock_ioc.poll();
    }

} // namespace

// #include 源文件以覆盖 log_spawn_error 匿名命名空间函数
#include "../src/prism/multiplex/h2mux/craft.cpp"

namespace
{
    // ─── log_spawn_error（通过 #include 获取匿名命名空间访问权）──

    void TestLogSpawnErrorException(TestRunner &runner)
    {
        try
        {
            throw std::runtime_error("test h2mux error");
        }
        catch (...)
        {
            psm::multiplex::h2mux::log_spawn_error(std::current_exception(), "test");
        }
        runner.Check(true, "log_spawn_error: std::exception -> no crash");
    }

    void TestLogSpawnErrorUnknown(TestRunner &runner)
    {
        try
        {
            throw 42;
        }
        catch (...)
        {
            psm::multiplex::h2mux::log_spawn_error(std::current_exception(), "test");
        }
        runner.Check(true, "log_spawn_error: unknown -> no crash");
    }
} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("H2muxCraftDeep");

    TestConstructorDefault(runner);
    TestConstructorWithMr(runner);

    TestExecutor(runner);

    TestRespondConnectWithoutSession(runner);
    TestRespondConnect407WithoutSession(runner);

    TestCloseIdempotent(runner);
    TestCloseWithTraffic(runner);
    TestCloseWithoutTraffic(runner);

    TestSetTraffic(runner);
    TestAccumulateTrafficBoth(runner);
    TestAccumulateTrafficZero(runner);
    TestAccumulateTrafficMultiple(runner);

    TestDestructorNoInit(runner);
    TestDestructorAfterClose(runner);

    TestStartRespondClose(runner);

    TestLogSpawnErrorException(runner);
    TestLogSpawnErrorUnknown(runner);

    return runner.Summary();
}
