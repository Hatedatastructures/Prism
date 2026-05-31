/**
 * @file YamuxCraftDeep.cpp
 * @brief multiplex/yamux/craft 深度同步逻辑测试
 * @details 通过 #include 源文件访问匿名命名空间中的 log_spawn_error，
 *          以及 craft 类的构造、close、remove_duct/remove_parcel、
 *          executor、send_fin 等同步方法。
 *          直接构造 craft（final 类）对象验证核心逻辑。
 */

#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include <boost/asio/co_spawn.hpp>

#include "common/TestRunner.hpp"
#include "common/MockTransport.hpp"

#include <prism/connect/pool/pool.hpp>
#include <prism/connect/dial/router.hpp>
#include <prism/resolve/dns/dns.hpp>
#include <prism/multiplex/yamux/craft.hpp>
#include <prism/stats/traffic.hpp>

using psm::testing::TestRunner;
using MockTransport = psm::testing::MockTransport;
namespace multiplex = psm::multiplex;
namespace yamux = psm::multiplex::yamux;
namespace net = boost::asio;

namespace
{
    // ─── 构造辅助 ──────────────────────────────

    struct CraftFixture
    {
        std::shared_ptr<MockTransport> transport;
        std::unique_ptr<net::io_context> ioc;
        std::unique_ptr<psm::connect::connection_pool> pool;
        std::unique_ptr<psm::connect::router> router_ptr;
        std::shared_ptr<yamux::craft> craft_obj;
        static multiplex::config cfg;

        CraftFixture()
        {
            transport = std::make_shared<MockTransport>();
            ioc = std::make_unique<net::io_context>(1);
            pool = std::make_unique<psm::connect::connection_pool>(*ioc);
            psm::resolve::dns::config dns_cfg;
            psm::connect::router_options ropts{*pool, *ioc, dns_cfg};
            router_ptr = std::make_unique<psm::connect::router>(std::move(ropts));
            multiplex::core_options opts{transport, *router_ptr, cfg, nullptr};
            craft_obj = std::make_shared<yamux::craft>(std::move(opts));
        }
    };

    multiplex::config CraftFixture::cfg{};

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
        static multiplex::config cfg;
        psm::memory::unsynchronized_pool mr;
        multiplex::core_options opts{transport, *router_ptr, cfg, &mr};
        auto c = std::make_shared<yamux::craft>(std::move(opts));
        runner.Check(!c->is_active(), "constructor: with mr -> inactive");
    }

    // ─── executor ─────────────────────────────

    void TestExecutor(TestRunner &runner)
    {
        CraftFixture fx;
        auto ex = fx.craft_obj->executor();
        runner.Check(!!ex, "executor: non-empty");
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

    void TestCloseInactive(TestRunner &runner)
    {
        CraftFixture fx;
        fx.craft_obj->close();
        runner.Check(!fx.craft_obj->is_active(), "close: inactive close -> still inactive");
    }

    void TestCloseCancelsTransport(TestRunner &runner)
    {
        CraftFixture fx;
        fx.craft_obj->start();
        runner.Check(fx.craft_obj->is_active(), "close: start -> active");
        fx.craft_obj->close();
        runner.Check(fx.transport->is_cancelled(), "close: transport cancelled");
        runner.Check(fx.transport->is_closed(), "close: transport closed");
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

    // ─── remove_duct / remove_parcel ─────────

    void TestRemoveDuctNonexistent(TestRunner &runner)
    {
        CraftFixture fx;
        fx.craft_obj->remove_duct(999);
        runner.Check(true, "remove_duct: nonexistent -> no crash");
    }

    void TestRemoveParcelNonexistent(TestRunner &runner)
    {
        CraftFixture fx;
        fx.craft_obj->remove_parcel(999);
        runner.Check(true, "remove_parcel: nonexistent -> no crash");
    }

    void TestRemoveDuctMultiple(TestRunner &runner)
    {
        CraftFixture fx;
        fx.craft_obj->remove_duct(1);
        fx.craft_obj->remove_duct(2);
        fx.craft_obj->remove_duct(3);
        runner.Check(true, "remove_duct: multiple calls -> no crash");
    }

    void TestRemoveParcelMultiple(TestRunner &runner)
    {
        CraftFixture fx;
        fx.craft_obj->remove_parcel(1);
        fx.craft_obj->remove_parcel(2);
        fx.craft_obj->remove_parcel(3);
        runner.Check(true, "remove_parcel: multiple calls -> no crash");
    }

    void TestRemoveDuctAfterClose(TestRunner &runner)
    {
        CraftFixture fx;
        fx.craft_obj->close();
        fx.craft_obj->remove_duct(42);
        runner.Check(true, "remove_duct: after close -> no crash");
    }

    void TestRemoveParcelAfterClose(TestRunner &runner)
    {
        CraftFixture fx;
        fx.craft_obj->close();
        fx.craft_obj->remove_parcel(42);
        runner.Check(true, "remove_parcel: after close -> no crash");
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
        runner.Check(true, "accumulate: multiple calls -> no crash");
    }

    // ─── 析构函数 ─────────────────────────────

    void TestDestructorCallsClose(TestRunner &runner)
    {
        CraftFixture fx;
        runner.Check(!fx.craft_obj->is_active(), "destructor: created inactive");
        fx.craft_obj.reset();
        runner.Check(true, "destructor: reset -> no crash");
    }

    void TestDestructorAfterClose(TestRunner &runner)
    {
        CraftFixture fx;
        fx.craft_obj->close();
        fx.craft_obj.reset();
        runner.Check(true, "destructor: after close -> no crash");
    }

    // ─── send_fin（同步调用，协程由 co_spawn 调度） ──

    void TestSendFinNoCrash(TestRunner &runner)
    {
        CraftFixture fx;
        fx.craft_obj->send_fin(42);
        runner.Check(true, "send_fin: no crash (co_spawn dispatched)");
    }

    void TestSendFinAfterClose(TestRunner &runner)
    {
        CraftFixture fx;
        fx.craft_obj->close();
        fx.craft_obj->send_fin(1);
        runner.Check(true, "send_fin: after close -> no crash");
    }

    void TestSendFinMultipleStreams(TestRunner &runner)
    {
        CraftFixture fx;
        fx.craft_obj->send_fin(1);
        fx.craft_obj->send_fin(2);
        fx.craft_obj->send_fin(3);
        runner.Check(true, "send_fin: multiple streams -> no crash");
    }

} // namespace

// #include 源文件以覆盖 log_spawn_error 匿名命名空间函数
#include "../src/prism/multiplex/yamux/craft.cpp"

namespace
{
    // ─── log_spawn_error（通过 #include 获取匿名命名空间访问权）──

    void TestLogSpawnErrorException(TestRunner &runner)
    {
        try
        {
            throw std::runtime_error("test yamux error");
        }
        catch (...)
        {
            psm::multiplex::yamux::log_spawn_error(std::current_exception(), 1, "test");
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
            psm::multiplex::yamux::log_spawn_error(std::current_exception(), 2, "test");
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

    TestRunner runner("YamuxCraftDeep");

    TestConstructorDefault(runner);
    TestConstructorWithMr(runner);

    TestExecutor(runner);

    TestCloseIdempotent(runner);
    TestCloseInactive(runner);
    TestCloseCancelsTransport(runner);
    TestCloseWithTraffic(runner);
    TestCloseWithoutTraffic(runner);

    TestRemoveDuctNonexistent(runner);
    TestRemoveParcelNonexistent(runner);
    TestRemoveDuctMultiple(runner);
    TestRemoveParcelMultiple(runner);
    TestRemoveDuctAfterClose(runner);
    TestRemoveParcelAfterClose(runner);

    TestSetTraffic(runner);
    TestAccumulateTrafficBoth(runner);
    TestAccumulateTrafficZero(runner);
    TestAccumulateTrafficMultiple(runner);

    TestDestructorCallsClose(runner);
    TestDestructorAfterClose(runner);

    TestSendFinNoCrash(runner);
    TestSendFinAfterClose(runner);
    TestSendFinMultipleStreams(runner);

    TestLogSpawnErrorException(runner);
    TestLogSpawnErrorUnknown(runner);

    return runner.Summary();
}
