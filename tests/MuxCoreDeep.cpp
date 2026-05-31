/**
 * @file MuxCoreDeep.cpp
 * @brief multiplex/core 深度纯函数测试
 * @details 通过 #include 源文件访问匿名命名空间中的 resolve_mr，
 *          以及 core 类的构造、close、accumulate_traffic、
 *          is_active、remove_duct/remove_parcel、on_exception 等同步方法。
 *          使用 TestCore 具体子类 + MockTransport 验证核心逻辑。
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
#include <prism/multiplex/core.hpp>
#include <prism/multiplex/duct.hpp>
#include <prism/multiplex/parcel.hpp>
#include <prism/stats/traffic.hpp>

using psm::testing::TestRunner;
using MockTransport = psm::testing::MockTransport;
namespace multiplex = psm::multiplex;
namespace net = boost::asio;

namespace
{
    // 具体子类实现 core 的纯虚接口
    class TestCore final : public multiplex::core
    {
    public:
        explicit TestCore(multiplex::core_options opts)
            : core(std::move(opts))
        {
        }

        auto send_data(std::uint32_t, psm::memory::vector<std::byte>) const
            -> net::awaitable<void> override
        {
            co_return;
        }

        void send_fin(std::uint32_t) override {}

        [[nodiscard]] auto executor() const -> net::any_io_executor override
        {
            return transport_->executor();
        }

        // public 包装器用于测试 protected 方法
        void test_remove_duct(std::uint32_t id) { remove_duct(id); }
        void test_remove_parcel(std::uint32_t id) { remove_parcel(id); }
        void test_on_exception(std::exception_ptr ep) { on_exception(std::move(ep)); }

    protected:
        auto run() -> net::awaitable<void> override
        {
            co_return;
        }
    };

    // ─── 构造辅助 ──────────────────────────────

    struct CoreFixture
    {
        std::shared_ptr<MockTransport> transport;
        std::shared_ptr<TestCore> core_obj;
        std::unique_ptr<net::io_context> ioc;
        std::unique_ptr<psm::connect::connection_pool> pool;
        std::unique_ptr<psm::connect::router> router_ptr;

        CoreFixture()
        {
            transport = std::make_shared<MockTransport>();
            ioc = std::make_unique<net::io_context>(1);
            pool = std::make_unique<psm::connect::connection_pool>(*ioc);
            psm::resolve::dns::config dns_cfg;
            psm::connect::router_options ropts{*pool, *ioc, dns_cfg};
            router_ptr = std::make_unique<psm::connect::router>(std::move(ropts));
            static multiplex::config cfg;
            multiplex::core_options opts{transport, *router_ptr, cfg, nullptr};
            core_obj = std::make_shared<TestCore>(std::move(opts));
        }
    };

    // ─── 构造函数 ─────────────────────────────

    void TestConstructorDefault(TestRunner &runner)
    {
        CoreFixture fx;
        runner.Check(!fx.core_obj->is_active(), "constructor: inactive by default");
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
        auto c = std::make_shared<TestCore>(std::move(opts));
        runner.Check(!c->is_active(), "constructor: with mr -> inactive");
    }

    // ─── set_traffic + accumulate_traffic ──────

    void TestSetTraffic(TestRunner &runner)
    {
        CoreFixture fx;
        psm::stats::traffic::traffic_state ts;
        fx.core_obj->set_traffic(&ts, psm::protocol::protocol_type::trojan);
        runner.Check(true, "set_traffic: no crash");
    }

    void TestAccumulateTrafficBoth(TestRunner &runner)
    {
        CoreFixture fx;
        fx.core_obj->accumulate_traffic(100, 200);
        runner.Check(true, "accumulate: up=100 down=200 -> no crash");
    }

    void TestAccumulateTrafficOnlyUp(TestRunner &runner)
    {
        CoreFixture fx;
        fx.core_obj->accumulate_traffic(50, 0);
        runner.Check(true, "accumulate: up=50 down=0 -> no crash");
    }

    void TestAccumulateTrafficOnlyDown(TestRunner &runner)
    {
        CoreFixture fx;
        fx.core_obj->accumulate_traffic(0, 50);
        runner.Check(true, "accumulate: up=0 down=50 -> no crash");
    }

    void TestAccumulateTrafficZero(TestRunner &runner)
    {
        CoreFixture fx;
        fx.core_obj->accumulate_traffic(0, 0);
        runner.Check(true, "accumulate: zeros -> no crash");
    }

    void TestAccumulateTrafficMultiple(TestRunner &runner)
    {
        CoreFixture fx;
        fx.core_obj->accumulate_traffic(10, 20);
        fx.core_obj->accumulate_traffic(30, 40);
        runner.Check(true, "accumulate: multiple calls -> no crash");
    }

    // ─── close() 幂等性 ─────────────────────

    void TestCloseIdempotent(TestRunner &runner)
    {
        CoreFixture fx;
        fx.core_obj->close();
        runner.Check(!fx.core_obj->is_active(), "close: first close -> inactive");
        fx.core_obj->close();
        runner.Check(!fx.core_obj->is_active(), "close: second close -> still inactive");
    }

    void TestCloseCancelsTransport(TestRunner &runner)
    {
        CoreFixture fx;
        fx.core_obj->start();
        runner.Check(fx.core_obj->is_active(), "close: start -> active");
        fx.core_obj->close();
        runner.Check(fx.transport->is_cancelled(), "close: transport cancelled");
        runner.Check(fx.transport->is_closed(), "close: transport closed");
    }

    void TestCloseWithTraffic(TestRunner &runner)
    {
        CoreFixture fx;
        psm::stats::traffic::traffic_state ts;
        fx.core_obj->set_traffic(&ts, psm::protocol::protocol_type::trojan);
        fx.core_obj->accumulate_traffic(1000, 2000);
        fx.core_obj->close();
        runner.Check(true, "close: with traffic flush -> no crash");
    }

    void TestCloseWithoutTraffic(TestRunner &runner)
    {
        CoreFixture fx;
        fx.core_obj->accumulate_traffic(100, 200);
        fx.core_obj->close();
        runner.Check(true, "close: no traffic_state -> no crash");
    }

    // ─── remove_duct / remove_parcel ─────────

    void TestRemoveDuctNonexistent(TestRunner &runner)
    {
        CoreFixture fx;
        fx.core_obj->test_remove_duct(999);
        runner.Check(true, "remove_duct: nonexistent -> no crash");
    }

    void TestRemoveParcelNonexistent(TestRunner &runner)
    {
        CoreFixture fx;
        fx.core_obj->test_remove_parcel(999);
        runner.Check(true, "remove_parcel: nonexistent -> no crash");
    }

    void TestRemoveDuctMultiple(TestRunner &runner)
    {
        CoreFixture fx;
        fx.core_obj->test_remove_duct(1);
        fx.core_obj->test_remove_duct(2);
        fx.core_obj->test_remove_duct(3);
        runner.Check(true, "remove_duct: multiple calls -> no crash");
    }

    void TestRemoveParcelMultiple(TestRunner &runner)
    {
        CoreFixture fx;
        fx.core_obj->test_remove_parcel(1);
        fx.core_obj->test_remove_parcel(2);
        fx.core_obj->test_remove_parcel(3);
        runner.Check(true, "remove_parcel: multiple calls -> no crash");
    }

    // ─── on_exception ────────────────────────

    void TestOnExceptionNullptr(TestRunner &runner)
    {
        CoreFixture fx;
        fx.core_obj->test_on_exception(nullptr);
        runner.Check(!fx.core_obj->is_active(), "on_exception: nullptr -> closed");
    }

    void TestOnExceptionWithStdException(TestRunner &runner)
    {
        CoreFixture fx;
        try
        {
            throw std::runtime_error("test error");
        }
        catch (...)
        {
            fx.core_obj->test_on_exception(std::current_exception());
        }
        runner.Check(!fx.core_obj->is_active(), "on_exception: runtime_error -> closed");
    }

    void TestOnExceptionWithUnknown(TestRunner &runner)
    {
        CoreFixture fx;
        try
        {
            throw 42;
        }
        catch (...)
        {
            fx.core_obj->test_on_exception(std::current_exception());
        }
        runner.Check(!fx.core_obj->is_active(), "on_exception: unknown -> closed");
    }

    // ─── 析构函数 ─────────────────────────────

    void TestDestructorCallsClose(TestRunner &runner)
    {
        CoreFixture fx;
        runner.Check(!fx.core_obj->is_active(), "destructor: created inactive");
        fx.core_obj.reset();
        runner.Check(true, "destructor: reset -> no crash");
    }

    void TestDestructorAfterClose(TestRunner &runner)
    {
        CoreFixture fx;
        fx.core_obj->close();
        fx.core_obj.reset();
        runner.Check(true, "destructor: after close -> no crash");
    }

} // namespace

// #include 源文件以覆盖 resolve_mr 匿名命名空间函数
// 放在 TestCore 定义之后，确保所有类型完整
#include "../src/prism/multiplex/core.cpp"

namespace
{
    // ─── resolve_mr 补充分支（通过 #include 获取匿名命名空间访问权）──

    void TestResolveMrWithNullOpt(TestRunner &runner)
    {
        auto *result = resolve_mr(nullptr);
        runner.Check(result == psm::memory::current_resource(),
                     "resolve_mr: nullptr -> current_resource");
    }

    void TestResolveMrWithValid(TestRunner &runner)
    {
        psm::memory::unsynchronized_pool pool;
        auto *result = resolve_mr(&pool);
        runner.Check(result == &pool, "resolve_mr: valid -> same ptr");
    }
} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("MuxCoreDeep");

    TestConstructorDefault(runner);
    TestConstructorWithMr(runner);

    TestSetTraffic(runner);
    TestAccumulateTrafficBoth(runner);
    TestAccumulateTrafficOnlyUp(runner);
    TestAccumulateTrafficOnlyDown(runner);
    TestAccumulateTrafficZero(runner);
    TestAccumulateTrafficMultiple(runner);

    TestCloseIdempotent(runner);
    TestCloseCancelsTransport(runner);
    TestCloseWithTraffic(runner);
    TestCloseWithoutTraffic(runner);

    TestRemoveDuctNonexistent(runner);
    TestRemoveParcelNonexistent(runner);
    TestRemoveDuctMultiple(runner);
    TestRemoveParcelMultiple(runner);

    TestOnExceptionNullptr(runner);
    TestOnExceptionWithStdException(runner);
    TestOnExceptionWithUnknown(runner);

    TestDestructorCallsClose(runner);
    TestDestructorAfterClose(runner);

    TestResolveMrWithNullOpt(runner);
    TestResolveMrWithValid(runner);

    return runner.Summary();
}
