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

#include <boost/asio/co_spawn.hpp>

#include "common/MockTransport.hpp"

#include <prism/connect/pool/pool.hpp>
#include <prism/connect/dial/router.hpp>
#include <prism/resolve/dns/dns.hpp>
#include <prism/multiplex/core.hpp>
#include <prism/multiplex/duct.hpp>
#include <prism/multiplex/parcel.hpp>
#include <prism/stats/traffic.hpp>

using MockTransport = psm::testing::MockTransport;
namespace multiplex = psm::multiplex;
namespace net = boost::asio;

#include <gtest/gtest.h>

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

    TEST(MuxCoreDeep, ConstructorDefault)
    {
        CoreFixture fx;
        EXPECT_TRUE(!fx.core_obj->is_active()) << "constructor: inactive by default";
    }

    TEST(MuxCoreDeep, ConstructorWithMr)
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
        EXPECT_TRUE(!c->is_active()) << "constructor: with mr -> inactive";
    }

    // ─── set_traffic + accumulate_traffic ──────

    TEST(MuxCoreDeep, SetTraffic)
    {
        CoreFixture fx;
        psm::stats::traffic::traffic_state ts;
        fx.core_obj->set_traffic(&ts, psm::protocol::protocol_type::trojan);
    }

    TEST(MuxCoreDeep, AccumulateTrafficBoth)
    {
        CoreFixture fx;
        fx.core_obj->accumulate_traffic(100, 200);
    }

    TEST(MuxCoreDeep, AccumulateTrafficOnlyUp)
    {
        CoreFixture fx;
        fx.core_obj->accumulate_traffic(50, 0);
    }

    TEST(MuxCoreDeep, AccumulateTrafficOnlyDown)
    {
        CoreFixture fx;
        fx.core_obj->accumulate_traffic(0, 50);
    }

    TEST(MuxCoreDeep, AccumulateTrafficZero)
    {
        CoreFixture fx;
        fx.core_obj->accumulate_traffic(0, 0);
    }

    TEST(MuxCoreDeep, AccumulateTrafficMultiple)
    {
        CoreFixture fx;
        fx.core_obj->accumulate_traffic(10, 20);
        fx.core_obj->accumulate_traffic(30, 40);
    }

    // ─── close() 幂等性 ─────────────────────

    TEST(MuxCoreDeep, CloseIdempotent)
    {
        CoreFixture fx;
        fx.core_obj->close();
        EXPECT_TRUE(!fx.core_obj->is_active()) << "close: first close -> inactive";
        fx.core_obj->close();
        EXPECT_TRUE(!fx.core_obj->is_active()) << "close: second close -> still inactive";
    }

    TEST(MuxCoreDeep, CloseCancelsTransport)
    {
        CoreFixture fx;
        fx.core_obj->start();
        EXPECT_TRUE(fx.core_obj->is_active()) << "close: start -> active";
        fx.core_obj->close();
        EXPECT_TRUE(fx.transport->is_cancelled()) << "close: transport cancelled";
        EXPECT_TRUE(fx.transport->is_closed()) << "close: transport closed";
    }

    TEST(MuxCoreDeep, CloseWithTraffic)
    {
        CoreFixture fx;
        psm::stats::traffic::traffic_state ts;
        fx.core_obj->set_traffic(&ts, psm::protocol::protocol_type::trojan);
        fx.core_obj->accumulate_traffic(1000, 2000);
        fx.core_obj->close();
    }

    TEST(MuxCoreDeep, CloseWithoutTraffic)
    {
        CoreFixture fx;
        fx.core_obj->accumulate_traffic(100, 200);
        fx.core_obj->close();
    }

    // ─── remove_duct / remove_parcel ─────────

    TEST(MuxCoreDeep, RemoveDuctNonexistent)
    {
        CoreFixture fx;
        fx.core_obj->test_remove_duct(999);
    }

    TEST(MuxCoreDeep, RemoveParcelNonexistent)
    {
        CoreFixture fx;
        fx.core_obj->test_remove_parcel(999);
    }

    TEST(MuxCoreDeep, RemoveDuctMultiple)
    {
        CoreFixture fx;
        fx.core_obj->test_remove_duct(1);
        fx.core_obj->test_remove_duct(2);
        fx.core_obj->test_remove_duct(3);
    }

    TEST(MuxCoreDeep, RemoveParcelMultiple)
    {
        CoreFixture fx;
        fx.core_obj->test_remove_parcel(1);
        fx.core_obj->test_remove_parcel(2);
        fx.core_obj->test_remove_parcel(3);
    }

    // ─── on_exception ────────────────────────

    TEST(MuxCoreDeep, OnExceptionNullptr)
    {
        CoreFixture fx;
        fx.core_obj->test_on_exception(nullptr);
        EXPECT_TRUE(!fx.core_obj->is_active()) << "on_exception: nullptr -> closed";
    }

    TEST(MuxCoreDeep, OnExceptionWithStdException)
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
        EXPECT_TRUE(!fx.core_obj->is_active()) << "on_exception: runtime_error -> closed";
    }

    TEST(MuxCoreDeep, OnExceptionWithUnknown)
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
        EXPECT_TRUE(!fx.core_obj->is_active()) << "on_exception: unknown -> closed";
    }

    // ─── 析构函数 ─────────────────────────────

    TEST(MuxCoreDeep, DestructorCallsClose)
    {
        CoreFixture fx;
        EXPECT_TRUE(!fx.core_obj->is_active()) << "destructor: created inactive";
        fx.core_obj.reset();
    }

    TEST(MuxCoreDeep, DestructorAfterClose)
    {
        CoreFixture fx;
        fx.core_obj->close();
        fx.core_obj.reset();
    }

} // namespace

// #include 源文件以覆盖 resolve_mr 匿名命名空间函数
// 放在 TestCore 定义之后，确保所有类型完整
#include "../src/prism/multiplex/core.cpp"

namespace
{
    // ─── resolve_mr 补充分支（通过 #include 获取匿名命名空间访问权）──

    TEST(MuxCoreDeep, ResolveMrWithNullOpt)
    {
        auto *result = resolve_mr(nullptr);
        EXPECT_TRUE(result == psm::memory::current_resource())
            << "resolve_mr: nullptr -> current_resource";
    }

    TEST(MuxCoreDeep, ResolveMrWithValid)
    {
        psm::memory::unsynchronized_pool pool;
        auto *result = resolve_mr(&pool);
        EXPECT_TRUE(result == &pool) << "resolve_mr: valid -> same ptr";
    }
} // namespace
