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

#include <boost/asio/co_spawn.hpp>

#include "common/MockTransport.hpp"

#include <prism/connect/pool/pool.hpp>
#include <prism/connect/dial/router.hpp>
#include <prism/resolve/dns/dns.hpp>
#include <prism/multiplex/yamux/craft.hpp>
#include <prism/stats/traffic.hpp>

using MockTransport = psm::testing::MockTransport;
namespace multiplex = psm::multiplex;
namespace yamux = psm::multiplex::yamux;
namespace net = boost::asio;

#include <gtest/gtest.h>

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

    TEST(YamuxCraftDeep, ConstructorDefault)
    {
        CraftFixture fx;
        EXPECT_TRUE(!fx.craft_obj->is_active()) << "constructor: inactive by default";
    }

    TEST(YamuxCraftDeep, ConstructorWithMr)
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
        EXPECT_TRUE(!c->is_active()) << "constructor: with mr -> inactive";
    }

    // ─── executor ─────────────────────────────

    TEST(YamuxCraftDeep, Executor)
    {
        CraftFixture fx;
        auto ex = fx.craft_obj->executor();
        EXPECT_TRUE(!!ex) << "executor: non-empty";
    }

    // ─── close() 幂等性 ─────────────────────

    TEST(YamuxCraftDeep, CloseIdempotent)
    {
        CraftFixture fx;
        fx.craft_obj->close();
        EXPECT_TRUE(!fx.craft_obj->is_active()) << "close: first close -> inactive";
        fx.craft_obj->close();
        EXPECT_TRUE(!fx.craft_obj->is_active()) << "close: second close -> still inactive";
    }

    TEST(YamuxCraftDeep, CloseInactive)
    {
        CraftFixture fx;
        fx.craft_obj->close();
        EXPECT_TRUE(!fx.craft_obj->is_active()) << "close: inactive close -> still inactive";
    }

    TEST(YamuxCraftDeep, CloseCancelsTransport)
    {
        CraftFixture fx;
        fx.craft_obj->start();
        EXPECT_TRUE(fx.craft_obj->is_active()) << "close: start -> active";
        fx.craft_obj->close();
        EXPECT_TRUE(fx.transport->is_cancelled()) << "close: transport cancelled";
        EXPECT_TRUE(fx.transport->is_closed()) << "close: transport closed";
    }

    TEST(YamuxCraftDeep, CloseWithTraffic)
    {
        CraftFixture fx;
        psm::stats::traffic::traffic_state ts;
        fx.craft_obj->set_traffic(&ts, psm::protocol::protocol_type::trojan);
        fx.craft_obj->accumulate_traffic(1000, 2000);
        fx.craft_obj->close();
    }

    TEST(YamuxCraftDeep, CloseWithoutTraffic)
    {
        CraftFixture fx;
        fx.craft_obj->accumulate_traffic(100, 200);
        fx.craft_obj->close();
    }

    // ─── remove_duct / remove_parcel ─────────

    TEST(YamuxCraftDeep, RemoveDuctNonexistent)
    {
        CraftFixture fx;
        fx.craft_obj->remove_duct(999);
    }

    TEST(YamuxCraftDeep, RemoveParcelNonexistent)
    {
        CraftFixture fx;
        fx.craft_obj->remove_parcel(999);
    }

    TEST(YamuxCraftDeep, RemoveDuctMultiple)
    {
        CraftFixture fx;
        fx.craft_obj->remove_duct(1);
        fx.craft_obj->remove_duct(2);
        fx.craft_obj->remove_duct(3);
    }

    TEST(YamuxCraftDeep, RemoveParcelMultiple)
    {
        CraftFixture fx;
        fx.craft_obj->remove_parcel(1);
        fx.craft_obj->remove_parcel(2);
        fx.craft_obj->remove_parcel(3);
    }

    TEST(YamuxCraftDeep, RemoveDuctAfterClose)
    {
        CraftFixture fx;
        fx.craft_obj->close();
        fx.craft_obj->remove_duct(42);
    }

    TEST(YamuxCraftDeep, RemoveParcelAfterClose)
    {
        CraftFixture fx;
        fx.craft_obj->close();
        fx.craft_obj->remove_parcel(42);
    }

    // ─── set_traffic + accumulate_traffic ──────

    TEST(YamuxCraftDeep, SetTraffic)
    {
        CraftFixture fx;
        psm::stats::traffic::traffic_state ts;
        fx.craft_obj->set_traffic(&ts, psm::protocol::protocol_type::trojan);
    }

    TEST(YamuxCraftDeep, AccumulateTrafficBoth)
    {
        CraftFixture fx;
        fx.craft_obj->accumulate_traffic(100, 200);
    }

    TEST(YamuxCraftDeep, AccumulateTrafficZero)
    {
        CraftFixture fx;
        fx.craft_obj->accumulate_traffic(0, 0);
    }

    TEST(YamuxCraftDeep, AccumulateTrafficMultiple)
    {
        CraftFixture fx;
        fx.craft_obj->accumulate_traffic(10, 20);
        fx.craft_obj->accumulate_traffic(30, 40);
    }

    // ─── 析构函数 ─────────────────────────────

    TEST(YamuxCraftDeep, DestructorCallsClose)
    {
        CraftFixture fx;
        EXPECT_TRUE(!fx.craft_obj->is_active()) << "destructor: created inactive";
        fx.craft_obj.reset();
    }

    TEST(YamuxCraftDeep, DestructorAfterClose)
    {
        CraftFixture fx;
        fx.craft_obj->close();
        fx.craft_obj.reset();
    }

    // ─── send_fin（同步调用，协程由 co_spawn 调度） ──

    TEST(YamuxCraftDeep, SendFinNoCrash)
    {
        CraftFixture fx;
        fx.craft_obj->send_fin(42);
    }

    TEST(YamuxCraftDeep, SendFinAfterClose)
    {
        CraftFixture fx;
        fx.craft_obj->close();
        fx.craft_obj->send_fin(1);
    }

    TEST(YamuxCraftDeep, SendFinMultipleStreams)
    {
        CraftFixture fx;
        fx.craft_obj->send_fin(1);
        fx.craft_obj->send_fin(2);
        fx.craft_obj->send_fin(3);
    }

} // namespace

// #include 源文件以覆盖 log_spawn_error 匿名命名空间函数
#include "../src/prism/multiplex/yamux/craft.cpp"

namespace
{
    // ─── log_spawn_error（通过 #include 获取匿名命名空间访问权）──

    TEST(YamuxCraftDeep, LogSpawnErrorException)
    {
        try
        {
            throw std::runtime_error("test yamux error");
        }
        catch (...)
        {
            psm::multiplex::yamux::log_spawn_error(std::current_exception(), 1, "test");
        }
    }

    TEST(YamuxCraftDeep, LogSpawnErrorUnknown)
    {
        try
        {
            throw 42;
        }
        catch (...)
        {
            psm::multiplex::yamux::log_spawn_error(std::current_exception(), 2, "test");
        }
    }
} // namespace
