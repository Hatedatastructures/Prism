/**
 * @file YamuxCraftDeep.cpp
 * @brief multiplex/yamux/craft 深度同步逻辑测试
 * @details 通过 #include 源文件访问匿名命名空间中的 log_spawn_error，
 *          以及 craft 类的构造、close、drop/drop、
 *          executor、fin 等同步方法。
 *          直接构造 craft（final 类）对象验证核心逻辑。
 */

#include <prism/diagnose/log.hpp>
#include <prism/foundation/foundation.hpp>
#include <prism/net/connection/dialer/dialer.hpp>
#include <prism/net/dns/resolver.hpp>
#include <prism/protocol/multiplex/yamux/control.hpp>

#include <boost/asio/co_spawn.hpp>

#include "common/MockTransport.hpp"

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
        std::unique_ptr<psm::connect::dialer> router_ptr;
        std::shared_ptr<yamux::control> craft_obj;
        static multiplex::config cfg;

        CraftFixture()
        {
            transport = std::make_shared<MockTransport>();
            ioc = std::make_unique<net::io_context>(1);
            psm::dns::config dns_cfg;
            psm::connect::dialer_options ropts{*ioc, dns_cfg};
            router_ptr = std::make_unique<psm::connect::dialer>(std::move(ropts));
            multiplex::multiplexer_options opts{transport, nullptr, cfg, nullptr};
            craft_obj = std::make_shared<yamux::control>(std::move(opts));
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
        psm::dns::config dns_cfg;
        psm::connect::dialer_options ropts{*ioc, dns_cfg};
        auto router_ptr = std::make_unique<psm::connect::dialer>(std::move(ropts));
        static multiplex::config cfg;
        psm::memory::unsynchronized_pool mr;
        multiplex::multiplexer_options opts{transport, nullptr, cfg, &mr};
        auto c = std::make_shared<yamux::control>(std::move(opts));
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
        EXPECT_TRUE(fx.transport->IsCancelled()) << "close: transport cancelled";
        EXPECT_TRUE(fx.transport->IsClosed()) << "close: transport closed";
    }

    // ─── drop / drop ─────────

    TEST(YamuxCraftDeep, RemoveDuctNonexistent)
    {
        CraftFixture fx;
        fx.craft_obj->drop(999);
    }

    TEST(YamuxCraftDeep, RemoveParcelNonexistent)
    {
        CraftFixture fx;
        fx.craft_obj->drop(999);
    }

    TEST(YamuxCraftDeep, RemoveDuctMultiple)
    {
        CraftFixture fx;
        fx.craft_obj->drop(1);
        fx.craft_obj->drop(2);
        fx.craft_obj->drop(3);
    }

    TEST(YamuxCraftDeep, RemoveParcelMultiple)
    {
        CraftFixture fx;
        fx.craft_obj->drop(1);
        fx.craft_obj->drop(2);
        fx.craft_obj->drop(3);
    }

    TEST(YamuxCraftDeep, RemoveDuctAfterClose)
    {
        CraftFixture fx;
        fx.craft_obj->close();
        fx.craft_obj->drop(42);
    }

    TEST(YamuxCraftDeep, RemoveParcelAfterClose)
    {
        CraftFixture fx;
        fx.craft_obj->close();
        fx.craft_obj->drop(42);
    }

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

    // ─── fin（同步调用，协程由 co_spawn 调度） ──

    TEST(YamuxCraftDeep, SendFinNoCrash)
    {
        CraftFixture fx;
        fx.craft_obj->fin(42);
    }

    TEST(YamuxCraftDeep, SendFinAfterClose)
    {
        CraftFixture fx;
        fx.craft_obj->close();
        fx.craft_obj->fin(1);
    }

    TEST(YamuxCraftDeep, SendFinMultipleStreams)
    {
        CraftFixture fx;
        fx.craft_obj->fin(1);
        fx.craft_obj->fin(2);
        fx.craft_obj->fin(3);
    }

} // namespace

// #include 源文件以覆盖 log_spawn_error 匿名命名空间函数
#include "../src/prism/protocol/multiplex/yamux/control.cpp"

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
            psm::multiplex::yamux::log_spawn_error(std::current_exception(), 1, "test", nullptr);
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
            psm::multiplex::yamux::log_spawn_error(std::current_exception(), 2, "test", nullptr);
        }
    }
} // namespace
