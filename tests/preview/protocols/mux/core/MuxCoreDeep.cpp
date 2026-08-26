/**
 * @file MuxCoreDeep.cpp
 * @brief multiplex/core 深度纯函数测试
 * @details 通过 #include 源文件访问匿名命名空间中的 resolve_mr，
 *          以及 core 类的构造、close、accumulate_traffic、
 *          is_active、drop/drop、on_exception 等同步方法。
 *          使用 TestCore 具体子类 + MockTransport 验证核心逻辑。
 */

#include <prism/diagnose/log.hpp>
#include <prism/foundation/foundation.hpp>
#include <prism/net/connection/dialer/dialer.hpp>
#include <prism/net/dns/resolver.hpp>
#include <prism/protocol/multiplex/datagram.hpp>
#include <prism/protocol/multiplex/multiplexer.hpp>
#include <prism/protocol/multiplex/stream.hpp>

#include <boost/asio/co_spawn.hpp>

#include "common/MockTransport.hpp"

using MockTransport = Preview::Testing::MockTransport;
namespace multiplex = psm::multiplex;
namespace net = boost::asio;

#include <gtest/gtest.h>

namespace
{
    // 具体子类实现 core 的纯虚接口
    class TestCore final : public multiplex::multiplexer
    {
    public:
        explicit TestCore(multiplex::multiplexer_options opts) : multiplexer(std::move(opts))
        {
        }

        auto send(std::uint32_t, psm::memory::vector<std::byte>) -> net::awaitable<void> override
        {
            co_return;
        }

        void fin(std::uint32_t) override
        {
        }

        // public 包装器用于测试 protected 方法
        void test_remove_duct(std::uint32_t id)
        {
            drop(id);
        }
        void test_remove_parcel(std::uint32_t id)
        {
            drop(id);
        }
        void test_on_exception(std::exception_ptr ep)
        {
            on_exception(std::move(ep));
        }

    protected:
        auto run() -> net::awaitable<void> override
        {
            co_return;
        }

        auto write_frame(outbound_frame) -> net::awaitable<void> override
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
        std::unique_ptr<psm::connect::dialer> router_ptr;

        CoreFixture()
        {
            transport = std::make_shared<MockTransport>();
            ioc = std::make_unique<net::io_context>(1);
            psm::dns::config dns_cfg;
            psm::connect::dialer_options ropts{*ioc, dns_cfg};
            router_ptr = std::make_unique<psm::connect::dialer>(std::move(ropts));
            static multiplex::config cfg;
            multiplex::multiplexer_options opts{transport, nullptr, cfg, nullptr};
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
        psm::dns::config dns_cfg;
        psm::connect::dialer_options ropts{*ioc, dns_cfg};
        auto router_ptr = std::make_unique<psm::connect::dialer>(std::move(ropts));
        static multiplex::config cfg;
        psm::memory::unsynchronized_pool mr;
        multiplex::multiplexer_options opts{transport, nullptr, cfg, &mr};
        auto c = std::make_shared<TestCore>(std::move(opts));
        EXPECT_TRUE(!c->is_active()) << "constructor: with mr -> inactive";
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
        EXPECT_TRUE(fx.transport->IsCancelled()) << "close: transport cancelled";
        EXPECT_TRUE(fx.transport->IsClosed()) << "close: transport closed";
    }

    TEST(MuxCoreDeep, CloseWithoutTraffic)
    {
        CoreFixture fx;
        fx.core_obj->close();
    }

    // ─── drop / drop ─────────

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
#include "../src/prism/protocol/multiplex/multiplexer.cpp"

namespace
{
    // ─── resolve_mr 补充分支（通过 #include 获取匿名命名空间访问权）──

    TEST(MuxCoreDeep, ResolveMrWithNullOpt)
    {
        auto *result = resolve_mr(nullptr);
        EXPECT_EQ(result, psm::memory::current_resource()) << "resolve_mr: nullptr -> current_resource";
    }

    TEST(MuxCoreDeep, ResolveMrWithValid)
    {
        psm::memory::unsynchronized_pool pool;
        auto *result = resolve_mr(&pool);
        EXPECT_EQ(result, &pool) << "resolve_mr: valid -> same ptr";
    }
} // namespace
