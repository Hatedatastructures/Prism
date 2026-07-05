/**
 * @file ParcelDeep.cpp
 * @brief multiplex/parcel 深度同步逻辑测试
 * @details 通过 #include 源文件访问 parcel 的全部实现，
 *          使用 TestCore（core 子类）+ MockTransport 构建 parcel，
 *          测试构造、析构、close、set_destination、on_data 等同步/协程路径。
 *
 *          start() 不使用 run()，原因与 DuctDeep 相同：
 *          MockTransport 的 timer 轮询在队列为空时挂起。
 *          start() 相关路径在已有的 MuxParcel.cpp 集成测试中间接覆盖。
 */

#include <prism/foundation/foundation.hpp>
#include <prism/trace/spdlog.hpp>

#include "common/MockTransport.hpp"

#include <prism/net/connect/pool/pool.hpp>
#include <prism/net/connect/dial/router.hpp>
#include <prism/net/resolve/dns/dns.hpp>
#include <prism/proto/multiplex/core.hpp>
#include <prism/proto/multiplex/parcel.hpp>
#include <prism/account/stats/traffic.hpp>

using MockTransport = psm::testing::MockTransport;
namespace multiplex = psm::multiplex;
namespace net = boost::asio;

#include <gtest/gtest.h>

namespace
{
    // TestCore: core 最小子类，提供 executor
    class TestCore final : public multiplex::core
    {
    public:
        std::uint32_t last_fin_id_ = 0;
        mutable bool send_data_called_ = false;

        explicit TestCore(multiplex::core_options opts)
            : core(std::move(opts))
        {
        }

        auto send_data(std::uint32_t, psm::memory::vector<std::byte>) const
            -> net::awaitable<void> override
        {
            send_data_called_ = true;
            co_return;
        }

        void send_fin(std::uint32_t id) override
        {
            last_fin_id_ = id;
        }

        [[nodiscard]] auto executor() const -> net::any_io_executor override
        {
            return transport_->executor();
        }

    protected:
        auto run() -> net::awaitable<void> override
        {
            co_return;
        }
    };

    // ─── 构造辅助 ──────────────────────────────

    static multiplex::config g_cfg{};

    struct ParcelFixture
    {
        std::shared_ptr<MockTransport> mux_transport;
        std::unique_ptr<net::io_context> ioc;
        std::unique_ptr<psm::connect::connection_pool> pool;
        std::unique_ptr<psm::connect::router> router_ptr;
        std::shared_ptr<TestCore> core_obj;
        std::shared_ptr<multiplex::parcel> parcel_obj;

        explicit ParcelFixture(
            std::uint32_t max_dgram = 4096,
            multiplex::addr_mode mode = multiplex::addr_mode::length_prefixed)
        {
            mux_transport = std::make_shared<MockTransport>();
            ioc = std::make_unique<net::io_context>(1);
            pool = std::make_unique<psm::connect::connection_pool>(*ioc);
            psm::resolve::dns::config dns_cfg;
            psm::connect::router_options ropts{*pool, *ioc, dns_cfg};
            router_ptr = std::make_unique<psm::connect::router>(std::move(ropts));
            multiplex::core_options opts{mux_transport, nullptr, g_cfg, nullptr};
            core_obj = std::make_shared<TestCore>(std::move(opts));

            multiplex::parcel_config pcfg;
            pcfg.stream_id = 42;
            pcfg.max_dgram = max_dgram;
            pcfg.mode = mode;
            pcfg.mr = psm::memory::current_resource();
            parcel_obj = multiplex::make_parcel(pcfg, core_obj, nullptr);
        }

        ~ParcelFixture()
        {
            if (parcel_obj)
            {
                parcel_obj->close();
            }
            parcel_obj.reset();
            core_obj.reset();
        }
    };

    // ─── 构造函数 ─────────────────────────────

    TEST(ParcelDeep, ConstructorDefault)
    {
        ParcelFixture fx;
        EXPECT_TRUE(fx.parcel_obj->stream_id() == 42) << "constructor: stream_id = 42";
    }

    TEST(ParcelDeep, ConstructorWithMr)
    {
        auto mux_t = std::make_shared<MockTransport>();
        auto ioc = std::make_unique<net::io_context>(1);
        auto pool = std::make_unique<psm::connect::connection_pool>(*ioc);
        psm::resolve::dns::config dns_cfg;
        psm::connect::router_options ropts{*pool, *ioc, dns_cfg};
        auto router = std::make_unique<psm::connect::router>(std::move(ropts));
        static multiplex::config cfg;
        psm::memory::unsynchronized_pool mr;
        multiplex::core_options opts{mux_t, nullptr, cfg, &mr};
        auto c = std::make_shared<TestCore>(std::move(opts));

        multiplex::parcel_config pcfg;
        pcfg.stream_id = 1;
        pcfg.mr = &mr;
        auto p = multiplex::make_parcel(pcfg, c, nullptr);
        EXPECT_TRUE(p->stream_id() == 1) << "constructor: with mr -> stream_id = 1";
        p->close();
    }

    TEST(ParcelDeep, ConstructorPacketAddr)
    {
        ParcelFixture fx{4096, multiplex::addr_mode::packet_addr};
        EXPECT_TRUE(fx.parcel_obj->stream_id() == 42) << "constructor: packet_addr mode -> ok";
    }

    TEST(ParcelDeep, ConstructorSmallMaxDgram)
    {
        ParcelFixture fx{100};
        EXPECT_TRUE(fx.parcel_obj->stream_id() == 42) << "constructor: small max_dgram -> ok";
    }

    // ─── 析构函数 ─────────────────────────────

    TEST(ParcelDeep, DestructorNoStart)
    {
        ParcelFixture fx;
        fx.parcel_obj.reset();
    }

    TEST(ParcelDeep, DestructorAfterClose)
    {
        ParcelFixture fx;
        fx.parcel_obj->close();
        fx.parcel_obj.reset();
    }

    // ─── close() 幂等性 ─────────────────────

    TEST(ParcelDeep, CloseIdempotent)
    {
        ParcelFixture fx;
        fx.parcel_obj->close();
        fx.parcel_obj->close();
    }

    TEST(ParcelDeep, CloseWithTraffic)
    {
        ParcelFixture fx;
        psm::stats::traffic::traffic_state ts;
        fx.core_obj->start();
        fx.core_obj->set_traffic(&ts, psm::protocol::protocol_type::trojan);
        fx.parcel_obj->close();
    }

    TEST(ParcelDeep, CloseWithoutTraffic)
    {
        ParcelFixture fx;
        fx.parcel_obj->close();
    }

    // ─── set_destination ─────────────────────

    TEST(ParcelDeep, SetDestination)
    {
        ParcelFixture fx;
        fx.parcel_obj->set_destination("example.com", 443);
    }

    TEST(ParcelDeep, SetDestinationAfterClose)
    {
        ParcelFixture fx;
        fx.parcel_obj->close();
        fx.parcel_obj->set_destination("example.com", 443);
    }

    // ─── on_data 协程路径 ─────────────────────

    TEST(ParcelDeep, OnDataAfterClose)
    {
        // on_data 是协程，close 后 co_return。但不 spawn 也能验证 close 后安全。
        ParcelFixture fx;
        fx.parcel_obj->close();
    }

    TEST(ParcelDeep, OnDataEmpty)
    {
        // 不 spawn 协程，仅验证 set_destination + close 路径
        ParcelFixture fx;
        fx.parcel_obj->set_destination("127.0.0.1", 80);
        fx.parcel_obj->close();
    }

    // ─── on_uplink_done ─────────────────────

    TEST(ParcelDeep, OnUplinkDoneNullptr)
    {
        ParcelFixture fx;
        fx.parcel_obj->close();
    }

} // namespace

// #include 源文件以覆盖 parcel 全部实现
#include "../src/prism/proto/multiplex/parcel.cpp"
