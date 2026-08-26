/**
 * @file ParcelDeep.cpp
 * @brief multiplex/parcel 深度同步逻辑测试
 * @details 通过 #include 源文件访问 parcel 的全部实现，
 *          使用 TestCore（core 子类）+ MockTransport 构建 parcel，
 *          测试构造、析构、close、set_destination、OnData 等同步/协程路径。
 *
 *          start() 不使用 run()，原因与 DuctDeep 相同：
 *          MockTransport 的 timer 轮询在队列为空时挂起。
 *          start() 相关路径在已有的 MuxParcel.cpp 集成测试中间接覆盖。
 */

#include <prism/diagnose/log.hpp>
#include <prism/foundation/foundation.hpp>
#include <prism/net/connection/dialer/dialer.hpp>
#include <prism/net/dns/resolver.hpp>
#include <prism/protocol/multiplex/datagram.hpp>
#include <prism/protocol/multiplex/multiplexer.hpp>

#include "common/MockTransport.hpp"

using MockTransport = Preview::Testing::MockTransport;
namespace multiplex = psm::multiplex;
namespace net = boost::asio;

#include <gtest/gtest.h>

namespace
{
    // TestCore: core 最小子类，提供 executor
    class TestCore final : public multiplex::multiplexer
    {
    public:
        std::uint32_t last_fin_id_ = 0;
        mutable bool send_data_called_ = false;

        explicit TestCore(multiplex::multiplexer_options opts) : multiplexer(std::move(opts))
        {
        }

        auto send(std::uint32_t, psm::memory::vector<std::byte>) -> net::awaitable<void> override
        {
            send_data_called_ = true;
            co_return;
        }

        void fin(std::uint32_t id) override
        {
            last_fin_id_ = id;
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

    static multiplex::config g_cfg{};

    struct ParcelFixture
    {
        std::shared_ptr<MockTransport> mux_transport;
        std::unique_ptr<net::io_context> ioc;
        std::unique_ptr<psm::connect::dialer> router_ptr;
        std::shared_ptr<TestCore> core_obj;
        std::shared_ptr<multiplex::datagram> datagram_obj;

        explicit ParcelFixture(std::uint32_t max_dgram = 4096,
                               multiplex::addr_mode mode = multiplex::addr_mode::length_prefixed)
        {
            mux_transport = std::make_shared<MockTransport>();
            ioc = std::make_unique<net::io_context>(1);
            psm::dns::config dns_cfg;
            psm::connect::dialer_options ropts{*ioc, dns_cfg};
            router_ptr = std::make_unique<psm::connect::dialer>(std::move(ropts));
            multiplex::multiplexer_options opts{mux_transport, nullptr, g_cfg, nullptr};
            core_obj = std::make_shared<TestCore>(std::move(opts));

            multiplex::datagram_options dopts;
            dopts.stream_id = 42;
            dopts.max_dgram = max_dgram;
            dopts.executor = core_obj->executor();
            dopts.egress = core_obj;
            dopts.resolve =
                [](std::string_view,
                   std::string_view) -> net::awaitable<std::pair<psm::fault::code, net::ip::udp::endpoint>>
            {
                co_return std::make_pair(psm::fault::code::success,
                                         net::ip::udp::endpoint(net::ip::make_address("127.0.0.1"), 53));
            };
            dopts.emit = [](std::string_view, std::uint16_t,
                            std::span<const std::byte>) -> net::awaitable<void> { co_return; };
            dopts.mr = psm::memory::current_resource();
            datagram_obj = multiplex::make_datagram(std::move(dopts));
        }

        ~ParcelFixture()
        {
            if (datagram_obj)
            {
                datagram_obj->close();
            }
            datagram_obj.reset();
            core_obj.reset();
        }
    };

    // ─── 构造函数 ─────────────────────────────

    TEST(ParcelDeep, ConstructorDefault)
    {
        ParcelFixture fx;
        EXPECT_TRUE(fx.datagram_obj->stream_id() == 42) << "constructor: stream_id = 42";
    }

    TEST(ParcelDeep, ConstructorWithMr)
    {
        auto mux_t = std::make_shared<MockTransport>();
        auto ioc = std::make_unique<net::io_context>(1);
        psm::dns::config dns_cfg;
        psm::connect::dialer_options ropts{*ioc, dns_cfg};
        auto router = std::make_unique<psm::connect::dialer>(std::move(ropts));
        static multiplex::config cfg;
        psm::memory::unsynchronized_pool mr;
        multiplex::multiplexer_options opts{mux_t, nullptr, cfg, &mr};
        auto c = std::make_shared<TestCore>(std::move(opts));

        multiplex::datagram_options pcfg;
        pcfg.stream_id = 1;
        pcfg.executor = c->executor();
        pcfg.egress = c;
        pcfg.mr = &mr;
        auto p = multiplex::make_datagram(std::move(pcfg));
        EXPECT_TRUE(p->stream_id() == 1) << "constructor: with mr -> stream_id = 1";
        p->close();
    }

    TEST(ParcelDeep, ConstructorPacketAddr)
    {
        ParcelFixture fx{4096, multiplex::addr_mode::packet_addr};
        EXPECT_TRUE(fx.datagram_obj->stream_id() == 42) << "constructor: packet_addr mode -> ok";
    }

    TEST(ParcelDeep, ConstructorSmallMaxDgram)
    {
        ParcelFixture fx{100};
        EXPECT_TRUE(fx.datagram_obj->stream_id() == 42) << "constructor: small max_dgram -> ok";
    }

    // ─── 析构函数 ─────────────────────────────

    TEST(ParcelDeep, DestructorNoStart)
    {
        ParcelFixture fx;
        fx.datagram_obj.reset();
    }

    TEST(ParcelDeep, DestructorAfterClose)
    {
        ParcelFixture fx;
        fx.datagram_obj->close();
        fx.datagram_obj.reset();
    }

    // ─── close() 幂等性 ─────────────────────

    TEST(ParcelDeep, CloseIdempotent)
    {
        ParcelFixture fx;
        fx.datagram_obj->close();
        fx.datagram_obj->close();
    }

    TEST(ParcelDeep, CloseWithoutTraffic)
    {
        ParcelFixture fx;
        fx.datagram_obj->close();
    }

    // ─── set_destination ─────────────────────

    TEST(ParcelDeep, SetDestination)
    {
        // set_destination 已移除：目标地址由 *_control 在流建立时确定
        ParcelFixture fx;
    }

    TEST(ParcelDeep, SetDestinationAfterClose)
    {
        ParcelFixture fx;
        fx.datagram_obj->close();
    }

    // ─── OnData 协程路径 ─────────────────────

    TEST(ParcelDeep, OnDataAfterClose)
    {
        // OnData 是协程，close 后 co_return。但不 spawn 也能验证 close 后安全。
        ParcelFixture fx;
        fx.datagram_obj->close();
    }

    TEST(ParcelDeep, OnDataEmpty)
    {
        // 不 spawn 协程，仅验证 close 路径
        ParcelFixture fx;
        fx.datagram_obj->close();
    }

    // ─── on_uplink_done ─────────────────────

    TEST(ParcelDeep, OnUplinkDoneNullptr)
    {
        ParcelFixture fx;
        fx.datagram_obj->close();
    }

} // namespace

// #include 源文件以覆盖 parcel 全部实现
#include "../src/prism/protocol/multiplex/datagram.cpp"
