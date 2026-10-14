#pragma once

/**
 * @file SmuxCraftDeepSupport.hpp
 * @brief SMUX craft 深度测试共享 fixture。
 * @details Conn、地址激活和生命周期测试共同使用同一个真实 dialer、outbound
 *          与 control owner；本头不承载 TEST 宏。
 */

#include <memory>
#include <utility>

#include "TestSupport/Production/ProductionMockTransport.hpp"
#include <prism/net/connection/dialer/dialer.hpp>
#include <prism/net/connection/outbound/direct.hpp>
#include <prism/net/dns/resolver.hpp>
#include <prism/protocol/multiplex/smux/control.hpp>

namespace Preview::Testing::SmuxCraft
{
    namespace Multiplex = psm::multiplex;
    namespace Smux = psm::multiplex::smux;
    using ProductionMockTransport = Psm::Testing::ProductionMockTransport;

    struct CraftFixture final
    {
        std::shared_ptr<ProductionMockTransport> transport;
        std::unique_ptr<psm::connect::dialer> router_ptr;
        std::unique_ptr<psm::outbound::direct> outbound_ptr;
        std::shared_ptr<Smux::control> craft_obj;
        inline static Multiplex::config cfg{};

        CraftFixture()
        {
            transport = std::make_shared<ProductionMockTransport>();
            psm::dns::config DnsConfig;
            psm::connect::dialer_options Options{transport->GetIoContext(), DnsConfig};
            router_ptr = std::make_unique<psm::connect::dialer>(std::move(Options));
            outbound_ptr = std::make_unique<psm::outbound::direct>(*router_ptr);
            Multiplex::multiplexer_options MuxOptions{transport, outbound_ptr.get(), cfg, nullptr};
            craft_obj = std::make_shared<Smux::control>(std::move(MuxOptions));
        }

        auto &IoContext()
        {
            return transport->GetIoContext();
        }

        auto &ioc()
        {
            return transport->GetIoContext();
        }

        void poll(int max_iters = 500)
        {
            for (int Index = 0; Index < max_iters; ++Index)
            {
                ioc().poll_one();
            }
            ioc().restart();
        }
    };
}
