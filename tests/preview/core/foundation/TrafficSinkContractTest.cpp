/**
 * @file TrafficSinkContractTest.cpp
 * @brief TrafficSink 基础契约测试
 * @details 验证协议数据面只依赖 Foundation 中的最小流量接口，
 *          不需要引入 Runtime::Context。
 */

#include <gtest/gtest.h>

#include <cstddef>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

#include <preview/Foundation/Utility/TrafficSink.hpp>
#include <preview/Protocols/Socks5/UdpAssoc.hpp>
#include <preview/Protocols/Vless/UdpTunnel.hpp>

namespace
{

    class RecordingSink final : public Preview::Foundation::TrafficSink
    {
    public:
        auto Report(std::string_view Identity, std::size_t Up,
                    std::size_t Down) -> void override
        {
            Identity_ = std::string(Identity);
            Up_ = Up;
            Down_ = Down;
        }

        std::string Identity_;
        std::size_t Up_{0};
        std::size_t Down_{0};
    };

    static_assert(std::is_same_v<
                  decltype(std::declval<Preview::Socks5::UdpAssocOptions>().traffic),
                  Preview::Foundation::TrafficSink *>);
    static_assert(std::is_same_v<
                  decltype(std::declval<Preview::Vless::UdpTunnelOptions>().traffic),
                  Preview::Foundation::TrafficSink *>);

    TEST(TrafficSinkContract, ReportsProtocolTraffic)
    {
        RecordingSink Sink;
        Preview::Socks5::UdpAssocOptions SocksOptions;
        Preview::Vless::UdpTunnelOptions VlessOptions;
        SocksOptions.traffic = &Sink;
        VlessOptions.traffic = &Sink;

        ASSERT_EQ(SocksOptions.traffic, &Sink);
        ASSERT_EQ(VlessOptions.traffic, &Sink);

        Sink.Report("alice", 128, 256);

        EXPECT_EQ(Sink.Identity_, "alice");
        EXPECT_EQ(Sink.Up_, 128U);
        EXPECT_EQ(Sink.Down_, 256U);
    }

} // namespace
