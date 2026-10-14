/**
 * @file TrafficSinkContractTest.cpp
 * @brief TrafficSink 基础契约测试
 * @details 验证协议数据面只依赖 Foundation 中的最小流量接口，
 *          不需要引入 Runtime::Context。
 */

#include <gtest/gtest.h>

#include <cstddef>
#include <memory>
#include <type_traits>
#include <utility>

#include <Preview/Foundation/Utility/TrafficSink.hpp>
#include <Preview/Protocols/Socks5/UdpAssoc.hpp>
#include <Preview/Protocols/Vless/UdpTunnel.hpp>

namespace
{

    class RecordingSink final : public Preview::Foundation::TrafficSink
    {
    public:
        auto Report(Preview::Foundation::TrafficEvent Event) noexcept -> void override
        {
            Account_ = Event.Account;
            Up_ = Event.Up;
            Down_ = Event.Down;
        }

        auto Retire(Preview::Foundation::TrafficRetirement Owner)
            -> boost::asio::awaitable<std::expected<void, Preview::Fault::Failure>> override
        { (void)Owner; co_return std::expected<void, Preview::Fault::Failure>{}; }

        Preview::AccountId Account_{};
        std::size_t Up_{0};
        std::size_t Down_{0};
    };

    static_assert(std::is_same_v<
                  decltype(std::declval<Preview::Socks5::UdpAssocOptions>().Traffic),
                  std::shared_ptr<Preview::Foundation::TrafficSink>>);
    static_assert(std::is_same_v<
                  decltype(std::declval<Preview::Vless::UdpTunnelOptions>().Traffic),
                  std::shared_ptr<Preview::Foundation::TrafficSink>>);

    TEST(TrafficSinkContract, ReportsProtocolTraffic)
    {
        auto Sink = std::make_shared<RecordingSink>();
        Preview::Socks5::UdpAssocOptions SocksOptions;
        Preview::Vless::UdpTunnelOptions VlessOptions;
        SocksOptions.Traffic = Sink;
        VlessOptions.Traffic = Sink;

        ASSERT_EQ(SocksOptions.Traffic, Sink);
        ASSERT_EQ(VlessOptions.Traffic, Sink);

        Sink->Report(Preview::Foundation::TrafficEvent{
            .Account = Preview::AccountId{7}, .Up = 128, .Down = 256});

        EXPECT_EQ(Sink->Account_, Preview::AccountId{7});
        EXPECT_EQ(Sink->Up_, 128U);
        EXPECT_EQ(Sink->Down_, 256U);
    }

} // namespace
