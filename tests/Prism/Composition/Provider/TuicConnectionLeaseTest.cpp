/**
 * @file TuicConnectionLeaseTest.cpp
 * @brief TUIC stream lease 与 connection lease 的组合层生命周期合同。
 */

#include "TuicFactoryFixture.hpp"

#include <gtest/gtest.h>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <cstddef>
#include <memory>
#include <string>
#include <vector>

namespace
{
    namespace Net = boost::asio;

    using Prism::Testing::TuicFactory::MakeConnectWire;
    using Prism::Testing::TuicFactory::MakePacketWire;
    using Prism::Testing::TuicFactory::RecordingDatagramProvider;
    using Prism::Testing::TuicFactory::ScriptedStreamProvider;
    using Prism::Testing::TuicFactory::TestExporter;
    using Prism::Testing::TuicFactory::TuicTestHarness;
} // namespace

TEST(TuicConnectionLease, CloseRetainsConnectionQuotaUntilPendingRelayCompletes)
{
    TuicTestHarness Harness;
    using Gate=Prism::Testing::TuicFactory::Gate;
    auto Entered=std::make_shared<Gate>(Harness.Io.get_executor(),1);
    auto Release=std::make_shared<Gate>(Harness.Io.get_executor(),1);
    Harness.Binding().Services.RelayStream=[Entered,Release](Prism::Tuic::StreamRelayRequest Request)
        ->Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
        (void)Entered->try_send(boost::system::error_code{});
        co_await Release->async_receive(Net::use_awaitable);
        Request.Inbound->Close();
        co_return std::expected<void, Prism::Fault::Failure>{};
};
    auto Options=Harness.Configure();
    Options.OnUnidirectional(std::make_shared<ScriptedStreamProvider>(Harness.Io.get_executor(),Harness.ValidAuthWire()));
    Options.OnExporter(TestExporter);Harness.Io.run();Harness.Io.restart();
    Options.OnStream(std::make_shared<ScriptedStreamProvider>(Harness.Io.get_executor(),MakeConnectWire()));
    auto Check=[&]()->Net::awaitable<void>
    {
        co_await Entered->async_receive(Net::use_awaitable);
        Options.OnClosed();co_await Net::post(Net::use_awaitable);
        EXPECT_EQ(Harness.AccountActiveConnections(),1U);
        EXPECT_EQ(Harness.AccountActiveStreams(),1U);
        (void)Release->try_send(boost::system::error_code{});
    };
    Net::co_spawn(Harness.Io,Check(),[](std::exception_ptr Error){EXPECT_FALSE(Error);});
    Harness.Io.run();
    EXPECT_EQ(Harness.AccountActiveConnections(),0U);
    EXPECT_EQ(Harness.AccountActiveStreams(),0U);
    Harness.CloseAndDrain(Options);
}

TEST(TuicConnectionLease, BidiHandlerCompletionRetainsLeaseUntilQuicClose)
{
    TuicTestHarness Harness;
    ASSERT_TRUE(Harness.Installed());

    std::size_t RelayCalls = 0;
    std::size_t LeaseCalls = 0;
    std::size_t CloseOwnerCalls = 0;
    Harness.Binding().Services.RelayStream = [&RelayCalls, &LeaseCalls](
                                                 Prism::Tuic::StreamRelayRequest Request)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        ++RelayCalls;
        LeaseCalls += static_cast<std::size_t>(static_cast<bool>(Request.Lease));
        Request.Inbound->Close();
        co_return std::expected<void, Prism::Fault::Failure>{};
    };
    Harness.Binding().Admission.CloseOwner = [&CloseOwnerCalls]()
        -> std::expected<void, Prism::Fault::Failure>
    {
        ++CloseOwnerCalls;
        return {};
    };

    auto Options = Harness.Configure();
    Options.OnUnidirectional(std::make_shared<ScriptedStreamProvider>(
        Harness.Io.get_executor(), Harness.ValidAuthWire()));
    Options.OnExporter(TestExporter);
    Harness.Io.run();

    Harness.Io.restart();
    auto BidiProvider = std::make_shared<ScriptedStreamProvider>(
        Harness.Io.get_executor(), MakeConnectWire());
    Options.OnStream(BidiProvider);
    Harness.Io.run();

    EXPECT_EQ(Harness.Authenticator()->Calls(), 1U);
    EXPECT_TRUE(Harness.Authenticator()->LeaseHeldAtSuccess());
    EXPECT_EQ(RelayCalls, 1U);
    EXPECT_EQ(LeaseCalls, 1U);
    EXPECT_TRUE(BidiProvider->IsClosed());
    EXPECT_EQ(Harness.AccountActiveConnections(), 1U);

    Options.OnClosed();
    Harness.Io.restart();
    Harness.Io.run();
    EXPECT_EQ(CloseOwnerCalls, 1U);
    EXPECT_EQ(Harness.AccountActiveConnections(), 0U);
    Harness.CloseAndDrain(Options);
}

TEST(TuicConnectionLease, UdpOnlyCompletionRetainsConnectionLeaseUntilQuicClose)
{
    TuicTestHarness Harness;
    ASSERT_TRUE(Harness.Installed());

    std::size_t ExchangeCalls = 0;
    std::size_t CloseOwnerCalls = 0;
    std::string ReceivedPayload;
    Harness.Binding().Services.ExchangeDatagram = [&ExchangeCalls, &ReceivedPayload](
                                                      Prism::Tuic::DatagramRequest Request)
        -> Net::awaitable<Prism::Tuic::DatagramResult>
    {
        ++ExchangeCalls;
        ReceivedPayload.assign(Request.Payload.begin(), Request.Payload.end());
        co_return Prism::Tuic::DatagramResult{
            Prism::Error::None, std::move(Request.Target), std::move(Request.Payload)};
    };
    Harness.Binding().Admission.CloseOwner = [&CloseOwnerCalls]()
        -> std::expected<void, Prism::Fault::Failure>
    {
        ++CloseOwnerCalls;
        return {};
    };

    auto Options = Harness.Configure();
    Options.OnUnidirectional(std::make_shared<ScriptedStreamProvider>(
        Harness.Io.get_executor(), Harness.ValidAuthWire()));
    Options.OnExporter(TestExporter);
    Harness.Io.run();

    EXPECT_EQ(Harness.Authenticator()->Calls(), 1U);
    EXPECT_TRUE(Harness.Authenticator()->LeaseHeldAtSuccess());
    EXPECT_EQ(Harness.AccountActiveConnections(), 1U);

    Harness.Io.restart();
    auto DatagramProvider = std::make_shared<RecordingDatagramProvider>(
        Harness.Io.get_executor());
    DatagramProvider->Inject(MakePacketWire());
    Options.OnDatagram(DatagramProvider);
    Harness.Io.run();

    EXPECT_EQ(ExchangeCalls, 1U);
    EXPECT_EQ(DatagramProvider->ReceiveCalls(), 2U);
    EXPECT_EQ(DatagramProvider->SendCalls(), 1U);
    EXPECT_EQ(ReceivedPayload, "udp-payload");
    EXPECT_EQ(Harness.AccountActiveConnections(), 1U);

    Options.OnClosed();
    Harness.Io.restart();
    Harness.Io.run();
    EXPECT_EQ(CloseOwnerCalls, 1U);
    EXPECT_EQ(Harness.AccountActiveConnections(), 0U);
    Harness.CloseAndDrain(Options);
}
