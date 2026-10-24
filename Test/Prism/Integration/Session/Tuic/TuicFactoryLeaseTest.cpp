/**
 * @file TuicFactoryLeaseTest.cpp
 * @brief TUIC Account connection lease contracts through Native QUIC callbacks.
 */

#include <TestSupport/Prism/TuicFactoryFixture.hpp>

#include <gtest/gtest.h>

#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>

#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace
{
    namespace Net = boost::asio;

    using Prism::Testing::TuicFactory::Gate;
    using Prism::Testing::TuicFactory::MakeConnectWire;
    using Prism::Testing::TuicFactory::MakePacketWire;
    using Prism::Testing::TuicFactory::RecordingDatagramProvider;
    using Prism::Testing::TuicFactory::ScriptedStreamProvider;
    using Prism::Testing::TuicFactory::TestExporter;
    using Prism::Testing::TuicFactory::TuicTestHarness;
} // namespace


TEST(TuicFactory, AuthenticatesUdpOnlyUniBeforeDatagramWithoutBidi)
{
    TuicTestHarness Harness;
    ASSERT_TRUE(Harness.Installed());
    std::size_t ExchangeCalls = 0;
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
    auto Options = Harness.Configure();
    auto AuthProvider = std::make_shared<ScriptedStreamProvider>(
        Harness.Io.get_executor(), Harness.ValidAuthWire());
    auto Datagram = std::make_shared<RecordingDatagramProvider>(Harness.Io.get_executor());
    Datagram->Inject(MakePacketWire());

    Options.OnDatagram(Datagram);
    Options.OnUnidirectional(AuthProvider);
    Options.OnExporter(TestExporter);
    Harness.Io.run();

    EXPECT_EQ(Harness.Authenticator()->Calls(), 1U);
    EXPECT_TRUE(Harness.Authenticator()->LeaseHeldAtSuccess());
    EXPECT_EQ(ExchangeCalls, 1U);
    EXPECT_EQ(Datagram->ReceiveCalls(), 2U);
    EXPECT_EQ(Datagram->SendCalls(), 1U);
    EXPECT_EQ(ReceivedPayload, "udp-payload");
    EXPECT_EQ(Harness.AccountActiveConnections(), 1U);
    Options.OnClosed();
    Harness.Io.restart();
    Harness.Io.run();
    EXPECT_EQ(Harness.AccountActiveConnections(), 0U);
    Harness.CloseAndDrain(Options);
}


TEST(TuicFactory, AuthenticationFailureClosesBidiProvider)
{
    TuicTestHarness Harness;
    ASSERT_TRUE(Harness.Installed());
    std::size_t RelayCalls = 0;
    Harness.Binding().Services.RelayStream = [&RelayCalls](Prism::Tuic::StreamRelayRequest)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        ++RelayCalls;
        co_return std::expected<void, Prism::Fault::Failure>{};
    };
    auto Options = Harness.Configure();
    auto AuthProvider = std::make_shared<ScriptedStreamProvider>(
        Harness.Io.get_executor(), Harness.InvalidAuthWire());
    auto BidiProvider = std::make_shared<ScriptedStreamProvider>(
        Harness.Io.get_executor(), MakeConnectWire());

    Options.OnUnidirectional(AuthProvider);
    Options.OnExporter(TestExporter);
    Options.OnStream(BidiProvider);
    Harness.Io.run();

    EXPECT_EQ(Harness.Authenticator()->Calls(), 0U);
    EXPECT_EQ(RelayCalls, 0U);
    EXPECT_TRUE(BidiProvider->IsClosed());
    EXPECT_EQ(Harness.AccountActiveConnections(), 0U);
    Harness.CloseAndDrain(Options);
}


TEST(TuicFactory, ConcurrentBidiStreamsShareOneAuthentication)
{
    TuicTestHarness Harness;
    ASSERT_TRUE(Harness.Installed());
    std::size_t HandlerCalls = 0;
    std::size_t LeaseCalls = 0;
    Harness.Binding().Services.RelayStream = [&HandlerCalls, &LeaseCalls](
                                                   Prism::Tuic::StreamRelayRequest Request)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        ++HandlerCalls;
        LeaseCalls += static_cast<std::size_t>(static_cast<bool>(Request.Lease));
        Request.Inbound->Close();
        co_return std::expected<void, Prism::Fault::Failure>{};
    };
    auto Options = Harness.Configure();
    auto AuthProvider = std::make_shared<ScriptedStreamProvider>(
        Harness.Io.get_executor(), Harness.ValidAuthWire());
    auto AuthRelease = std::make_shared<Gate>(Harness.Io.get_executor(), 1);
    AuthProvider->SetGate(AuthRelease);
    auto FirstBidi = std::make_shared<ScriptedStreamProvider>(
        Harness.Io.get_executor(), MakeConnectWire());
    auto SecondBidi = std::make_shared<ScriptedStreamProvider>(
        Harness.Io.get_executor(), MakeConnectWire());

    Options.OnUnidirectional(AuthProvider);
    Options.OnExporter(TestExporter);
    Options.OnStream(FirstBidi);
    Options.OnStream(SecondBidi);
    Net::post(Harness.Io, [AuthRelease]
              { (void)AuthRelease->try_send(boost::system::error_code{}); });
    Harness.Io.run();

    EXPECT_EQ(Harness.Authenticator()->Calls(), 1U);
    EXPECT_EQ(HandlerCalls, 2U);
    EXPECT_EQ(LeaseCalls, 2U);
    EXPECT_TRUE(FirstBidi->IsClosed());
    EXPECT_TRUE(SecondBidi->IsClosed());
    EXPECT_EQ(Harness.AccountActiveConnections(), 1U);
    Options.OnClosed();
    Harness.Io.restart();
    Harness.Io.run();
    EXPECT_EQ(Harness.AccountActiveConnections(), 0U);
    Harness.CloseAndDrain(Options);
}


TEST(TuicFactory, CloseCancelsPendingAuthenticationAndCallsOwnerOnce)
{
    TuicTestHarness Harness;
    ASSERT_TRUE(Harness.Installed());
    std::size_t CloseOwnerCalls = 0;
    Harness.Binding().Admission.CloseOwner = [&CloseOwnerCalls]()
        -> std::expected<void, Prism::Fault::Failure>
    {
        ++CloseOwnerCalls;
        return {};
    };
    auto Options = Harness.Configure();
    auto BidiProvider = std::make_shared<ScriptedStreamProvider>(
        Harness.Io.get_executor(), std::vector<std::byte>{});

    Options.OnStream(BidiProvider);
    Net::post(Harness.Io, [&Options]
              {
                  Options.OnClosed();
                  Options.OnClosed();
              });
    Harness.Io.run();

    EXPECT_TRUE(BidiProvider->IsClosed());
    EXPECT_EQ(CloseOwnerCalls, 1U);
    EXPECT_EQ(Harness.CompletionCalls(), 1U);
    EXPECT_EQ(Harness.AccountActiveConnections(), 0U);
    Harness.CloseAndDrain(Options);
    EXPECT_EQ(CloseOwnerCalls, 1U);
    EXPECT_EQ(Harness.CompletionCalls(), 1U);
}
