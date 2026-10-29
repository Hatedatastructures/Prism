/**
 * @file FactoryTest.cpp
 * @brief TUIC Native QUIC uni-auth/exporter callback contract.
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


TEST(TuicFactory, MapsTypedAdmissionServicesToNativeCallbacks)
{
    TuicTestHarness Harness;
    ASSERT_TRUE(Harness.Installed());
    auto Options = Harness.Configure();

    EXPECT_EQ(Harness.Binding().Admission.MaxPendingBidiStreams,8U);
    ASSERT_TRUE(Options.Owner);
    EXPECT_TRUE(static_cast<bool>(Options.OnUnidirectional));
    EXPECT_TRUE(static_cast<bool>(Options.OnExporter));
    EXPECT_TRUE(static_cast<bool>(Options.OnStream));
    EXPECT_TRUE(static_cast<bool>(Options.OnDatagram));
    Harness.CloseAndDrain(Options);
    EXPECT_EQ(Harness.CompletionCalls(), 1U);
}


TEST(TuicFactory, KeepsHandshakeDatagramProviderBeforeAuthentication)
{
    TuicTestHarness Harness;
    ASSERT_TRUE(Harness.Installed());
    std::size_t ExchangeCalls = 0;
    Harness.Binding().Services.ExchangeDatagram = [&ExchangeCalls](Prism::Tuic::DatagramRequest Request)
        -> Net::awaitable<Prism::Tuic::DatagramResult>
    {
        ++ExchangeCalls;
        co_return Prism::Tuic::DatagramResult{
            Prism::Error::None, std::move(Request.Target), std::move(Request.Payload)};
    };
    auto Options = Harness.Configure();
    auto Provider = std::make_shared<RecordingDatagramProvider>(Harness.Io.get_executor());
    Provider->Inject(MakePacketWire());

    Options.OnDatagram(Provider);
    Harness.Io.run();

    EXPECT_FALSE(Provider->IsClosed());
    EXPECT_EQ(ExchangeCalls, 0U);
    Harness.CloseAndDrain(Options);
}
