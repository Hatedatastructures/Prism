/** @file CancelClassTest.cpp @brief AnyTLS relay 取消原因分类回归。 */
#include <gtest/gtest.h>

#include <Prism/Protocols/Anytls/Detail/Session/State.hpp>
#include <Prism/Lifecycle/Task/Registry.hpp>

#include <boost/asio/io_context.hpp>

#include <memory>

TEST(AnytlsSessionCancellation, QueueOverflowCancellationRemainsFailureDuringRootStop)
{
    boost::asio::io_context Io;
    auto Tasks = std::make_shared<Prism::Lifecycle::TaskRegistry>(Io.get_executor());
    Prism::Anytls::Detail::StreamState Stream(Io.get_executor(), std::move(Tasks));
    const Prism::Fault::Failure Canceled{Prism::Fault::Code::Canceled};

    EXPECT_TRUE(Stream.IsExpectedRelayCancellation(Canceled, true));
    Stream.MarkInputTermination(Prism::Anytls::Detail::StreamState::InputTermination::QueueOverflow);
    EXPECT_FALSE(Stream.IsExpectedRelayCancellation(Canceled, true));
    Stream.MarkInputTermination(Prism::Anytls::Detail::StreamState::InputTermination::PeerFin);
    EXPECT_FALSE(Stream.IsExpectedRelayCancellation(Canceled, false));

    Prism::Anytls::Detail::StreamState PeerFinStream(Io.get_executor(), Tasks);
    PeerFinStream.MarkInputTermination(Prism::Anytls::Detail::StreamState::InputTermination::PeerFin);
    EXPECT_TRUE(PeerFinStream.IsExpectedRelayCancellation(Canceled, false));
    EXPECT_FALSE(PeerFinStream.IsExpectedRelayCancellation(
        Prism::Fault::Failure{Prism::Fault::Code::ConnectionReset}, false));
}
