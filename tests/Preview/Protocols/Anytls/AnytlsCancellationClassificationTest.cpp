/** @file AnytlsCancellationClassificationTest.cpp @brief AnyTLS relay 取消原因分类回归。 */
#include <gtest/gtest.h>

#include <Preview/Protocols/Anytls/Detail/Session/State.hpp>
#include <Preview/Lifecycle/TaskRegistry.hpp>

#include <boost/asio/io_context.hpp>

#include <memory>

TEST(AnytlsSessionCancellation, QueueOverflowCancellationRemainsFailureDuringRootStop)
{
    boost::asio::io_context Io;
    auto Tasks = std::make_shared<Preview::Lifecycle::TaskRegistry>(Io.get_executor());
    Preview::Anytls::Detail::StreamState Stream(Io.get_executor(), std::move(Tasks));
    const Preview::Fault::Failure Canceled{Preview::Fault::Code::Canceled};

    EXPECT_TRUE(Stream.IsExpectedRelayCancellation(Canceled, true));
    Stream.MarkInputTermination(Preview::Anytls::Detail::StreamState::InputTermination::QueueOverflow);
    EXPECT_FALSE(Stream.IsExpectedRelayCancellation(Canceled, true));
    Stream.MarkInputTermination(Preview::Anytls::Detail::StreamState::InputTermination::PeerFin);
    EXPECT_FALSE(Stream.IsExpectedRelayCancellation(Canceled, false));

    Preview::Anytls::Detail::StreamState PeerFinStream(Io.get_executor(), Tasks);
    PeerFinStream.MarkInputTermination(Preview::Anytls::Detail::StreamState::InputTermination::PeerFin);
    EXPECT_TRUE(PeerFinStream.IsExpectedRelayCancellation(Canceled, false));
    EXPECT_FALSE(PeerFinStream.IsExpectedRelayCancellation(
        Preview::Fault::Failure{Preview::Fault::Code::ConnectionReset}, false));
}
