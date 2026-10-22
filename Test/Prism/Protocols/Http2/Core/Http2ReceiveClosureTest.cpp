/**
 * @file Http2ReceiveClosureTest.cpp
 * @brief HTTP/2 stream receive-closure classification.
 */
#include <gtest/gtest.h>
#include <boost/asio.hpp>
#include <Prism/Protocols/Http2/Session.hpp>
#include <optional>
#include <system_error>
#include <vector>

namespace
{
    namespace Net = boost::asio;
}

TEST(Http2ReceiveClosure, ResetWithNoErrorCodeRemainsReset)
{
    Net::io_context Io;
    auto Sender = std::make_shared<Prism::Http2::Session>(Io.get_executor(), false);
    auto Receiver = std::make_shared<Prism::Http2::Session>(Io.get_executor(), true);
    std::optional<Prism::Http2::StreamReceiveClosure> Closure;
    Receiver->OnStreamClose = [&Closure](const Prism::Http2::StreamReceiveClosure &Value)
    { Closure = Value; };
    Sender->SendSettings();
    const auto OpenedStream = Sender->OpenStream(
        Prism::Http2::HeaderList{{":method", "CONNECT"}, {":authority", "example.test:443"}}, false);
    ASSERT_TRUE(OpenedStream);
    const auto StreamId = *OpenedStream;
    std::vector<std::byte> Wire;
    ASSERT_TRUE(Sender->Collect(Wire));
    std::error_code Error;
    ASSERT_TRUE(Receiver->Feed(Wire, Error));
    ASSERT_FALSE(Error);

    ASSERT_TRUE(Sender->ResetStream(StreamId, Prism::Http2::ErrorNoError));
    Wire.clear();
    ASSERT_TRUE(Sender->Collect(Wire));
    Error.clear();
    ASSERT_TRUE(Receiver->Feed(Wire, Error));
    ASSERT_FALSE(Error);
    ASSERT_TRUE(Closure.has_value());
    EXPECT_EQ(Closure->StreamId, StreamId);
    EXPECT_EQ(Closure->Kind, Prism::Http2::StreamReceiveClosureKind::Reset);
    EXPECT_EQ(Closure->ErrorCode, Prism::Http2::ErrorNoError);
}
