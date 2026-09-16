/**
 * @file NativeHttp3Session.cpp
 * @brief 原生 HTTP/3 与 QUIC provider 会话契约回归
 */

#include <Preview/Protocols/Http3/NativeServer.hpp>
#include <Preview/Protocols/Http3/NativeClient.hpp>

#include <boost/asio/io_context.hpp>

#include <gtest/gtest.h>

#include <type_traits>

namespace
{

    static_assert(std::is_move_constructible_v<Preview::Http3::NativeServerSessionOptions>);
    static_assert(requires(Preview::Http3::NativeServerSession &Session)
                  {
                      Session.Run();
                      Session.Close();
                      Session.Authenticated();
                      Session.ProtocolReady();
                  });
    static_assert(std::is_move_constructible_v<Preview::Http3::NativeClientSessionOptions>);
    static_assert(requires(Preview::Http3::NativeClientSession &Session)
                  {
                      Session.Authenticate();
                      Session.OpenBidirectionalStream();
                      Session.Close();
                  });

    TEST(NativeHttp3Session, ExposesAsyncProviderContract)
    {
        Preview::Http3::NativeServerSessionOptions Options;
        EXPECT_FALSE(Options.OpenUnidirectional);
        EXPECT_FALSE(Options.AcceptUnidirectional);
        EXPECT_FALSE(Options.AcceptBidirectional);
    }

    TEST(NativeHttp3Session, ClientDefaultsToUnAuthenticated)
    {
        boost::asio::io_context Io;
        Preview::Http3::NativeClientSessionOptions Options;
        Options.Executor = Io.get_executor();
        auto Session = std::make_shared<Preview::Http3::NativeClientSession>(std::move(Options));
        EXPECT_FALSE(Session->Authenticated());
        EXPECT_FALSE(Session->HandshakeReady());
        EXPECT_FALSE(Session->ProtocolReady());
        EXPECT_EQ(Session->StatusCode(), 0);
        Session->Close();
    }

} // namespace
