/**
 * @file NativeHttp3Session.cpp
 * @brief 原生 HTTP/3 与 QUIC provider 会话契约回归
 */

#include <Preview/Protocols/Http3/NativeServer.hpp>
#include <Preview/Protocols/Http3/NativeClient.hpp>

#include <boost/asio/io_context.hpp>

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <type_traits>
#include <utility>
#include <vector>

namespace
{

    static_assert(!std::is_copy_constructible_v<Preview::Http3::HeaderBlock>);
    static_assert(std::is_move_constructible_v<Preview::Http3::HeaderBlock>);
    static_assert(!std::is_copy_constructible_v<Preview::Http3::RequestHead>);
    static_assert(std::is_move_constructible_v<Preview::Http3::RequestEvent>);
    static_assert(!std::is_copy_constructible_v<Preview::Http3::DataEvent>);
    static_assert(std::is_move_constructible_v<Preview::Http3::DataEvent>);
    static_assert(std::is_move_constructible_v<Preview::Http3::NativeServerSessionOptions>);
    static_assert(requires(Preview::Http3::NativeServerSession &Session)
                  {
                      Session.Run();
                      Session.Close();
                      Session.ProtocolReady();
                  });
    static_assert(std::is_move_constructible_v<Preview::Http3::NativeClientSessionOptions>);
    static_assert(requires(Preview::Http3::NativeClientSession &Session,
                           Preview::Http3::RequestHead Request)
                  {
                      Session.SendRequest(std::move(Request));
                      Session.OpenBidirectionalStream();
                      Session.Close();
                  });

    TEST(NativeHttp3Session, ExposesAsyncProviderContract)
    {
        Preview::Http3::NativeServerSessionOptions Options;
        EXPECT_FALSE(Options.OpenUnidirectional);
        EXPECT_FALSE(Options.AcceptUnidirectional);
        EXPECT_FALSE(Options.AcceptBidirectional);
        EXPECT_FALSE(Options.OnEvent);
    }

    TEST(NativeHttp3Session, ClientDefaultsToUnready)
    {
        boost::asio::io_context Io;
        Preview::Http3::NativeClientSessionOptions Options;
        Options.Executor = Io.get_executor();
        auto Session = std::make_shared<Preview::Http3::NativeClientSession>(std::move(Options));
        EXPECT_FALSE(Session->HandshakeReady());
        EXPECT_FALSE(Session->ProtocolReady());
        Session->Close();
    }

    TEST(NativeHttp3Session, EventHeadersAndDataMoveWithoutBorrowedPayload)
    {
        EXPECT_THROW(
            Preview::Http3::HeaderBlock(nullptr),
            std::invalid_argument);
        auto MemoryOwner = std::make_shared<Preview::Memory::SessionResource<>>();
        Preview::Http3::HeaderBlock Headers(MemoryOwner);
        Headers.Fields.push_back({":method", "GET"});
        Headers.Fields.push_back({":path", "/generic"});

        Preview::Http3::RequestEvent Request{
            0, Preview::Http3::RequestHead{std::move(Headers), true}};
        Preview::Http3::ServerEvent Event{std::move(Request)};
        ASSERT_TRUE(std::holds_alternative<Preview::Http3::RequestEvent>(Event));
        const auto &RequestValue = std::get<Preview::Http3::RequestEvent>(Event);
        ASSERT_EQ(RequestValue.Head.Headers.Fields.size(), 2U);
        EXPECT_EQ(RequestValue.Head.Headers.Fields[0].Name, ":method");
        EXPECT_EQ(RequestValue.Head.Headers.Fields[0].value, "GET");
        EXPECT_EQ(RequestValue.Head.Headers.Fields[1].Name, ":path");
        EXPECT_EQ(RequestValue.Head.Headers.Fields[1].value, "/generic");
        EXPECT_TRUE(RequestValue.Head.Fin);
        EXPECT_EQ(RequestValue.Head.Headers.Owner, MemoryOwner);

        Preview::Http3::DataEvent Data{
            0, std::vector<std::byte>{std::byte{0x41}, std::byte{0x42}}, true};
        Preview::Http3::ServerEvent DataValue{std::move(Data)};
        ASSERT_TRUE(std::holds_alternative<Preview::Http3::DataEvent>(DataValue));
        const auto &Payload = std::get<Preview::Http3::DataEvent>(DataValue);
        ASSERT_EQ(Payload.Data.size(), 2U);
        EXPECT_EQ(Payload.Data[0], std::byte{0x41});
        EXPECT_EQ(Payload.Data[1], std::byte{0x42});
        EXPECT_TRUE(Payload.Fin);
    }

    TEST(NativeHttp3Session, GenericResponseAllowsArbitraryStatusAndFields)
    {
        auto MemoryOwner = std::make_shared<Preview::Memory::SessionResource<>>();
        Preview::Http3::HeaderBlock Headers(MemoryOwner);
        Headers.Fields.push_back({"content-type", "application/octet-stream"});
        Headers.Fields.push_back({"x-h3-test", "value"});
        Preview::Http3::ResponseHead Response{7, 418, std::move(Headers), true};

        EXPECT_EQ(Response.StreamId, 7);
        EXPECT_EQ(Response.Status, 418);
        ASSERT_EQ(Response.Headers.Fields.size(), 2U);
        EXPECT_EQ(Response.Headers.Fields[0].Name, "content-type");
        EXPECT_EQ(Response.Headers.Fields[1].Name, "x-h3-test");
        EXPECT_TRUE(Response.Fin);
    }

    TEST(NativeHttp3Session, RequestFinIsAGenericWireChoice)
    {
        auto ClosedOwner = std::make_shared<Preview::Memory::SessionResource<>>();
        Preview::Http3::RequestHead ClosedRequest{
            Preview::Http3::HeaderBlock(ClosedOwner), true};
        EXPECT_TRUE(ClosedRequest.Fin);

        auto OpenOwner = std::make_shared<Preview::Memory::SessionResource<>>();
        Preview::Http3::RequestHead OpenRequest{
            Preview::Http3::HeaderBlock(OpenOwner), false};
        EXPECT_FALSE(OpenRequest.Fin);
    }

} // namespace
