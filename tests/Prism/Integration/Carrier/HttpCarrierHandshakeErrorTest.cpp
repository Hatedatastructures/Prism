#include <Prism/Protocols/Ws/Detail/StreamOwner.hpp>
/**
 * @file HttpCarrierHandshakeErrorTest.cpp
 * @brief TrustTunnel、Gun 与 WebSocket Conn 错误测试。
 */
#include "../../Protocols/Ws/WsFactorySupport.hpp"
#include "CarrierErrorFixture.hpp"

/** @brief 完整执行 ReadHandshakeMissingKey 场景并排空协议连接。 */
auto RunWsReadMissingKey(SharedTransmission ClientEndpoint, SharedTransmission ServerEndpoint)
    -> Net::awaitable<void>
{
    auto Server = std::make_shared<Ws::Detail::StreamOwner<>>(
    ServerEndpoint,
    Prism::Tests::WsFactorySupport::WebSocketTestBytes(), false);
    // 有 Upgrade 但无 Sec-WebSocket-Key → bad_magic
    co_await WriteRaw(ClientEndpoint, "GET / HTTP/1.1\r\nHost: example.com\r\n"
    "Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n");
    std::string Key;
    const auto Result = co_await Server->ReadHandshake(Key);
    EXPECT_FALSE(Result);
    if (!Result) EXPECT_EQ(Result.error().Code, Prism::Fault::Code::BadMessage);
    co_await ExpectCloseTransmission(Server);
    co_return;
}


/** @brief 完整执行 ReadHandshakeBadMagic 场景并排空协议连接。 */
auto RunWsReadBadMagic(SharedTransmission ClientEndpoint, SharedTransmission ServerEndpoint)
    -> Net::awaitable<void>
{
    auto Server = std::make_shared<Ws::Detail::StreamOwner<>>(
    ServerEndpoint,
    Prism::Tests::WsFactorySupport::WebSocketTestBytes(), false);
    // 普通 HTTP 请求（无 Upgrade）→ bad_magic
    co_await WriteRaw(ClientEndpoint, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
    std::string Key;
    const auto Result = co_await Server->ReadHandshake(Key);
    EXPECT_FALSE(Result);
    if (!Result) EXPECT_EQ(Result.error().Code, Prism::Fault::Code::BadMessage);
    co_await ExpectCloseTransmission(Server);
    co_return;
}


/** @brief 完整执行 ReadHandshakeBadMagic 场景并排空协议连接。 */
auto RunGunReadBadMagic(SharedTransmission ClientEndpoint, SharedTransmission ServerEndpoint)
    -> Net::awaitable<void>
{
    auto Server = std::make_shared<Gun::Conn<>>(
    ServerEndpoint);
    // 非 CONNECT 首行 → bad_magic
    co_await WriteRaw(ClientEndpoint, "GET / HTTP/2\r\n\r\n");
    std::string Host;
    const auto ErrorValue = co_await Server->ReadHandshake(Host);
    EXPECT_EQ(ErrorValue, Error::BadMagic);
    co_await ExpectCloseTransmission(Server);
    co_return;
}


inline constexpr const char *TestKey = "dGhlIHNhbXBsZSBub25jZQ==";

namespace
{
    /// 验证 TrustTunnel 错误 Basic Auth 会返回 bad_auth。
    auto RunTrustTunnelWrongCredentials(SharedTransmission Client, SharedTransmission Server)
        -> Net::awaitable<void>
    {
        auto Creation = Trusttunnel::Detail::Conn<>::Create(Trusttunnel::ConnRequest{
            Server, "user", "pass"});
        EXPECT_TRUE(Creation);
        if (!Creation)
        {
            co_return;
        }
        auto Connection = std::move(*Creation);
        const std::string Header =
            "CONNECT example.com:443 HTTP/2\r\n"
            "Proxy-Authorization: " + Trusttunnel::BasicAuth("wrong", "creds") + "\r\n\r\n";
        co_await WriteRaw(Client, Header);
        std::string Target;
        const auto Result = co_await Connection->ReadHandshake(Target);
        EXPECT_EQ(Result, Error::BadAuth);
        co_await ExpectCloseTransmission(Connection);
    }

    struct TrustTunnelPayloadRequest final
    {
        SharedTransmission Client;
        SharedTransmission Server;
        std::string Payload;
        bool &Succeeded;
    };

    /// 验证握手后同一批次到达的 payload 不会丢失。
    auto RunTrustTunnelPayload(TrustTunnelPayloadRequest Request) -> Net::awaitable<void>
    {
        auto Creation = Trusttunnel::Detail::Conn<>::Create(Trusttunnel::ConnRequest{
            Request.Server, "user", "pass"});
        EXPECT_TRUE(Creation);
        if (!Creation)
        {
            co_return;
        }
        auto Connection = std::move(*Creation);
        const std::string Header =
            "CONNECT example.com:443 HTTP/2\r\nProxy-Authorization: " +
            Trusttunnel::BasicAuth("user", "pass") + "\r\n\r\n" + Request.Payload;
        const auto Write = co_await Request.Client->WriteSome(AsBytes(AsU8Span(Header)));
        ExpectFullWrite(Write, Header.size());
        const auto Shutdown = co_await Request.Client->WriteShutdown();
        EXPECT_TRUE(Shutdown);
        std::string Target;
        EXPECT_EQ(co_await Connection->ReadHandshake(Target), Error::None);
        EXPECT_EQ(Target, "example.com");
        std::array<std::byte, 128> Buffer{};
        std::error_code ReadError;
        const auto Read = co_await Connection->ReadSome(Buffer);
        const auto Count = Read.Bytes;
        ReadError = PrismApi::Fault::ToNative(Read.Failure);
        Request.Succeeded = !ReadError && Count == Request.Payload.size() &&
                            std::memcmp(Buffer.data(), Request.Payload.data(), Request.Payload.size()) == 0;
        co_await ExpectCloseTransmission(Connection);
    }

    /// 运行返回非 101 状态的 WebSocket 原始服务端。
    auto RunWsBadStatusCase(SharedTransmission ClientEndpoint, SharedTransmission ServerEndpoint)
        -> Net::awaitable<void>
    {
        auto Server = ServerEndpoint;
        const auto ServerTask = SpawnTask(Server->Executor(), RunWsBadStatusServer(Server));
        auto Client = std::make_shared<Ws::Detail::StreamOwner<>>(
            ClientEndpoint,
            Prism::Tests::WsFactorySupport::WebSocketTestBytes(), false);
        const auto Result = co_await Client->WriteHandshake(TestKey, "example.com");
        EXPECT_FALSE(Result);
        if (!Result) EXPECT_EQ(Result.error().Code, Prism::Fault::Code::BadMessage);
        co_await WaitForTask(ServerTask);
        co_await ExpectCloseTransmission(Client);
    }

    /// 运行返回错误 Sec-WebSocket-Accept 的原始服务端。
    auto RunWsBadAcceptCase(SharedTransmission ClientEndpoint, SharedTransmission ServerEndpoint)
        -> Net::awaitable<void>
    {
        auto Server = ServerEndpoint;
        const auto ServerTask = SpawnTask(Server->Executor(), RunWsBadAcceptServer(Server));
        auto Client = std::make_shared<Ws::Detail::StreamOwner<>>(
            ClientEndpoint,
            Prism::Tests::WsFactorySupport::WebSocketTestBytes(), false);
        const auto Result = co_await Client->WriteHandshake(TestKey, "example.com");
        EXPECT_FALSE(Result);
        if (!Result) EXPECT_EQ(Result.error().Code, Prism::Fault::Code::AuthFailed);
        co_await WaitForTask(ServerTask);
        co_await ExpectCloseTransmission(Client);
    }

    /// 运行读取请求后主动关闭的 WebSocket 原始服务端。
    auto RunWsCloseCase(SharedTransmission ClientEndpoint, SharedTransmission ServerEndpoint)
        -> Net::awaitable<void>
    {
        auto Server = ServerEndpoint;
        const auto ServerTask = SpawnTask(Server->Executor(), RunWsCloseServer(Server));
        auto Client = std::make_shared<Ws::Detail::StreamOwner<>>(
            ClientEndpoint,
            Prism::Tests::WsFactorySupport::WebSocketTestBytes(), false);
        const auto Result = co_await Client->WriteHandshake(TestKey, "example.com");
        EXPECT_FALSE(Result);
        if (!Result) EXPECT_EQ(Result.error().Code, Prism::Fault::Code::Eof);
        co_await WaitForTask(ServerTask);
        co_await ExpectCloseTransmission(Client);
    }

    /// 验证有效 WebSocket 请求在对端关闭时返回 io_error。
    auto RunWsReadIoError(SharedTransmission Client, SharedTransmission Server) -> Net::awaitable<void>
    {
        auto Connection = std::make_shared<Ws::Detail::StreamOwner<>>(
            Server,
            Prism::Tests::WsFactorySupport::WebSocketTestBytes(), false);
        const std::string Request = "GET / HTTP/1.1\r\nHost: example.com\r\n"
                                    "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                                    "Sec-WebSocket-Key: " + std::string(TestKey) + "\r\n"
                                    "Sec-WebSocket-Version: 13\r\n\r\n";
        co_await WriteRaw(Client, Request);
        co_await ExpectCloseTransmission(Client);
        std::string Key;
        const auto Result = co_await Connection->ReadHandshake(Key);
        EXPECT_FALSE(Result);
        if (!Result) EXPECT_EQ(Result.error().Code, Prism::Fault::Code::Eof);
        co_await ExpectCloseTransmission(Connection);
    }

    /** @brief 验证 TrustTunnel 对端 EOF 返回 BadMagic。 */
    auto RunTrustTunnelReadHandshakeEof(
        SharedTransmission ClientEndpoint,
        SharedTransmission ServerEndpoint) -> Net::awaitable<void>
    {
        auto Creation = Trusttunnel::Detail::Conn<>::Create(Trusttunnel::ConnRequest{
            ServerEndpoint, "user", "pass"});
        EXPECT_TRUE(Creation);
        if (!Creation)
        {
            co_return;
        }
        auto Server = std::move(*Creation);
        co_await ExpectCloseTransmission(ClientEndpoint);
        std::string Target;
        EXPECT_EQ(co_await Server->ReadHandshake(Target), Error::BadMagic);
        co_await ExpectCloseTransmission(Server);
    }

    /** @brief 验证 TrustTunnel 拒绝非 CONNECT 请求首行。 */
    auto RunTrustTunnelReadHandshakeBadMagic(
        SharedTransmission ClientEndpoint,
        SharedTransmission ServerEndpoint) -> Net::awaitable<void>
    {
        auto Creation = Trusttunnel::Detail::Conn<>::Create(Trusttunnel::ConnRequest{
            ServerEndpoint, "user", "pass"});
        EXPECT_TRUE(Creation);
        if (!Creation)
        {
            co_return;
        }
        auto Server = std::move(*Creation);
        const std::string Request = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        co_await WriteRaw(ClientEndpoint, Request);
        std::string Target;
        EXPECT_EQ(co_await Server->ReadHandshake(Target), Error::BadMagic);
        co_await ExpectCloseTransmission(Server);
    }

    /** @brief 验证 TrustTunnel CONNECT 缺少认证头时返回 BadAuth。 */
    auto RunTrustTunnelReadHandshakeMissingAuth(
        SharedTransmission ClientEndpoint,
        SharedTransmission ServerEndpoint) -> Net::awaitable<void>
    {
        auto Creation = Trusttunnel::Detail::Conn<>::Create(Trusttunnel::ConnRequest{
            ServerEndpoint, "user", "pass"});
        EXPECT_TRUE(Creation);
        if (!Creation)
        {
            co_return;
        }
        auto Server = std::move(*Creation);
        const std::string Request = "CONNECT example.com:443 HTTP/2\r\n\r\n";
        co_await WriteRaw(ClientEndpoint, Request);
        std::string Target;
        EXPECT_EQ(co_await Server->ReadHandshake(Target), Error::BadAuth);
        co_await ExpectCloseTransmission(Server);
    }

    /** @brief 验证 TrustTunnel 写 CONNECT 头时对端关闭会返回 IoError。 */
    auto RunTrustTunnelWriteHandshakeIoError(
        SharedTransmission ClientEndpoint,
        SharedTransmission ServerEndpoint) -> Net::awaitable<void>
    {
        auto Creation = Trusttunnel::Detail::Conn<>::Create(Trusttunnel::ConnRequest{
            ClientEndpoint, "user", "pass"});
        EXPECT_TRUE(Creation);
        if (!Creation)
        {
            co_return;
        }
        auto Client = std::move(*Creation);
        co_await ExpectCloseTransmission(ServerEndpoint);
        EXPECT_EQ(co_await Client->WriteHandshake("example.com", 443), Error::IoError);
        co_await ExpectCloseTransmission(Client);
    }
}

TEST(StealthTrustTunnelConnError, ReadHandshakeEof)
    {
        Net::io_context Context;
        auto Pair = MakeOwnedMemoryPair(Context.get_executor());
        auto& [ClientEndpoint, ServerEndpoint] = Pair;

        RunMemoryCase(Context, Pair, RunTrustTunnelReadHandshakeEof(
            ClientEndpoint, ServerEndpoint));
    }

    TEST(StealthTrustTunnelConnError, ReadHandshakeBadMagic)
    {
        Net::io_context Context;
        auto Pair = MakeOwnedMemoryPair(Context.get_executor());
        auto& [ClientEndpoint, ServerEndpoint] = Pair;

        RunMemoryCase(Context, Pair, RunTrustTunnelReadHandshakeBadMagic(
            ClientEndpoint, ServerEndpoint));
    }

    TEST(StealthTrustTunnelConnError, ReadHandshakeMissingAuth)
    {
        Net::io_context Context;
        auto Pair = MakeOwnedMemoryPair(Context.get_executor());
        auto& [ClientEndpoint, ServerEndpoint] = Pair;

        RunMemoryCase(Context, Pair, RunTrustTunnelReadHandshakeMissingAuth(
            ClientEndpoint, ServerEndpoint));
    }

    TEST(StealthTrustTunnelConnError, ReadHandshakeWrongCreds)
    {
        Net::io_context Context;
        auto Pair = MakeOwnedMemoryPair(Context.get_executor());
        auto& [ClientEndpoint, ServerEndpoint] = Pair;

        RunMemoryCase(Context, Pair, RunTrustTunnelWrongCredentials(ClientEndpoint, ServerEndpoint));
    }

    TEST(StealthTrustTunnelConnError, WriteHandshakeIoError)
    {
        Net::io_context Context;
        auto Pair = MakeOwnedMemoryPair(Context.get_executor());
        auto& [ClientEndpoint, ServerEndpoint] = Pair;

        RunMemoryCase(Context, Pair, RunTrustTunnelWriteHandshakeIoError(
            ClientEndpoint, ServerEndpoint));
    }

    TEST(StealthTrustTunnelConnError, ReadHandshakeRejectsOverreportedRead)
    {
        Net::io_context Context;
        auto Raw = std::make_shared<PrismMockTransport>(Context.get_executor());
        Raw->OverreportRead = true;
        auto Creation = Trusttunnel::Detail::Conn<>::Create(
            Trusttunnel::ConnRequest{Raw, "user", "pass"});
        if (!Creation)
        {
            CheckTransmissionClose(DriveCloseTransmission(Context, Raw));
        }
        ASSERT_TRUE(Creation);
        auto Server = std::move(*Creation);

        RunCoroutine(Context,
                 [&]() -> Net::awaitable<void>
                 {
                     std::string Target;
                     EXPECT_EQ(co_await Server->ReadHandshake(Target), Error::BadLength);
                 });

        CheckTransmissionClose(DriveCloseTransmission(Context, Server));
    }

    TEST(StealthTrustTunnelConnError, PreservesPayloadCoalescedWithHandshake)
    {
        Net::io_context Context;
        auto Pair = MakeOwnedMemoryPair(Context.get_executor());
        auto& [ClientEndpoint, ServerEndpoint] = Pair;
        const std::string Payload = "trusttunnel coalesced payload";
        bool Ok = false;

        RunMemoryCase(Context, Pair, RunTrustTunnelPayload(
            TrustTunnelPayloadRequest{ClientEndpoint, ServerEndpoint, Payload, Ok}));

        EXPECT_TRUE(Ok);
    }

    TEST(StealthTrustTunnelConnError, NotOpenReadWrite)
    {
        Net::io_context Context;
        auto Pair = MakeOwnedMemoryPair(Context.get_executor());
        auto& [ClientEndpoint, ServerEndpoint] = Pair;
        auto Creation = Trusttunnel::Detail::Conn<>::Create(Trusttunnel::ConnRequest{
            ClientEndpoint, "user", "pass"});
        if (!Creation)
        {
            CheckTransmissionClose(DriveCloseTransmission(Context, Pair.Client));
            CheckTransmissionClose(DriveCloseTransmission(Context, Pair.Server));
        }
        ASSERT_TRUE(Creation);
        auto Conn = std::move(*Creation);
        RunMemoryCase(Context, Pair, CheckNotOpenReadWrite(Conn));
    }

    // =========================================================================
    // gun Conn 错误路径
    // =========================================================================

    TEST(StealthGunConnError, ReadHandshakeEof)
    {
        Net::io_context Context;
        auto Pair = MakeOwnedMemoryPair(Context.get_executor());
        auto& [ClientEndpoint, ServerEndpoint] = Pair;

        RunMemoryCase(Context, Pair,
                 [&]() -> Net::awaitable<void>
                 {
                     auto Server = std::make_shared<Gun::Conn<>>(
                         ServerEndpoint);
                     co_await ExpectCloseTransmission(ClientEndpoint); // 对端关闭 → 无 CONNECT 首行 → bad_magic
                     std::string Host;
                     const auto ErrorValue = co_await Server->ReadHandshake(Host);
                     EXPECT_EQ(ErrorValue, Error::BadMagic);
                     co_await ExpectCloseTransmission(Server);
        });
    }

    TEST(StealthGunConnError, ReadHandshakeRejectsOverreportedRead)
    {
        Net::io_context Context;
        auto Raw = std::make_shared<PrismMockTransport>(Context.get_executor());
        Raw->OverreportRead = true;
        auto Server = std::make_shared<Gun::Conn<>>(Raw);

        RunCoroutine(Context,
                 [&]() -> Net::awaitable<void>
                 {
                     std::string Host;
                     EXPECT_EQ(co_await Server->ReadHandshake(Host), Error::BadLength);
                 });

        CheckTransmissionClose(DriveCloseTransmission(Context, Server));
    }

    TEST(StealthGunConnError, ReadHandshakeBadMagic)
    {
        Net::io_context Context;
        auto Pair = MakeOwnedMemoryPair(Context.get_executor());
        auto& [ClientEndpoint, ServerEndpoint] = Pair;

        RunMemoryCase(Context, Pair, RunGunReadBadMagic(ClientEndpoint, ServerEndpoint));
    }

    TEST(StealthGunConnError, WriteHandshakeIoError)
    {
        Net::io_context Context;
        auto Pair = MakeOwnedMemoryPair(Context.get_executor());
        auto& [ClientEndpoint, ServerEndpoint] = Pair;

        RunMemoryCase(Context, Pair,
                 [&]() -> Net::awaitable<void>
                 {
                     auto Client = std::make_shared<Gun::Conn<>>(
                         ClientEndpoint);
                     co_await ExpectCloseTransmission(ServerEndpoint); // 对端全关 → 发送 CONNECT 帧失败 → io_error
                     const auto ErrorValue = co_await Client->WriteHandshake("example.com");
                     EXPECT_EQ(ErrorValue, Error::IoError);
                     co_await ExpectCloseTransmission(Client);
                 });
    }

    TEST(StealthGunConnError, NotOpenReadWrite)
    {
        Net::io_context Context;
        auto Pair = MakeOwnedMemoryPair(Context.get_executor());
        auto& [ClientEndpoint, ServerEndpoint] = Pair;
        auto Conn = std::make_shared<Gun::Conn<>>(ClientEndpoint);
        RunMemoryCase(Context, Pair, CheckNotOpenReadWrite(Conn));
    }

    // =========================================================================
    // WebSocket Conn 错误路径
    // =========================================================================

    TEST(StealthWsConnError, WriteHandshakeNon101)
    {
        Net::io_context Context;
        auto Pair = MakeOwnedMemoryPair(Context.get_executor());
        auto& [ClientEndpoint, ServerEndpoint] = Pair;

        RunMemoryCase(Context, Pair, RunWsBadStatusCase(
            ClientEndpoint, ServerEndpoint));
    }

    TEST(StealthWsConnError, WriteHandshakeBadAccept)
    {
        Net::io_context Context;
        auto Pair = MakeOwnedMemoryPair(Context.get_executor());
        auto& [ClientEndpoint, ServerEndpoint] = Pair;

        RunMemoryCase(Context, Pair, RunWsBadAcceptCase(
            ClientEndpoint, ServerEndpoint));
    }

    TEST(StealthWsConnError, WriteHandshakeEof)
    {
        Net::io_context Context;
        auto Pair = MakeOwnedMemoryPair(Context.get_executor());
        auto& [ClientEndpoint, ServerEndpoint] = Pair;

        RunMemoryCase(Context, Pair, RunWsCloseCase(
            ClientEndpoint, ServerEndpoint));
    }

    TEST(StealthWsConnError, ReadHandshakeBadMagic)
    {
        Net::io_context Context;
        auto Pair = MakeOwnedMemoryPair(Context.get_executor());
        auto& [ClientEndpoint, ServerEndpoint] = Pair;

        RunMemoryCase(Context, Pair, RunWsReadBadMagic(ClientEndpoint, ServerEndpoint));
    }

    TEST(StealthWsConnError, ReadHandshakeRejectsOverreportedRead)
    {
        Net::io_context Context;
        auto Raw = std::make_shared<PrismMockTransport>(Context.get_executor());
        Raw->OverreportRead = true;
        auto Server = std::make_shared<Ws::Detail::StreamOwner<>>(Raw, Prism::Tests::WsFactorySupport::WebSocketTestBytes(), false);

        RunCoroutine(Context,
                 [&]() -> Net::awaitable<void>
                 {
                     std::string Key;
                      const auto Result = co_await Server->ReadHandshake(Key);
                      EXPECT_FALSE(Result);
                      if (!Result)
                      {
                          EXPECT_EQ(Result.error().Code, Prism::Fault::Code::BadMessage);
                      }
                 });

        CheckTransmissionClose(DriveCloseTransmission(Context, Server));
    }

    TEST(StealthWsConnError, ReadHandshakeMissingKey)
    {
        Net::io_context Context;
        auto Pair = MakeOwnedMemoryPair(Context.get_executor());
        auto& [ClientEndpoint, ServerEndpoint] = Pair;

        RunMemoryCase(Context, Pair, RunWsReadMissingKey(ClientEndpoint, ServerEndpoint));
    }

    TEST(StealthWsConnError, ReadHandshakeIoError)
    {
        Net::io_context Context;
        auto Pair = MakeOwnedMemoryPair(Context.get_executor());
        auto& [ClientEndpoint, ServerEndpoint] = Pair;

        RunMemoryCase(Context, Pair, RunWsReadIoError(ClientEndpoint, ServerEndpoint));
    }

    TEST(StealthWsConnError, NotOpenReadWrite)
    {
        Net::io_context Context;
        auto Pair = MakeOwnedMemoryPair(Context.get_executor());
        auto& [ClientEndpoint, ServerEndpoint] = Pair;
        auto Conn = std::make_shared<Ws::Detail::StreamOwner<>>(
            ClientEndpoint,
            Prism::Tests::WsFactorySupport::WebSocketTestBytes(), false);
        RunMemoryCase(Context, Pair, CheckNotOpenReadWrite(Conn));
    }


