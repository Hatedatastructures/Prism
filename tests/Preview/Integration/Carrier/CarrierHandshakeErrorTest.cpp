/**
 * @file CarrierHandshakeErrorTest.cpp
 * @brief AnyTLS、ShadowTLS 与 Restls Conn 错误测试。
 */
#include "CarrierErrorFixture.hpp"

/** @brief 完整执行 ReadHandshakeBadLength 场景并排空协议连接。 */
auto RunRestlsReadBadLength(SharedTransmission ClientEndpoint, SharedTransmission ServerEndpoint)
    -> Net::awaitable<void>
{
    // ServerRandom 长度非法（33 字节）→ bad_length
    auto Server = std::make_shared<Restls::Detail::Conn<>>(
    ServerEndpoint, "pw");
    const std::array<std::uint8_t, 33> LongRandom{};
    const auto ErrorValue =
    co_await Server->ReadHandshake(std::span<const std::uint8_t>(LongRandom));
    EXPECT_EQ(ErrorValue, Error::BadLength);
    co_await ExpectCloseTransmission(Server);
    co_return;
}


/** @brief 完整执行 WriteHandshakeBadLength 场景并排空协议连接。 */
auto RunRestlsWriteBadLength(SharedTransmission ClientEndpoint, SharedTransmission ServerEndpoint)
    -> Net::awaitable<void>
{
    // ServerRandom 长度非法（31 字节）→ bad_length
    auto Client = std::make_shared<Restls::Detail::Conn<>>(
    ClientEndpoint, "pw");
    const std::array<std::uint8_t, 31> ShortRandom{};
    const auto ErrorValue =
    co_await Client->WriteHandshake(std::span<const std::uint8_t>(ShortRandom));
    EXPECT_EQ(ErrorValue, Error::BadLength);
    co_await ExpectCloseTransmission(Client);
    co_return;
}


/** @brief 完整执行 ReadHandshakeEof 场景并排空协议连接。 */
auto RunAnyTlsReadEof(SharedTransmission ClientEndpoint, SharedTransmission ServerEndpoint)
    -> Net::awaitable<void>
{
    // 服务端：对端直接关闭 → 读帧头 EOF → unexpected_eof
    auto Server =
    std::make_shared<Anytls::Conn<>>(
    ServerEndpoint, "pw");
    co_await ExpectCloseTransmission(ClientEndpoint);
    const auto ErrorValue = co_await Server->ReadHandshake();
    EXPECT_EQ(ErrorValue, Error::UnexpectedEof);
    co_await ExpectCloseTransmission(Server);
    co_return;
}


auto RunAnyTlsPartialFrame(SharedTransmission Client, SharedTransmission Server) -> Net::awaitable<void>;

auto RunAnyTlsBadAuth(SharedTransmission Client, SharedTransmission Server) -> Net::awaitable<void>;

auto RunShadowTlsBadAuth(SharedTransmission Client, SharedTransmission Server) -> Net::awaitable<void>;

TEST(StealthAnyTlsConnError, ReadHandshakeEof)
    {
        Net::io_context Context;
        auto Pair = MakeOwnedMemoryPair(Context.get_executor());
        auto& [ClientEndpoint, ServerEndpoint] = Pair;

        RunMemoryCase(Context, Pair, RunAnyTlsReadEof(ClientEndpoint, ServerEndpoint));

    }

    TEST(StealthAnyTlsConnError, ReadHandshakePartialFrameEof)
    {
        Net::io_context Context;
        auto Pair = MakeOwnedMemoryPair(Context.get_executor());
        auto& [ClientEndpoint, ServerEndpoint] = Pair;

        RunMemoryCase(Context, Pair, RunAnyTlsPartialFrame(ClientEndpoint, ServerEndpoint));

    }

    TEST(StealthAnyTlsConnError, ReadHandshakeBadAuth)
    {
        Net::io_context Context;
        auto Pair = MakeOwnedMemoryPair(Context.get_executor());
        auto& [ClientEndpoint, ServerEndpoint] = Pair;

        RunMemoryCase(Context, Pair, RunAnyTlsBadAuth(ClientEndpoint, ServerEndpoint));
    }

    TEST(StealthAnyTlsConnError, WriteHandshakeIoError)
    {
        Net::io_context Context;
        auto Pair = MakeOwnedMemoryPair(Context.get_executor());
        auto& [ClientEndpoint, ServerEndpoint] = Pair;

        RunMemoryCase(Context, Pair,
                 [&]() -> Net::awaitable<void>
                 {
                     auto Client = std::make_shared<Anytls::Conn<>>(
                         ClientEndpoint, "pw");
                     co_await ExpectCloseTransmission(ServerEndpoint); // 对端全关 → 发送失败 → io_error
                     const auto ErrorValue = co_await Client->WriteHandshake();
                     EXPECT_EQ(ErrorValue, Error::IoError);
                     co_await ExpectCloseTransmission(Client);
                 });
    }

    TEST(StealthAnyTlsConnError, NotOpenReadWrite)
    {
        Net::io_context Context;
        auto Pair = MakeOwnedMemoryPair(Context.get_executor());
        auto& [ClientEndpoint, ServerEndpoint] = Pair;
        auto Conn = std::make_shared<Anytls::Conn<>>(ClientEndpoint, "pw");
        RunMemoryCase(Context, Pair, CheckNotOpenReadWrite(Conn));
    }

    // =========================================================================
    // ShadowTLS v3 Conn 错误路径
    // =========================================================================

    TEST(StealthShadowTlsConnError, ReadHandshakeEof)
    {
        Net::io_context Context;
        auto Pair = MakeOwnedMemoryPair(Context.get_executor());
        auto& [ClientEndpoint, ServerEndpoint] = Pair;

        RunMemoryCase(Context, Pair,
                 [&]() -> Net::awaitable<void>
                 {
                     auto Server = std::make_shared<Shadowtls::Detail::Conn<>>(
                         ServerEndpoint, "pw");
                     co_await ExpectCloseTransmission(ClientEndpoint); // 对端关闭 → 读 ClientHello EOF → unexpected_eof
                     const auto ErrorValue = co_await Server->ReadHandshake();
                     EXPECT_EQ(ErrorValue, Error::UnexpectedEof);
                     co_await ExpectCloseTransmission(Server);
        });
    }

    TEST(StealthShadowTlsConnError, ReadHandshakeRejectsOverreportedRead)
    {
        Net::io_context Context;
        auto Raw = std::make_shared<Preview::PreviewMockTransport>(Context.get_executor());
        Raw->OverreportRead = true;
        auto Server = std::make_shared<Shadowtls::Detail::Conn<>>(Raw, "pw");

        RunCoroutine(Context,
                 [&]() -> Net::awaitable<void>
                 {
                     const auto ErrorValue = co_await Server->ReadHandshake();
                     EXPECT_EQ(ErrorValue, Error::UnexpectedEof);
                     EXPECT_EQ(Raw->ReadsDone, 1u);
                 });

        CheckTransmissionClose(DriveCloseTransmission(Context, Server));
    }

    TEST(StealthShadowTlsConnError, ReadHandshakeBadAuth)
    {
        Net::io_context Context;
        auto Pair = MakeOwnedMemoryPair(Context.get_executor());
        auto& [ClientEndpoint, ServerEndpoint] = Pair;
        RunMemoryCase(Context, Pair, RunShadowTlsBadAuth(ClientEndpoint, ServerEndpoint));
    }

    TEST(StealthShadowTlsConnError, WriteHandshakeIoError)
    {
        Net::io_context Context;
        auto Pair = MakeOwnedMemoryPair(Context.get_executor());
        auto& [ClientEndpoint, ServerEndpoint] = Pair;
        const auto ServerRandom = MakeRandom(0x33, Shadowtls::TlsRndSize);
        const auto ClientRandom = MakeRandom(0x44, Shadowtls::TlsRndSize);

        RunMemoryCase(Context, Pair,
                 [&]() -> Net::awaitable<void>
                 {
                     auto Client = std::make_shared<Shadowtls::Detail::Conn<>>(
                         ClientEndpoint, "pw");
                     co_await ExpectCloseTransmission(ServerEndpoint); // 对端全关 → 发送失败 → io_error
                     const auto ErrorValue = co_await Client->WriteHandshake(
                         std::span<const std::uint8_t>(ServerRandom), std::span<const std::uint8_t>(ClientRandom));
                     EXPECT_EQ(ErrorValue, Error::IoError);
                     co_await ExpectCloseTransmission(Client);
                 });
    }

    TEST(StealthShadowTlsConnError, NotOpenReadWrite)
    {
        Net::io_context Context;
        auto Pair = MakeOwnedMemoryPair(Context.get_executor());
        auto& [ClientEndpoint, ServerEndpoint] = Pair;
        auto Conn =
            std::make_shared<Shadowtls::Detail::Conn<>>(ClientEndpoint, "pw");
        RunMemoryCase(Context, Pair, CheckNotOpenReadWrite(Conn));
    }

    /// 验证 AnyTLS 帧头部分写入后半关闭会返回 EOF。
    auto RunAnyTlsPartialFrame(SharedTransmission Client, SharedTransmission Server)
        -> Net::awaitable<void>
    {
        auto Connection = std::make_shared<Anytls::Conn<>>(
            Server, "pw");
        std::string Frame;
        EXPECT_EQ(Anytls::BuildAuthFrame("pw", 16, Frame), Error::None);
        const auto Write = co_await Client->WriteSome(
            AsBytes(AsU8Span(Frame).first(Anytls::AuthFrameHdrlen)));
        ExpectFullWrite(Write, Anytls::AuthFrameHdrlen);
        const auto Shutdown = co_await Client->WriteShutdown();
        EXPECT_TRUE(Shutdown);
        const auto Result = co_await Connection->ReadHandshake();
        EXPECT_EQ(Result, Error::UnexpectedEof);
        co_await ExpectCloseTransmission(Connection);
    }

    /// 验证 AnyTLS 错误密码会被服务端拒绝。
    auto RunAnyTlsBadAuth(SharedTransmission Client, SharedTransmission Server) -> Net::awaitable<void>
    {
        auto Connection = std::make_shared<Anytls::Conn<>>(
            Server, "Expect-pw");
        std::string Frame;
        EXPECT_EQ(Anytls::BuildAuthFrame("wrong-pw", 16, Frame), Error::None);
        const auto Write = co_await Client->WriteSome(AsBytes(AsU8Span(Frame)));
        ExpectFullWrite(Write, Frame.size());
        const auto Result = co_await Connection->ReadHandshake();
        EXPECT_EQ(Result, Error::BadAuth);
        co_await ExpectCloseTransmission(Connection);
    }

    /// 验证 ShadowTLS 错误密码的 ClientHello 会被拒绝。
    auto RunShadowTlsBadAuth(SharedTransmission Client, SharedTransmission Server) -> Net::awaitable<void>
    {
        const auto ServerRandom = MakeRandom(0x11, Shadowtls::TlsRndSize);
        const auto ClientRandom = MakeRandom(0x22, Shadowtls::TlsRndSize);
        auto ClientConnection = std::make_shared<Shadowtls::Detail::Conn<>>(
            Client, "wrong-pw");
        const auto WriteResult = co_await ClientConnection->WriteHandshake(
            std::span<const std::uint8_t>(ServerRandom),
            std::span<const std::uint8_t>(ClientRandom));
        EXPECT_EQ(WriteResult, Error::None);
        auto ServerConnection = std::make_shared<Shadowtls::Detail::Conn<>>(
            Server, "Expect-pw");
        const auto ReadResult = co_await ServerConnection->ReadHandshake();
        EXPECT_EQ(ReadResult, Error::BadAuth);
        co_await ExpectCloseTransmission(ClientConnection);
        co_await ExpectCloseTransmission(ServerConnection);
    }

    // =========================================================================
    // Restls Conn 错误路径
    // =========================================================================

    TEST(StealthRestlsConnError, WriteHandshakeBadLength)
    {
        Net::io_context Context;
        auto Pair = MakeOwnedMemoryPair(Context.get_executor());
        auto& [ClientEndpoint, ServerEndpoint] = Pair;

        RunMemoryCase(Context, Pair, RunRestlsWriteBadLength(ClientEndpoint, ServerEndpoint));
    }

    TEST(StealthRestlsConnError, ReadHandshakeBadLength)
    {
        Net::io_context Context;
        auto Pair = MakeOwnedMemoryPair(Context.get_executor());
        auto& [ClientEndpoint, ServerEndpoint] = Pair;

        RunMemoryCase(Context, Pair, RunRestlsReadBadLength(ClientEndpoint, ServerEndpoint));
    }

    TEST(StealthRestlsConnError, NotOpenReadWrite)
    {
        Net::io_context Context;
        auto Pair = MakeOwnedMemoryPair(Context.get_executor());
        auto& [ClientEndpoint, ServerEndpoint] = Pair;
        auto Conn = std::make_shared<Restls::Detail::Conn<>>(ClientEndpoint, "pw");
        RunMemoryCase(Context, Pair, CheckNotOpenReadWrite(Conn));
    }

    // =========================================================================
    // TrustTunnel Conn 错误路径
    // =========================================================================

