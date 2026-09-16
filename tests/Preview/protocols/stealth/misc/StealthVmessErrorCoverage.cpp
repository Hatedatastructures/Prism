/**
 * @file StealthVmessErrorCoverage.cpp
 * @brief stealth Conn 与 vmess Conn 错误路径覆盖
 * @details 针对测试库 Conn 装饰器的握手错误路径与数据面错误分支：
 * 1. stealth 各方案（anytls / shadowtls / reality / restls /
 *    trusttunnel / gun / ws）ReadHandshake / WriteHandshake
 *    错误路径：底层 EOF、校验失败（bad_auth）、魔数不匹配
 *    （bad_magic）、密钥派生失败（kdf_error）、发送失败（io_error）
 * 2. vmess Conn 数据面错误分支：未握手读写（not_open）、
 *    chunk 解密失败（bad_auth）、EOF（unexpected_eof）、
 *    结束块（Finish）→ 流结束（0 且无错误）
 * @note 使用 MakeMemoryPair 建立内存传输对，手动注入合法/非法
 *       字节流触发各错误分支；全部采用 co_spawn + ioc.run() 模式。
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <exception>
#include <memory>
#include <string>
#include <span>
#include <system_error>
#include <utility>
#include <vector>

#include <Preview/Transport/MemoryStream.hpp>
#include <TestSupport/Preview/PreviewMockTransport.hpp>
#include <Preview/Protocols/Vmess/Codec.hpp>
#include <Preview/Protocols/Vmess/Vmess.hpp>
#include <Preview/Protocols/Anytls/Codec.hpp>
#include <Preview/Protocols/Anytls/Conn.hpp>
#include <Preview/Protocols/Gun/Conn.hpp>
#include <Preview/Protocols/Reality/Codec.hpp>
#include <Preview/Protocols/Reality/Conn.hpp>
#include <Preview/Protocols/Restls/Conn.hpp>
#include <Preview/Protocols/Shadowtls/Conn.hpp>
#include <Preview/Protocols/Trusttunnel/Codec.hpp>
#include <Preview/Protocols/Trusttunnel/Conn.hpp>
#include <Preview/Protocols/Ws/Codec.hpp>
#include <Preview/Protocols/Ws/Conn.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    namespace PreviewApi = ::Preview;
    namespace Anytls = PreviewApi::Anytls;
    namespace Shadowtls = PreviewApi::Shadowtls;
    namespace Reality = PreviewApi::Reality;
    namespace Restls = PreviewApi::Restls;
    namespace Trusttunnel = PreviewApi::Trusttunnel;
    namespace Gun = PreviewApi::Gun;
    namespace Ws = PreviewApi::Ws;
    namespace Vmess = PreviewApi::Vmess;

    using PreviewApi::AsBytes;
    using PreviewApi::AsU8Span;
    using PreviewApi::Error;
    using PreviewApi::MakeMemoryPair;
    using PreviewApi::MemoryStream;
    using PreviewApi::PreviewMockTransport;
    using SharedTransmission = PreviewApi::SharedTransmission;
    using CompletionChannel = Net::experimental::channel<void(boost::system::error_code)>;

    struct TaskState final
    {
        std::shared_ptr<CompletionChannel> Done;
        std::shared_ptr<std::exception_ptr> Exception;
    };

    template <typename Awaitable>
    auto SpawnTask(Net::any_io_executor Executor, Awaitable Operation) -> TaskState
    {
        TaskState State;
        State.Done = std::make_shared<CompletionChannel>(Executor, 1);
        State.Exception = std::make_shared<std::exception_ptr>();
        auto Completion = [State](std::exception_ptr ErrorValue) -> void
        {
            *State.Exception = ErrorValue;
            (void)State.Done->try_send(boost::system::error_code{});
        };
        Net::co_spawn(Executor, std::move(Operation), std::move(Completion));
        return State;
    }

    auto WaitForTask(TaskState State) -> Net::awaitable<void>
    {
        boost::system::error_code WaitError;
        auto ReceiveOperation = State.Done->async_receive(
            Net::redirect_error(Net::use_awaitable, WaitError));
        (void)co_await std::move(ReceiveOperation);
        if (WaitError)
        {
            throw std::system_error(WaitError);
        }
        if (*State.Exception)
        {
            std::rethrow_exception(*State.Exception);
        }
        co_return;
    }

    /// 运行协程直至完成（异常重抛）
    template <typename Awaitable>
    auto RunCoroutine(Net::io_context &Context, Awaitable Operation) -> void
    {
        auto Exception = std::make_shared<std::exception_ptr>();
        auto Completion = [Exception, ContextPointer = &Context](std::exception_ptr ErrorValue) -> void
        {
            *Exception = ErrorValue;
            ContextPointer->stop();
        };
        Net::co_spawn(Context, std::move(Operation), std::move(Completion));
        Context.run();
        if (*Exception)
        {
            std::rethrow_exception(*Exception);
        }
    }

    /// 构造固定模式随机数
    auto MakeRandom(std::uint8_t Seed, std::size_t Length) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Result(Length);
        for (std::size_t Index = 0; Index < Length; ++Index)
        {
            Result[Index] = static_cast<std::uint8_t>(Index * 7 + Seed);
        }
        return Result;
    }

    /// 字符串 → 字节视图写入（测试辅助）
    auto WriteRaw(MemoryStream &Stream, std::string_view Data) -> Net::awaitable<void>
    {
        std::error_code ErrorCode;
        const auto DataBytes = std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(Data.data()), Data.size());
        auto WriteOperation = Stream.async_write_some(DataBytes, ErrorCode);
        (void)co_await std::move(WriteOperation);
        co_return;
    }

    /// 未握手 Conn：读写返回 not_open（所有 stealth 方案共用）
    template <typename ConnectionType>
    auto CheckNotOpenReadWrite(
        const std::shared_ptr<ConnectionType> &Connection,
        Net::io_context &Context) -> void
    {
        RunCoroutine(Context,
                 [Connection]() -> Net::awaitable<void>
                 {
                     std::array<std::byte, 64> Buffer{};
                     std::error_code ErrorCode;
                     auto ReadOperation = Connection->async_read_some(Buffer, ErrorCode);
                     const auto BytesRead = co_await std::move(ReadOperation);
                     EXPECT_EQ(BytesRead, 0u);
                     EXPECT_EQ(ErrorCode, make_error_code(Error::NotOpen));
                     ErrorCode.clear();
                     const auto WriteBuffer = std::span<const std::byte>(Buffer.data(), 4);
                     auto WriteOperation = Connection->async_write_some(WriteBuffer, ErrorCode);
                     const auto BytesWritten = co_await std::move(WriteOperation);
                     EXPECT_EQ(BytesWritten, 0u);
                     EXPECT_EQ(ErrorCode, make_error_code(Error::NotOpen));
                 });
    }

    template <typename Awaitable>
    auto run_coro(Net::io_context &Context, Awaitable Operation) -> void
    {
        RunCoroutine(Context, std::move(Operation));
    }

    auto make_random(std::uint8_t Seed, std::size_t Length) -> std::vector<std::uint8_t>
    {
        return MakeRandom(Seed, Length);
    }

    auto write_raw(MemoryStream &Stream, std::string_view Data) -> Net::awaitable<void>
    {
        co_await WriteRaw(Stream, Data);
    }

    template <typename ConnectionType>
    auto check_not_open_read_write(
        const std::shared_ptr<ConnectionType> &Connection,
        Net::io_context &Context) -> void
    {
        CheckNotOpenReadWrite(Connection, Context);
    }

    auto CloseTransmission(const SharedTransmission &Transport) -> void
    {
        if (Transport)
        {
            Transport->Cancel();
            Transport->Close();
        }
    }

    auto RunWsBadStatusServer(SharedTransmission Server) -> Net::awaitable<void>
    {
        std::array<std::uint8_t, 512> RequestBuffer{};
        std::error_code ErrorCode;
        const auto RequestBytes = AsBytes(std::span<std::uint8_t>(RequestBuffer));
        auto ReadOperation = Server->async_read_some(RequestBytes, ErrorCode);
        const auto BytesRead = co_await std::move(ReadOperation);
        EXPECT_GT(BytesRead, 0U);
        const std::string Response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        const auto ResponseBytes = std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(Response.data()), Response.size());
        auto WriteOperation = Server->async_write_some(ResponseBytes, ErrorCode);
        (void)co_await std::move(WriteOperation);
        co_return;
    }

    auto RunWsBadAcceptServer(SharedTransmission Server) -> Net::awaitable<void>
    {
        std::array<std::uint8_t, 512> RequestBuffer{};
        std::error_code ErrorCode;
        const auto RequestBytes = AsBytes(std::span<std::uint8_t>(RequestBuffer));
        auto ReadOperation = Server->async_read_some(RequestBytes, ErrorCode);
        const auto BytesRead = co_await std::move(ReadOperation);
        EXPECT_GT(BytesRead, 0U);
        const std::string Response =
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Accept: wrong-Accept-value\r\n\r\n";
        const auto ResponseBytes = std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(Response.data()), Response.size());
        auto WriteOperation = Server->async_write_some(ResponseBytes, ErrorCode);
        (void)co_await std::move(WriteOperation);
        co_return;
    }

    auto RunWsCloseServer(SharedTransmission Server) -> Net::awaitable<void>
    {
        std::array<std::uint8_t, 512> RequestBuffer{};
        std::error_code ErrorCode;
        const auto RequestBytes = AsBytes(std::span<std::uint8_t>(RequestBuffer));
        auto ReadOperation = Server->async_read_some(RequestBytes, ErrorCode);
        const auto BytesRead = co_await std::move(ReadOperation);
        EXPECT_GT(BytesRead, 0U);
        CloseTransmission(Server);
        co_return;
    }

    auto RunVmessGarbageServer(SharedTransmission Server) -> Net::awaitable<void>
    {
        std::array<std::uint8_t, 18> Garbage{};
        Garbage.fill(0xFF);
        std::error_code ErrorCode;
        const auto GarbageBytes = AsBytes(std::span<const std::uint8_t>(Garbage));
        auto WriteOperation = Server->async_write_some(GarbageBytes, ErrorCode);
        (void)co_await std::move(WriteOperation);
        EXPECT_FALSE(ErrorCode);
        co_return;
    }

    auto RunVmessBadChunkServer(
        SharedTransmission Server,
        std::array<std::uint8_t, 16> Uuid) -> Net::awaitable<void>
    {
        Vmess::ServerConfig Config;
        Config.uuid = Uuid;
        auto [ErrorCode, Request, Connection] = co_await Vmess::Accept(Server, Config);
        if (ErrorCode != Error::None || !Connection)
        {
            EXPECT_TRUE(false) << "Accept Failed";
            co_return;
        }
        const auto ResponseBodyKey = Vmess::detail::Sha256(Request.RequestKey);
        const auto ResponseBodyIv = Vmess::detail::Sha256(Request.RequestNonce);
        std::array<std::uint8_t, 16> ResponseKey{};
        std::array<std::uint8_t, 16> ResponseNonce{};
        std::memcpy(ResponseKey.data(), ResponseBodyKey.data(), ResponseKey.size());
        std::memcpy(ResponseNonce.data(), ResponseBodyIv.data(), ResponseNonce.size());
        Vmess::ChunkEncryptor Encoder(
            std::span<const std::uint8_t, 16>(ResponseKey),
            std::span<const std::uint8_t, 16>(ResponseNonce),
            Request.Option);
        std::array<std::uint8_t, 64> Garbage{};
        const std::array<std::uint8_t, 1> Payload{0xA5};
        const auto FrameSize = Encoder.Seal(Payload, Garbage);
        Garbage[FrameSize - 1] ^= 0xFF;
        const auto GarbageBytes = AsBytes(
            std::span<const std::uint8_t>(Garbage).first(FrameSize));
        std::error_code WriteError;
        auto WriteOperation = Connection->NextLayer()->async_write_some(GarbageBytes, WriteError);
        (void)co_await std::move(WriteOperation);
        EXPECT_FALSE(WriteError);
        Connection->Close();
        co_return;
    }

    auto RunVmessCloseServer(
        SharedTransmission Server,
        std::array<std::uint8_t, 16> Uuid) -> Net::awaitable<void>
    {
        Vmess::ServerConfig Config;
        Config.uuid = Uuid;
        auto [ErrorCode, Request, Connection] = co_await Vmess::Accept(Server, Config);
        (void)Request;
        EXPECT_EQ(ErrorCode, Error::None);
        if (Connection)
        {
            Connection->Close();
        }
        co_return;
    }

    auto RunVmessFinishServer(
        SharedTransmission Server,
        std::array<std::uint8_t, 16> Uuid) -> Net::awaitable<void>
    {
        Vmess::ServerConfig Config;
        Config.uuid = Uuid;
        auto [ErrorCode, Request, Connection] = co_await Vmess::Accept(Server, Config);
        if (ErrorCode != Error::None || !Connection)
        {
            EXPECT_TRUE(false) << "Accept Failed";
            co_return;
        }
        const auto ResponseBodyKey = Vmess::detail::Sha256(Request.RequestKey);
        const auto ResponseBodyIv = Vmess::detail::Sha256(Request.RequestNonce);
        std::array<std::uint8_t, 16> ResponseKey{};
        std::array<std::uint8_t, 16> ResponseNonce{};
        std::memcpy(ResponseKey.data(), ResponseBodyKey.data(), ResponseKey.size());
        std::memcpy(ResponseNonce.data(), ResponseBodyIv.data(), ResponseNonce.size());
        Vmess::ChunkEncryptor Encoder(
            std::span<const std::uint8_t, 16>(ResponseKey),
            std::span<const std::uint8_t, 16>(ResponseNonce),
            Request.Option);
        std::array<std::uint8_t, 34> EndBlock{};
        const auto EndBlockSize = Encoder.Finish(EndBlock);
        const auto EndBlockBytes = AsBytes(
            std::span<const std::uint8_t>(EndBlock).first(EndBlockSize));
        std::error_code WriteError;
        auto WriteOperation = Connection->NextLayer()->async_write_some(EndBlockBytes, WriteError);
        (void)co_await std::move(WriteOperation);
        EXPECT_FALSE(WriteError);
        Connection->Close();
        co_return;
    }

    // =========================================================================
    // AnyTLS Conn 错误路径
    // =========================================================================

    TEST(StealthAnyTlsConnError, ReadHandshakeEof)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     // 服务端：对端直接关闭 → 读帧头 EOF → unexpected_eof
                     auto Server =
                         std::make_shared<Anytls::Conn<>>(std::make_shared<MemoryStream>(std::move(b)), "pw");
                     a.Close();
                     const auto err = co_await Server->ReadHandshake();
                     EXPECT_EQ(err, Error::UnexpectedEof);
                 });
    }

    TEST(StealthAnyTlsConnError, ReadHandshakePartialFrameEof)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto Server =
                         std::make_shared<Anytls::Conn<>>(std::make_shared<MemoryStream>(std::move(b)), "pw");
                     // 只发帧头（Hash + padlen），随后半关 → 读 padding 时 EOF
                     std::string Frame;
                     EXPECT_EQ(Anytls::BuildAuthFrame("pw", 16, Frame), Error::None);
                     std::error_code ec;
                     co_await a.async_write_some(
                         AsBytes(AsU8Span(Frame).first(Anytls::AuthFrameHdrlen)), ec);
                     EXPECT_FALSE(ec);
                     a.Shutdown();
                     const auto err = co_await Server->ReadHandshake();
                     EXPECT_EQ(err, Error::UnexpectedEof);
                 });
    }

    TEST(StealthAnyTlsConnError, ReadHandshakeBadAuth)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto Server = std::make_shared<Anytls::Conn<>>(
                         std::make_shared<MemoryStream>(std::move(b)), "Expect-pw");
                     // 客户端用错误密码构造认证帧 → 密码哈希不匹配 → bad_auth
                     std::string Frame;
                     EXPECT_EQ(Anytls::BuildAuthFrame("wrong-pw", 16, Frame), Error::None);
                     std::error_code ec;
                     co_await a.async_write_some(AsBytes(AsU8Span(Frame)), ec);
                     EXPECT_FALSE(ec);
                     const auto err = co_await Server->ReadHandshake();
                     EXPECT_EQ(err, Error::BadAuth);
                 });
    }

    TEST(StealthAnyTlsConnError, WriteHandshakeIoError)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto Client = std::make_shared<Anytls::Conn<>>(
                         std::make_shared<MemoryStream>(std::move(a)), "pw");
                     b.Close(); // 对端全关 → 发送失败 → io_error
                     const auto err = co_await Client->WriteHandshake();
                     EXPECT_EQ(err, Error::IoError);
                 });
    }

    TEST(StealthAnyTlsConnError, NotOpenReadWrite)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        auto Conn = std::make_shared<Anytls::Conn<>>(std::make_shared<MemoryStream>(std::move(a)), "pw");
        check_not_open_read_write(Conn, ioc);
    }

    // =========================================================================
    // ShadowTLS v3 Conn 错误路径
    // =========================================================================

    TEST(StealthShadowTlsConnError, ReadHandshakeEof)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto Server = std::make_shared<Shadowtls::Conn<>>(
                         std::make_shared<MemoryStream>(std::move(b)), "pw");
                     a.Close(); // 对端关闭 → 读 ClientHello EOF → unexpected_eof
                     const auto err = co_await Server->ReadHandshake();
                     EXPECT_EQ(err, Error::UnexpectedEof);
        });
    }

    TEST(StealthShadowTlsConnError, ReadHandshakeRejectsOverreportedRead)
    {
        Net::io_context ioc;
        auto Raw = std::make_shared<Preview::PreviewMockTransport>(ioc.get_executor());
        Raw->OverreportRead = true;

        run_coro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto Server = std::make_shared<Shadowtls::Conn<>>(Raw, "pw");
                     const auto err = co_await Server->ReadHandshake();
                     EXPECT_EQ(err, Error::UnexpectedEof);
                     EXPECT_EQ(Raw->ReadsDone, 1u);
                 });
    }

    TEST(StealthShadowTlsConnError, ReadHandshakeBadAuth)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        const auto server_rnd = make_random(0x11, Shadowtls::TlsRndSize);
        const auto client_rnd = make_random(0x22, Shadowtls::TlsRndSize);

        run_coro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     // 客户端用错误密码构造 ClientHello（SessionId HMAC 不匹配）
                     auto Client = std::make_shared<Shadowtls::Conn<>>(
                         std::make_shared<MemoryStream>(std::move(a)), "wrong-pw");
                     const auto werr = co_await Client->WriteHandshake(
                         std::span<const std::uint8_t>(server_rnd), std::span<const std::uint8_t>(client_rnd));
                     EXPECT_EQ(werr, Error::None);
                     auto Server = std::make_shared<Shadowtls::Conn<>>(
                         std::make_shared<MemoryStream>(std::move(b)), "Expect-pw");
                     const auto err = co_await Server->ReadHandshake();
                     EXPECT_EQ(err, Error::BadAuth);
                 });
    }

    TEST(StealthShadowTlsConnError, WriteHandshakeIoError)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        const auto server_rnd = make_random(0x33, Shadowtls::TlsRndSize);
        const auto client_rnd = make_random(0x44, Shadowtls::TlsRndSize);

        run_coro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto Client = std::make_shared<Shadowtls::Conn<>>(
                         std::make_shared<MemoryStream>(std::move(a)), "pw");
                     b.Close(); // 对端全关 → 发送失败 → io_error
                     const auto err = co_await Client->WriteHandshake(
                         std::span<const std::uint8_t>(server_rnd), std::span<const std::uint8_t>(client_rnd));
                     EXPECT_EQ(err, Error::IoError);
                 });
    }

    TEST(StealthShadowTlsConnError, NotOpenReadWrite)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        auto Conn =
            std::make_shared<Shadowtls::Conn<>>(std::make_shared<MemoryStream>(std::move(a)), "pw");
        check_not_open_read_write(Conn, ioc);
    }

    // =========================================================================
    // Reality Conn 错误路径
    // =========================================================================

    /// 生成 X25519 密钥对（断言成功，规避 nodiscard）
    auto make_keypair(std::array<std::uint8_t, Reality::KeyLen> &priv,
                      std::array<std::uint8_t, Reality::KeyLen> &pub) -> void
    {
        EXPECT_FALSE(Reality::GenerateKeypair(priv, pub));
    }

    /// 构造客户端密封的 SessionId（false = 成功）
    auto make_reality_sealed(std::span<const std::uint8_t> priv_cli,
                             std::span<const std::uint8_t> pub_srv,
                             std::span<const std::uint8_t> ClientRandom,
                             std::span<const std::uint8_t> hello,
                             std::span<const std::uint8_t, 8> ShortId,
                             std::array<std::uint8_t, Reality::SessionIdAuthLen> &sealed) -> bool
    {
        std::array<std::uint8_t, Reality::KeyLen> shared{};
        if (Reality::X25519Shared(priv_cli, pub_srv, shared))
        {
            return true;
        }
        std::array<std::uint8_t, Reality::KeyLen> AuthKey{};
        if (Reality::DeriveAuthKey(shared, ClientRandom, AuthKey))
        {
            return true;
        }
        std::array<std::uint8_t, 16> plain{};
        plain[0] = 0x01; // version = 1
        std::copy(ShortId.begin(), ShortId.end(), plain.begin() + 8);
        return Reality::SealSessionId(
            Reality::SessionIdSealInput{AuthKey, ClientRandom, plain, hello}, sealed);
    }

    TEST(StealthRealityConnError, ReadHandshakeEof)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        std::array<std::uint8_t, Reality::KeyLen> priv{};
        std::array<std::uint8_t, Reality::KeyLen> pub{};
        make_keypair(priv, pub);
        const auto ClientRandom = make_random(0x55, 32);
        const auto hello = make_random(0x66, 96);
        std::array<std::uint8_t, Reality::MaxShortIdLen> ShortId{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

        run_coro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto Server = std::make_shared<Reality::Conn<>>(
                         std::make_shared<MemoryStream>(std::move(b)), priv);
                     a.Close(); // 对端关闭 → 读 SessionId EOF → unexpected_eof
                     Reality::HandshakeParams params{std::span<const std::uint8_t>(ClientRandom), hello,
                                                      ShortId};
                     std::array<std::uint8_t, Reality::MaxShortIdLen> out_sid{};
                     const auto err = co_await Server->ReadHandshake(pub, params, out_sid);
                     EXPECT_EQ(err, Error::UnexpectedEof);
                 });
    }

    TEST(StealthRealityConnError, ReadHandshakeBadAuth)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        std::array<std::uint8_t, Reality::KeyLen> priv_cli{};
        std::array<std::uint8_t, Reality::KeyLen> pub_cli{};
        std::array<std::uint8_t, Reality::KeyLen> priv_srv{};
        std::array<std::uint8_t, Reality::KeyLen> pub_srv{};
        make_keypair(priv_cli, pub_cli);
        make_keypair(priv_srv, pub_srv);
        const auto ClientRandom = make_random(0x55, 32);
        const auto hello = make_random(0x66, 96);
        std::array<std::uint8_t, Reality::MaxShortIdLen> ShortId{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

        run_coro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     // 构造合法 sealed SessionId 后篡改 1 字节 → GCM tag 校验失败 → bad_auth
                     std::array<std::uint8_t, Reality::SessionIdAuthLen> sealed{};
                     EXPECT_FALSE(make_reality_sealed(priv_cli, pub_srv,
                                                      std::span<const std::uint8_t>(ClientRandom), hello,
                                                      ShortId, sealed));
                     sealed[0] ^= 0xFF;
                     std::error_code ec;
                     co_await a.async_write_some(AsBytes(std::span<const std::uint8_t>(sealed)), ec);
                     EXPECT_FALSE(ec);

                     auto Server = std::make_shared<Reality::Conn<>>(
                         std::make_shared<MemoryStream>(std::move(b)), priv_srv);
                     Reality::HandshakeParams params{std::span<const std::uint8_t>(ClientRandom), hello,
                                                      ShortId};
                     std::array<std::uint8_t, Reality::MaxShortIdLen> out_sid{};
                     const auto err = co_await Server->ReadHandshake(pub_cli, params, out_sid);
                     EXPECT_EQ(err, Error::BadAuth);
                 });
    }

    TEST(StealthRealityConnError, ReadHandshakeKdfError)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        std::array<std::uint8_t, Reality::KeyLen> priv{};
        std::array<std::uint8_t, Reality::KeyLen> pub{};
        make_keypair(priv, pub);
        const auto ClientRandom = make_random(0x55, 32);
        const auto hello = make_random(0x66, 96);
        std::array<std::uint8_t, Reality::MaxShortIdLen> ShortId{};

        run_coro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     // 先喂 32 字节（SessionId 读取），再以非法长度公钥 → kdf_error
                     std::array<std::uint8_t, 32> junk{};
                     junk.fill(0xAA);
                     std::error_code ec;
                     co_await a.async_write_some(AsBytes(std::span<const std::uint8_t>(junk)), ec);
                     EXPECT_FALSE(ec);

                     auto Server = std::make_shared<Reality::Conn<>>(
                         std::make_shared<MemoryStream>(std::move(b)), priv);
                     const std::array<std::uint8_t, 16> bad_pub{};
                     Reality::HandshakeParams params{std::span<const std::uint8_t>(ClientRandom), hello,
                                                      ShortId};
                     std::array<std::uint8_t, Reality::MaxShortIdLen> out_sid{};
                     const auto err = co_await Server->ReadHandshake(bad_pub, params, out_sid);
                     EXPECT_EQ(err, Error::KdfError);
                 });
    }

    TEST(StealthRealityConnError, WriteHandshakeKdfError)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        std::array<std::uint8_t, Reality::KeyLen> priv{};
        std::array<std::uint8_t, Reality::KeyLen> pub{};
        make_keypair(priv, pub);
        const auto ClientRandom = make_random(0x55, 32);
        const auto hello = make_random(0x66, 96);
        std::array<std::uint8_t, Reality::MaxShortIdLen> ShortId{};

        run_coro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto Client = std::make_shared<Reality::Conn<>>(
                         std::make_shared<MemoryStream>(std::move(a)), priv);
                     const std::array<std::uint8_t, 16> bad_pub{};
                     Reality::HandshakeParams params{std::span<const std::uint8_t>(ClientRandom), hello,
                                                      ShortId};
                     const auto err = co_await Client->WriteHandshake(bad_pub, params);
                     EXPECT_EQ(err, Error::KdfError);
                 });
    }

    TEST(StealthRealityConnError, WriteHandshakeIoError)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        std::array<std::uint8_t, Reality::KeyLen> priv_cli{};
        std::array<std::uint8_t, Reality::KeyLen> pub_cli{};
        std::array<std::uint8_t, Reality::KeyLen> priv_srv{};
        std::array<std::uint8_t, Reality::KeyLen> pub_srv{};
        make_keypair(priv_cli, pub_cli);
        make_keypair(priv_srv, pub_srv);
        const auto ClientRandom = make_random(0x55, 32);
        const auto hello = make_random(0x66, 96);
        std::array<std::uint8_t, Reality::MaxShortIdLen> ShortId{};

        run_coro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto Client = std::make_shared<Reality::Conn<>>(
                         std::make_shared<MemoryStream>(std::move(a)), priv_cli);
                     b.Close(); // 对端全关 → 发送 sealed SessionId 失败 → io_error
                     Reality::HandshakeParams params{std::span<const std::uint8_t>(ClientRandom), hello,
                                                      ShortId};
                     const auto err = co_await Client->WriteHandshake(pub_srv, params);
                     EXPECT_EQ(err, Error::IoError);
                 });
    }

    TEST(StealthRealityConnError, NotOpenReadWrite)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        auto Conn = std::make_shared<Reality::Conn<>>(std::make_shared<MemoryStream>(std::move(a)),
                                                      std::array<std::uint8_t, 32>{});
        check_not_open_read_write(Conn, ioc);
    }

    // =========================================================================
    // Restls Conn 错误路径
    // =========================================================================

    TEST(StealthRestlsConnError, WriteHandshakeBadLength)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     // ServerRandom 长度非法（31 字节）→ bad_length
                     auto Client = std::make_shared<Restls::Conn<>>(
                         std::make_shared<MemoryStream>(std::move(a)), "pw");
                     const std::array<std::uint8_t, 31> short_rnd{};
                     const auto err =
                         co_await Client->WriteHandshake(std::span<const std::uint8_t>(short_rnd));
                     EXPECT_EQ(err, Error::BadLength);
                 });
    }

    TEST(StealthRestlsConnError, ReadHandshakeBadLength)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     // ServerRandom 长度非法（33 字节）→ bad_length
                     auto Server = std::make_shared<Restls::Conn<>>(
                         std::make_shared<MemoryStream>(std::move(b)), "pw");
                     const std::array<std::uint8_t, 33> long_rnd{};
                     const auto err =
                         co_await Server->ReadHandshake(std::span<const std::uint8_t>(long_rnd));
                     EXPECT_EQ(err, Error::BadLength);
                 });
    }

    TEST(StealthRestlsConnError, NotOpenReadWrite)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        auto Conn = std::make_shared<Restls::Conn<>>(std::make_shared<MemoryStream>(std::move(a)), "pw");
        check_not_open_read_write(Conn, ioc);
    }

    // =========================================================================
    // TrustTunnel Conn 错误路径
    // =========================================================================

    TEST(StealthTrustTunnelConnError, ReadHandshakeEof)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto Server = std::make_shared<Trusttunnel::Conn<>>(
                         std::make_shared<MemoryStream>(std::move(b)), "user", "pass");
                     a.Close(); // 对端关闭 → 头块不完整 → bad_magic
                     std::string Target;
                     const auto err = co_await Server->ReadHandshake(Target);
                     EXPECT_EQ(err, Error::BadMagic);
                 });
    }

    TEST(StealthTrustTunnelConnError, ReadHandshakeBadMagic)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto Server = std::make_shared<Trusttunnel::Conn<>>(
                         std::make_shared<MemoryStream>(std::move(b)), "user", "pass");
                     // 非 CONNECT 首行 → bad_magic
                     co_await write_raw(a, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
                     std::string Target;
                     const auto err = co_await Server->ReadHandshake(Target);
                     EXPECT_EQ(err, Error::BadMagic);
                 });
    }

    TEST(StealthTrustTunnelConnError, ReadHandshakeMissingAuth)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto Server = std::make_shared<Trusttunnel::Conn<>>(
                         std::make_shared<MemoryStream>(std::move(b)), "user", "pass");
                     // CONNECT 但无 Proxy-Authorization 头 → bad_auth
                     co_await write_raw(a, "CONNECT example.com:443 HTTP/2\r\n\r\n");
                     std::string Target;
                     const auto err = co_await Server->ReadHandshake(Target);
                     EXPECT_EQ(err, Error::BadAuth);
                 });
    }

    TEST(StealthTrustTunnelConnError, ReadHandshakeWrongCreds)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto Server = std::make_shared<Trusttunnel::Conn<>>(
                         std::make_shared<MemoryStream>(std::move(b)), "user", "pass");
                     // Basic Auth 凭据错误 → bad_auth
                     const std::string Header =
                         "CONNECT example.com:443 HTTP/2\r\n"
                         "Proxy-Authorization: " +
                         Trusttunnel::BasicAuth("wrong", "creds") + "\r\n\r\n";
                     co_await write_raw(a, Header);
                     std::string Target;
                     const auto err = co_await Server->ReadHandshake(Target);
                     EXPECT_EQ(err, Error::BadAuth);
                 });
    }

    TEST(StealthTrustTunnelConnError, WriteHandshakeIoError)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto Client = std::make_shared<Trusttunnel::Conn<>>(
                         std::make_shared<MemoryStream>(std::move(a)), "user", "pass");
                     b.Close(); // 对端全关 → 发送 CONNECT 头失败 → io_error
                     const auto err = co_await Client->WriteHandshake("example.com", 443);
                     EXPECT_EQ(err, Error::IoError);
        });
    }

    TEST(StealthTrustTunnelConnError, ReadHandshakeRejectsOverreportedRead)
    {
        Net::io_context ioc;
        auto Raw = std::make_shared<PreviewMockTransport>(ioc.get_executor());
        Raw->OverreportRead = true;
        auto Server = std::make_shared<Trusttunnel::Conn<>>(Raw, "user", "pass");

        run_coro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     std::string Target;
                     EXPECT_EQ(co_await Server->ReadHandshake(Target), Error::BadLength);
                 });
    }

    TEST(StealthTrustTunnelConnError, PreservesPayloadCoalescedWithHandshake)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        const std::string Payload = "trusttunnel coalesced payload";
        bool Ok = false;

        run_coro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto Server = std::make_shared<Trusttunnel::Conn<>>(
                         std::make_shared<MemoryStream>(std::move(b)), "user", "pass");
                     const std::string Header =
                         "CONNECT example.com:443 HTTP/2\r\nProxy-Authorization: " +
                         Trusttunnel::BasicAuth("user", "pass") + "\r\n\r\n" + Payload;
                     std::error_code WriteError;
                     co_await a.async_write_some(AsBytes(AsU8Span(Header)), WriteError);
                     EXPECT_FALSE(WriteError);
                     a.Shutdown();

                     std::string Target;
                     const auto HandshakeError = co_await Server->ReadHandshake(Target);
                     EXPECT_EQ(HandshakeError, Error::None);
                     EXPECT_EQ(Target, "example.com");
                     std::array<std::byte, 128> Buffer{};
                     std::error_code ReadError;
                     const auto Count = co_await Server->async_read_some(Buffer, ReadError);
                     Ok = !ReadError && Count == Payload.size() &&
                          std::memcmp(Buffer.data(), Payload.data(), Payload.size()) == 0;
                     Server->Close();
                 });

        EXPECT_TRUE(Ok);
    }

    TEST(StealthTrustTunnelConnError, NotOpenReadWrite)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        auto Conn = std::make_shared<Trusttunnel::Conn<>>(std::make_shared<MemoryStream>(std::move(a)),
                                                          "user", "pass");
        check_not_open_read_write(Conn, ioc);
    }

    // =========================================================================
    // gun Conn 错误路径
    // =========================================================================

    TEST(StealthGunConnError, ReadHandshakeEof)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto Server = std::make_shared<Gun::Conn<>>(std::make_shared<MemoryStream>(std::move(b)));
                     a.Close(); // 对端关闭 → 无 CONNECT 首行 → bad_magic
                     std::string host;
                     const auto err = co_await Server->ReadHandshake(host);
                     EXPECT_EQ(err, Error::BadMagic);
        });
    }

    TEST(StealthGunConnError, ReadHandshakeRejectsOverreportedRead)
    {
        Net::io_context ioc;
        auto Raw = std::make_shared<PreviewMockTransport>(ioc.get_executor());
        Raw->OverreportRead = true;
        auto Server = std::make_shared<Gun::Conn<>>(Raw);

        run_coro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     std::string Host;
                     EXPECT_EQ(co_await Server->ReadHandshake(Host), Error::BadLength);
                 });
    }

    TEST(StealthGunConnError, ReadHandshakeBadMagic)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto Server = std::make_shared<Gun::Conn<>>(std::make_shared<MemoryStream>(std::move(b)));
                     // 非 CONNECT 首行 → bad_magic
                     co_await write_raw(a, "GET / HTTP/2\r\n\r\n");
                     std::string host;
                     const auto err = co_await Server->ReadHandshake(host);
                     EXPECT_EQ(err, Error::BadMagic);
                 });
    }

    TEST(StealthGunConnError, WriteHandshakeIoError)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto Client = std::make_shared<Gun::Conn<>>(std::make_shared<MemoryStream>(std::move(a)));
                     b.Close(); // 对端全关 → 发送 CONNECT 帧失败 → io_error
                     const auto err = co_await Client->WriteHandshake("example.com");
                     EXPECT_EQ(err, Error::IoError);
                 });
    }

    TEST(StealthGunConnError, NotOpenReadWrite)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        auto Conn = std::make_shared<Gun::Conn<>>(std::make_shared<MemoryStream>(std::move(a)));
        check_not_open_read_write(Conn, ioc);
    }

    // =========================================================================
    // WebSocket Conn 错误路径
    // =========================================================================

    /// 标准测试密钥（RFC 6455 示例）
    inline constexpr const char *kTestKey = "dGhlIHNhbXBsZSBub25jZQ==";

    TEST(StealthWsConnError, WriteHandshakeNon101)
    {
        Net::io_context Context;
        auto [ClientEndpoint, ServerEndpoint] = MakeMemoryPair(Context.get_executor());

        RunCoroutine(Context,
                 [&]() -> Net::awaitable<void>
                 {
                     // 原始服务端：回复 200（非 101）→ 客户端 bad_magic
                     auto Server = std::make_shared<MemoryStream>(std::move(ServerEndpoint));
                     const auto ServerTask = SpawnTask(
                         Server->Executor(), RunWsBadStatusServer(Server));

                     auto Client = std::make_shared<Ws::Conn<>>(
                         std::make_shared<MemoryStream>(std::move(ClientEndpoint)));
                     const auto ErrorCode = co_await Client->WriteHandshake(kTestKey, "example.com");
                     EXPECT_EQ(ErrorCode, Error::BadMagic);
                     co_await WaitForTask(ServerTask);
                 });
    }

    TEST(StealthWsConnError, WriteHandshakeBadAccept)
    {
        Net::io_context Context;
        auto [ClientEndpoint, ServerEndpoint] = MakeMemoryPair(Context.get_executor());

        RunCoroutine(Context,
                 [&]() -> Net::awaitable<void>
                 {
                     // 原始服务端：101 但 Sec-WebSocket-Accept 错误 → 客户端 bad_auth
                     auto Server = std::make_shared<MemoryStream>(std::move(ServerEndpoint));
                     const auto ServerTask = SpawnTask(
                         Server->Executor(), RunWsBadAcceptServer(Server));

                     auto Client = std::make_shared<Ws::Conn<>>(
                         std::make_shared<MemoryStream>(std::move(ClientEndpoint)));
                     const auto ErrorCode = co_await Client->WriteHandshake(kTestKey, "example.com");
                     EXPECT_EQ(ErrorCode, Error::BadAuth);
                     co_await WaitForTask(ServerTask);
                 });
    }

    TEST(StealthWsConnError, WriteHandshakeEof)
    {
        Net::io_context Context;
        auto [ClientEndpoint, ServerEndpoint] = MakeMemoryPair(Context.get_executor());

        RunCoroutine(Context,
                 [&]() -> Net::awaitable<void>
                 {
                     // 原始服务端：读取请求后直接关闭 → 客户端读响应 EOF → bad_magic
                     auto Server = std::make_shared<MemoryStream>(std::move(ServerEndpoint));
                     const auto ServerTask = SpawnTask(
                         Server->Executor(), RunWsCloseServer(Server));

                     auto Client = std::make_shared<Ws::Conn<>>(
                         std::make_shared<MemoryStream>(std::move(ClientEndpoint)));
                     const auto ErrorCode = co_await Client->WriteHandshake(kTestKey, "example.com");
                     EXPECT_EQ(ErrorCode, Error::BadMagic);
                     co_await WaitForTask(ServerTask);
                 });
    }

    TEST(StealthWsConnError, ReadHandshakeBadMagic)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto Server = std::make_shared<Ws::Conn<>>(std::make_shared<MemoryStream>(std::move(b)));
                     // 普通 HTTP 请求（无 Upgrade）→ bad_magic
                     co_await write_raw(a, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
                     std::string key;
                     const auto err = co_await Server->ReadHandshake(key);
                     EXPECT_EQ(err, Error::BadMagic);
        });
    }

    TEST(StealthWsConnError, ReadHandshakeRejectsOverreportedRead)
    {
        Net::io_context ioc;
        auto Raw = std::make_shared<PreviewMockTransport>(ioc.get_executor());
        Raw->OverreportRead = true;
        auto Server = std::make_shared<Ws::Conn<>>(Raw);

        run_coro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     std::string Key;
                     EXPECT_EQ(co_await Server->ReadHandshake(Key), Error::BadLength);
                 });
    }

    TEST(StealthWsConnError, ReadHandshakeMissingKey)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto Server = std::make_shared<Ws::Conn<>>(std::make_shared<MemoryStream>(std::move(b)));
                     // 有 Upgrade 但无 Sec-WebSocket-Key → bad_magic
                     co_await write_raw(a, "GET / HTTP/1.1\r\nHost: example.com\r\n"
                                           "Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n");
                     std::string key;
                     const auto err = co_await Server->ReadHandshake(key);
                     EXPECT_EQ(err, Error::BadMagic);
                 });
    }

    TEST(StealthWsConnError, ReadHandshakeIoError)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto Server = std::make_shared<Ws::Conn<>>(std::make_shared<MemoryStream>(std::move(b)));
                     // 有效 Upgrade 请求后对端关闭 → 发送 101 响应失败 → io_error
                     const std::string req = "GET / HTTP/1.1\r\nHost: example.com\r\n"
                                             "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                                             "Sec-WebSocket-Key: " +
                                             std::string(kTestKey) + "\r\n"
                                             "Sec-WebSocket-Version: 13\r\n\r\n";
                     co_await write_raw(a, req);
                     a.Close();
                     std::string key;
                     const auto err = co_await Server->ReadHandshake(key);
                     EXPECT_EQ(err, Error::IoError);
                 });
    }

    TEST(StealthWsConnError, NotOpenReadWrite)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        auto Conn = std::make_shared<Ws::Conn<>>(std::make_shared<MemoryStream>(std::move(a)));
        check_not_open_read_write(Conn, ioc);
    }

    // =========================================================================
    // VMess Conn 错误路径
    // =========================================================================

    /// 测试 UUID（固定值，两字节交替模式便于识别）
    auto test_uuid() -> std::array<std::uint8_t, 16>
    {
        std::array<std::uint8_t, 16> uuid{};
        for (std::size_t i = 0; i < uuid.size(); ++i)
        {
            uuid[i] = static_cast<std::uint8_t>(0x20 + i);
        }
        return uuid;
    }

    /// 构造 vmess 目标地址
    auto make_addr(Vmess::AddressType Type, std::string host, std::uint16_t port) -> Vmess::Address
    {
        Vmess::Address addr{};
        addr.Type = Type;
        addr.Host = std::move(host);
        addr.Port = port;
        return addr;
    }

    TEST(StealthVmessConnError, NotOpenReadWrite)
    {
        Net::io_context ioc;

        run_coro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     // 未握手 Conn：流式读写与数据报收发均返回 not_open
                     auto c = std::make_shared<Vmess::Conn<>>(test_uuid());
                     std::array<std::byte, 64> buf{};
                     std::error_code ec;
                     const auto n = co_await c->async_read_some(buf, ec);
                     EXPECT_EQ(n, 0u);
                     EXPECT_EQ(ec, make_error_code(Error::NotOpen));
                     ec.clear();
                     const auto w = co_await c->async_write_some(std::span<const std::byte>(buf.data(), 4), ec);
                     EXPECT_EQ(w, 0u);
                     EXPECT_EQ(ec, make_error_code(Error::NotOpen));
                     std::vector<std::uint8_t> payload;
                     const auto rerr = co_await c->AsyncReceiveDatagram(payload);
                     EXPECT_EQ(rerr, Error::NotOpen);
                     const auto serr = co_await c->AsyncSendDatagram(std::span<const std::uint8_t>{});
                     EXPECT_EQ(serr, Error::NotOpen);
                 });
    }

    TEST(StealthVmessConnError, WriteHandshakeBadResponse)
    {
        Net::io_context Context;
        auto [ClientEndpoint, ServerEndpoint] = MakeMemoryPair(Context.get_executor());

        RunCoroutine(Context,
                 [&]() -> Net::awaitable<void>
                 {
                     // 原始服务端：回复垃圾长度块 → 响应长度解密失败 → bad_auth
                     auto Server = std::make_shared<MemoryStream>(std::move(ServerEndpoint));
                     const auto ServerTask = SpawnTask(
                         Server->Executor(), RunVmessGarbageServer(Server));

                     auto Client = std::make_shared<Vmess::Conn<>>(test_uuid());
                     const auto ErrorCode = co_await Client->WriteHandshake(
                         std::make_shared<MemoryStream>(std::move(ClientEndpoint)),
                         make_addr(Vmess::AddressType::Domain, "example.com", 443));
                     EXPECT_EQ(ErrorCode, Error::BadAuth);
                     co_await WaitForTask(ServerTask);
                 });
    }

    TEST(StealthVmessConnError, WriteHandshakeIoError)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto cli = std::make_shared<Vmess::Conn<>>(test_uuid());
                     b.Close(); // 对端全关 → 发送认证头失败 → io_error
                     const auto err = co_await cli->WriteHandshake(
                         std::make_shared<MemoryStream>(std::move(a)),
                         make_addr(Vmess::AddressType::Domain, "example.com", 443));
                     EXPECT_EQ(err, Error::IoError);
                 });
    }

    TEST(StealthVmessConnError, ReadHandshakeBadAuth)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     // 垃圾认证头达到最小帧长后，长度字段 AEAD 校验失败 → bad_auth
                     std::array<std::uint8_t, 60> garbage{};
                     garbage.fill(0xFF);
                     std::error_code ec;
                     co_await a.async_write_some(AsBytes(std::span<const std::uint8_t>(garbage)), ec);
                     EXPECT_FALSE(ec);

                     auto Server = std::make_shared<Vmess::Conn<>>(test_uuid());
                     auto [err, msg] =
                         co_await Server->ReadHandshake(std::make_shared<MemoryStream>(std::move(b)));
                     EXPECT_EQ(err, Error::BadAuth);
                     (void)msg;
                 });
    }

    TEST(StealthVmessConnError, ReadHandshakeIoError)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto Server = std::make_shared<Vmess::Conn<>>(test_uuid());
                     a.Close(); // 对端关闭 → 读认证头前缀 EOF → io_error
                     auto [err, msg] =
                         co_await Server->ReadHandshake(std::make_shared<MemoryStream>(std::move(b)));
                     EXPECT_EQ(err, Error::IoError);
                      (void)msg;
                  });
    }

    TEST(StealthVmessConnError, ReadHandshakeRejectsOverreportedRead)
    {
        Net::io_context ioc;
        auto Raw = std::make_shared<Preview::PreviewMockTransport>(ioc.get_executor());
        Raw->OverreportRead = true;

        run_coro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto Server = std::make_shared<Vmess::Conn<>>(test_uuid());
                     auto [err, msg] = co_await Server->ReadHandshake(Raw);
                     EXPECT_EQ(err, Error::IoError);
                     EXPECT_EQ(Raw->ReadsDone, 1u);
                     (void)msg;
                 });
    }

    TEST(StealthVmessConnError, ChunkTagMismatch)
    {
        Net::io_context Context;
        auto [ClientEndpoint, ServerEndpoint] = MakeMemoryPair(Context.get_executor());
        const auto Uuid = test_uuid();

        RunCoroutine(Context,
                 [&]() -> Net::awaitable<void>
                 {
                     // 服务端：Accept 握手后写入垃圾 chunk 头 → 客户端 tag 校验失败
                     auto Server = std::make_shared<MemoryStream>(std::move(ServerEndpoint));
                     const auto ServerTask = SpawnTask(
                         Server->Executor(), RunVmessBadChunkServer(Server, Uuid));

                     Vmess::ClientConfig Config;
                     Config.uuid = Uuid;
                     auto [HandshakeError, Client] = co_await Vmess::Connect(
                         std::make_shared<MemoryStream>(std::move(ClientEndpoint)), Config,
                         make_addr(Vmess::AddressType::Domain, "example.com", 443));
                     EXPECT_EQ(HandshakeError, Error::None);
                     if (!Client)
                     {
                         co_return;
                     }
                     // 空缓冲写入：直接返回 0 且无错误
                     std::error_code ErrorCode;
                     auto EmptyWrite = Client->async_write_some(std::span<const std::byte>{}, ErrorCode);
                     const auto EmptyWritten = co_await std::move(EmptyWrite);
                     EXPECT_EQ(EmptyWritten, 0u);
                     EXPECT_FALSE(ErrorCode);
                     // 垃圾 chunk 头 → 长度字段 tag 校验失败 → bad_auth
                     std::array<std::byte, 64> Buffer{};
                     auto ReadOperation = Client->async_read_some(Buffer, ErrorCode);
                     const auto BytesRead = co_await std::move(ReadOperation);
                     EXPECT_EQ(BytesRead, 0u);
                     EXPECT_EQ(ErrorCode, make_error_code(Error::BadAuth));
                     Client->Close();
                     co_await WaitForTask(ServerTask);
                 });
    }

    TEST(StealthVmessConnError, EofDuringChunkRead)
    {
        Net::io_context Context;
        auto [ClientEndpoint, ServerEndpoint] = MakeMemoryPair(Context.get_executor());
        const auto Uuid = test_uuid();

        RunCoroutine(Context,
                 [&]() -> Net::awaitable<void>
                 {
                     // 服务端：Accept 握手后直接关闭 → 客户端读 chunk 头 EOF
                     auto Server = std::make_shared<MemoryStream>(std::move(ServerEndpoint));
                     const auto ServerTask = SpawnTask(
                         Server->Executor(), RunVmessCloseServer(Server, Uuid));

                     Vmess::ClientConfig Config;
                     Config.uuid = Uuid;
                     auto [HandshakeError, Client] = co_await Vmess::Connect(
                         std::make_shared<MemoryStream>(std::move(ClientEndpoint)), Config,
                         make_addr(Vmess::AddressType::Domain, "example.com", 443));
                     EXPECT_EQ(HandshakeError, Error::None);
                     if (!Client)
                     {
                         co_return;
                     }
                     std::array<std::byte, 64> Buffer{};
                     std::error_code ErrorCode;
                     auto ReadOperation = Client->async_read_some(Buffer, ErrorCode);
                     const auto BytesRead = co_await std::move(ReadOperation);
                     EXPECT_EQ(BytesRead, 0u);
                     EXPECT_EQ(ErrorCode, make_error_code(Error::UnexpectedEof));
                     Client->Close();
                     co_await WaitForTask(ServerTask);
                 });
    }

    TEST(StealthVmessConnError, FinishBlockThenEof)
    {
        Net::io_context Context;
        auto [ClientEndpoint, ServerEndpoint] = MakeMemoryPair(Context.get_executor());
        const auto Uuid = test_uuid();

        RunCoroutine(Context,
                 [&]() -> Net::awaitable<void>
                 {
                     // 服务端：Accept 握手 → 写结束块 → 关闭
                     auto Server = std::make_shared<MemoryStream>(std::move(ServerEndpoint));
                     const auto ServerTask = SpawnTask(
                         Server->Executor(), RunVmessFinishServer(Server, Uuid));

                     Vmess::ClientConfig Config;
                     Config.uuid = Uuid;
                     auto [HandshakeError, Client] = co_await Vmess::Connect(
                         std::make_shared<MemoryStream>(std::move(ClientEndpoint)), Config,
                         make_addr(Vmess::AddressType::Domain, "example.com", 443));
                     EXPECT_EQ(HandshakeError, Error::None);
                     if (!Client)
                     {
                         co_return;
                     }
                     // 结束块 → 流结束：0 字节且无错误（ReadChunk 置 Eof_ 分支）
                     std::array<std::byte, 64> Buffer{};
                     std::error_code ErrorCode;
                     auto FirstRead = Client->async_read_some(Buffer, ErrorCode);
                     const auto FirstCount = co_await std::move(FirstRead);
                     EXPECT_EQ(FirstCount, 0u);
                     EXPECT_FALSE(ErrorCode);
                     // 再次读取：Eof_ 已置位 → 仍返回 0 且无错误（入口 Eof_ 分支）
                     auto SecondRead = Client->async_read_some(Buffer, ErrorCode);
                     const auto SecondCount = co_await std::move(SecondRead);
                     EXPECT_EQ(SecondCount, 0u);
                     EXPECT_FALSE(ErrorCode);
                     Client->Close();
                     co_await WaitForTask(ServerTask);
                 });
    }

    TEST(StealthVmessConnError, DatagramFinishEof)
    {
        Net::io_context Context;
        auto [ClientEndpoint, ServerEndpoint] = MakeMemoryPair(Context.get_executor());
        const auto Uuid = test_uuid();

        RunCoroutine(Context,
                 [&]() -> Net::awaitable<void>
                 {
                     // 服务端：Accept（udp 命令）→ 写结束块 → 关闭
                     auto Server = std::make_shared<MemoryStream>(std::move(ServerEndpoint));
                     const auto ServerTask = SpawnTask(
                         Server->Executor(), RunVmessFinishServer(Server, Uuid));

                     Vmess::ClientConfig Config;
                     Config.uuid = Uuid;
                     auto [HandshakeError, Client] = co_await Vmess::Connect({
                         std::make_shared<MemoryStream>(std::move(ClientEndpoint)), Config,
                         make_addr(Vmess::AddressType::Domain, "example.com", 443),
                         static_cast<std::uint8_t>(Vmess::Command::Udp)});
                     EXPECT_EQ(HandshakeError, Error::None);
                     if (!Client)
                     {
                         co_return;
                     }
                     // 结束块 → 数据报接收 unexpected_eof（ReadChunk 置 Eof_ 分支）
                     std::vector<std::uint8_t> Payload;
                     const auto FirstError = co_await Client->AsyncReceiveDatagram(Payload);
                     EXPECT_EQ(FirstError, Error::UnexpectedEof);
                     // 再次接收：Eof_ 已置位 → 直接 unexpected_eof（入口 Eof_ 分支）
                     const auto SecondError = co_await Client->AsyncReceiveDatagram(Payload);
                     EXPECT_EQ(SecondError, Error::UnexpectedEof);
                     Client->Close();
                     co_await WaitForTask(ServerTask);
                 });
    }

} // namespace
