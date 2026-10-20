/**
 * @file ShadowtlsConnSession.cpp
 * @brief ShadowTLS v3 Conn 会话层双向测试（Client + Server 视角）
 * @details 覆盖：
 * 1. 客户端 Connect / 服务端 Accept 握手（ClientHello SessionId HMAC）→ 双向回显
 * 2. 错误分支：bad_auth（密码不匹配）/ not_open（未握手读写）
 * 3. 装饰器链方法：Executor / Close / Cancel / NextLayer / Release
 * @note 使用 MakeMemoryPair 建立内存传输对，同一进程内双向互操作。
 */

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <Prism/Transport/MemoryStream.hpp>
#include <Prism/Foundation/Fault/Handling.hpp>
#include <Prism/Protocols/Shadowtls/Detail/ClientHello.hpp>
#include <Prism/Protocols/Shadowtls/Detail/Conn.hpp>
#include <Prism/Protocols/Shadowtls/Detail/Retirement.hpp>
#include <Prism/Protocols/Shadowtls/Shadowtls.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    namespace Shadowtls = Prism::Shadowtls;
    using Prism::Error;
    using Prism::MakeMemoryPair;
    using Prism::MemoryStream;
    using Prism::SharedTransmission;

    auto ErrorOf(const Shadowtls::Failure &Failure) -> Error
    {
        const auto Native = boost::system::error_code(Failure.Native);
        if (&Native.category() == &Prism::ErrorCategory())
            return static_cast<Error>(Native.value());
        return Shadowtls::ToProtocolError(Failure.Code);
    }

    auto ErrorOf(const Prism::Fault::Failure &Failure) -> Error
    {
        const auto Native = boost::system::error_code(Failure.Native);
        if (Native && &Native.category() == &Prism::ErrorCategory())
            return static_cast<Error>(Native.value());
        return Shadowtls::ToProtocolError(Failure.Code);
    }

    auto ErrorOf(const Prism::Transmission::ControlResult &Outcome) -> Error
    {
        return Outcome ? Error::None : ErrorOf(Outcome.error());
    }

    template <class Value>
    auto ErrorOf(const Shadowtls::Result<Value> &Outcome) -> Error
    {
        if (Outcome)
        {
            return Error::None;
        }
        return ErrorOf(Outcome.error());
    }

    template <class Value>
    auto TakeValue(Shadowtls::Result<Value> &Outcome) -> Value
    {
        if (!Outcome) return {};
        return std::move(*Outcome);
    }

    auto RetireTransport(SharedTransmission Transport) -> Net::awaitable<void>
    {
        auto Retired = co_await Shadowtls::Detail::TransportRetirement::RetireAndDrain(
            std::move(Transport));
        EXPECT_EQ(ErrorOf(Retired), Error::None);
    }

    /// 运行协程直至完成（异常重抛）
    template <typename A>
    auto RunCoroutine(Net::io_context &IoContext, A Coroutine) -> void
    {
        std::exception_ptr Exception;
        Net::co_spawn(IoContext, std::move(Coroutine),
                      [&](std::exception_ptr ErrorValue)
                      {
                          Exception = ErrorValue;
                          IoContext.stop();
                      });
        IoContext.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    /// 构造 32 字节随机数（固定模式）
    auto make_random(std::uint8_t seed) -> std::array<std::uint8_t, 32>
    {
        std::array<std::uint8_t, 32> rnd{};
        for (std::size_t i = 0; i < rnd.size(); ++i)
        {
            rnd[i] = static_cast<std::uint8_t>(i * 3 + seed);
        }
        return rnd;
    }

    using CompletionChannel =
        Net::experimental::channel<void(boost::system::error_code, bool)>;

    struct ShadowEchoServerRequest final
    {
        SharedTransmission Server;
        std::string Payload;
        std::shared_ptr<CompletionChannel> Done;
    };

    /** @brief 服务端完成 ShadowTLS HMAC 握手并回显 inner payload。 */
    auto RunShadowEchoServer(ShadowEchoServerRequest Request) -> Net::awaitable<void>
    {
        bool Succeeded = false;
        try
        {
            auto Accepted = co_await Shadowtls::Accept(
                Request.Server, Shadowtls::ServerConfig{"pw123456"});
            const auto ErrorValue = ErrorOf(Accepted);
            auto Connection = TakeValue(Accepted);
            if (ErrorValue != Error::None || !Connection)
            {
                EXPECT_TRUE(false) << "Accept Failed";
            }
            else
            {
                std::array<std::byte, 1024> Buffer{};
                const auto Read = co_await Connection->ReadSome(Buffer);
                EXPECT_FALSE(Read.Failure.Failed());
                EXPECT_EQ(std::string(reinterpret_cast<const char *>(Buffer.data()), Read.Bytes), Request.Payload);
                const auto Written = co_await Connection->WriteSome(
                    std::span<const std::byte>(Buffer.data(), Read.Bytes));
                EXPECT_FALSE(Written.Failure.Failed());
                co_await RetireTransport(Connection);
                Succeeded = true;
            }
        }
        catch (...)
        {
            Succeeded = false;
        }
        (void)Request.Done->try_send(boost::system::error_code{}, Succeeded);
    }

    struct ShadowEchoRequest final
    {
        SharedTransmission Client;
        SharedTransmission Server;
        std::array<std::uint8_t, Shadowtls::TlsRndSize> ServerRandom;
        std::array<std::uint8_t, Shadowtls::TlsRndSize> ClientRandom;
        std::string Payload;
    };

    /** @brief 驱动 ShadowTLS client/server echo 并等待服务端实际退出。 */
    auto RunShadowEcho(ShadowEchoRequest Request) -> Net::awaitable<void>
    {
        const auto Done = std::make_shared<CompletionChannel>(Request.Server->Executor(), 1);
        Net::co_spawn(Request.Server->Executor(), RunShadowEchoServer(
            ShadowEchoServerRequest{Request.Server, Request.Payload, Done}),
            [Done](std::exception_ptr Failure)
            { (void)Done->try_send(boost::system::error_code{}, Failure == nullptr); });
        auto Connected = co_await Shadowtls::Connect({
            Request.Client, Shadowtls::ClientConfig{"pw123456"}, Request.ServerRandom, Request.ClientRandom});
        const auto ErrorValue = ErrorOf(Connected);
        auto Connection = TakeValue(Connected);
        EXPECT_EQ(ErrorValue, Error::None);
        if (Connection)
        {
            const auto Written = co_await Connection->WriteSome(
                std::span<const std::byte>(reinterpret_cast<const std::byte *>(Request.Payload.data()),
                                           Request.Payload.size()));
            EXPECT_FALSE(Written.Failure.Failed());
            EXPECT_EQ(Written.Bytes, Request.Payload.size());
            std::array<std::byte, 1024> Buffer{};
            const auto Read = co_await Connection->ReadSome(Buffer);
            EXPECT_FALSE(Read.Failure.Failed());
            EXPECT_EQ(std::string(reinterpret_cast<const char *>(Buffer.data()), Read.Bytes), Request.Payload);
            co_await RetireTransport(Connection);
        }
        const auto ServerCompleted = co_await Done->async_receive(Net::use_awaitable);
        EXPECT_TRUE(ServerCompleted);
    }

    struct ProtectedServerRequest final
    {
        SharedTransmission Server;
        std::array<std::uint8_t, Shadowtls::TlsRndSize> ServerRandom;
        std::string Payload;
        std::shared_ptr<CompletionChannel> Done;
    };

    /** @brief 服务端开启显式 record protection、回显并确认 peer EOF。 */
    auto RunProtectedServer(ProtectedServerRequest Request) -> Net::awaitable<void>
    {
        bool Succeeded = false;
        try
        {
            auto Connection = std::make_shared<Shadowtls::Detail::Conn<>>(
                std::move(Request.Server), "record-pw");
            auto Handshake = co_await Connection->ReadHandshake();
            const auto ErrorValue = ErrorOf(Handshake);
            EXPECT_EQ(ErrorValue, Error::None);
            EXPECT_TRUE(Handshake);
            if (Handshake)
            {
                EXPECT_EQ(ErrorOf(Connection->EnableRecordProtection(
                    Request.ServerRandom,
                    Shadowtls::RecordDirections{
                        .Write = Shadowtls::TagServer,
                        .Read = Shadowtls::TagClient})), Error::None);
                std::array<std::byte, 128> Buffer{};
                const auto Read = co_await Connection->ReadSome(Buffer);
                EXPECT_FALSE(Read.Failure.Failed());
                EXPECT_EQ(std::string(reinterpret_cast<const char *>(Buffer.data()), Read.Bytes), Request.Payload);
                const auto Written = co_await Connection->WriteSome(
                    std::span<const std::byte>(Buffer.data(), Read.Bytes));
                EXPECT_FALSE(Written.Failure.Failed());
                EXPECT_EQ(Written.Bytes, Read.Bytes);
                std::array<std::byte, 1> CloseBuffer{};
                const auto Eof = co_await Connection->ReadSome(CloseBuffer);
                EXPECT_EQ(Eof.Bytes, 0U);
                EXPECT_EQ(Eof.Failure.Code, Prism::Fault::Code::Eof);
                co_await RetireTransport(Connection);
                Succeeded = true;
            }
            else
            {
                co_await RetireTransport(Connection);
            }
        }
        catch (...)
        {
            Succeeded = false;
        }
        (void)Request.Done->try_send(boost::system::error_code{}, Succeeded);
    }

    struct ProtectedRequest final
    {
        SharedTransmission Client;
        SharedTransmission Server;
        std::array<std::uint8_t, Shadowtls::TlsRndSize> ServerRandom;
        std::array<std::uint8_t, Shadowtls::TlsRndSize> ClientRandom;
        std::string Payload;
    };

    /** @brief 驱动显式 record protection、partial read/write 和 close notify。 */
    auto RunProtectedRecords(ProtectedRequest Request) -> Net::awaitable<void>
    {
        const auto Done = std::make_shared<CompletionChannel>(Request.Server->Executor(), 1);
        Net::co_spawn(Request.Server->Executor(), RunProtectedServer(
            ProtectedServerRequest{Request.Server, Request.ServerRandom, Request.Payload, Done}),
            [Done](std::exception_ptr Failure)
            { (void)Done->try_send(boost::system::error_code{}, Failure == nullptr); });
        auto Connection = std::make_shared<Shadowtls::Detail::Conn<>>(
            std::move(Request.Client), "record-pw");
        auto Handshake = co_await Connection->WriteHandshake(Request.ServerRandom, Request.ClientRandom);
        const auto ErrorValue = ErrorOf(Handshake);
        EXPECT_EQ(ErrorValue, Error::None);
        if (Handshake)
        {
            EXPECT_EQ(ErrorOf(Connection->EnableRecordProtection(Request.ServerRandom)), Error::None);
            const auto Written = co_await Connection->WriteSome(
                std::span<const std::byte>(reinterpret_cast<const std::byte *>(Request.Payload.data()),
                                           Request.Payload.size()));
            EXPECT_FALSE(Written.Failure.Failed());
            EXPECT_EQ(Written.Bytes, Request.Payload.size());
            std::array<std::byte, 128> Buffer{};
            const auto Read = co_await Connection->ReadSome(Buffer);
            EXPECT_FALSE(Read.Failure.Failed());
            EXPECT_EQ(std::string(reinterpret_cast<const char *>(Buffer.data()), Read.Bytes), Request.Payload);
            const std::array<std::uint8_t, 7> CloseNotify{0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00};
            auto *RawClient = Connection->NextLayer();
            EXPECT_NE(RawClient, nullptr);
            if (RawClient)
            {
                const auto CloseWritten = co_await RawClient->WriteSome(
                    std::as_bytes(std::span<const std::uint8_t>(CloseNotify)));
                EXPECT_FALSE(CloseWritten.Failure.Failed());
            }
        }
        co_await RetireTransport(Connection);
        const auto ServerCompleted = co_await Done->async_receive(Net::use_awaitable);
        EXPECT_TRUE(ServerCompleted);
    }

    struct RawPeerCloseServerRequest final
    {
        SharedTransmission Server;
        std::array<std::uint8_t, Shadowtls::TlsRndSize> ServerRandom;
        std::string Payload;
        std::shared_ptr<CompletionChannel> Done;
    };

    /** @brief 服务端完成 record boundary 回显并等待对端自然 EOF。 */
    auto RunRawPeerCloseServer(RawPeerCloseServerRequest Request) -> Net::awaitable<void>
    {
        bool Succeeded = false;
        try
        {
            auto Connection = std::make_shared<Shadowtls::Detail::Conn<>>(
                std::move(Request.Server), "close-pw");
            auto Handshake = co_await Connection->ReadHandshake();
            const auto ErrorValue = ErrorOf(Handshake);
            EXPECT_EQ(ErrorValue, Error::None);
            EXPECT_TRUE(Handshake);
            if (Handshake)
            {
                EXPECT_EQ(ErrorOf(Connection->EnableRecordProtection(
                    Request.ServerRandom,
                    Shadowtls::RecordDirections{
                        .Write = Shadowtls::TagServer,
                        .Read = Shadowtls::TagClient})), Error::None);
                std::array<std::byte, 128> Buffer{};
                const auto Read = co_await Connection->ReadSome(Buffer);
                EXPECT_FALSE(Read.Failure.Failed());
                EXPECT_EQ(std::string(reinterpret_cast<const char *>(Buffer.data()), Read.Bytes), Request.Payload);
                const auto Written = co_await Connection->WriteSome(
                    std::span<const std::byte>(Buffer.data(), Read.Bytes));
                EXPECT_FALSE(Written.Failure.Failed());
                EXPECT_EQ(Written.Bytes, Read.Bytes);
                const auto Eof = co_await Connection->ReadSome(Buffer);
                EXPECT_EQ(Eof.Bytes, 0U);
                EXPECT_EQ(Eof.Failure.Code, Prism::Fault::Code::Eof);
                co_await RetireTransport(Connection);
                Succeeded = true;
            }
            else
            {
                co_await RetireTransport(Connection);
            }
        }
        catch (...)
        {
            Succeeded = false;
        }
        (void)Request.Done->try_send(boost::system::error_code{}, Succeeded);
    }

    struct RawPeerCloseRequest final
    {
        SharedTransmission Client;
        SharedTransmission Server;
        std::array<std::uint8_t, Shadowtls::TlsRndSize> ServerRandom;
        std::array<std::uint8_t, Shadowtls::TlsRndSize> ClientRandom;
        std::string Payload;
    };

    /** @brief 驱动 record boundary close，并等待服务端完成 EOF 观察。 */
    auto RunRawPeerClose(RawPeerCloseRequest Request) -> Net::awaitable<void>
    {
        const auto Done = std::make_shared<CompletionChannel>(Request.Server->Executor(), 1);
        Net::co_spawn(Request.Server->Executor(), RunRawPeerCloseServer(
            RawPeerCloseServerRequest{Request.Server, Request.ServerRandom, Request.Payload, Done}),
            [Done](std::exception_ptr Failure)
            { (void)Done->try_send(boost::system::error_code{}, Failure == nullptr); });

        auto Client = std::make_shared<Shadowtls::Detail::Conn<>>(
            std::move(Request.Client), "close-pw");
        auto Handshake = co_await Client->WriteHandshake(
            std::span<const std::uint8_t>(Request.ServerRandom),
            std::span<const std::uint8_t>(Request.ClientRandom));
        const auto HandshakeError = ErrorOf(Handshake);
        EXPECT_EQ(HandshakeError, Error::None);
        EXPECT_TRUE(Handshake);
        if (Handshake)
        {
            EXPECT_EQ(ErrorOf(Client->EnableRecordProtection(Request.ServerRandom)), Error::None);
            const auto Written = co_await Client->WriteSome(
                std::span<const std::byte>(reinterpret_cast<const std::byte *>(Request.Payload.data()),
                                           Request.Payload.size()));
            EXPECT_FALSE(Written.Failure.Failed());
            EXPECT_EQ(Written.Bytes, Request.Payload.size());
            std::array<std::byte, 128> Buffer{};
            const auto Read = co_await Client->ReadSome(Buffer);
            EXPECT_FALSE(Read.Failure.Failed());
            EXPECT_EQ(Read.Bytes, Request.Payload.size());
        }
        co_await RetireTransport(Client);
        const auto ServerCompleted = co_await Done->async_receive(Net::use_awaitable);
        EXPECT_TRUE(ServerCompleted);
    }

    /** @brief 构造并认证标准 TLS ClientHello wire。 */
    auto MakeStandardClientHelloWire() -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Hello(75, 0);
        Hello[0] = 0x03;
        Hello[1] = 0x03;
        for (std::size_t I = 0; I < Shadowtls::TlsRndSize; ++I)
        {
            Hello[2 + I] = static_cast<std::uint8_t>(0x60 + I);
        }
        Hello[34] = Shadowtls::TlsSessionIdSz;
        Hello[67] = 0;
        Hello[68] = 2;
        Hello[69] = 0x13;
        Hello[70] = 0x01;
        Hello[71] = 1;
        Hello[72] = 0;
        Hello[73] = 0;
        Hello[74] = 0;
        std::vector<std::uint8_t> Record(Shadowtls::TlsHdrsize + 4 + Hello.size(), 0);
        Record[0] = 0x16;
        Record[1] = 0x03;
        Record[2] = 0x03;
        const auto BodyLength = static_cast<std::uint16_t>(4 + Hello.size());
        Record[3] = static_cast<std::uint8_t>(BodyLength >> 8);
        Record[4] = static_cast<std::uint8_t>(BodyLength);
        Record[5] = Shadowtls::HsTypeClienthello;
        Record[7] = static_cast<std::uint8_t>(Hello.size() >> 8);
        Record[8] = static_cast<std::uint8_t>(Hello.size());
        std::copy(Hello.begin(), Hello.end(), Record.begin() + 9);
        std::span<std::uint8_t, Shadowtls::TlsSessionIdSz> SessionId(
            Record.data() + Shadowtls::TlsHdrsize + Shadowtls::SessionIdStart,
            Shadowtls::TlsSessionIdSz);
        EXPECT_EQ(Shadowtls::Detail::GenerateSessionId(
                      Shadowtls::Detail::SessionIdInput{"pw", std::span<const std::uint8_t>(Record).subspan(5),
                                                SessionId}),
                  Error::None);
        return Record;
    }

    struct ReadStandardClientHelloRequest final
    {
        SharedTransmission Source;
        SharedTransmission Target;
        std::vector<std::uint8_t> Wire;
    };

    /** @brief 发送标准 ClientHello 并验证服务端保留完整 wire。 */
    auto RunReadStandardClientHello(ReadStandardClientHelloRequest Request) -> Net::awaitable<void>
    {
        const auto Written = co_await Request.Source->WriteSome(
            std::span<const std::byte>(reinterpret_cast<const std::byte *>(Request.Wire.data()),
                                       Request.Wire.size()));
        EXPECT_FALSE(Written.Failure.Failed());
        EXPECT_EQ(Written.Bytes, Request.Wire.size());
        auto Connection = std::make_shared<Shadowtls::Detail::Conn<>>(Request.Target, "pw");
        EXPECT_EQ(ErrorOf(co_await Connection->ReadStandardHandshake()), Error::None);
        EXPECT_EQ(Connection->TakeClientHelloWire(), Request.Wire);
        co_await RetireTransport(Connection);
    }

    struct AcceptStandardClientHelloRequest final
    {
        SharedTransmission Reader;
        std::string Password;
    };

    /** @brief 以命名 awaitable 接收标准 ClientHello，保留真实返回类型。 */
    auto RunAcceptStandardClientHello(AcceptStandardClientHelloRequest Request)
        -> Net::awaitable<Shadowtls::Result<Shadowtls::ServerHandover>>
    {
        co_return co_await Shadowtls::AcceptStandard(
            std::move(Request.Reader), Shadowtls::ServerConfig{std::move(Request.Password)});
    }

    struct WriteStandardClientHelloRequest final
    {
        SharedTransmission Writer;
        SharedTransmission Reader;
        std::vector<std::uint8_t> Template;
        std::string Password;
    };

    /** @brief 写入并验证标准 ClientHello 的 SessionId/HMAC 与服务端 wire。 */
    auto RunWriteStandardClientHello(WriteStandardClientHelloRequest Request) -> Net::awaitable<void>
    {
        const auto ReaderExecutor = Request.Reader->Executor();
        auto ReaderTask = Net::co_spawn(
            ReaderExecutor,
            RunAcceptStandardClientHello(
                AcceptStandardClientHelloRequest{Request.Reader, Request.Password}),
            Net::use_awaitable);
        auto WriterResult = co_await Shadowtls::ConnectStandard(
            Shadowtls::StandardConnectParameters{
                Request.Writer,
                Shadowtls::ClientConfig{Request.Password},
                std::span<const std::uint8_t>(Request.Template)});
        const auto WriteError = ErrorOf(WriterResult);
        auto WriterOutcome = TakeValue(WriterResult);
        auto WriterWire = std::move(WriterOutcome.ClientHelloWire);
        auto Writer = std::move(WriterOutcome.Connection);
        EXPECT_EQ(WriteError, Error::None);
        auto ReaderResult = co_await std::move(ReaderTask);
        const auto ReadError = ErrorOf(ReaderResult);
        auto Handover = TakeValue(ReaderResult);
        auto ReaderWire = std::move(Handover.ClientHelloWire);
        auto Reader = std::move(Handover.Connection);
        EXPECT_EQ(ReadError, Error::None);
        EXPECT_EQ(WriterWire, ReaderWire);
        EXPECT_TRUE(Shadowtls::Detail::VerifyClientHello(
            Request.Password,
            std::span<const std::byte>(reinterpret_cast<const std::byte *>(WriterWire.data()),
                                       WriterWire.size())));
        if (Writer)
        {
            co_await RetireTransport(Writer);
        }
        if (Reader)
        {
            co_await RetireTransport(Reader);
        }
    }

    struct BadAuthServerRequest final
    {
        SharedTransmission Server;
        std::shared_ptr<CompletionChannel> Done;
    };

    /** @brief 服务端确认错误密码只产生 BadAuth 且不交付连接。 */
    auto RunBadAuthServer(BadAuthServerRequest Request) -> Net::awaitable<void>
    {
        bool Succeeded = false;
        try
        {
            auto Accepted = co_await Shadowtls::Accept(
                Request.Server, Shadowtls::ServerConfig{"Expect-pw"});
            const auto ErrorValue = ErrorOf(Accepted);
            auto Connection = TakeValue(Accepted);
            EXPECT_EQ(ErrorValue, Error::BadAuth);
            EXPECT_FALSE(Connection);
            Succeeded = ErrorValue == Error::BadAuth && !Connection;
            if (Connection) co_await RetireTransport(Connection);
        }
        catch (...)
        {
            Succeeded = false;
        }
        (void)Request.Done->try_send(boost::system::error_code{}, Succeeded);
    }

    struct BadAuthRequest final
    {
        SharedTransmission Client;
        SharedTransmission Server;
        std::array<std::uint8_t, Shadowtls::TlsRndSize> ServerRandom;
        std::array<std::uint8_t, Shadowtls::TlsRndSize> ClientRandom;
    };

    /** @brief 驱动错误密码握手并等待服务端完成认证拒绝。 */
    auto RunBadAuth(BadAuthRequest Request) -> Net::awaitable<void>
    {
        const auto Done = std::make_shared<CompletionChannel>(Request.Server->Executor(), 1);
        Net::co_spawn(Request.Server->Executor(), RunBadAuthServer(
            BadAuthServerRequest{Request.Server, Done}),
            [Done](std::exception_ptr Failure)
            { (void)Done->try_send(boost::system::error_code{}, Failure == nullptr); });
        auto Connected = co_await Shadowtls::Connect({
            Request.Client,
            Shadowtls::ClientConfig{"wrong-pw"},
            std::span<const std::uint8_t>(Request.ServerRandom),
            std::span<const std::uint8_t>(Request.ClientRandom)});
        const auto HandshakeError = ErrorOf(Connected);
        auto Client = TakeValue(Connected);
        EXPECT_EQ(HandshakeError, Error::None);
        if (Client)
        {
            co_await RetireTransport(Client);
        }
        const auto ServerCompleted = co_await Done->async_receive(Net::use_awaitable);
        EXPECT_TRUE(ServerCompleted);
    }

    struct NotOpenRequest final
    {
        SharedTransmission Client;
    };

    /** @brief 验证未握手 Conn 的错误、导航、取消和底层所有权释放。 */
    auto RunNotOpen(NotOpenRequest Request) -> Net::awaitable<void>
    {
        auto Connection = std::make_shared<Shadowtls::Detail::Conn<>>(std::move(Request.Client), "pw");
        std::array<std::byte, 64> Buffer{};
        const auto Read = co_await Connection->ReadSome(Buffer);
        EXPECT_EQ(Read.Bytes, 0U);
        EXPECT_EQ(ErrorOf(Read.Failure), Error::NotOpen);
        const auto Written = co_await Connection->WriteSome(std::span<const std::byte>(Buffer.data(), 4));
        EXPECT_EQ(Written.Bytes, 0U);
        EXPECT_EQ(ErrorOf(Written.Failure), Error::NotOpen);
        auto Canceled = Connection->Cancel();
        EXPECT_EQ(ErrorOf(Canceled), Error::None);
        co_await RetireTransport(Connection);
        EXPECT_TRUE(Connection->Executor());
        EXPECT_NE(Connection->NextLayer(), nullptr);
        EXPECT_NE(Connection->lowest_layer<MemoryStream>(), nullptr);
        const auto *ConstConnection = Connection.get();
        EXPECT_NE(ConstConnection->NextLayer(), nullptr);
        auto Released = Connection->Release();
        EXPECT_TRUE(Released);
        EXPECT_EQ(Connection->NextLayer(), nullptr);
    }

    TEST(ShadowtlsConnSession, HandshakeClientServerEcho)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        const auto server_rnd = make_random(0x11);
        const auto client_rnd = make_random(0x22);
        const std::string payload = "shadowtls echo payload";

        RunCoroutine(ioc, RunShadowEcho(ShadowEchoRequest{
            std::make_shared<MemoryStream>(std::move(a)),
            std::make_shared<MemoryStream>(std::move(b)), server_rnd, client_rnd, payload}));
    }

    TEST(ShadowtlsConnSession, StandardApplicationRecordsAfterExplicitEnable)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        const auto server_rnd = make_random(0x61);
        const auto client_rnd = make_random(0x72);
        const std::string payload = "shadowtls protected payload";

        RunCoroutine(ioc, RunProtectedRecords(ProtectedRequest{
            std::make_shared<MemoryStream>(std::move(a)),
            std::make_shared<MemoryStream>(std::move(b)), server_rnd, client_rnd, payload}));
    }

    TEST(ShadowtlsConnSession, RawPeerCloseAtRecordBoundaryIsCleanEof)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        const auto server_rnd = make_random(0x31);
        const auto client_rnd = make_random(0x42);
        const std::string payload = "shadowtls close-boundary payload";

        RunCoroutine(ioc, RunRawPeerClose(RawPeerCloseRequest{
            std::make_shared<MemoryStream>(std::move(a)),
            std::make_shared<MemoryStream>(std::move(b)), server_rnd, client_rnd, payload}));
    }

    TEST(ShadowtlsConnSession, ReadsAndRetainsStandardClientHelloWire)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        RunCoroutine(ioc, RunReadStandardClientHello(ReadStandardClientHelloRequest{
            std::make_shared<MemoryStream>(std::move(a)),
            std::make_shared<MemoryStream>(std::move(b)), MakeStandardClientHelloWire()}));
    }

    TEST(ShadowtlsConnSession, WritesStandardClientHelloWithComputedSessionId)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        std::vector<std::uint8_t> Template(Shadowtls::TlsHdrsize + 4 + 75, 0);
        Template[0] = 0x16;
        Template[1] = 0x03;
        Template[2] = 0x03;
        const auto BodyLength = static_cast<std::uint16_t>(4 + 75);
        Template[3] = static_cast<std::uint8_t>(BodyLength >> 8);
        Template[4] = static_cast<std::uint8_t>(BodyLength);
        Template[5] = Shadowtls::HsTypeClienthello;
        Template[7] = 0;
        Template[8] = 75;
        Template[9] = 0x03;
        Template[10] = 0x03;
        for (std::size_t I = 0; I < Shadowtls::TlsRndSize; ++I)
        {
            Template[11 + I] = static_cast<std::uint8_t>(0x20 + I);
        }
        Template[43] = Shadowtls::TlsSessionIdSz;
        Template[76] = 0;
        Template[77] = 2;
        Template[78] = 0x13;
        Template[79] = 0x01;
        Template[80] = 1;
        Template[81] = 0;
        Template[82] = 0;
        Template[83] = 0;
        const std::string Password = "standard-pw";

        RunCoroutine(ioc, RunWriteStandardClientHello(WriteStandardClientHelloRequest{
            std::make_shared<MemoryStream>(std::move(a)),
            std::make_shared<MemoryStream>(std::move(b)), std::move(Template), Password}));
    }

    TEST(ShadowtlsConnSession, StandardHandshakeRejectsNullTransport)
    {
        EXPECT_THROW((void)std::make_shared<Shadowtls::Detail::Conn<>>(nullptr, "pw"), std::invalid_argument);
        Net::io_context ioc;
        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     const Shadowtls::ServerConfig ServerConfig{"pw"};
                     const Shadowtls::ClientConfig ClientConfig{"pw"};
                     EXPECT_EQ(ErrorOf(co_await Shadowtls::AcceptStandard(nullptr, ServerConfig)), Error::NotOpen);
                     EXPECT_EQ(ErrorOf(co_await Shadowtls::ConnectStandard({
                         nullptr, ClientConfig, std::span<const std::uint8_t>{}})), Error::NotOpen);
                 });
    }

    TEST(ShadowtlsConnSession, BadAuthRejected)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        RunCoroutine(ioc, RunBadAuth(BadAuthRequest{
            std::make_shared<MemoryStream>(std::move(a)),
            std::make_shared<MemoryStream>(std::move(b)), make_random(0x33), make_random(0x44)}));
    }

    TEST(ShadowtlsConnSession, NotOpenRejected)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        RunCoroutine(ioc, RunNotOpen(NotOpenRequest{
            std::make_shared<MemoryStream>(std::move(a))}));
    }

} // namespace
