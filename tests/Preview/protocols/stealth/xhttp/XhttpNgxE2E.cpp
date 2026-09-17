/**
 * @file XhttpNgxE2E.cpp
 * @brief XHTTP Stream-one 端到端测试（T2-2，Preview 自包含实现）
 * @details 模拟 h2 客户端（Preview Http2）：
 *          1. TLS 握手（自签证书）
 *          2. h2 SETTINGS + POST / 请求（Stream-one）
 *          3. 请求体发送数据，服务端响应 200 + echo
 *          4. 客户端验证回显
 * @note 使用自包含 Http2 实现（非 nghttp2）。
 */

#include <Preview/Protocols/Http2/Impl.hpp>
#include <Preview/Transport/MemoryStream.hpp>
#include <Preview/Protocols/Xhttp/Xhttp.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    namespace SSL = Net::ssl;
    namespace Http2 = Preview::Http2;
    namespace Xhttp = Preview::Xhttp;

    using Net::experimental::awaitable_operators::operator&&;
    using Net::experimental::awaitable_operators::operator||;

    using SharedTransmission = Preview::SharedTransmission;
    using SharedSslContext = std::shared_ptr<SSL::context>;

    struct EchoRequest final
    {
        SharedTransmission Raw;
        SharedSslContext Context;
        std::string Payload;
        std::shared_ptr<bool> Succeeded;
    };

    struct StreamOneScenarioRequest final
    {
        Net::any_io_executor Executor;
        EchoRequest Client;
        EchoRequest Server;
        std::shared_ptr<bool> TimedOut;
    };

    struct FactoryClientRequest final
    {
        SharedTransmission Raw;
        SharedSslContext Context;
        Xhttp::Config Config;
        std::string Host;
        std::string Payload;
        std::shared_ptr<bool> Succeeded;
    };

    struct FactoryServerRequest final
    {
        SharedTransmission Raw;
        SharedSslContext Context;
        Xhttp::Config Config;
        std::string Payload;
        std::shared_ptr<bool> Succeeded;
    };

    struct FactoryScenarioRequest final
    {
        Net::any_io_executor Executor;
        SharedTransmission ClientRaw;
        SharedTransmission ServerRaw;
        SharedSslContext ClientContext;
        SharedSslContext ServerContext;
        Xhttp::Config Config;
        std::string Payload;
        std::shared_ptr<bool> ClientSucceeded;
        std::shared_ptr<bool> ServerSucceeded;
        std::shared_ptr<bool> TimedOut;
    };

    auto LoadSelfSigned(SSL::context &Context) -> void
    {
        auto *PkeyContext = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
        EVP_PKEY *PrivateKey = nullptr;
        if (PkeyContext && EVP_PKEY_keygen_init(PkeyContext) > 0 &&
            EVP_PKEY_CTX_set_rsa_keygen_bits(PkeyContext, 2048) > 0)
        {
            EVP_PKEY_keygen(PkeyContext, &PrivateKey);
        }
        EVP_PKEY_CTX_free(PkeyContext);
        ASSERT_NE(PrivateKey, nullptr);

        auto *Certificate = X509_new();
        X509_set_version(Certificate, 2);
        ASN1_INTEGER_set(X509_get_serialNumber(Certificate), 1);
        X509_gmtime_adj(X509_get_notBefore(Certificate), 0);
        X509_gmtime_adj(X509_get_notAfter(Certificate), 3600 * 24);

        auto *Name = X509_NAME_new();
        X509_NAME_add_entry_by_txt(Name, "CN", MBSTRING_ASC,
                                   reinterpret_cast<const unsigned char *>("xhttp-test"), -1, -1, 0);
        X509_set_subject_name(Certificate, Name);
        X509_set_issuer_name(Certificate, Name);
        X509_NAME_free(Name);

        X509_set_pubkey(Certificate, PrivateKey);
        X509_sign(Certificate, PrivateKey, EVP_sha256());

        SSL_CTX_use_certificate(Context.native_handle(), Certificate);
        SSL_CTX_use_PrivateKey(Context.native_handle(), PrivateKey);

        X509_free(Certificate);
        EVP_PKEY_free(PrivateKey);
    }

    auto HasPayload(std::span<const std::byte> Received, std::string_view Expected) -> bool
    {
        if (Received.size() < Expected.size())
        {
            return false;
        }
        const auto ReceivedView = std::string_view(
            reinterpret_cast<const char *>(Received.data()), Expected.size());
        return ReceivedView == Expected;
    }

    template <typename Stream>
    auto WriteHttp2Wire(
        Stream &StreamValue,
        std::vector<std::byte> &Wire,
        boost::system::error_code &ErrorCode) -> Net::awaitable<bool>
    {
        if (Wire.empty())
        {
            co_return true;
        }
        auto Output = std::move(Wire);
        Wire.clear();
        const auto OutputBuffer = Net::buffer(Output.data(), Output.size());
        auto WriteOperation = StreamValue.async_write_some(
            OutputBuffer, Net::redirect_error(Net::use_awaitable, ErrorCode));
        const auto Written = co_await std::move(WriteOperation);
        co_return !ErrorCode && Written == Output.size();
    }

    /// h2 客户端：TLS + SETTINGS + POST + 数据 + echo 验证。
    auto RunHttp2Client(EchoRequest Request) -> Net::awaitable<void>
    {
        *Request.Succeeded = false;
        Preview::Transport::Connector Connector(std::move(Request.Raw));
        auto Stream = std::make_shared<SSL::stream<Preview::Transport::Connector>>(
            std::move(Connector), *Request.Context);

        boost::system::error_code HandshakeError;
        auto HandshakeOperation = Stream->async_handshake(
            SSL::stream_base::client,
            Net::redirect_error(Net::use_awaitable, HandshakeError));
        co_await std::move(HandshakeOperation);
        if (HandshakeError)
        {
            co_return;
        }

        auto Session = std::make_shared<Http2::SessionImpl>(Stream->get_executor(), false);
        Session->SendSettings();

        Http2::HeaderList Headers = {
            {":method", "POST"},
            {":path", "/"},
            {":scheme", "https"},
            {":authority", "example.com"},
        };
        const auto StreamId = Session->OpenStream(Headers, false);
        if (StreamId < 0)
        {
            co_return;
        }

        const auto PayloadBytes = std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(Request.Payload.data()), Request.Payload.size());
        if (Session->SubmitData(StreamId, PayloadBytes, true) != 0)
        {
            co_return;
        }

        std::vector<std::byte> Wire;
        (void)Session->Collect(Wire);
        auto HeadersValid = std::make_shared<bool>(false);
        auto Received = std::make_shared<std::vector<std::byte>>();
        Session->OnHeaders = [HeadersValid](
                                 std::int32_t, const Http2::HeaderList &Headers, bool)
        {
            bool HasStatus = false;
            bool HasContentType = false;
            for (const auto &Header : Headers)
            {
                if (Header.Name == ":status")
                {
                    HasStatus = true;
                    EXPECT_EQ(Header.value, "200");
                }
                if (Header.Name == "content-type")
                {
                    HasContentType = true;
                    EXPECT_EQ(Header.value, "text/event-stream");
                }
            }
            EXPECT_TRUE(HasStatus);
            EXPECT_TRUE(HasContentType);
            *HeadersValid = HasStatus && HasContentType;
        };
        Session->OnData = [Received](std::int32_t, std::span<const std::byte> Data)
        {
            Received->insert(Received->end(), Data.begin(), Data.end());
        };

        boost::system::error_code WriteError;
        auto InitialWrite = WriteHttp2Wire(*Stream, Wire, WriteError);
        const auto InitialWriteSucceeded = co_await std::move(InitialWrite);
        if (!InitialWriteSucceeded)
        {
            co_return;
        }

        std::array<std::byte, 8192> Buffer{};
        boost::system::error_code ReadError;
        const auto Deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (Received->size() < Request.Payload.size() &&
               std::chrono::steady_clock::now() < Deadline)
        {
            const auto ReadBuffer = Net::buffer(Buffer.data(), Buffer.size());
            auto ReadOperation = Stream->async_read_some(
                ReadBuffer, Net::redirect_error(Net::use_awaitable, ReadError));
            const auto BytesRead = co_await std::move(ReadOperation);
            if (ReadError || BytesRead == 0)
            {
                break;
            }

            std::error_code FeedError;
            const auto InputSpan = std::span<const std::byte>(Buffer.data(), BytesRead);
            if (!Session->Feed(InputSpan, FeedError))
            {
                break;
            }
            if (Session->Collect(Wire))
            {
                WriteError.clear();
                auto ResponseWrite = WriteHttp2Wire(*Stream, Wire, WriteError);
                const auto ResponseWriteSucceeded = co_await std::move(ResponseWrite);
                if (!ResponseWriteSucceeded)
                {
                    break;
                }
            }
        }

        const auto ReceivedBytes = std::span<const std::byte>(*Received);
        *Request.Succeeded = *HeadersValid && HasPayload(ReceivedBytes, Request.Payload);
        co_return;
    }

    /// XHTTP 服务端：Accept + echo。
    auto RunXhttpServer(EchoRequest Request) -> Net::awaitable<void>
    {
        *Request.Succeeded = false;
        Xhttp::Config Config;
        auto Transport = co_await Xhttp::Accept(std::move(Request.Raw), *Request.Context, Config);
        if (!Transport)
        {
            co_return;
        }

        std::array<std::byte, 4096> Buffer{};
        std::error_code ReadError;
        std::size_t Total = 0;
        while (true)
        {
            auto ReadOperation = Transport->async_read_some(Buffer, ReadError);
            Net::steady_timer Watchdog(Transport->Executor());
            Watchdog.expires_after(std::chrono::seconds(2));
            auto WatchdogOperation = Watchdog.async_wait(Net::use_awaitable);
            auto ReadRace = co_await (std::move(ReadOperation) || std::move(WatchdogOperation));
            if (ReadRace.index() == 1)
            {
                Transport->Close();
                co_return;
            }

            const auto BytesRead = std::get<0>(std::move(ReadRace));
            if (ReadError || BytesRead == 0)
            {
                break;
            }
            Total += BytesRead;

            std::error_code WriteError;
            const auto EchoSpan = std::span<const std::byte>(Buffer.data(), BytesRead);
            auto WriteOperation = Transport->AsyncWrite(EchoSpan, WriteError);
            const auto BytesWritten = co_await std::move(WriteOperation);
            if (WriteError || BytesWritten != EchoSpan.size())
            {
                Transport->Close();
                co_return;
            }
            if (Total >= Request.Payload.size())
            {
                break;
            }
        }

        *Request.Succeeded = Total >= Request.Payload.size();
        Transport->Close();
        co_return;
    }

    auto RunWatchdog(
        Net::any_io_executor Executor,
        std::chrono::seconds Timeout,
        const std::shared_ptr<bool> &TimedOut) -> Net::awaitable<void>
    {
        Net::steady_timer Timer(Executor);
        Timer.expires_after(Timeout);
        boost::system::error_code ErrorCode;
        auto WaitOperation = Timer.async_wait(Net::redirect_error(Net::use_awaitable, ErrorCode));
        co_await std::move(WaitOperation);
        if (!ErrorCode)
        {
            *TimedOut = true;
        }
        co_return;
    }

    auto RunStreamOnePair(StreamOneScenarioRequest Request) -> Net::awaitable<void>
    {
        auto ClientOperation = Net::co_spawn(
            Request.Executor, RunHttp2Client(Request.Client), Net::use_awaitable);
        auto ServerOperation = Net::co_spawn(
            Request.Executor, RunXhttpServer(Request.Server), Net::use_awaitable);
        co_await (std::move(ClientOperation) && std::move(ServerOperation));
        co_return;
    }

    auto RunStreamOneScenario(StreamOneScenarioRequest Request) -> Net::awaitable<void>
    {
        auto PairOperation = Net::co_spawn(
            Request.Executor, RunStreamOnePair(Request), Net::use_awaitable);
        auto WatchdogOperation = Net::co_spawn(
            Request.Executor,
            RunWatchdog(Request.Executor, std::chrono::seconds(5), Request.TimedOut),
            Net::use_awaitable);
        try
        {
            auto RaceResult = co_await (std::move(PairOperation) || std::move(WatchdogOperation));
            (void)RaceResult;
        }
        catch (...)
        {
            *Request.Client.Succeeded = false;
            *Request.Server.Succeeded = false;
        }
        if (Request.Client.Raw)
        {
            Request.Client.Raw->Close();
        }
        if (Request.Server.Raw)
        {
            Request.Server.Raw->Close();
        }
        co_return;
    }

    auto RunFactoryClient(FactoryClientRequest Request) -> Net::awaitable<void>
    {
        *Request.Succeeded = false;
        auto Transport = co_await Xhttp::Connect(
            std::move(Request.Raw), *Request.Context, Request.Config, Request.Host);
        if (!Transport)
        {
            co_return;
        }

        const auto PayloadBytes = std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(Request.Payload.data()), Request.Payload.size());
        std::error_code WriteError;
        auto WriteOperation = Transport->AsyncWrite(PayloadBytes, WriteError);
        const auto BytesWritten = co_await std::move(WriteOperation);
        if (WriteError || BytesWritten != PayloadBytes.size())
        {
            Transport->Close();
            co_return;
        }

        auto XhttpTransport = std::static_pointer_cast<Xhttp::XhttpTransport>(Transport);
        try
        {
            auto FinishOperation = XhttpTransport->Finish();
            co_await std::move(FinishOperation);
        }
        catch (...)
        {
            Transport->Close();
            co_return;
        }

        std::vector<std::byte> Received;
        std::array<std::byte, 256> Buffer{};
        std::error_code ReadError;
        while (Received.size() < Request.Payload.size())
        {
            auto ReadOperation = Transport->async_read_some(Buffer, ReadError);
            const auto BytesRead = co_await std::move(ReadOperation);
            if (ReadError || BytesRead == 0)
            {
                Transport->Close();
                co_return;
            }
            const auto ReceivedSpan = std::span<const std::byte>(Buffer.data(), BytesRead);
            Received.insert(Received.end(), ReceivedSpan.begin(), ReceivedSpan.end());
        }

        const auto ReceivedBytes = std::span<const std::byte>(Received);
        *Request.Succeeded = HasPayload(ReceivedBytes, Request.Payload);
        Transport->Close();
        co_return;
    }

    auto RunFactoryServer(FactoryServerRequest Request) -> Net::awaitable<void>
    {
        *Request.Succeeded = false;
        auto Transport = co_await Xhttp::Accept(
            std::move(Request.Raw), *Request.Context, Request.Config);
        if (!Transport)
        {
            co_return;
        }

        std::array<std::byte, 256> Buffer{};
        std::error_code ReadError;
        auto ReadOperation = Transport->async_read_some(Buffer, ReadError);
        const auto BytesRead = co_await std::move(ReadOperation);
        if (ReadError || BytesRead == 0)
        {
            Transport->Close();
            co_return;
        }

        const auto EchoSpan = std::span<const std::byte>(Buffer.data(), BytesRead);
        std::error_code WriteError;
        auto WriteOperation = Transport->AsyncWrite(EchoSpan, WriteError);
        const auto BytesWritten = co_await std::move(WriteOperation);
        *Request.Succeeded = !WriteError && BytesWritten == EchoSpan.size();
        Transport->Close();
        co_return;
    }

    auto RunFactoryPair(FactoryScenarioRequest Request) -> Net::awaitable<void>
    {
        FactoryClientRequest ClientRequest{
            Request.ClientRaw,
            Request.ClientContext,
            Request.Config,
            "example.com",
            Request.Payload,
            Request.ClientSucceeded};
        FactoryServerRequest ServerRequest{
            Request.ServerRaw,
            Request.ServerContext,
            Request.Config,
            Request.Payload,
            Request.ServerSucceeded};
        auto ClientOperation = Net::co_spawn(
            Request.Executor, RunFactoryClient(std::move(ClientRequest)), Net::use_awaitable);
        auto ServerOperation = Net::co_spawn(
            Request.Executor, RunFactoryServer(std::move(ServerRequest)), Net::use_awaitable);
        co_await (std::move(ClientOperation) && std::move(ServerOperation));
        co_return;
    }

    auto RunFactoryScenario(FactoryScenarioRequest Request) -> Net::awaitable<void>
    {
        auto PairOperation = Net::co_spawn(
            Request.Executor, RunFactoryPair(Request), Net::use_awaitable);
        auto WatchdogOperation = Net::co_spawn(
            Request.Executor,
            RunWatchdog(Request.Executor, std::chrono::seconds(5), Request.TimedOut),
            Net::use_awaitable);
        try
        {
            auto RaceResult = co_await (std::move(PairOperation) || std::move(WatchdogOperation));
            (void)RaceResult;
        }
        catch (...)
        {
            *Request.ClientSucceeded = false;
            *Request.ServerSucceeded = false;
        }
        if (Request.ClientRaw)
        {
            Request.ClientRaw->Close();
        }
        if (Request.ServerRaw)
        {
            Request.ServerRaw->Close();
        }
        co_return;
    }

    auto RunSplitClient(FactoryScenarioRequest Request) -> Net::awaitable<void>
    {
        *Request.ClientSucceeded = false;
        auto Transport = co_await Xhttp::Connect(
            std::move(Request.ClientRaw), *Request.ClientContext, Request.Config, "example.com");
        if (!Transport)
        {
            co_return;
        }
        const auto PayloadBytes = std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(Request.Payload.data()), Request.Payload.size());
        std::error_code WriteError;
        const auto Written = co_await Transport->AsyncWrite(PayloadBytes, WriteError);
        if (WriteError || Written != PayloadBytes.size())
        {
            Transport->Close();
            co_return;
        }
        std::vector<std::byte> Received(Request.Payload.size());
        std::error_code ReadError;
        const auto Read = co_await Transport->AsyncRead(Received, ReadError);
        *Request.ClientSucceeded = !ReadError && Read == Received.size() &&
                                   std::equal(Received.begin(), Received.end(), PayloadBytes.begin());
        Transport->Close();
        co_return;
    }

    auto RunSplitServer(FactoryScenarioRequest Request) -> Net::awaitable<void>
    {
        *Request.ServerSucceeded = false;
        auto Transport = co_await Xhttp::Accept(
            std::move(Request.ServerRaw), *Request.ServerContext, Request.Config);
        if (!Transport)
        {
            co_return;
        }
        std::vector<std::byte> Received(Request.Payload.size());
        std::error_code ReadError;
        const auto Read = co_await Transport->AsyncRead(Received, ReadError);
        if (ReadError || Read != Received.size())
        {
            Transport->Close();
            co_return;
        }
        std::error_code WriteError;
        const auto Written = co_await Transport->AsyncWrite(Received, WriteError);
        *Request.ServerSucceeded = !WriteError && Written == Received.size();
        Transport->Close();
        co_return;
    }

    auto RunSplitPair(FactoryScenarioRequest Request) -> Net::awaitable<void>
    {
        auto ClientOperation = Net::co_spawn(
            Request.Executor, RunSplitClient(Request), Net::use_awaitable);
        auto ServerOperation = Net::co_spawn(
            Request.Executor, RunSplitServer(Request), Net::use_awaitable);
        co_await (std::move(ClientOperation) && std::move(ServerOperation));
        co_return;
    }

    auto RunSplitScenario(FactoryScenarioRequest Request) -> Net::awaitable<void>
    {
        auto PairOperation = Net::co_spawn(
            Request.Executor, RunSplitPair(Request), Net::use_awaitable);
        auto WatchdogOperation = Net::co_spawn(
            Request.Executor,
            RunWatchdog(Request.Executor, std::chrono::seconds(5), Request.TimedOut),
            Net::use_awaitable);
        try
        {
            auto RaceResult = co_await (std::move(PairOperation) || std::move(WatchdogOperation));
            (void)RaceResult;
        }
        catch (...)
        {
            *Request.ClientSucceeded = false;
            *Request.ServerSucceeded = false;
        }
        if (Request.ClientRaw)
        {
            Request.ClientRaw->Close();
        }
        if (Request.ServerRaw)
        {
            Request.ServerRaw->Close();
        }
        co_return;
    }

    template <typename Awaitable>
    auto RunCoroutine(
        const std::shared_ptr<Net::io_context> &IoContext,
        Awaitable Coroutine) -> void
    {
        IoContext->restart();
        auto Exception = std::make_shared<std::exception_ptr>();
        auto Completion = [IoContext, Exception](std::exception_ptr Error) -> void
        {
            *Exception = Error;
            IoContext->stop();
        };
        Net::co_spawn(*IoContext, std::move(Coroutine), std::move(Completion));
        IoContext->run();
        if (*Exception)
        {
            std::rethrow_exception(*Exception);
        }
    }
} // namespace

TEST(XhttpNgxE2E, StreamOneEcho)
{
    auto IoContext = std::make_shared<Net::io_context>();
    auto ServerContext = std::make_shared<SSL::context>(SSL::context::tlsv13);
    LoadSelfSigned(*ServerContext);

    auto ClientContext = std::make_shared<SSL::context>(SSL::context::tlsv13);
    ClientContext->set_verify_mode(SSL::verify_none);

    auto [A, B] = Preview::MakeMemoryPair(IoContext->get_executor());
    auto ClientRaw = std::make_shared<Preview::MemoryStream>(std::move(A));
    auto ServerRaw = std::make_shared<Preview::MemoryStream>(std::move(B));

    const std::string Payload = "xhttp-Stream-one-echo";
    auto ClientSucceeded = std::make_shared<bool>(false);
    auto ServerSucceeded = std::make_shared<bool>(false);
    auto TimedOut = std::make_shared<bool>(false);
    StreamOneScenarioRequest Request{
        IoContext->get_executor(),
        EchoRequest{ClientRaw, ClientContext, Payload, ClientSucceeded},
        EchoRequest{ServerRaw, ServerContext, Payload, ServerSucceeded},
        TimedOut};

    RunCoroutine(IoContext, RunStreamOneScenario(std::move(Request)));
    EXPECT_FALSE(*TimedOut);
    EXPECT_TRUE(*ServerSucceeded);
    EXPECT_TRUE(*ClientSucceeded);
}

TEST(XhttpNgxE2E, ClientFactoryProvidesStreamOneTransport)
{
    auto IoContext = std::make_shared<Net::io_context>();
    auto ServerContext = std::make_shared<SSL::context>(SSL::context::tlsv13);
    LoadSelfSigned(*ServerContext);
    auto ClientContext = std::make_shared<SSL::context>(SSL::context::tlsv13_client);
    ClientContext->set_verify_mode(SSL::verify_none);

    auto [A, B] = Preview::MakeMemoryPair(IoContext->get_executor());
    auto ClientRaw = std::make_shared<Preview::MemoryStream>(std::move(A));
    auto ServerRaw = std::make_shared<Preview::MemoryStream>(std::move(B));
    Xhttp::Config Config;
    const std::string Payload = "xhttp-client-factory-echo";
    auto ClientSucceeded = std::make_shared<bool>(false);
    auto ServerSucceeded = std::make_shared<bool>(false);
    auto TimedOut = std::make_shared<bool>(false);
    FactoryScenarioRequest Request{
        IoContext->get_executor(),
        ClientRaw,
        ServerRaw,
        ClientContext,
        ServerContext,
        Config,
        Payload,
        ClientSucceeded,
        ServerSucceeded,
        TimedOut};

    RunCoroutine(IoContext, RunFactoryScenario(std::move(Request)));
    EXPECT_FALSE(*TimedOut);
    EXPECT_TRUE(*ServerSucceeded);
    EXPECT_TRUE(*ClientSucceeded);
}

TEST(XhttpNgxE2E, SplitModesEcho)
{
    for (const auto Mode : {"StreamUp", "PacketUp"})
    {
        auto IoContext = std::make_shared<Net::io_context>();
        auto ServerContext = std::make_shared<SSL::context>(SSL::context::tlsv13);
        LoadSelfSigned(*ServerContext);
        auto ClientContext = std::make_shared<SSL::context>(SSL::context::tlsv13_client);
        ClientContext->set_verify_mode(SSL::verify_none);

        auto [A, B] = Preview::MakeMemoryPair(IoContext->get_executor());
        auto ClientRaw = std::make_shared<Preview::MemoryStream>(std::move(A));
        auto ServerRaw = std::make_shared<Preview::MemoryStream>(std::move(B));
        Xhttp::Config Config;
        Config.Path = "/xhttp";
        Config.Mode = Mode;
        const std::string Payload = std::string("xhttp-") + Mode + "-echo";
        auto ClientSucceeded = std::make_shared<bool>(false);
        auto ServerSucceeded = std::make_shared<bool>(false);
        auto TimedOut = std::make_shared<bool>(false);
        FactoryScenarioRequest Request{
            IoContext->get_executor(),
            ClientRaw,
            ServerRaw,
            ClientContext,
            ServerContext,
            Config,
            Payload,
            ClientSucceeded,
            ServerSucceeded,
            TimedOut};

        RunCoroutine(IoContext, RunSplitScenario(std::move(Request)));
        EXPECT_FALSE(*TimedOut) << Mode;
        EXPECT_TRUE(*ServerSucceeded) << Mode;
        EXPECT_TRUE(*ClientSucceeded) << Mode;
    }
}
