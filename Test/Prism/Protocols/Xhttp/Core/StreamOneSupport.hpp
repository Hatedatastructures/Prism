#pragma once

#include "Retirement.hpp"

/**
 * @file StreamOneSupport.hpp
 * @brief XHTTP Stream-one 端到端测试共享 TLS、HTTP/2 和 transport fixture。
 * @details 模拟 h2 客户端（Prism Http2）：
 *          1. TLS 握手（自签证书）
 *          2. h2 SETTINGS + POST / 请求（Stream-one）
 *          3. 请求体发送数据，服务端响应 200 + echo
 *          4. 客户端验证回显
 * @note 使用自包含 Http2 实现（非 nghttp2）；本头不承载 TEST 宏。
 */

#include <Prism/Protocols/Http2/Session.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Transport/MemoryStream.hpp>
#include <Prism/Protocols/Xhttp/Xhttp.hpp>
#include <Prism/Protocols/Xhttp/Detail/Stream/Transport.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
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
    namespace Http2 = Prism::Http2;
    namespace Xhttp = Prism::Xhttp;

    using Net::experimental::awaitable_operators::operator&&;
    using Net::experimental::awaitable_operators::operator||;

    using SharedTransmission = Prism::SharedTransmission;
    using SharedSslContext = std::shared_ptr<SSL::context>;
    using XhttpTest::CloseAndDrainXhttp;

    /** @brief 校验 Stream-one 响应头并发布原有断言结果。 */
    struct XhttpResponseHeaderValidator final
    {
        std::shared_ptr<bool> HeadersValid;

        auto operator()(std::int32_t, const Http2::HeaderList &Headers, bool) const -> void
        {
            bool HasStatus = false;
            bool HasContentType = false;
            for (const auto &Header : Headers)
            {
                if (Header.Name == ":status")
                {
                    HasStatus = true;
                    EXPECT_EQ(Header.Value, "200");
                }
                if (Header.Name == "content-type")
                {
                    HasContentType = true;
                    EXPECT_EQ(Header.Value, "text/event-stream");
                }
            }
            EXPECT_TRUE(HasStatus);
            EXPECT_TRUE(HasContentType);
            *HeadersValid = HasStatus && HasContentType;
        }
    };


    [[nodiscard]] inline auto MakeXhttpFactoryBytes()
        -> std::shared_ptr<Prism::Memory::BytePool>
    {
        return std::make_shared<Prism::Memory::BytePool>(
            Prism::Memory::BytePoolOptions{.BlockCount = 8});
    }

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
        struct SplitTrace final
        {
            std::string ClientStage;
            std::string ServerStage;
            std::string ClientError;
            std::string ServerError;
            std::string ServerRetirementError;
            std::size_t ClientBytes{0};
            std::size_t ServerBytes{0};
            std::uint64_t ClientHash{1469598103934665603ULL};
            std::uint64_t ServerHash{1469598103934665603ULL};
            std::string Exception;
        };
        std::shared_ptr<SplitTrace> Trace{};
    };

    auto ErrorText(const std::error_code &Error) -> std::string
    {
        if (!Error)
        {
            return {};
        }
        return std::string(Error.category().name()) + ":" + std::to_string(Error.value()) + ":" +
               Error.message();
    }

    auto HashBytes(std::uint64_t &Hash, std::span<const std::byte> Data) -> void
    {
        for (const auto Byte : Data)
        {
            Hash ^= std::to_integer<std::uint8_t>(Byte);
            Hash *= 1099511628211ULL;
        }
    }

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
        Prism::Transport::Connector Connector(std::move(Request.Raw));
        auto Stream = std::make_shared<SSL::stream<Prism::Transport::Connector>>(
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

        auto Session = std::make_shared<Http2::Session>(Stream->get_executor(), false);
        Session->SendSettings();

        Http2::HeaderList Headers = {
            {":method", "POST"},
            {":path", "/"},
            {":scheme", "https"},
            {":authority", "example.com"},
        };
        const auto StreamId = Session->OpenStream(Headers, false);
        if (!StreamId)
        {
            co_return;
        }
        const auto Http2StreamId = *StreamId;

        const auto PayloadBytes = std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(Request.Payload.data()), Request.Payload.size());
        if (Session->SubmitData(Http2StreamId, PayloadBytes, true) !=
            Prism::Http2::SubmitDataStatus::Accepted)
        {
            co_return;
        }

        std::vector<std::byte> Wire;
        (void)Session->Collect(Wire);
        auto HeadersValid = std::make_shared<bool>(false);
        auto Received = std::make_shared<std::vector<std::byte>>();
        Session->OnHeaders = XhttpResponseHeaderValidator{HeadersValid};
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
        auto Accepted = co_await Xhttp::Accept(Xhttp::AcceptRequest{
            std::move(Request.Raw), *Request.Context, Config, MakeXhttpFactoryBytes()});
        if (!Accepted)
        {
            co_return;
        }
        auto Transport = std::move(Accepted->Transport);

        std::array<std::byte, 4096> Buffer{};
        std::error_code ReadError;
        std::size_t Total = 0;
        while (true)
        {
            auto ReadOperation = Transport->ReadSome(Buffer);
            Net::steady_timer Watchdog(Transport->Executor());
            Watchdog.expires_after(std::chrono::seconds(2));
            auto WatchdogOperation = Watchdog.async_wait(Net::use_awaitable);
            auto ReadRace = co_await (std::move(ReadOperation) || std::move(WatchdogOperation));
            if (ReadRace.index() == 1)
            {
                const auto Retirement = co_await CloseAndDrainXhttp(Transport);
                if (!Retirement) *Request.Succeeded = false;
                co_return;
            }

            const auto Read = std::get<0>(std::move(ReadRace));
            ReadError = Prism::Fault::ToNative(Read.Failure);
            const auto BytesRead = Read.Bytes;
            if (ReadError || BytesRead == 0)
            {
                break;
            }
            Total += BytesRead;

            std::error_code WriteError;
            const auto EchoSpan = std::span<const std::byte>(Buffer.data(), BytesRead);
            const auto Write = co_await Transport->WriteExact(EchoSpan);
            WriteError = Prism::Fault::ToNative(Write.Failure);
            const auto BytesWritten = Write.Bytes;
            if (WriteError || BytesWritten != EchoSpan.size())
            {
                const auto Retirement = co_await CloseAndDrainXhttp(Transport);
                if (!Retirement) *Request.Succeeded = false;
                co_return;
            }
            if (Total >= Request.Payload.size())
            {
                break;
            }
        }

        *Request.Succeeded = Total >= Request.Payload.size();
        const auto Retirement = co_await CloseAndDrainXhttp(Transport);
        *Request.Succeeded = *Request.Succeeded && Retirement.has_value();
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
            const auto Retirement = co_await CloseAndDrainXhttp(Request.Client.Raw);
            if (!Retirement) *Request.Client.Succeeded = false;
        }
        if (Request.Server.Raw)
        {
            const auto Retirement = co_await CloseAndDrainXhttp(Request.Server.Raw);
            if (!Retirement) *Request.Server.Succeeded = false;
        }
        co_return;
    }

    auto RunSplitClient(FactoryScenarioRequest Request) -> Net::awaitable<void>
    {
        *Request.ClientSucceeded = false;
        if (Request.Trace) Request.Trace->ClientStage = "connect:start";
        auto Connected = co_await Xhttp::Connect(Xhttp::ClientConnectRequest{
            std::move(Request.ClientRaw), Request.ClientContext.get(), Request.Config,
            "example.com", MakeXhttpFactoryBytes()});
        if (!Connected)
        {
            if (Request.Trace) Request.Trace->ClientStage = "connect:null";
            co_return;
        }
        auto Transport = std::move(*Connected);
        if (Request.Trace) Request.Trace->ClientStage = "connect:ok";
        const auto PayloadBytes = std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(Request.Payload.data()), Request.Payload.size());
        std::error_code WriteError;
        if (Request.Trace) Request.Trace->ClientStage = "write:start";
        const auto Write = co_await Transport->WriteExact(PayloadBytes);
        WriteError = Prism::Fault::ToNative(Write.Failure);
        const auto Written = Write.Bytes;
        if (Request.Trace)
        {
            Request.Trace->ClientBytes = Written;
            Request.Trace->ClientError = ErrorText(WriteError);
        }
        if (WriteError || Written != PayloadBytes.size())
        {
            if (Request.Trace) Request.Trace->ClientStage = "write:fail";
            const auto Retirement = co_await CloseAndDrainXhttp(Transport);
            if (!Retirement) *Request.ClientSucceeded = false;
            co_return;
        }
        if (Request.Trace) Request.Trace->ClientStage = "write:ok";
        std::vector<std::byte> Received(Request.Payload.size());
        std::error_code ReadError;
        if (Request.Trace) Request.Trace->ClientStage = "read:start";
        const auto ReadResult = co_await Transport->ReadExact(Received);
        ReadError = Prism::Fault::ToNative(ReadResult.Failure);
        const auto Read = ReadResult.Bytes;
        if (Request.Trace)
        {
            Request.Trace->ClientBytes = Read;
            Request.Trace->ClientError = ErrorText(ReadError);
            HashBytes(Request.Trace->ClientHash,
                      std::span<const std::byte>(Received).first((std::min)(Read, Received.size())));
        }
        *Request.ClientSucceeded = !ReadError && Read == Received.size() &&
                                   std::equal(Received.begin(), Received.end(), PayloadBytes.begin());
        const auto Retirement = co_await CloseAndDrainXhttp(Transport);
        *Request.ClientSucceeded = *Request.ClientSucceeded && Retirement.has_value();
        if (Request.Trace)
            if (*Request.ClientSucceeded)
                Request.Trace->ClientStage = "read:ok";
            else
                Request.Trace->ClientStage = "read:fail";
        co_return;
    }

    auto RunSplitServer(FactoryScenarioRequest Request) -> Net::awaitable<void>
    {
        *Request.ServerSucceeded = false;
        if (Request.Trace) Request.Trace->ServerStage = "accept:start";
        auto Accepted = co_await Xhttp::Accept(Xhttp::AcceptRequest{
            std::move(Request.ServerRaw), *Request.ServerContext, Request.Config,
            MakeXhttpFactoryBytes()});
        if (!Accepted)
        {
            if (Request.Trace) Request.Trace->ServerStage = "accept:null";
            co_return;
        }
        auto Transport = std::move(Accepted->Transport);
        if (Request.Trace) Request.Trace->ServerStage = "accept:ok";
        std::vector<std::byte> Received(Request.Payload.size());
        std::error_code ReadError;
        if (Request.Trace) Request.Trace->ServerStage = "read:start";
        const auto ReadResult = co_await Transport->ReadExact(Received);
        ReadError = Prism::Fault::ToNative(ReadResult.Failure);
        const auto Read = ReadResult.Bytes;
        if (Request.Trace)
        {
            Request.Trace->ServerBytes = Read;
            Request.Trace->ServerError = ErrorText(ReadError);
            HashBytes(Request.Trace->ServerHash,
                      std::span<const std::byte>(Received).first((std::min)(Read, Received.size())));
        }
        if (ReadError || Read != Received.size())
        {
            if (Request.Trace) Request.Trace->ServerStage = "read:fail";
            const auto Retirement = co_await CloseAndDrainXhttp(Transport);
            if (!Retirement) *Request.ServerSucceeded = false;
            co_return;
        }
        std::error_code WriteError;
        if (Request.Trace) Request.Trace->ServerStage = "write:start";
        const auto Write = co_await Transport->WriteExact(Received);
        WriteError = Prism::Fault::ToNative(Write.Failure);
        const auto Written = Write.Bytes;
        if (Request.Trace)
        {
            Request.Trace->ServerBytes = Written;
            Request.Trace->ServerError = ErrorText(WriteError);
        }
        *Request.ServerSucceeded = !WriteError && Written == Received.size();
        const auto Retirement = co_await CloseAndDrainXhttp(Transport);
        *Request.ServerSucceeded = *Request.ServerSucceeded && Retirement.has_value();
        if (Request.Trace)
            if (*Request.ServerSucceeded)
                Request.Trace->ServerStage = "write:ok";
            else
                Request.Trace->ServerStage = "write:fail";
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
            if (Request.Trace) Request.Trace->Exception = "pair:exception";
        }
        if (Request.ClientRaw)
        {
            const auto Retirement = co_await CloseAndDrainXhttp(Request.ClientRaw);
            if (!Retirement) *Request.ClientSucceeded = false;
        }
        if (Request.ServerRaw)
        {
            const auto Retirement = co_await CloseAndDrainXhttp(Request.ServerRaw);
            if (!Retirement) *Request.ServerSucceeded = false;
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
        auto Completion = [Exception](std::exception_ptr Error) -> void
        {
            *Exception = Error;
        };
        Net::co_spawn(*IoContext, std::move(Coroutine), std::move(Completion));
        IoContext->run();
        if (*Exception)
        {
            std::rethrow_exception(*Exception);
        }
    }
} // namespace
