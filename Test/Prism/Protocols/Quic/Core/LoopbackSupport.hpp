#pragma once

/**
 * @file LoopbackSupport.hpp
 * @brief 原生 QUIC loopback 测试共享 fixture 与协程辅助。
 * @details 共享真实 UDP socket、TLS 上下文、握手和关闭驱动，不承载 TEST 宏。
 */

#include <gtest/gtest.h>

#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <array>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <expected>
#include <functional>
#include <future>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#include <Prism/Protocols/Quic/Native.hpp>
#include <TestSupport/Prism/QuicFactory.hpp>

namespace
{
    namespace Net = boost::asio;
    namespace Ssl = Net::ssl;
    using boost::asio::experimental::awaitable_operators::operator&&;

    auto LoadSelfSigned(Ssl::context &Context) -> void
    {
        auto *KeyContext = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
        EVP_PKEY *Key = nullptr;
        ASSERT_NE(KeyContext, nullptr);
        ASSERT_GT(EVP_PKEY_keygen_init(KeyContext), 0);
        ASSERT_GT(EVP_PKEY_CTX_set_rsa_keygen_bits(KeyContext, 2048), 0);
        ASSERT_GT(EVP_PKEY_keygen(KeyContext, &Key), 0);
        EVP_PKEY_CTX_free(KeyContext);
        ASSERT_NE(Key, nullptr);

        auto *Certificate = X509_new();
        ASSERT_NE(Certificate, nullptr);
        ASSERT_GT(X509_set_version(Certificate, 2), 0);
        ASSERT_GT(ASN1_INTEGER_set(X509_get_serialNumber(Certificate), 1), 0);
        ASSERT_NE(X509_gmtime_adj(X509_get_notBefore(Certificate), 0), nullptr);
        ASSERT_NE(X509_gmtime_adj(X509_get_notAfter(Certificate), 3600), nullptr);

        auto *Name = X509_NAME_new();
        ASSERT_NE(Name, nullptr);
        ASSERT_GT(X509_NAME_add_entry_by_txt(Name, "CN", MBSTRING_ASC,
                                              reinterpret_cast<const unsigned char *>("localhost"), -1, -1,
                                              0),
                  0);
        ASSERT_GT(X509_set_subject_name(Certificate, Name), 0);
        ASSERT_GT(X509_set_issuer_name(Certificate, Name), 0);
        X509_NAME_free(Name);
        ASSERT_GT(X509_set_pubkey(Certificate, Key), 0);
        ASSERT_GT(X509_sign(Certificate, Key, EVP_sha256()), 0);
        ASSERT_EQ(SSL_CTX_use_certificate(Context.native_handle(), Certificate), 1);
        ASSERT_EQ(SSL_CTX_use_PrivateKey(Context.native_handle(), Key), 1);
        X509_free(Certificate);
        EVP_PKEY_free(Key);
    }

    struct LoopbackLifecycle final
    {
        std::function<void()> OnTimeout;
        std::function<void()> OnFailure;
        std::chrono::seconds Timeout{5};
    };

    struct LoopbackState final
    {
        bool TaskCompleted{false};
        bool WatchdogCompleted{false};
        bool TimeoutExpired{false};
        std::exception_ptr Failure;
    };

    /** @brief 驱动 loopback task 与 watchdog，自然等待双方真实退栈。 */
    auto RunLoopback(
        Net::io_context &Ioc,
        auto Task,
        LoopbackLifecycle Lifecycle) -> void
    {
        auto Watchdog = std::make_shared<Net::steady_timer>(Ioc);
        Watchdog->expires_after(Lifecycle.Timeout);
        auto State = std::make_shared<LoopbackState>();
        Net::co_spawn(
            Ioc,
            [Watchdog, Lifecycle, State]() -> Net::awaitable<void>
            {
                boost::system::error_code ErrorCode; co_await Watchdog->async_wait(Net::redirect_error(Net::use_awaitable, ErrorCode));
                if (!ErrorCode && !State->TaskCompleted)
                {
                    State->TimeoutExpired = true;
                    try { Lifecycle.OnTimeout(); }
                    catch (...) { if (!State->Failure) State->Failure = std::current_exception(); }
                }
            },
            [State](std::exception_ptr Ep)
            {
                State->WatchdogCompleted = true;
                if (Ep && !State->Failure) State->Failure = std::move(Ep);
            });
        Net::co_spawn(Ioc, std::move(Task),
                      [Lifecycle, Watchdog, State](std::exception_ptr Ep) {
                          State->TaskCompleted = true;
                          if (Ep && !State->Failure) State->Failure = Ep;
                          if (Ep) { try { Lifecycle.OnFailure(); } catch (...) { if (!State->Failure) State->Failure = std::current_exception(); } }
                          Watchdog->cancel();
                      });
        Ioc.run();
        if (State->Failure)
        {
            std::rethrow_exception(State->Failure);
        }
        if (State->TimeoutExpired)
        {
            throw std::runtime_error("native QUIC loopback watchdog expired");
        }
    }

    auto ConfigureH3Tls(Ssl::context &ServerTls, Ssl::context &ClientTls) -> void
    {
        LoadSelfSigned(ServerTls);
        SSL_CTX_set_alpn_select_cb(
            ServerTls.native_handle(),
            [](SSL *, const unsigned char **Out, unsigned char *OutLength, const unsigned char *In, unsigned int InLength, void *) -> int
            {
                static constexpr unsigned char H3[] = {0x02, 'h', '3'};
                if (SSL_select_next_proto(const_cast<unsigned char **>(Out), OutLength, H3, sizeof(H3), In,
                                          InLength) == OPENSSL_NPN_NEGOTIATED)
                {
                    return SSL_TLSEXT_ERR_OK;
                }
                return SSL_TLSEXT_ERR_ALERT_FATAL;
            },
            nullptr);
        static constexpr unsigned char H3Alpn[] = {0x02, 'h', '3'};
        ClientTls.set_verify_mode(Ssl::verify_none);
        ASSERT_EQ(SSL_CTX_set_alpn_protos(ClientTls.native_handle(), H3Alpn, sizeof(H3Alpn)), 0);
    }

    struct NativeLoopbackPeers final
    {
        explicit NativeLoopbackPeers(
            Net::io_context &Ioc,
            const std::size_t MaxDatagrams = 64,
            Prism::Quic::ServerLifecycleHandler OnLifecycle = {})
            : ServerTls(std::make_shared<Ssl::context>(Ssl::context::tlsv13_server)),
              ClientTls(std::make_shared<Ssl::context>(Ssl::context::tlsv13_client))
        {
            ConfigureH3Tls(*ServerTls, *ClientTls);
            ServerSocket = std::make_shared<Net::ip::udp::socket>(
                Ioc, Net::ip::udp::endpoint(Net::ip::address_v4::loopback(), 0));
            ClientSocket = std::make_shared<Net::ip::udp::socket>(
                Ioc, Net::ip::udp::endpoint(Net::ip::address_v4::loopback(), 0));

            Prism::Quic::ServerOptions ServerOptions;
            ServerOptions.Executor = Ioc.get_executor();
            ServerOptions.Socket = ServerSocket;
            ServerOptions.Sender = Prism::Testing::Quic::MakeSender(ServerSocket);
            ServerOptions.TlsContext = ServerTls;
            ServerOptions.ExpectedAlpn = "h3";
            ServerOptions.MaxDatagrams = MaxDatagrams;
            ServerOptions.OnLifecycle = std::move(OnLifecycle);
            Server = std::make_shared<Prism::Quic::Server>(ServerOptions);

            Prism::Quic::ClientOptions ClientOptions;
            ClientOptions.Executor = Ioc.get_executor();
            ClientOptions.Socket = ClientSocket;
            ClientOptions.Peer = ServerSocket->local_endpoint();
            ClientOptions.TlsContext = ClientTls;
            ClientOptions.ServerName = "localhost";
            Client = std::make_shared<Prism::Quic::Client>(ClientOptions);
        }

        std::shared_ptr<Ssl::context> ServerTls;
        std::shared_ptr<Ssl::context> ClientTls;
        std::shared_ptr<Net::ip::udp::socket> ServerSocket;
        std::shared_ptr<Net::ip::udp::socket> ClientSocket;
        std::shared_ptr<Prism::Quic::Server> Server;
        std::shared_ptr<Prism::Quic::Client> Client;
    };

    auto ReadExactStream(
        Prism::Quic::SharedStreamProvider Stream,
        std::span<std::byte> Buffer) -> Net::awaitable<std::size_t>
    {
        std::size_t Done = 0;
        while (Done < Buffer.size())
        {
            std::error_code ReadError;
            const auto Count = co_await Stream->Read(Buffer.subspan(Done), ReadError);
            if (ReadError || Count == 0 || Count > Buffer.size() - Done)
            {
                co_return Done;
            }
            Done += Count;
        }
        co_return Done;
    }

    enum class DatagramProviderAction : std::uint8_t
    {
        Cancel,
        Close,
    };

    using DatagramSignal = Net::experimental::channel<void(boost::system::error_code)>;

    struct PendingDatagramRead final
    {
        PendingDatagramRead(Net::any_io_executor Executor, Prism::Quic::SharedDatagramProvider ProviderValue)
            : Started(Executor, 1), Completed(std::move(Executor), 1), Provider(std::move(ProviderValue))
        {
        }

        DatagramSignal Started, Completed;
        Prism::Quic::SharedDatagramProvider Provider;
        std::array<std::byte, 4> Buffer{};
        std::size_t Count{0};
        std::error_code Error;
        std::exception_ptr Failure;
    };

    struct DatagramProviderCleanup final
    {
        auto Close() noexcept -> void
        {
            if (Closed)
            {
                return;
            }
            Closed = true;
            for (const auto &Provider : Providers)
            {
                try
                {
                    if (Provider)
                    {
                        Provider->Close();
                    }
                }
                catch (...)
                {
                }
            }
        }

        ~DatagramProviderCleanup() noexcept
        {
            Close();
        }

        std::array<Prism::Quic::SharedDatagramProvider, 2> Providers;
        bool Closed{false};
    };

    struct DatagramProviderFollowup final
    {
        std::shared_ptr<Prism::Quic::Client> Client;
        std::shared_ptr<Prism::Quic::Server> Server;
        Prism::Quic::SharedDatagramProvider ClientDatagram;
        Prism::Quic::SharedDatagramProvider ServerDatagram;
        bool &TimedOut;
    };

    auto VerifyDatagramAfterCancel(DatagramProviderFollowup Followup) -> Net::awaitable<void>
    {
        const std::array<std::byte, 4> Payload{
            std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44}};
        std::array<std::byte, 4> Received{};
        std::error_code SendError;
        std::error_code ReadError;
        EXPECT_EQ(co_await Followup.ClientDatagram->Send(Payload, SendError), Payload.size());
        if (Followup.TimedOut)
        {
            co_return;
        }
        EXPECT_FALSE(SendError);
        EXPECT_EQ(co_await Followup.ServerDatagram->Receive(Received, ReadError), Payload.size());
        if (Followup.TimedOut)
        {
            co_return;
        }
        EXPECT_FALSE(ReadError);
        EXPECT_EQ(Received, Payload);
    }

    auto CloseStreamForTest(const Prism::Quic::SharedStreamProvider &Provider) -> void
    {
        if (Provider)
        {
            const auto Closed = Provider->Close();
            EXPECT_TRUE(Closed);
        }
    }

    [[nodiscard]] auto AcceptAndReadStream(
        const std::shared_ptr<Prism::Quic::Server> &Server,
        std::span<std::byte> Buffer)
        -> Net::awaitable<std::pair<Prism::Quic::SharedStreamProvider, std::size_t>>
    {
        const auto Accepted = co_await Server->AcceptBidirectionalStream();
        if (!Accepted)
        {
            co_return std::pair<Prism::Quic::SharedStreamProvider, std::size_t>{nullptr, 0U};
        }
        auto Stream = std::move(*Accepted);
        const auto Count = co_await ReadExactStream(Stream, Buffer);
        co_return std::pair{std::move(Stream), Count};
    }

    [[nodiscard]] auto OpenAndAcceptBidirectionalStreams(
        const std::shared_ptr<Prism::Quic::Client> &Client,
        const std::shared_ptr<Prism::Quic::Server> &Server)
        -> Net::awaitable<std::expected<
            std::pair<Prism::Quic::SharedStreamProvider,
                      Prism::Quic::SharedStreamProvider>,
            Prism::Fault::Failure>>
    {
        auto Opened = co_await Client->OpenBidirectionalStream();
        if (!Opened)
        {
            co_return std::unexpected(Opened.error());
        }
        auto ClientStream = std::move(*Opened);
        const std::array<std::byte, 1> Announcement{std::byte{0x5A}};
        std::error_code WriteError;
        const auto Written = co_await ClientStream->Write(Announcement, WriteError);
        if (WriteError || Written != Announcement.size())
        {
            CloseStreamForTest(ClientStream);
            const auto Failure = WriteError
                ? Prism::Fault::FromNative(WriteError)
                : Prism::Fault::Failure{Prism::Fault::Code::IoError};
            co_return std::unexpected(Failure);
        }
        auto Accepted = co_await Server->AcceptBidirectionalStream();
        if (!Accepted)
        {
            CloseStreamForTest(ClientStream);
            co_return std::unexpected(Accepted.error());
        }
        co_return std::pair{
            std::move(ClientStream), std::move(*Accepted)};
    }

    auto VerifyBidiAfterDatagramClose(DatagramProviderFollowup Followup) -> Net::awaitable<void>
    {
        auto OpenedClientStream = co_await Followup.Client->OpenBidirectionalStream();
        if (Followup.TimedOut)
        {
            if (OpenedClientStream) CloseStreamForTest(*OpenedClientStream);
            co_return;
        }
        EXPECT_TRUE(OpenedClientStream);
        if (!OpenedClientStream)
        {
            co_return;
        }
        auto ClientStream = std::move(*OpenedClientStream);

        const std::array<std::byte, 1> Payload{std::byte{0xA5}};
        std::array<std::byte, 1> Received{};
        std::error_code WriteError;
        const auto Written = co_await ClientStream->Write(Payload, WriteError);
        if (Followup.TimedOut)
        {
            CloseStreamForTest(ClientStream);
            co_return;
        }
        EXPECT_EQ(Written, Payload.size());
        EXPECT_FALSE(WriteError);
        if (WriteError || Written != Payload.size())
        {
            CloseStreamForTest(ClientStream);
            co_return;
        }

        auto AcceptedServerStream = co_await Followup.Server->AcceptBidirectionalStream();
        if (Followup.TimedOut)
        {
            CloseStreamForTest(ClientStream);
            if (AcceptedServerStream) CloseStreamForTest(*AcceptedServerStream);
            co_return;
        }
        EXPECT_TRUE(AcceptedServerStream);
        if (!AcceptedServerStream)
        {
            CloseStreamForTest(ClientStream);
            co_return;
        }
        auto ServerStream = std::move(*AcceptedServerStream);

        std::error_code ReadError;
        const auto Read = co_await ServerStream->Read(Received, ReadError);
        if (Followup.TimedOut)
        {
            CloseStreamForTest(ClientStream);
            CloseStreamForTest(ServerStream);
            co_return;
        }
        EXPECT_EQ(Read, Received.size());
        EXPECT_FALSE(ReadError);
        EXPECT_EQ(Received, Payload);
        CloseStreamForTest(ClientStream);
        CloseStreamForTest(ServerStream);
    }

    struct DatagramLifecycleRequest final
    {
        Net::io_context &Ioc;
        std::shared_ptr<Prism::Quic::Client> Client;
        std::shared_ptr<Prism::Quic::Server> Server;
        DatagramProviderAction Action;
        std::shared_ptr<DatagramProviderCleanup> Cleanup;
        std::shared_ptr<bool> TimedOut;
    };

    /** @brief 驱动 datagram provider cancel/close 生命周期并等待 pending read。 */
    auto RunDatagramProviderLifecycleOperation(DatagramLifecycleRequest Request)
        -> Net::awaitable<void>
    {
        auto ClosePeers = [&]()
        {
            Request.Client->Close();
            Request.Server->Close();
        };
        if (*Request.TimedOut)
        {
            co_return;
        }
        Request.Server->Start();
        Request.Client->Start();
        const auto Handshake = co_await (
            Request.Client->WaitHandshake() && Request.Server->WaitHandshake());
        if (*Request.TimedOut)
        {
            co_return;
        }
        EXPECT_TRUE(std::get<0>(Handshake) && std::get<1>(Handshake));
        if (!std::get<0>(Handshake) || !std::get<1>(Handshake))
        {
            ClosePeers();
            co_return;
        }
        auto ClientDatagram = Request.Client->Datagram();
        auto ServerDatagram = Request.Server->Datagram();
        Request.Cleanup->Providers = {ClientDatagram, ServerDatagram};
        EXPECT_TRUE(ClientDatagram && ServerDatagram);
        if (!ClientDatagram || !ServerDatagram)
        {
            ClosePeers();
            co_return;
        }
        auto Pending = std::make_shared<PendingDatagramRead>(
            Request.Ioc.get_executor(), ServerDatagram);
        Net::co_spawn(
            Request.Ioc,
            [Pending]() -> Net::awaitable<void>
            {
                (void)Pending->Started.try_send(boost::system::error_code{});
                Pending->Count = co_await Pending->Provider->Receive(
                    Pending->Buffer, Pending->Error);
            },
            [Pending](std::exception_ptr Ep)
            {
                Pending->Failure = std::move(Ep);
                (void)Pending->Completed.try_send(boost::system::error_code{});
            });
        co_await Pending->Started.async_receive(Net::use_awaitable);
        co_await Net::post(Request.Ioc.get_executor(), Net::use_awaitable);
        if (*Request.TimedOut)
        {
            co_await Pending->Completed.async_receive(Net::use_awaitable);
            co_return;
        }
        if (Request.Action == DatagramProviderAction::Cancel)
        {
            ServerDatagram->Cancel();
        }
        else
        {
            ServerDatagram->Close();
        }
        co_await Pending->Completed.async_receive(Net::use_awaitable);
        if (*Request.TimedOut)
        {
            co_return;
        }
        if (Pending->Failure)
        {
            Request.Cleanup->Close();
            ClosePeers();
            std::rethrow_exception(Pending->Failure);
        }
        EXPECT_EQ(Pending->Count, 0U);
        auto ExpectedErrorValue = Prism::Error::BrokenPipe;
        if (Request.Action == DatagramProviderAction::Cancel)
        {
            ExpectedErrorValue = Prism::Error::Canceled;
        }
        const auto ExpectedError = static_cast<std::error_code>(
            Prism::make_error_code(ExpectedErrorValue));
        EXPECT_EQ(Pending->Error, ExpectedError);
        EXPECT_EQ(ServerDatagram->IsClosed(),
                  Request.Action == DatagramProviderAction::Close);
        EXPECT_FALSE(Request.Server->Health().Closed ||
                     Request.Client->Health().Closed);
        const DatagramProviderFollowup Followup{
            Request.Client, Request.Server, ClientDatagram, ServerDatagram,
            *Request.TimedOut};
        if (Request.Action == DatagramProviderAction::Cancel)
        {
            co_await VerifyDatagramAfterCancel(Followup);
        }
        else
        {
            co_await VerifyBidiAfterDatagramClose(Followup);
        }
        Request.Cleanup->Close();
        ClosePeers();
        if (*Request.TimedOut)
        {
            co_return;
        }
        const auto [ClientDrain, ServerDrain] = co_await (
            Request.Client->Drain() && Request.Server->Drain());
        EXPECT_TRUE(ClientDrain);
        EXPECT_TRUE(ServerDrain);
        EXPECT_TRUE(Request.Client->IsRetired());
        EXPECT_TRUE(Request.Server->IsRetired());
    }

    auto RunDatagramProviderLifecycle(const DatagramProviderAction Action) -> void
    {
        Net::io_context Ioc;
        NativeLoopbackPeers Peers(Ioc);
        const auto Server = Peers.Server;
        const auto Client = Peers.Client;
        auto ProviderCleanup = std::make_shared<DatagramProviderCleanup>();
        auto TimedOut = std::make_shared<bool>(false);
        RunLoopback(
            Ioc,
            RunDatagramProviderLifecycleOperation(DatagramLifecycleRequest{
                Ioc, Client, Server, Action, ProviderCleanup, TimedOut}),
            LoopbackLifecycle{
                [Client, Server, ProviderCleanup, TimedOut]
                {
                    *TimedOut = true;
                    ProviderCleanup->Close();
                    Client->Close();
                    Server->Close();
                },
                [Client, Server, ProviderCleanup]
                {
                    ProviderCleanup->Close();
                    Client->Close();
                    Server->Close();
                },
                std::chrono::seconds(10)});
        if (*TimedOut)
        {
            ADD_FAILURE() << "Native QUIC datagram provider lifecycle timed out after 10 seconds";
        }
    }

    auto RetainAcceptedStream(NativeLoopbackPeers &Peers,
                              Prism::Quic::SharedStreamProvider &Survivor)
        -> Net::awaitable<void>
    {
        Peers.Server->Start();
        Peers.Client->Start();
        if (!co_await Peers.Client->WaitHandshake())
        {
            throw std::runtime_error("native handshake failed");
        }
        auto OpenedOutbound = co_await Peers.Client->OpenBidirectionalStream();
        if (!OpenedOutbound)
        {
            throw std::runtime_error("native outbound stream missing");
        }
        auto Outbound = std::move(*OpenedOutbound);
        const std::array<std::byte, 1> Payload{std::byte{'S'}};
        std::error_code Error;
        EXPECT_EQ(co_await Outbound->Write(Payload, Error), 1U);
        EXPECT_FALSE(Error);
        auto AcceptedSurvivor = co_await Peers.Server->AcceptBidirectionalStream();
        if (!AcceptedSurvivor)
        {
            throw std::runtime_error("native accepted stream missing");
        }
        Survivor = std::move(*AcceptedSurvivor);
        std::array<std::byte, 1> Received{};
        EXPECT_EQ(co_await Survivor->Read(Received, Error), 1U);
        EXPECT_FALSE(Error);
        EXPECT_EQ(Received, Payload);
        Peers.Client->Close();
        const auto Drained=co_await Peers.Server->Drain();
        EXPECT_TRUE(Drained);
    }

} // namespace

