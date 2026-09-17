/**
 * @file NativeQuicLoopback.cpp
 * @brief Preview 原生 ngtcp2 QUIC UDP loopback 测试
 * @details 使用两个真实 UDP socket 和 TLS 1.3 自签证书，验证：
 *          - Client/Server Initial 与握手完成
 *          - 双向 QUIC stream 收发和大于单包的数据
 *          - QUIC DATAGRAM provider 的数据报边界
 *          - 关闭/取消后的资源收口
 * @note 本测试不依赖生产 src/prism 或 include/prism。
 */

#include <gtest/gtest.h>

#include <boost/asio/experimental/awaitable_operators.hpp>
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
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <future>
#include <memory>
#include <span>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <Preview/Protocols/Quic/Native.hpp>

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

    auto RunLoopback(Net::io_context &Ioc, auto Task, auto OnTimeout) -> void
    {
        auto Watchdog = std::make_shared<Net::steady_timer>(Ioc);
        Watchdog->expires_after(std::chrono::seconds(5));
        Net::co_spawn(
            Ioc,
            [Watchdog, OnTimeout = std::move(OnTimeout), &Ioc]() -> Net::awaitable<void>
            {
                boost::system::error_code ErrorCode;
                co_await Watchdog->async_wait(Net::redirect_error(Net::use_awaitable, ErrorCode));
                if (!ErrorCode)
                {
                    OnTimeout();
                    Ioc.stop();
                }
            },
            Net::detached);
        std::exception_ptr Failure;
        Net::co_spawn(Ioc, std::move(Task), [&](std::exception_ptr Ep)
                      {
                          Failure = std::move(Ep);
                          Ioc.stop();
                      });
        Ioc.run();
        Watchdog->cancel();
        Ioc.restart();
        Ioc.run();
        if (Failure)
        {
            std::rethrow_exception(Failure);
        }
    }

    TEST(NativeQuicLoopback, RandomSourceFailureRejectsConnection)
    {
        Net::io_context Ioc;
        Ssl::context ClientTls(Ssl::context::tlsv13_client);
        auto ClientSocket = std::make_shared<Net::ip::udp::socket>(
            Ioc, Net::ip::udp::endpoint(Net::ip::address_v4::loopback(), 0));
        const Preview::Quic::RandomSource FailingRandom = [](std::uint8_t *, int) { return 0; };
        auto Client = std::make_shared<Preview::Quic::Client>(Preview::Quic::ClientOptions{
            Ioc.get_executor(), ClientSocket,
            Net::ip::udp::endpoint(Net::ip::address_v4::loopback(), 1), ClientTls.native_handle(), "localhost",
            FailingRandom});

        RunLoopback(
            Ioc,
            [&]() -> Net::awaitable<void>
            {
                Client->Start();
                EXPECT_FALSE(co_await Client->WaitHandshake());
                Client->Close();
            },
            [Client]() { Client->Close(); });
    }

    TEST(NativeQuicLoopback, CloseFromForeignExecutor)
    {
        Net::io_context ConnectionIoc;
        Net::io_context CallerIoc;
        Ssl::context ClientTls(Ssl::context::tlsv13_client);
        auto Socket = std::make_shared<Net::ip::udp::socket>(
            ConnectionIoc, Net::ip::udp::endpoint(Net::ip::address_v4::loopback(), 0));
        auto Client = std::make_shared<Preview::Quic::Client>(Preview::Quic::ClientOptions{
            ConnectionIoc.get_executor(), Socket,
            Net::ip::udp::endpoint(Net::ip::address_v4::loopback(), 1), ClientTls.native_handle(), "localhost"});

        std::promise<void> CloseCalled;
        auto CloseCalledFuture = CloseCalled.get_future();
        std::thread Caller([&CallerIoc, Client, &CloseCalled]() mutable
                            {
                                Net::post(CallerIoc,
                                          [Client = std::move(Client), &CloseCalled]() mutable
                                          {
                                              Client->Close();
                                              CloseCalled.set_value();
                                          });
                                CallerIoc.run();
                            });

        CloseCalledFuture.wait();
        ConnectionIoc.run();
        Caller.join();
        EXPECT_FALSE(Socket->is_open());
    }

    TEST(NativeQuicLoopback, HandshakeStreamAndDatagramRoundtrip)
    {
        Net::io_context Ioc;
        Ssl::context ServerTls(Ssl::context::tlsv13_server);
        LoadSelfSigned(ServerTls);
        static constexpr unsigned char H3Alpn[] = {0x02, 'h', '3'};
        SSL_CTX_set_alpn_select_cb(
            ServerTls.native_handle(),
            [](SSL *, const unsigned char **Out, unsigned char *OutLength, const unsigned char *In,
               unsigned int InLength, void *) -> int
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
        Ssl::context ClientTls(Ssl::context::tlsv13_client);
        ClientTls.set_verify_mode(Ssl::verify_none);
        ASSERT_EQ(SSL_CTX_set_alpn_protos(ClientTls.native_handle(), H3Alpn, sizeof(H3Alpn)), 0);

        auto ServerSocket = std::make_shared<Net::ip::udp::socket>(
            Ioc, Net::ip::udp::endpoint(Net::ip::address_v4::loopback(), 0));
        auto ClientSocket = std::make_shared<Net::ip::udp::socket>(
            Ioc, Net::ip::udp::endpoint(Net::ip::address_v4::loopback(), 0));
        const auto ServerEndpoint = ServerSocket->local_endpoint();

        Preview::Quic::ServerOptions ServerOptions;
        ServerOptions.Executor = Ioc.get_executor();
        ServerOptions.Socket = ServerSocket;
        ServerOptions.TlsContext = ServerTls.native_handle();
        ServerOptions.ExpectedAlpn = "h3";
        auto Server = std::make_shared<Preview::Quic::Server>(ServerOptions);

        Preview::Quic::ClientOptions ClientOptions;
        ClientOptions.Executor = Ioc.get_executor();
        ClientOptions.Socket = ClientSocket;
        ClientOptions.Peer = ServerEndpoint;
        ClientOptions.TlsContext = ClientTls.native_handle();
        ClientOptions.ServerName = "localhost";
        auto Client = std::make_shared<Preview::Quic::Client>(ClientOptions);

        RunLoopback(
            Ioc,
            [&]() -> Net::awaitable<void>
            {
                Server->Start();
                Client->Start();
                const auto Handshake = co_await (Client->WaitHandshake() && Server->WaitHandshake());
                EXPECT_TRUE(std::get<0>(Handshake));
                EXPECT_TRUE(std::get<1>(Handshake));
                EXPECT_FALSE(Client->Health().BoundedFailure);
                EXPECT_FALSE(Server->Health().BoundedFailure);
                EXPECT_TRUE(Client->Health().SocketReady);
                EXPECT_TRUE(Client->Health().ReceiveLoopReady);
                EXPECT_TRUE(Client->Health().HandshakeReady);
                EXPECT_TRUE(Server->Health().SocketReady);
                EXPECT_TRUE(Server->Health().ReceiveLoopReady);
                EXPECT_TRUE(Server->Health().HandshakeReady);
                if (!std::get<0>(Handshake) || !std::get<1>(Handshake))
                {
                    Client->Close();
                    Server->Close();
                    co_return;
                }

                auto ClientStream = co_await Client->OpenBidirectionalStream();
                EXPECT_NE(ClientStream, nullptr);
                if (!ClientStream)
                {
                    Client->Close();
                    Server->Close();
                    co_return;
                }

                std::vector<std::byte> Message(128 * 1024, std::byte{0x5A});
                auto ReadExact = [](Preview::Quic::SharedStreamProvider Stream,
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
                };

                std::vector<std::byte> Received(Message.size());
                auto AcceptAndRead = [&]() -> Net::awaitable<std::pair<Preview::Quic::SharedStreamProvider,
                                                                         std::size_t>>
                {
                    auto Stream = co_await Server->AcceptBidirectionalStream();
                    if (!Stream)
                    {
                        co_return std::pair<Preview::Quic::SharedStreamProvider, std::size_t>{nullptr, 0};
                    }
                    const auto Count = co_await ReadExact(Stream, std::span<std::byte>(Received));
                    co_return std::pair{std::move(Stream), Count};
                };

                std::error_code ClientWriteError;
                const auto [ClientWritten, ReceiveResult] =
                    co_await (ClientStream->Write(Message, ClientWriteError) && AcceptAndRead());
                auto ServerStream = std::move(ReceiveResult.first);
                const auto ReceivedLength = ReceiveResult.second;
                EXPECT_NE(ServerStream, nullptr);
                EXPECT_EQ(ClientWritten, Message.size());
                EXPECT_FALSE(ClientWriteError);
                EXPECT_EQ(ReceivedLength, Received.size());
                EXPECT_EQ(Received, Message);
                if (ClientWriteError || ClientWritten != Message.size() || ReceivedLength != Received.size())
                {
                    Client->Close();
                    Server->Close();
                    co_return;
                }
                ClientStream->ShutdownWrite();

                std::vector<std::byte> Echo(Message.size());
                std::error_code ServerWriteError;
                const auto [ServerWritten, EchoLength] =
                    co_await (ServerStream->Write(Received, ServerWriteError) &&
                              ReadExact(ClientStream, std::span<std::byte>(Echo)));
                EXPECT_EQ(ServerWritten, Received.size());
                EXPECT_FALSE(ServerWriteError);
                EXPECT_EQ(EchoLength, Echo.size());
                EXPECT_EQ(Echo, Message);

                std::error_code Ec;

                auto ClientDatagram = Client->Datagram();
                auto ServerDatagram = Server->Datagram();
                EXPECT_NE(ClientDatagram, nullptr);
                EXPECT_NE(ServerDatagram, nullptr);
                if (!ClientDatagram || !ServerDatagram)
                {
                    Client->Close();
                    Server->Close();
                    co_return;
                }
                const std::array<std::byte, 7> Datagram{
                    std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
                    std::byte{0x05}, std::byte{0x06}, std::byte{0x07}};
                EXPECT_EQ(co_await ClientDatagram->Send(Datagram, Ec), Datagram.size());
                EXPECT_FALSE(Ec);
                std::array<std::byte, 32> DatagramReceived{};
                EXPECT_EQ(co_await ServerDatagram->Receive(DatagramReceived, Ec), Datagram.size());
                EXPECT_FALSE(Ec);
                EXPECT_TRUE(std::equal(Datagram.begin(), Datagram.end(), DatagramReceived.begin()));

                ClientStream->Close();
                ServerStream->Close();
                Client->Close();
                Server->Close();
            },
            [Client, Server]()
            {
                Client->Close();
                Server->Close();
            });
    }

    TEST(NativeQuicLoopback, UnidirectionalStreamsRoundtrip)
    {
        Net::io_context Ioc;
        Ssl::context ServerTls(Ssl::context::tlsv13_server);
        LoadSelfSigned(ServerTls);
        static constexpr unsigned char H3Alpn[] = {0x02, 'h', '3'};
        SSL_CTX_set_alpn_select_cb(
            ServerTls.native_handle(),
            [](SSL *, const unsigned char **Out, unsigned char *OutLength, const unsigned char *In,
               unsigned int InLength, void *) -> int
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
        Ssl::context ClientTls(Ssl::context::tlsv13_client);
        ClientTls.set_verify_mode(Ssl::verify_none);
        ASSERT_EQ(SSL_CTX_set_alpn_protos(ClientTls.native_handle(), H3Alpn, sizeof(H3Alpn)), 0);

        auto ServerSocket = std::make_shared<Net::ip::udp::socket>(
            Ioc, Net::ip::udp::endpoint(Net::ip::address_v4::loopback(), 0));
        auto ClientSocket = std::make_shared<Net::ip::udp::socket>(
            Ioc, Net::ip::udp::endpoint(Net::ip::address_v4::loopback(), 0));
        const auto ServerEndpoint = ServerSocket->local_endpoint();
        Preview::Quic::ServerOptions ServerOptions;
        ServerOptions.Executor = Ioc.get_executor();
        ServerOptions.Socket = ServerSocket;
        ServerOptions.TlsContext = ServerTls.native_handle();
        ServerOptions.ExpectedAlpn = "h3";
        auto Server = std::make_shared<Preview::Quic::Server>(ServerOptions);

        Preview::Quic::ClientOptions ClientOptions;
        ClientOptions.Executor = Ioc.get_executor();
        ClientOptions.Socket = ClientSocket;
        ClientOptions.Peer = ServerEndpoint;
        ClientOptions.TlsContext = ClientTls.native_handle();
        ClientOptions.ServerName = "localhost";
        auto Client = std::make_shared<Preview::Quic::Client>(ClientOptions);

        RunLoopback(
            Ioc,
            [&]() -> Net::awaitable<void>
            {
                Server->Start();
                Client->Start();
                const auto Handshake = co_await (Client->WaitHandshake() && Server->WaitHandshake());
                EXPECT_TRUE(std::get<0>(Handshake));
                EXPECT_TRUE(std::get<1>(Handshake));
                if (!std::get<0>(Handshake) || !std::get<1>(Handshake))
                {
                    Client->Close();
                    Server->Close();
                    co_return;
                }

                const std::array<std::uint8_t, 16> Label{
                    0x12, 0x3E, 0x45, 0x67, 0xE8, 0x9B, 0x12, 0xD3,
                    0xA4, 0x56, 0x42, 0x66, 0x14, 0x17, 0x40, 0x00};
                std::array<std::uint8_t, 32> ClientExport{};
                std::array<std::uint8_t, 32> ServerExport{};
                EXPECT_TRUE(Client->ExportKeyingMaterial(ClientExport, Label, "tuic_password"));
                EXPECT_TRUE(Server->ExportKeyingMaterial(ServerExport, Label, "tuic_password"));
                EXPECT_EQ(ClientExport, ServerExport);

                auto ClientUni = co_await Client->OpenUnidirectionalStream();
                EXPECT_NE(ClientUni, nullptr);
                if (!ClientUni)
                {
                    Client->Close();
                    Server->Close();
                    co_return;
                }
                std::error_code Ec;
                const std::array<std::byte, 3> ClientMessage{
                    std::byte{0x03}, std::byte{0x01}, std::byte{0x02}};
                EXPECT_EQ(co_await ClientUni->Write(ClientMessage, Ec), ClientMessage.size());
                EXPECT_FALSE(Ec);
                auto ServerUni = co_await Server->AcceptUnidirectionalStream();
                EXPECT_NE(ServerUni, nullptr);
                if (!ServerUni)
                {
                    Client->Close();
                    Server->Close();
                    co_return;
                }
                std::array<std::byte, 8> ServerBuffer{};
                const auto ServerRead = co_await ServerUni->Read(ServerBuffer, Ec);
                EXPECT_FALSE(Ec);
                EXPECT_EQ(ServerRead, ClientMessage.size());
                EXPECT_TRUE(std::equal(ClientMessage.begin(), ClientMessage.end(), ServerBuffer.begin()));

                auto ServerCreated = co_await Server->OpenUnidirectionalStream();
                EXPECT_NE(ServerCreated, nullptr);
                if (!ServerCreated)
                {
                    Client->Close();
                    Server->Close();
                    co_return;
                }
                const std::array<std::byte, 2> ServerMessage{std::byte{0xA5}, std::byte{0x5A}};
                EXPECT_EQ(co_await ServerCreated->Write(ServerMessage, Ec), ServerMessage.size());
                EXPECT_FALSE(Ec);
                auto ClientReceived = co_await Client->AcceptUnidirectionalStream();
                EXPECT_NE(ClientReceived, nullptr);
                if (!ClientReceived)
                {
                    Client->Close();
                    Server->Close();
                    co_return;
                }
                std::array<std::byte, 8> ClientBuffer{};
                const auto ClientRead = co_await ClientReceived->Read(ClientBuffer, Ec);
                EXPECT_FALSE(Ec);
                EXPECT_EQ(ClientRead, ServerMessage.size());
                EXPECT_TRUE(std::equal(ServerMessage.begin(), ServerMessage.end(), ClientBuffer.begin()));

                ClientUni->Close();
                ServerUni->Close();
                ServerCreated->Close();
                ClientReceived->Close();
                Client->Close();
                Server->Close();
            },
            [Client, Server]()
            {
                Client->Close();
                Server->Close();
            });
    }

    TEST(NativeQuicLoopback, SharedSocketSecondServerCannotCloseFirstSocket)
    {
        Net::io_context Ioc;
        Ssl::context ServerTls(Ssl::context::tlsv13_server);
        auto ServerSocket = std::make_shared<Net::ip::udp::socket>(
            Ioc, Net::ip::udp::endpoint(Net::ip::address_v4::loopback(), 0));

        const auto Options = Preview::Quic::ServerOptions{
            Ioc.get_executor(), ServerSocket, ServerTls.native_handle()};
        auto First = std::make_shared<Preview::Quic::Server>(Options);
        auto Second = std::make_shared<Preview::Quic::Server>(Options);

        RunLoopback(
            Ioc,
            [&]() -> Net::awaitable<void>
            {
                First->Start();
                Second->Start();
                Second->Close();
                EXPECT_TRUE(ServerSocket->is_open());
                First->Close();
                co_return;
            },
            [First, Second]()
            {
                First->Close();
                Second->Close();
            });
    }

} // namespace
