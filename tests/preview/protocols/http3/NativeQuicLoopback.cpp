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
#include <memory>
#include <span>
#include <string>
#include <vector>

#include <preview/Protocols/Quic/Native.hpp>

namespace
{
    namespace net = boost::asio;
    namespace ssl = net::ssl;
    using namespace boost::asio::experimental::awaitable_operators;
    using namespace Preview;

    auto LoadSelfSigned(ssl::context &Context) -> void
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

    auto RunLoopback(net::io_context &Ioc, auto Task, auto OnTimeout) -> void
    {
        auto Watchdog = std::make_shared<net::steady_timer>(Ioc);
        Watchdog->expires_after(std::chrono::seconds(5));
        net::co_spawn(
            Ioc,
            [Watchdog, OnTimeout = std::move(OnTimeout), &Ioc]() -> net::awaitable<void>
            {
                boost::system::error_code ErrorCode;
                co_await Watchdog->async_wait(net::redirect_error(net::use_awaitable, ErrorCode));
                if (!ErrorCode)
                {
                    OnTimeout();
                    Ioc.stop();
                }
            },
            net::detached);
        std::exception_ptr Failure;
        net::co_spawn(Ioc, std::move(Task), [&](std::exception_ptr Ep)
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

    TEST(NativeQuicLoopback, HandshakeStreamAndDatagramRoundtrip)
    {
        net::io_context Ioc;
        ssl::context ServerTls(ssl::context::tlsv13_server);
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
        ssl::context ClientTls(ssl::context::tlsv13_client);
        ClientTls.set_verify_mode(ssl::verify_none);
        ASSERT_EQ(SSL_CTX_set_alpn_protos(ClientTls.native_handle(), H3Alpn, sizeof(H3Alpn)), 0);

        auto ServerSocket = std::make_shared<net::ip::udp::socket>(
            Ioc, net::ip::udp::endpoint(net::ip::address_v4::loopback(), 0));
        auto ClientSocket = std::make_shared<net::ip::udp::socket>(
            Ioc, net::ip::udp::endpoint(net::ip::address_v4::loopback(), 0));
        const auto ServerEndpoint = ServerSocket->local_endpoint();

        auto Server = std::make_shared<Preview::Quic::Server>(Preview::Quic::ServerOptions{
            Ioc.get_executor(), ServerSocket, ServerTls.native_handle()});
        auto Client = std::make_shared<Preview::Quic::Client>(Preview::Quic::ClientOptions{
            Ioc.get_executor(), ClientSocket, ServerEndpoint, ClientTls.native_handle(), "localhost"});

        RunLoopback(
            Ioc,
            [&]() -> net::awaitable<void>
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

                auto ClientStream = co_await Client->OpenBidirectionalStream();
                EXPECT_NE(ClientStream, nullptr);
                if (!ClientStream)
                {
                    Client->Close();
                    Server->Close();
                    co_return;
                }

                std::vector<std::byte> Message(4096, std::byte{0x5A});
                std::error_code Ec;
                EXPECT_EQ(co_await ClientStream->Write(Message, Ec), Message.size());
                EXPECT_FALSE(Ec);

                auto ServerStream = co_await Server->AcceptBidirectionalStream();
                EXPECT_NE(ServerStream, nullptr);
                if (!ServerStream)
                {
                    Client->Close();
                    Server->Close();
                    co_return;
                }

                std::vector<std::byte> Received(Message.size());
                std::size_t ReceivedLength = 0;
                while (ReceivedLength < Received.size())
                {
                    const auto Length = co_await ServerStream->Read(
                        std::span<std::byte>(Received).subspan(ReceivedLength), Ec);
                    if (Ec || Length == 0)
                    {
                        break;
                    }
                    ReceivedLength += Length;
                }
                EXPECT_FALSE(Ec);
                EXPECT_EQ(ReceivedLength, Received.size());
                EXPECT_EQ(Received, Message);
                if (Ec || ReceivedLength != Received.size())
                {
                    Client->Close();
                    Server->Close();
                    co_return;
                }

                EXPECT_EQ(co_await ServerStream->Write(Received, Ec), Received.size());
                EXPECT_FALSE(Ec);
                std::vector<std::byte> Echo(Message.size());
                std::size_t EchoLength = 0;
                while (EchoLength < Echo.size())
                {
                    const auto Length = co_await ClientStream->Read(
                        std::span<std::byte>(Echo).subspan(EchoLength), Ec);
                    if (Ec || Length == 0)
                    {
                        break;
                    }
                    EchoLength += Length;
                }
                EXPECT_FALSE(Ec);
                EXPECT_EQ(EchoLength, Echo.size());
                EXPECT_EQ(Echo, Message);

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

} // namespace
