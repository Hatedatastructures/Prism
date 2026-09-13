/**
 * @file InteropHysteria2.cpp
 * @brief Preview 原生 QUIC/HTTP3 与独立 sing-quic Hysteria2 客户端互操作
 * @details 覆盖 HTTP/3 认证、Hysteria2 TCP request/response 首帧、裸 TCP
 *          双向数据和对端 FIN 收口。
 */

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/ssl.hpp>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <array>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include <preview/Protocols/Http3/NativeServer.hpp>
#include <preview/Protocols/Hysteria2/Hysteria2.hpp>
#include <preview/Protocols/Quic/Native.hpp>

namespace
{

    namespace Net = boost::asio;
    namespace Ssl = Net::ssl;
    using Udp = Net::ip::udp;

    struct Options
    {
        std::string Address{"127.0.0.1:19088"};
        std::string Password{"hysteria2_password"};
        bool Udp{false};
    };

    struct HostPort
    {
        std::string Host;
        std::uint16_t Port{0};
    };

    struct StreamState
    {
        std::vector<std::byte> Pending;
        bool RequestDone{false};
    };

    [[nodiscard]] auto ParsePort(std::string_view Value) -> std::optional<std::uint16_t>
    {
        std::uint32_t Port = 0;
        if (Value.empty())
        {
            return std::nullopt;
        }
        const auto [End, Error] = std::from_chars(Value.data(), Value.data() + Value.size(), Port);
        if (Error != std::errc{} || End != Value.data() + Value.size() || Port > 65535)
        {
            return std::nullopt;
        }
        return static_cast<std::uint16_t>(Port);
    }

    [[nodiscard]] auto SplitHostPort(std::string_view Value) -> std::optional<HostPort>
    {
        if (Value.starts_with('['))
        {
            const auto Close = Value.find(']');
            if (Close == std::string_view::npos || Close + 1 >= Value.size() || Value[Close + 1] != ':')
            {
                return std::nullopt;
            }
            const auto Port = ParsePort(Value.substr(Close + 2));
            if (!Port)
            {
                return std::nullopt;
            }
            return HostPort{std::string(Value.substr(1, Close - 1)), *Port};
        }
        const auto Colon = Value.rfind(':');
        if (Colon == std::string_view::npos || Colon == 0)
        {
            return std::nullopt;
        }
        const auto Port = ParsePort(Value.substr(Colon + 1));
        if (!Port)
        {
            return std::nullopt;
        }
        return HostPort{std::string(Value.substr(0, Colon)), *Port};
    }

    [[nodiscard]] auto ParseOptions(int Argc, char **Argv) -> std::optional<Options>
    {
        Options Result;
        for (int Index = 1; Index + 1 < Argc; Index += 2)
        {
            const std::string_view Key = Argv[Index];
            const std::string_view Value = Argv[Index + 1];
            if (Key == "-addr")
            {
                Result.Address = Value;
            }
            else if (Key == "-password")
            {
                Result.Password = Value;
            }
            else if (Key == "-udp")
            {
                Result.Udp = Value == "1";
            }
        }
        return Result;
    }

    [[nodiscard]] auto LoadSelfSigned(Ssl::context &Context) -> bool
    {
        auto *KeyContext = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
        EVP_PKEY *Key = nullptr;
        if (!KeyContext || EVP_PKEY_keygen_init(KeyContext) <= 0 ||
            EVP_PKEY_CTX_set_rsa_keygen_bits(KeyContext, 2048) <= 0 ||
            EVP_PKEY_keygen(KeyContext, &Key) <= 0)
        {
            EVP_PKEY_CTX_free(KeyContext);
            return false;
        }
        EVP_PKEY_CTX_free(KeyContext);
        auto *Certificate = X509_new();
        auto *Name = X509_NAME_new();
        const bool Ready = Certificate && Name && X509_set_version(Certificate, 2) > 0 &&
                           ASN1_INTEGER_set(X509_get_serialNumber(Certificate), 1) > 0 &&
                           X509_gmtime_adj(X509_get_notBefore(Certificate), 0) != nullptr &&
                           X509_gmtime_adj(X509_get_notAfter(Certificate), 3600) != nullptr &&
                           X509_NAME_add_entry_by_txt(Name, "CN", MBSTRING_ASC,
                                                      reinterpret_cast<const unsigned char *>("localhost"), -1, -1,
                                                      0) > 0 &&
                           X509_set_subject_name(Certificate, Name) > 0 &&
                           X509_set_issuer_name(Certificate, Name) > 0 &&
                           X509_set_pubkey(Certificate, Key) > 0 &&
                           X509_sign(Certificate, Key, EVP_sha256()) > 0 &&
                           SSL_CTX_use_certificate(Context.native_handle(), Certificate) == 1 &&
                           SSL_CTX_use_PrivateKey(Context.native_handle(), Key) == 1;
        X509_NAME_free(Name);
        X509_free(Certificate);
        EVP_PKEY_free(Key);
        return Ready;
    }

    [[nodiscard]] auto ReadVarint(const std::vector<std::byte> &Data, std::size_t &Offset,
                                  std::uint64_t &Value) -> bool
    {
        if (Offset >= Data.size())
        {
            return false;
        }
        const auto First = std::to_integer<std::uint8_t>(Data[Offset]);
        const auto Length = std::size_t{1U} << (First >> 6U);
        if (Offset + Length > Data.size())
        {
            return false;
        }
        Value = First & 0x3FU;
        for (std::size_t Index = 1; Index < Length; ++Index)
        {
            Value = (Value << 8U) | std::to_integer<std::uint8_t>(Data[Offset + Index]);
        }
        Offset += Length;
        return true;
    }

    auto AppendVarint(std::vector<std::byte> &Output, const std::uint64_t Value) -> void
    {
        if (Value <= 63)
        {
            Output.push_back(static_cast<std::byte>(Value));
            return;
        }
        if (Value <= 16383)
        {
            Output.push_back(static_cast<std::byte>((Value >> 8U) | 0x40U));
            Output.push_back(static_cast<std::byte>(Value));
            return;
        }
        if (Value <= 1073741823)
        {
            Output.push_back(static_cast<std::byte>((Value >> 24U) | 0x80U));
            Output.push_back(static_cast<std::byte>(Value >> 16U));
            Output.push_back(static_cast<std::byte>(Value >> 8U));
            Output.push_back(static_cast<std::byte>(Value));
            return;
        }
        for (std::size_t Index = 0; Index < 8; ++Index)
        {
            const auto Shift = static_cast<unsigned>((7U - Index) * 8U);
            auto Prefix = 0U;
            if (Index == 0)
            {
                Prefix = 0xC0U;
            }
            Output.push_back(static_cast<std::byte>((Value >> Shift) | Prefix));
        }
    }

    [[nodiscard]] auto MakeTcpResponse(std::span<const std::byte> Payload) -> std::vector<std::byte>
    {
        std::vector<std::byte> Output;
        Output.reserve(3U + Payload.size());
        Output.push_back(std::byte{0});
        AppendVarint(Output, 0);
        AppendVarint(Output, 0);
        Output.insert(Output.end(), Payload.begin(), Payload.end());
        return Output;
    }

    struct TcpDataInput
    {
        StreamState &State;
        std::span<const std::byte> Data;
        bool Fin;
        bool &Echoed;
    };

    [[nodiscard]] auto HandleTcpData(TcpDataInput Input) -> Preview::Http3::NativeServerRawData
    {
        Preview::Http3::NativeServerRawData Action;
        if (Input.State.RequestDone)
        {
            Action.Data.assign(Input.Data.begin(), Input.Data.end());
            Action.Fin = Input.Fin;
            return Action;
        }

        Input.State.Pending.insert(Input.State.Pending.end(), Input.Data.begin(), Input.Data.end());
        std::size_t Offset = 0;
        std::uint64_t FrameType = 0;
        std::uint64_t AddressLength = 0;
        std::uint64_t PaddingLength = 0;
        if (!ReadVarint(Input.State.Pending, Offset, FrameType) || FrameType != 0x401 ||
            !ReadVarint(Input.State.Pending, Offset, AddressLength) || AddressLength == 0 ||
            AddressLength > 2048 || Offset + AddressLength > Input.State.Pending.size())
        {
            if (Input.Fin)
            {
                Action.Stop = true;
            }
            return Action;
        }
        Offset += static_cast<std::size_t>(AddressLength);
        if (!ReadVarint(Input.State.Pending, Offset, PaddingLength) || PaddingLength > 4096 ||
            Offset + PaddingLength > Input.State.Pending.size())
        {
            if (Input.Fin)
            {
                Action.Stop = true;
            }
            return Action;
        }
        Offset += static_cast<std::size_t>(PaddingLength);
        Input.State.RequestDone = true;
        Input.Echoed = true;
        Action.Data = MakeTcpResponse(std::span<const std::byte>(Input.State.Pending).subspan(Offset));
        Input.State.Pending.clear();
        Action.Stop = true;
        Action.GracefulClose = std::chrono::milliseconds(100);
        return Action;
    }

    auto RunServer(Options OptionsValue) -> Net::awaitable<int>
    {
        const auto Listen = SplitHostPort(OptionsValue.Address);
        if (!Listen)
        {
            std::fprintf(stderr, "FAIL: malformed Hysteria2 listen address\n");
            co_return 2;
        }
        boost::system::error_code AddressError;
        const auto Address = Net::ip::make_address(Listen->Host, AddressError);
        if (AddressError)
        {
            std::fprintf(stderr, "FAIL: Hysteria2 listen address is not an IP literal\n");
            co_return 2;
        }
        Ssl::context Tls(Ssl::context::tlsv13_server);
        if (!LoadSelfSigned(Tls))
        {
            std::fprintf(stderr, "FAIL: cannot create Hysteria2 self-signed certificate\n");
            co_return 1;
        }
        static constexpr unsigned char H3Alpn[] = {0x02, 'h', '3'};
        SSL_CTX_set_alpn_select_cb(
            Tls.native_handle(),
            [](SSL *, const unsigned char **Out, unsigned char *OutLength, const unsigned char *In,
               unsigned int InLength, void *) -> int
            {
                static constexpr unsigned char H3[] = {0x02, 'h', '3'};
                const auto Result = SSL_select_next_proto(
                    const_cast<unsigned char **>(Out),
                    OutLength,
                    H3,
                    sizeof(H3),
                    In,
                    InLength);
                if (Result == OPENSSL_NPN_NEGOTIATED)
                {
                    return SSL_TLSEXT_ERR_OK;
                }
                return SSL_TLSEXT_ERR_ALERT_FATAL;
            },
            nullptr);

        const auto Executor = co_await Net::this_coro::executor;
        auto Socket = std::make_shared<Udp::socket>(Executor, Udp::endpoint(Address, Listen->Port));
        auto QuicServer = std::make_shared<Preview::Quic::Server>(Preview::Quic::ServerOptions{
            Executor, Socket, Tls.native_handle()});
        QuicServer->Start();
        std::printf("READY: Preview Hysteria2 server on %s\n", OptionsValue.Address.c_str());
        std::fflush(stdout);
        auto HandshakeOperation = QuicServer->WaitHandshake();
        const auto HandshakeOk = co_await std::move(HandshakeOperation);
        if (!HandshakeOk)
        {
            QuicServer->Close();
            co_return 1;
        }

        auto States = std::make_shared<std::unordered_map<std::int64_t, StreamState>>();
        auto Echoed = std::make_shared<bool>(false);
        Preview::Http3::NativeServerSessionOptions SessionOptions;
        SessionOptions.Executor = Executor;
        SessionOptions.Http.authenticate = [Password = OptionsValue.Password](std::string_view Method,
                                                                                std::string_view Path,
                                                                                std::string_view Auth)
        {
            return Method == "POST" && Path == "/auth" && Auth == Password;
        };
        SessionOptions.OpenUnidirectional = [QuicServer]() -> Net::awaitable<Preview::Quic::SharedStreamProvider>
        {
            co_return co_await QuicServer->OpenUnidirectionalStream();
        };
        SessionOptions.AcceptUnidirectional = [QuicServer]() -> Net::awaitable<Preview::Quic::SharedStreamProvider>
        {
            co_return co_await QuicServer->AcceptUnidirectionalStream();
        };
        SessionOptions.AcceptBidirectional = [QuicServer]() -> Net::awaitable<Preview::Quic::SharedStreamProvider>
        {
            co_return co_await QuicServer->AcceptBidirectionalStream();
        };
        SessionOptions.OnRawData = [States, Echoed](const std::int64_t StreamId,
                                                    const std::span<const std::byte> Data, const bool Fin)
            -> Preview::Http3::NativeServerRawData
        {
            auto &State = (*States)[StreamId];
            return HandleTcpData(TcpDataInput{State, Data, Fin, *Echoed});
        };
        auto Session = std::make_shared<Preview::Http3::NativeServerSession>(std::move(SessionOptions));
        auto SessionOperation = Session->Run();
        const auto Code = co_await std::move(SessionOperation);
        QuicServer->Close();
        const auto Authenticated = Session->Authenticated();
        const auto EchoedValue = *Echoed;
        if (Code != Preview::Fault::Code::Success || !Authenticated || !EchoedValue)
        {
            auto AuthenticatedValue = 0;
            if (Authenticated)
            {
                AuthenticatedValue = 1;
            }
            auto EchoedStatus = 0;
            if (EchoedValue)
            {
                EchoedStatus = 1;
            }
            std::fprintf(stderr, "FAIL: Hysteria2 session code=%s authenticated=%d echoed=%d\n",
                         Preview::Fault::Describe(Code).data(),
                         AuthenticatedValue,
                         EchoedStatus);
            co_return 1;
        }
        std::printf("PASS: Preview Hysteria2 authenticated echo\n");
        co_return 0;
    }

    auto RunUdpServer(Options OptionsValue) -> Net::awaitable<int>
    {
        const auto Listen = SplitHostPort(OptionsValue.Address);
        if (!Listen)
        {
            std::fprintf(stderr, "FAIL: malformed Hysteria2 UDP listen address\n");
            co_return 2;
        }
        boost::system::error_code AddressError;
        const auto Address = Net::ip::make_address(Listen->Host, AddressError);
        if (AddressError)
        {
            std::fprintf(stderr, "FAIL: Hysteria2 UDP listen address is not an IP literal\n");
            co_return 2;
        }
        Ssl::context Tls(Ssl::context::tlsv13_server);
        if (!LoadSelfSigned(Tls))
        {
            std::fprintf(stderr, "FAIL: cannot create Hysteria2 UDP self-signed certificate\n");
            co_return 1;
        }
        static constexpr unsigned char H3Alpn[] = {0x02, 'h', '3'};
        SSL_CTX_set_alpn_select_cb(
            Tls.native_handle(),
            [](SSL *, const unsigned char **Out, unsigned char *OutLength, const unsigned char *In,
               unsigned int InLength, void *) -> int
            {
                static constexpr unsigned char H3[] = {0x02, 'h', '3'};
                const auto Result = SSL_select_next_proto(
                    const_cast<unsigned char **>(Out),
                    OutLength,
                    H3,
                    sizeof(H3),
                    In,
                    InLength);
                if (Result == OPENSSL_NPN_NEGOTIATED)
                {
                    return SSL_TLSEXT_ERR_OK;
                }
                return SSL_TLSEXT_ERR_ALERT_FATAL;
            },
            nullptr);

        const auto Executor = co_await Net::this_coro::executor;
        auto Socket = std::make_shared<Udp::socket>(Executor, Udp::endpoint(Address, Listen->Port));
        auto QuicServer = std::make_shared<Preview::Quic::Server>(Preview::Quic::ServerOptions{
            Executor, Socket, Tls.native_handle()});
        QuicServer->Start();
        std::printf("READY: Preview Hysteria2 UDP server on %s\n", OptionsValue.Address.c_str());
        std::fflush(stdout);
        auto HandshakeOperation = QuicServer->WaitHandshake();
        const auto HandshakeOk = co_await std::move(HandshakeOperation);
        if (!HandshakeOk)
        {
            QuicServer->Close();
            co_return 1;
        }

        using NotifyChannel = Net::experimental::channel<void(boost::system::error_code)>;
        auto Authenticated = std::make_shared<NotifyChannel>(Executor, 1);
        Preview::Http3::NativeServerSessionOptions SessionOptions;
        SessionOptions.Executor = Executor;
        SessionOptions.Http.EnableUdp = true;
        SessionOptions.Http.authenticate = [Password = OptionsValue.Password](std::string_view Method,
                                                                                std::string_view Path,
                                                                                std::string_view Auth)
        {
            return Method == "POST" && Path == "/auth" && Auth == Password;
        };
        SessionOptions.OnAuthenticated = [Authenticated]()
        {
            (void)Authenticated->try_send(boost::system::error_code{});
        };
        SessionOptions.OpenUnidirectional = [QuicServer]() -> Net::awaitable<Preview::Quic::SharedStreamProvider>
        {
            co_return co_await QuicServer->OpenUnidirectionalStream();
        };
        SessionOptions.AcceptUnidirectional = [QuicServer]() -> Net::awaitable<Preview::Quic::SharedStreamProvider>
        {
            co_return co_await QuicServer->AcceptUnidirectionalStream();
        };
        SessionOptions.AcceptBidirectional = [QuicServer]() -> Net::awaitable<Preview::Quic::SharedStreamProvider>
        {
            co_return co_await QuicServer->AcceptBidirectionalStream();
        };
        auto Session = std::make_shared<Preview::Http3::NativeServerSession>(std::move(SessionOptions));
        auto SessionOperation = Session->Run();
        Net::co_spawn(Executor, std::move(SessionOperation), Net::detached);

        boost::system::error_code AuthError;
        auto AuthOperation = Authenticated->async_receive(
            Net::redirect_error(Net::use_awaitable, AuthError));
        co_await std::move(AuthOperation);
        if (AuthError)
        {
            Session->Close();
            QuicServer->Close();
            co_return 1;
        }

        auto Dgram = Preview::Hysteria2::AcceptPacket(
            QuicServer->Datagram(), Preview::Hysteria2::ServerConfig{OptionsValue.Password});
        if (!Dgram)
        {
            Session->Close();
            QuicServer->Close();
            co_return 1;
        }
        Preview::Hysteria2::Address Source;
        std::vector<std::uint8_t> Payload;
        auto ReceiveOperation = Dgram->AsyncReceiveFrom(Source, Payload);
        const auto ReceiveError = co_await std::move(ReceiveOperation);
        auto SendError = Preview::Error::None;
        if (ReceiveError == Preview::Error::None)
        {
            auto SendOperation = Dgram->AsyncSendTo(Source, Payload);
            SendError = co_await std::move(SendOperation);
        }
        if (ReceiveError != Preview::Error::None || SendError != Preview::Error::None)
        {
            Dgram->Close();
            Session->Close();
            QuicServer->Close();
            co_return 1;
        }
        Dgram->Close();
        Session->Close();
        QuicServer->Close();
        std::printf("PASS: Preview Hysteria2 UDP authenticated echo (%zu bytes)\n", Payload.size());
        co_return 0;
    }

} // namespace

auto main(const int Argc, char **Argv) -> int
{
    const auto Options = ParseOptions(Argc, Argv);
    if (!Options)
    {
        std::fprintf(stderr, "FAIL: malformed Hysteria2 options\n");
        return 2;
    }
    Net::io_context Io;
    int ExitCode = 1;
    std::exception_ptr Failure;
    Net::co_spawn(
        Io,
        [&Io, &ExitCode, OptionsValue = *Options]() -> Net::awaitable<void>
        {
            auto Operation = RunServer(OptionsValue);
            if (OptionsValue.Udp)
            {
                Operation = RunUdpServer(OptionsValue);
            }
            ExitCode = co_await std::move(Operation);
            Io.stop();
        },
        [&Io, &Failure](std::exception_ptr Exception)
        {
            Failure = std::move(Exception);
            Io.stop();
        });
    Io.run();
    if (Failure)
    {
        try
        {
            std::rethrow_exception(Failure);
        }
        catch (const std::exception &Error)
        {
            std::fprintf(stderr, "FAIL: Hysteria2 coroutine exception: %s\n", Error.what());
        }
        catch (...)
        {
            std::fprintf(stderr, "FAIL: Hysteria2 coroutine exception\n");
        }
        return 1;
    }
    return ExitCode;
}
