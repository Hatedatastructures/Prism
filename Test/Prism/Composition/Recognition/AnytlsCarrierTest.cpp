/**
 * @file AnytlsCarrierTest.cpp
 * @brief Native TLS outer carrier to AnyTLS inner candidate integration tests.
 */

#include <gtest/gtest.h>
#include <TestSupport/Fixtures/StreamFactory.hpp>

#include <boost/asio.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/ssl.hpp>

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <array>
#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <expected>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#include <Prism/Composition/Recognition/AnytlsCarrier.hpp>
#include <Prism/Composition/Recognition/ProfileBuilder.hpp>
#include <Prism/Contract/Ingress/StreamFactory.hpp>
#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Foundation/Generation/Lifetime.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Runtime/Recognition/Recognition.hpp>
#include <Prism/Transport/Reliable.hpp>

namespace
{

    namespace Net = boost::asio;
    namespace Ssl = Net::ssl;
    namespace Core = Prism::Recognition;
    namespace Composition = Prism::Composition::Recognition;
    using Tcp = Net::ip::tcp;

    constexpr std::string_view Payload = "native-tls-anytls-handoff";

    struct ScenarioResult final
    {
        bool ProfileBuilt{false};
        bool TimedOut{false};
        Core::RecognitionStatus RecognitionStatus{Core::RecognitionStatus::NoMatch};
        Prism::Contract::ProtocolType Protocol{Prism::Contract::ProtocolType::Unknown};
        Prism::Fault::Code AcceptError{Prism::Fault::Code::ProtocolError};
        std::string Carrier;
        bool ProtocolAuthenticated{false};
        bool IsMux{false};
        bool HasTransport{false};
        bool PayloadRoundTrip{false};
        std::exception_ptr ServerException;
        std::exception_ptr ClientException;
    };

    struct ScenarioState final
    {
        std::shared_ptr<Tcp::acceptor> Acceptor;
        Composition::ProfileBuildResult BuiltProfile;
        std::shared_ptr<Prism::Foundation::GenerationUseState> GenerationUseState;
        std::string ClientPassword;
        std::uint16_t Port{0};
        Prism::SharedTransmission ActiveTransport;
        ScenarioResult Result;
        std::size_t Completed{0};
    };

    [[nodiscard]] auto MakeServerContext() -> std::shared_ptr<Ssl::context>
    {
        auto Context = std::make_shared<Ssl::context>(Ssl::context::tls_server);
        std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> Key(EVP_PKEY_new(), EVP_PKEY_free);
        std::unique_ptr<BIGNUM, decltype(&BN_free)> Exponent(BN_new(), BN_free);
        std::unique_ptr<RSA, decltype(&RSA_free)> RsaKey(RSA_new(), RSA_free);
        if (!Key || !Exponent || !RsaKey || BN_set_word(Exponent.get(), RSA_F4) != 1 ||
            RSA_generate_key_ex(RsaKey.get(), 2048, Exponent.get(), nullptr) != 1 ||
            EVP_PKEY_assign_RSA(Key.get(), RsaKey.get()) != 1)
        {
            return {};
        }
        (void)RsaKey.release();

        std::unique_ptr<X509, decltype(&X509_free)> Certificate(X509_new(), X509_free);
        if (!Certificate || X509_set_version(Certificate.get(), 2) != 1 ||
            ASN1_INTEGER_set(X509_get_serialNumber(Certificate.get()), 1) != 1 ||
            X509_gmtime_adj(X509_get_notBefore(Certificate.get()), 0) == nullptr ||
            X509_gmtime_adj(X509_get_notAfter(Certificate.get()), 24 * 60 * 60) == nullptr)
        {
            return {};
        }

        auto *Name = X509_get_subject_name(Certificate.get());
        constexpr unsigned char CommonName[] = "Prism AnyTLS Carrier Test";
        if (!Name || X509_NAME_add_entry_by_txt(Name, "CN", MBSTRING_ASC, CommonName, -1, -1, 0) != 1 ||
            X509_set_issuer_name(Certificate.get(), Name) != 1 ||
            X509_set_pubkey(Certificate.get(), Key.get()) != 1 ||
            X509_sign(Certificate.get(), Key.get(), EVP_sha256()) <= 0 ||
            SSL_CTX_use_certificate(Context->native_handle(), Certificate.get()) != 1 ||
            SSL_CTX_use_PrivateKey(Context->native_handle(), Key.get()) != 1 ||
            SSL_CTX_check_private_key(Context->native_handle()) != 1)
        {
            return {};
        }
        return Context;
    }

    [[nodiscard]] auto MakeCandidate(std::shared_ptr<Ssl::context> Context,
                                     std::string Password) -> Composition::CandidateBinding
    {
        Composition::AnytlsCarrierOptions Options;
        Options.Candidate = Composition::CandidateOptions{17, "native-anytls", 0, 0, false};
        Options.ServerNames = {"edge.example"};
        Options.Alpn = {"h2"};
        Options.NativeTls = std::move(Context);
        Options.Config.Configuration.Password = std::move(Password);
        Options.Config.Streams.Egress = Prism::Testing::UnavailableEgress();
        return Composition::MakeNativeTlsAnytlsCandidate(std::move(Options));
    }

    [[nodiscard]] auto ReadExact(Prism::SharedTransmission Transport,
                                 std::span<std::byte> Buffer) -> Net::awaitable<bool>
    {
        std::size_t Offset = 0;
        while (Offset < Buffer.size())
        {
            const auto Remaining = Buffer.size() - Offset;
            const auto Read = co_await Transport->ReadSome(Buffer.subspan(Offset));
            if (Read.Failure.Failed() || Read.Bytes == 0 || Read.Bytes > Remaining)
            {
                co_return false;
            }
            Offset += Read.Bytes;
        }
        co_return true;
    }

    [[nodiscard]] auto WriteAll(Prism::SharedTransmission Transport,
                                std::span<const std::byte> Buffer) -> Net::awaitable<bool>
    {
        std::size_t Offset = 0;
        while (Offset < Buffer.size())
        {
            const auto Remaining = Buffer.size() - Offset;
            const auto Written = co_await Transport->WriteSome(Buffer.subspan(Offset));
            if (Written.Failure.Failed() || Written.Bytes == 0 ||
                Written.Bytes > Remaining)
            {
                co_return false;
            }
            Offset += Written.Bytes;
        }
        co_return true;
    }

    [[nodiscard]] auto CloseAndDrain(Prism::SharedTransmission Transport)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        const auto Closed = Transport->Close();
        if (!Closed)
        {
            co_return std::unexpected(Closed.error());
        }
        co_return co_await Transport->Activity()->Drain();
    }

    auto RunServer(std::shared_ptr<ScenarioState> State) -> Net::awaitable<void>
    {
        try
        {
            boost::system::error_code AcceptError;
            auto Socket = co_await State->Acceptor->async_accept(
                Net::redirect_error(Net::use_awaitable, AcceptError));
            if (AcceptError)
            {
                co_return;
            }

            auto Raw = std::make_shared<Prism::Transport::Reliable>(std::move(Socket));
            State->ActiveTransport = Raw;
            auto Bytes = std::make_shared<Prism::Memory::BytePool>(
                Prism::Memory::BytePoolOptions{.BlockCount = 8});
            Core::Pipeline Pipeline(State->BuiltProfile.Profile, Bytes);
            const auto Recognition = co_await Pipeline.Recognize(Raw);
            State->Result.RecognitionStatus = Recognition.Status;
            State->Result.Protocol = Recognition.detected;
            State->Result.Carrier = Recognition.Carrier.Carrier;
            if (!Recognition.success)
            {
                const auto Drained = co_await CloseAndDrain(Raw);
                EXPECT_TRUE(Drained);
                State->ActiveTransport.reset();
                co_return;
            }

            auto Accept = State->BuiltProfile.Resolve(Recognition.Candidate);
            if (!Accept)
            {
                State->Result.AcceptError = Prism::Fault::Code::ProtocolError;
                const auto Drained = co_await CloseAndDrain(Raw);
                EXPECT_TRUE(Drained);
                State->ActiveTransport.reset();
                co_return;
            }

            auto Inbound = std::move(Recognition.transport);
            Prism::Contract::StreamAcceptInput Input;
            Input.Inbound = std::move(Inbound);
            Input.Bytes = Bytes;
            Input.GenerationUseState = State->GenerationUseState;
            auto Accepted = co_await Accept->Accept(std::move(Input));
            State->Result.AcceptError = Accepted ? Prism::Fault::Code::Success
                : Accepted.error().Code;
            if (!Accepted)
            {
                const auto Drained = co_await CloseAndDrain(Raw);
                EXPECT_TRUE(Drained);
                State->ActiveTransport.reset();
                co_return;
            }

            auto DataPlane = std::move(*Accepted);
            State->Result.ProtocolAuthenticated = DataPlane.ProtocolAuthenticated;
            State->Result.IsMux = DataPlane.IsMux();
            const auto Mux = DataPlane.Mux();
            if (!Mux || !Mux->Transport)
            {
                const auto Drained = co_await CloseAndDrain(Raw);
                EXPECT_TRUE(Drained);
                State->ActiveTransport.reset();
                co_return;
            }
            const auto Transport = Mux->Transport;
            State->Result.HasTransport = true;
            State->ActiveTransport = Transport;
            std::array<std::byte, Payload.size()> Received{};
            const auto ReadOk = co_await ReadExact(Transport, Received);
            const auto WriteOk = ReadOk && co_await WriteAll(Transport, Received);
            State->Result.PayloadRoundTrip = ReadOk && WriteOk;
            const auto Drained = co_await CloseAndDrain(Transport);
            EXPECT_TRUE(Drained);
            State->ActiveTransport.reset();
        }
        catch (...)
        {
            State->Result.ServerException = std::current_exception();
        }
        co_return;
    }

    auto RunClient(std::shared_ptr<ScenarioState> State) -> Net::awaitable<void>
    {
        try
        {
            Tcp::socket Socket(co_await Net::this_coro::executor);
            boost::system::error_code Error;
            co_await Socket.async_connect(
                Tcp::endpoint(Net::ip::address_v4::loopback(), State->Port),
                Net::redirect_error(Net::use_awaitable, Error));
            if (Error)
            {
                co_return;
            }

            Ssl::context ClientContext(Ssl::context::tls_client);
            ClientContext.set_verify_mode(Ssl::verify_none);
            Ssl::stream<Tcp::socket> Stream(std::move(Socket), ClientContext);
            if (SSL_set_tlsext_host_name(Stream.native_handle(), "edge.example") != 1)
            {
                co_return;
            }
            constexpr std::array<unsigned char, 3> Alpn{2U, 'h', '2'};
            if (SSL_set_alpn_protos(Stream.native_handle(), Alpn.data(), Alpn.size()) != 0)
            {
                co_return;
            }

            co_await Stream.async_handshake(
                Ssl::stream_base::client,
                Net::redirect_error(Net::use_awaitable, Error));
            if (Error)
            {
                co_return;
            }

            std::string AuthFrame;
            if (Prism::Anytls::BuildAuthFrame(State->ClientPassword, 3, AuthFrame) !=
                Prism::Error::None)
            {
                co_return;
            }
            co_await Net::async_write(
                Stream, Net::buffer(AuthFrame), Net::redirect_error(Net::use_awaitable, Error));
            if (Error)
            {
                co_return;
            }

            const auto Data = std::span<const std::byte>(
                reinterpret_cast<const std::byte *>(Payload.data()), Payload.size());
            co_await Net::async_write(
                Stream, Net::buffer(Data), Net::redirect_error(Net::use_awaitable, Error));
            if (Error)
            {
                co_return;
            }

            std::array<std::byte, Payload.size()> Echo{};
            co_await Net::async_read(
                Stream, Net::buffer(Echo), Net::redirect_error(Net::use_awaitable, Error));
            if (Error)
            {
                co_return;
            }
            const auto Expected = std::span<const std::byte>(
                reinterpret_cast<const std::byte *>(Payload.data()), Payload.size());
            State->Result.PayloadRoundTrip = State->Result.PayloadRoundTrip &&
                                             std::equal(Echo.begin(), Echo.end(),
                                                        Expected.begin(), Expected.end());
            Stream.lowest_layer().close(Error);
        }
        catch (...)
        {
            State->Result.ClientException = std::current_exception();
        }
        co_return;
    }

    auto RunWatchdog(std::shared_ptr<ScenarioState> State) -> Net::awaitable<void>
    {
        Net::steady_timer Timer(co_await Net::this_coro::executor);
        Timer.expires_after(std::chrono::seconds(5));
        boost::system::error_code Error;
        co_await Timer.async_wait(Net::redirect_error(Net::use_awaitable, Error));
        if (!Error && State->Completed < 2)
        {
            State->Result.TimedOut = true;
            State->Acceptor->close(Error);
            if (State->ActiveTransport)
            {
                const auto Canceled = State->ActiveTransport->Cancel();
                EXPECT_TRUE(Canceled);
                const auto Closed = State->ActiveTransport->Close();
                EXPECT_TRUE(Closed);
            }
        }
        co_return;
    }

    [[nodiscard]] auto RunScenario(std::string ServerPassword,
                                   std::string ClientPassword) -> ScenarioResult
    {
        Net::io_context Io;
        auto Acceptor = std::make_shared<Tcp::acceptor>(Io, Tcp::endpoint(Tcp::v4(), 0));
        auto Context = MakeServerContext();
        auto Binding = MakeCandidate(Context, std::move(ServerPassword));
        Composition::ProfileBuilderOptions ProfileOptions;
        ProfileOptions.Mode = Core::RecognitionMode::Configured;
        ProfileOptions.ConfiguredCandidate = Binding.Spec.Id;
        auto Built = Composition::ProfileBuilder::Build(std::move(Binding), ProfileOptions);
        if (!Built)
        {
            ScenarioResult Result;
            return Result;
        }

        auto State = std::make_shared<ScenarioState>();
        State->Acceptor = Acceptor;
        State->BuiltProfile = std::move(*Built);
        State->GenerationUseState =
            std::make_shared<Prism::Foundation::GenerationUseState>();
        State->ClientPassword = std::move(ClientPassword);
        State->Port = Acceptor->local_endpoint().port();
        State->Result.ProfileBuilt = true;

        const auto OnComplete = [&Io, State](std::exception_ptr Error)
        {
            if (Error && !State->Result.ServerException) State->Result.ServerException = std::move(Error);
            ++State->Completed;
            if (State->Completed == 2) Io.stop();
        };
        Net::co_spawn(Io, RunServer(State), OnComplete);
        Net::co_spawn(Io, RunClient(State), OnComplete);
        Net::co_spawn(Io, RunWatchdog(State), Net::detached);
        Io.run();
        return State->Result;
    }

} // namespace

TEST(AnytlsCarrier, NativeTlsCommitHandsOffToAnyTlsMuxAndPayload)
{
    const auto Result = RunScenario("anytls-secret", "anytls-secret");

    ASSERT_TRUE(Result.ProfileBuilt);
    EXPECT_FALSE(Result.TimedOut);
    EXPECT_EQ(Result.RecognitionStatus, Core::RecognitionStatus::Accepted);
    EXPECT_EQ(Result.Protocol, Prism::Contract::ProtocolType::AnyTls);
    EXPECT_EQ(Result.Carrier, "native");
    EXPECT_EQ(Result.AcceptError, Prism::Fault::Code::Success);
    EXPECT_TRUE(Result.ProtocolAuthenticated);
    EXPECT_TRUE(Result.IsMux);
    EXPECT_TRUE(Result.HasTransport);
    EXPECT_TRUE(Result.PayloadRoundTrip);
    EXPECT_FALSE(Result.ServerException);
    EXPECT_FALSE(Result.ClientException);
}

TEST(AnytlsCarrier, WrongInnerPasswordDoesNotPublishAnyTlsDataPlane)
{
    const auto Result = RunScenario("anytls-secret", "wrong-secret");

    ASSERT_TRUE(Result.ProfileBuilt);
    EXPECT_FALSE(Result.TimedOut);
    EXPECT_EQ(Result.RecognitionStatus, Core::RecognitionStatus::Accepted);
    EXPECT_EQ(Result.Protocol, Prism::Contract::ProtocolType::AnyTls);
    EXPECT_EQ(Result.Carrier, "native");
    EXPECT_NE(Result.AcceptError, Prism::Fault::Code::Success);
    EXPECT_FALSE(Result.ProtocolAuthenticated);
    EXPECT_FALSE(Result.IsMux);
    EXPECT_FALSE(Result.HasTransport);
    EXPECT_FALSE(Result.PayloadRoundTrip);
    EXPECT_FALSE(Result.ServerException);
}
