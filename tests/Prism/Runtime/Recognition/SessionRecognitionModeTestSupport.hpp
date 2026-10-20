/**
 * @file SessionRecognitionModeTestSupport.hpp
 * @brief SessionRecognitionModeTest.cpp 拆分后的模块共享测试夹具与构造辅助。
 */
#pragma once

#include <TestSupport/Prism/ProviderBindings.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
/**
 * @file SessionRecognitionModeTest.cpp
 * @brief Session 的配置化候选与直接接入分派测试
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <openssl/bio.h>
#include <openssl/ssl.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <expected>
#include <filesystem>
#include <functional>
#include <limits>
#include <memory>
#include <span>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include <Prism/Foundation/Utility/Diagnose/Facade.hpp>
#include <Prism/Composition/Recognition/CandidateFactory.hpp>
#include <Prism/Protocols/Vless/IngressFactory.hpp>
#include <Prism/Protocols/Trojan/IngressFactory.hpp>
#include <Prism/Protocols/Vmess/IngressFactory.hpp>
#include <Prism/Composition/Recognition/ProfileBuilder.hpp>
#include <Prism/Account/Account.hpp>
#include <Prism/Account/Authenticator.hpp>
#include <Prism/Foundation/Utility/Crypto/Base64.hpp>
#include <Prism/Protocols/Common/ExactIo.hpp>
#include <Prism/Protocols/Shadowsocks2022/Shadowsocks2022.hpp>
#include <Prism/Protocols/Socks5/Socks5.hpp>
#include <Prism/Protocols/Trojan/Trojan.hpp>
#include <Prism/Protocols/Vless/Vless.hpp>
#include <Prism/Protocols/Vmess/Vmess.hpp>
#include <Prism/Runtime/Session.hpp>
#include <Prism/Transport/MemoryStream.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>
#include <TestSupport/Fixtures/StreamFactory.hpp>
#include <TestSupport/Prism/PrismMockTransport.hpp>
#include <TestSupport/Prism/ProviderBindings.hpp>
#include <TestSupport/Fixtures/RecognitionWire.hpp>

namespace
{

    namespace Net = boost::asio;
    namespace Ssl = Net::ssl;
    namespace Core = Prism::Recognition;
    namespace Composition = Prism::Composition::Recognition;
    using CodeChannel = Net::experimental::channel<void(boost::system::error_code, Prism::Fault::Code)>;
    using ClientFlow = std::function<
        Net::awaitable<std::expected<void, Prism::Fault::Failure>>(Prism::SharedTransmission)>;

    struct ProfileFlowResult
    {
        Prism::Fault::Code SessionCode{Prism::Fault::Code::Success};
        Prism::Fault::Failure ClientFailure{};
        std::size_t ResolverCalls{0};
    };

    struct SessionWaitRequest
    {
        std::shared_ptr<CodeChannel> Done;
        std::shared_ptr<Prism::MemoryStream> Client;
        std::shared_ptr<Prism::MemoryStream> Inbound;
        std::shared_ptr<std::exception_ptr> Failure;
    };

    struct SessionNativeTlsProbeResult final
    {
        bool CompletedBeforeWatchdog{false};
        bool SessionCompleted{false};
        Prism::Fault::Code Code{Prism::Fault::Code::GenericError};
    };

    struct SessionNativeTlsProbeRequest final
    {
        Net::any_io_executor Executor;
        std::shared_ptr<Prism::Runtime::Session> Session;
        std::shared_ptr<Prism::PrismMockTransport> Raw;
        std::shared_ptr<CodeChannel> Done;
        std::shared_ptr<SessionNativeTlsProbeResult> Result;
    };

    auto MakeTls13ClientHello() -> std::vector<std::uint8_t>
    {
        std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> ClientContext(
            SSL_CTX_new(TLS_client_method()), &SSL_CTX_free);
        if (!ClientContext || SSL_CTX_set_min_proto_version(ClientContext.get(), TLS1_3_VERSION) != 1 ||
            SSL_CTX_set_max_proto_version(ClientContext.get(), TLS1_3_VERSION) != 1)
        {
            return {};
        }

        std::unique_ptr<SSL, decltype(&SSL_free)> Client(SSL_new(ClientContext.get()), &SSL_free);
        auto *ReadBio = BIO_new(BIO_s_mem());
        auto *WriteBio = BIO_new(BIO_s_mem());
        if (!Client || !ReadBio || !WriteBio)
        {
            BIO_free(ReadBio);
            BIO_free(WriteBio);
            return {};
        }
        SSL_set_bio(Client.get(), ReadBio, WriteBio);
        if (SSL_set_tlsext_host_name(Client.get(), "example.com") != 1)
        {
            return {};
        }
        SSL_set_connect_state(Client.get());
        const auto HandshakeResult = SSL_do_handshake(Client.get());
        if (HandshakeResult == 1 || SSL_get_error(Client.get(), HandshakeResult) != SSL_ERROR_WANT_READ)
        {
            return {};
        }

        const auto Pending = BIO_ctrl_pending(WriteBio);
        if (Pending <= 0 || Pending > std::numeric_limits<int>::max())
        {
            return {};
        }
        std::vector<std::uint8_t> ClientHello(static_cast<std::size_t>(Pending));
        const auto Read = BIO_read(WriteBio, ClientHello.data(), static_cast<int>(ClientHello.size()));
        if (Read < 0 || static_cast<std::size_t>(Read) != ClientHello.size())
        {
            return {};
        }
        return ClientHello;
    }

    auto MakeSessionNativeTlsContext() -> std::shared_ptr<Ssl::context>
    {
        auto Context = std::make_shared<Ssl::context>(Ssl::context::tls_server);
        const auto Repository = std::filesystem::path(PRISM_TEST_REPO_ROOT);
        Context->use_certificate_chain_file((Repository / "cert.pem").string());
        Context->use_private_key_file((Repository / "key.pem").string(), Ssl::context::pem);
        return Context;
    }

    auto RunSessionNativeTlsProbe(SessionNativeTlsProbeRequest Request) -> Net::awaitable<void>
    {
        Net::co_spawn(
            Request.Executor,
            Request.Session->Run(std::static_pointer_cast<Prism::Transmission>(Request.Raw)),
            [Done = Request.Done](std::exception_ptr Failure, Prism::Fault::Failure Result)
            {
                (void)Done->try_send(
                    boost::system::error_code{},
                    Failure ? Prism::Fault::Code::IoError : Result.Code);
            });

        Net::steady_timer Watchdog(Request.Executor);
        Watchdog.expires_after(std::chrono::milliseconds(250));
        boost::system::error_code Error;
        using Net::experimental::awaitable_operators::operator||;
        const auto Race = co_await (
            Request.Done->async_receive(Net::redirect_error(Net::use_awaitable, Error)) ||
            Watchdog.async_wait(Net::use_awaitable));
        if (Race.index() == 0U)
        {
            Request.Result->CompletedBeforeWatchdog = true;
            Request.Result->SessionCompleted = true;
            Request.Result->Code = std::get<0>(Race);
            co_return;
        }

        Request.Raw->SetReadError(std::make_error_code(std::errc::connection_reset));
        Net::steady_timer DrainWatchdog(Request.Executor);
        DrainWatchdog.expires_after(std::chrono::seconds(2));
        const auto DrainRace = co_await (
            Request.Done->async_receive(Net::redirect_error(Net::use_awaitable, Error)) ||
            DrainWatchdog.async_wait(Net::use_awaitable));
        if (DrainRace.index() == 0U)
        {
            Request.Result->SessionCompleted = true;
            Request.Result->Code = std::get<0>(DrainRace);
        }
    }

    auto CountSessionNativeTlsAccept(
        std::shared_ptr<std::size_t> Calls,
        Prism::Contract::StreamAcceptInput Input)
        -> Net::awaitable<Prism::Contract::AcceptOutcome>
    {
        ++*Calls;
        Prism::Contract::ProtocolDataPlane Plane;
        Plane.Root = Prism::Contract::StreamDataPlane{std::move(Input.Inbound)};
        co_return Plane;
    }

    auto WaitForSession(SessionWaitRequest Request)
        -> Net::awaitable<std::pair<bool, Prism::Fault::Code>>
    {
        using Net::experimental::awaitable_operators::operator||;
        const auto Executor = co_await Net::this_coro::executor;
        Net::steady_timer Watchdog(Executor);
        Watchdog.expires_after(std::chrono::seconds(5));
        boost::system::error_code DoneError;
        auto Completion = co_await (
            Request.Done->async_receive(Net::redirect_error(Net::use_awaitable, DoneError)) ||
            Watchdog.async_wait(Net::use_awaitable));
        if (Completion.index() == 0U)
        {
            co_return std::pair{true, std::get<0>(Completion)};
        }

        Request.Client->Close();
        Request.Inbound->Close();
        Watchdog.expires_after(std::chrono::seconds(1));
        auto Grace = co_await (
            Request.Done->async_receive(Net::redirect_error(Net::use_awaitable, DoneError)) ||
            Watchdog.async_wait(Net::use_awaitable));
        if (Grace.index() == 0U)
        {
            co_return std::pair{true, std::get<0>(Grace)};
        }
        co_return std::pair{false, Prism::Fault::Code::Timeout};
    }

    /** @brief 拥有识别场景的双方端点、会话完成通知和首异常。 */
    struct ProfileSessionOwner final : std::enable_shared_from_this<ProfileSessionOwner>
    {
        explicit ProfileSessionOwner(Net::any_io_executor ExecutorValue)
            : Executor(std::move(ExecutorValue)),
              Done(std::make_shared<CodeChannel>(Executor, 1)),
              Failure(std::make_shared<std::exception_ptr>())
        {
            auto [Writer, Reader] = Prism::MakeMemoryPair(Executor);
            Client = std::make_shared<Prism::MemoryStream>(std::move(Writer));
            Inbound = std::make_shared<Prism::MemoryStream>(std::move(Reader));
        }

        /** @brief 回调持有本 owner，直到 Session.Run 真正返回。 */
        auto Start(Prism::Runtime::SessionOptions Options) -> void
        {
            const auto Self = shared_from_this();
            Net::co_spawn(Executor, RunSession(std::move(Options)),
                [Self](std::exception_ptr Error) { Self->Complete(std::move(Error)); });
            Started = true;
        }

        auto RunSession(Prism::Runtime::SessionOptions Options) -> Net::awaitable<void>
        {
            Prism::Runtime::Session Session(std::move(Options));
            SessionCode = (co_await Session.Run(Inbound)).Code;
        }

        auto Complete(std::exception_ptr Error) -> void
        {
            if (Error && !*Failure) *Failure = std::move(Error);
            if (*Failure) SessionCode = Prism::Fault::Code::IoError;
            (void)Done->try_send(boost::system::error_code{}, SessionCode);
        }

        /** @brief 两个端点分别尝试关闭；一次关闭异常不跳过另一个端点。 */
        auto ClosePeers() noexcept -> void
        {
            try { Client->Close(); }
            catch (...) { if (!*Failure) *Failure = std::current_exception(); }
            try { Inbound->Close(); }
            catch (...) { if (!*Failure) *Failure = std::current_exception(); }
        }

        /** @brief 使用原五秒加一秒预算观察会话回调，完成后才交还结果。 */
        auto Join() -> Net::awaitable<Prism::Fault::Code>
        {
            if (!Started) co_return SessionCode;
            co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
            const auto Result = co_await WaitForSession({Done, Client, Inbound, Failure});
            EXPECT_TRUE(Result.first);
            EXPECT_FALSE(*Failure);
            co_return Result.second;
        }

        auto RunProfile(Prism::Runtime::SessionOptions Options, ClientFlow Flow)
            -> Net::awaitable<ProfileFlowResult>
        {
            ProfileFlowResult Result;
            std::exception_ptr FirstFailure;
            try
            {
                Start(std::move(Options));
                const auto ClientResult = co_await Flow(Client);
                if (!ClientResult)
                {
                    Result.ClientFailure = ClientResult.error();
                }
            }
            catch (...) { FirstFailure = std::current_exception(); }
            try { Client->Close(); }
            catch (...) { if (!FirstFailure) FirstFailure = std::current_exception(); }
            if (FirstFailure) ClosePeers();
            try { Result.SessionCode = co_await Join(); }
            catch (...) { if (!FirstFailure) FirstFailure = std::current_exception(); }
            ClosePeers();
            if (FirstFailure) std::rethrow_exception(FirstFailure);
            co_return Result;
        }

        auto ExchangeHttp(bool ExpectResponse) -> Net::awaitable<void>
        {
            const auto Request = Prism::Testing::RecognitionWire::MakeHttp();
            const auto Written = co_await Client->WriteExact(
                std::span<const std::byte>{Request});
            EXPECT_FALSE(Written.Failure.Failed());
            EXPECT_EQ(Written.Bytes, Request.size());
            if (ExpectResponse)
            {
                std::array<std::byte, 128> Reply{};
                const auto Read = co_await Client->ReadSome(std::span<std::byte>{Reply});
                EXPECT_FALSE(Read.Failure.Failed());
                EXPECT_NE(std::string_view(reinterpret_cast<const char *>(Reply.data()), Read.Bytes).find("200"),
                    std::string_view::npos);
            }
        }

        auto RunHttp(Prism::Runtime::SessionOptions Options, bool ExpectResponse)
            -> Net::awaitable<Prism::Fault::Code>
        {
            std::exception_ptr FirstFailure;
            try
            {
                Start(std::move(Options));
                co_await ExchangeHttp(ExpectResponse);
            }
            catch (...) { FirstFailure = std::current_exception(); }
            if (FirstFailure) ClosePeers();
            auto Result = Prism::Fault::Code::Success;
            try { Result = co_await Join(); }
            catch (...) { if (!FirstFailure) FirstFailure = std::current_exception(); }
            ClosePeers();
            if (FirstFailure) std::rethrow_exception(FirstFailure);
            co_return Result;
        }

        Net::any_io_executor Executor;
        std::shared_ptr<Prism::MemoryStream> Client, Inbound;
        std::shared_ptr<CodeChannel> Done;
        std::shared_ptr<std::exception_ptr> Failure;
        Prism::Fault::Code SessionCode{Prism::Fault::Code::IoError};
        bool Started{false};
    };

    /** @brief 驱动本夹具任务并自然排空其会话及完成回调。 */
    auto DriveSessionOperation(Net::io_context &Io, Net::awaitable<void> Operation) -> void
    {
        std::exception_ptr Failure;
        Net::co_spawn(Io, std::move(Operation),
            [&Failure](std::exception_ptr Error) { Failure = std::move(Error); });
        Io.run();
        if (Failure) std::rethrow_exception(Failure);
    }

    auto RunProfileFlow(Prism::Runtime::SessionOptions Options, ClientFlow Flow)
        -> ProfileFlowResult
    {
        Net::io_context Io;
        auto Owner = std::make_shared<ProfileSessionOwner>(Io.get_executor());
        auto ResolverCalls = std::make_shared<std::size_t>(0);
        auto ExistingResolver = Options.Services->ResolveCandidate;
        Options.Services->ResolveCandidate = [ExistingResolver, ResolverCalls](Core::CandidateId Id)
            -> std::shared_ptr<Prism::Contract::StreamFactory>
        {
            ++*ResolverCalls;
            if (ExistingResolver)
            {
                return ExistingResolver(Id);
            }
            return std::shared_ptr<Prism::Contract::StreamFactory>{};
        };
        const auto Executor = Io.get_executor();
        Options.Services->Dial = [Executor](const Prism::Network::Target &)
            -> Net::awaitable<std::expected<Prism::SharedTransmission, Prism::Fault::Failure>>
        {
            auto [Upstream, Peer] = Prism::MakeMemoryPair(Executor);
            Peer.Close();
            co_return std::make_shared<Prism::MemoryStream>(std::move(Upstream));
        };

        ProfileFlowResult Result;
        auto Operation = [Owner, &Result, Options = std::move(Options), Flow = std::move(Flow)]() mutable
            -> Net::awaitable<void>
        {
            Result = co_await Owner->RunProfile(std::move(Options), std::move(Flow));
        };
        DriveSessionOperation(Io, Operation());
        Result.ResolverCalls = *ResolverCalls;
        return Result;
    }

    auto ProviderGenerationUseState(const Composition::CandidateBinding& Binding)
        -> std::shared_ptr<Prism::Foundation::GenerationUseState>;

    auto CommonProviderGenerationUseState(
        const std::vector<Composition::CandidateBinding>& Bindings)
        -> std::shared_ptr<Prism::Foundation::GenerationUseState>;

    auto MakeSessionRecognitionBytePool() -> std::shared_ptr<Prism::Memory::BytePool>
    {
        return std::make_shared<Prism::Memory::BytePool>(
            Prism::Memory::BytePoolOptions{64U * 1024U, 64U});
    }

    auto MakeConfiguredOptions(Composition::CandidateBinding Binding)
        -> Prism::Runtime::SessionOptions
    {
        auto UseState = ProviderGenerationUseState(Binding);
        Composition::ProfileBuilderOptions BuilderOptions;
        BuilderOptions.Mode = Core::RecognitionMode::Configured;
        auto Built = Composition::ProfileBuilder::Build(std::move(Binding), std::move(BuilderOptions));
        EXPECT_TRUE(Built.has_value());
        Prism::Runtime::SessionOptions Options;
        Options.Services->Bytes = MakeSessionRecognitionBytePool();
        if (Built)
        {
            Options.Services->Profile = Built->Profile;
            Options.Services->ResolveCandidate = Built->Resolver;
            Options.Services->GenerationUseState = std::move(UseState);
        }
        return Options;
    }

    auto ProviderGenerationUseState(const Composition::CandidateBinding& Binding)
        -> std::shared_ptr<Prism::Foundation::GenerationUseState>
    {
        if (const auto Factory = std::dynamic_pointer_cast<Prism::Vless::IngressFactory>(Binding.Accept))
        {
            return Factory->GenerationUseState();
        }
        if (const auto Factory = std::dynamic_pointer_cast<Prism::Trojan::IngressFactory>(Binding.Accept))
        {
            return Factory->GenerationUseState();
        }
        if (const auto Factory = std::dynamic_pointer_cast<Prism::Vmess::IngressFactory>(Binding.Accept))
        {
            return Factory->GenerationUseState();
        }
        return {};
    }

    auto CommonProviderGenerationUseState(
        const std::vector<Composition::CandidateBinding>& Bindings)
        -> std::shared_ptr<Prism::Foundation::GenerationUseState>
    {
        std::shared_ptr<Prism::Foundation::GenerationUseState> UseState;
        for (const auto& Binding : Bindings)
        {
            const auto CandidateState = ProviderGenerationUseState(Binding);
            if (!CandidateState) continue;
            if (UseState && UseState != CandidateState)
            {
                ADD_FAILURE() << "provider candidates do not share one generation use state";
                return {};
            }
            UseState = CandidateState;
        }
        return UseState;
    }

    auto MakeMixedOptions(std::vector<Composition::CandidateBinding> Bindings)
        -> Prism::Runtime::SessionOptions
    {
        auto UseState = CommonProviderGenerationUseState(Bindings);
        Composition::ProfileBuilderOptions BuilderOptions;
        BuilderOptions.Mode = Core::RecognitionMode::MixedTrial;
        BuilderOptions.Budget.MaxCandidates = 2;
        auto Built = Composition::ProfileBuilder::Build(std::move(Bindings), std::move(BuilderOptions));
        EXPECT_TRUE(Built.has_value());
        Prism::Runtime::SessionOptions Options;
        Options.Services->Bytes = MakeSessionRecognitionBytePool();
        if (Built)
        {
            Options.Services->Profile = Built->Profile;
            Options.Services->ResolveCandidate = Built->Resolver;
            Options.Services->GenerationUseState = std::move(UseState);
        }
        return Options;
    }

    auto MakeDeterministicOptions(std::vector<Composition::CandidateBinding> Bindings)
        -> Prism::Runtime::SessionOptions
    {
        auto UseState = CommonProviderGenerationUseState(Bindings);
        Composition::ProfileBuilderOptions BuilderOptions;
        BuilderOptions.Mode = Core::RecognitionMode::Deterministic;
        BuilderOptions.Budget.MaxCandidates = 2;
        auto Built = Composition::ProfileBuilder::Build(std::move(Bindings), std::move(BuilderOptions));
        EXPECT_TRUE(Built.has_value());
        Prism::Runtime::SessionOptions Options;
        Options.Services->Bytes = MakeSessionRecognitionBytePool();
        if (Built)
        {
            Options.Services->Profile = Built->Profile;
            Options.Services->ResolveCandidate = Built->Resolver;
            Options.Services->GenerationUseState = std::move(UseState);
        }
        return Options;
    }

    auto RunSocks5Client(Prism::SharedTransmission Client, Prism::Socks5::ClientConfig Config)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        const Prism::Socks5::Address Target{Prism::Socks5::AddressType::Domain, "example.com", 443};
        auto Connected = co_await Prism::Socks5::Connect(Prism::Socks5::ConnectParameters{
            std::move(Client), Config, Target});
        if (!Connected)
        {
            co_return std::unexpected(Connected.error());
        }
        if (!*Connected)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::IoError});
        }
        auto Conn = std::move(*Connected);
        const auto Close = Conn->Close();
        const auto Drain = co_await Conn->Activity()->Drain();
        if (!Close) co_return std::unexpected(Close.error());
        if (!Drain) co_return std::unexpected(Drain.error());
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    auto RunVlessClient(Prism::SharedTransmission Client, Prism::Vless::ClientConfig Config)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        const Prism::Vless::Address Target{Prism::Vless::AddressType::Domain, "example.com", 443};
        auto Result = co_await Prism::Vless::Connect(
            Prism::Vless::ConnectParameters{std::move(Client), Config, Target});
        if (!Result)
        {
            co_return std::unexpected(Result.error());
        }
        if (!*Result)
        {
            co_return std::unexpected(Prism::Fault::Failure{
                Prism::Fault::Code::InvalidArgument});
        }
        auto Connection = std::move(*Result);
        const auto Close = Connection->Close();
        const auto Drain = co_await Connection->Activity()->Drain();
        if (!Close) co_return std::unexpected(Close.error());
        if (!Drain) co_return std::unexpected(Drain.error());
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    auto RunTrojanClient(Prism::SharedTransmission Client, std::string Password)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        const Prism::Trojan::Address Target{Prism::Trojan::AddressType::Domain, "example.com", 443};
        Prism::Trojan::ClientConfig Config{std::move(Password)};
        auto Result = co_await Prism::Trojan::Connect(
            Prism::Trojan::ConnectParameters{std::move(Client), Config, Target});
        if (!Result)
        {
            co_return std::unexpected(Result.error());
        }
        if (!*Result)
        {
            co_return std::unexpected(Prism::Fault::Failure{
                Prism::Fault::Code::InvalidArgument});
        }
        auto Connection = std::move(*Result);
        const auto Close = Connection->Close();
        const auto Drain = co_await Connection->Activity()->Drain();
        if (!Close) co_return std::unexpected(Close.error());
        if (!Drain) co_return std::unexpected(Drain.error());
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    auto RunVmessClient(Prism::SharedTransmission Client, Prism::Vmess::ClientConfig Config)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        const Prism::Vmess::Address Target{Prism::Vmess::AddressType::Domain, "example.com", 443};
        auto Result = co_await Prism::Vmess::Connect(
            Prism::Vmess::ConnectParameters{std::move(Client), Config, Target});
        if (!Result)
        {
            co_return std::unexpected(Result.error());
        }
        if (!*Result)
        {
            co_return std::unexpected(Prism::Fault::Failure{
                Prism::Fault::Code::InvalidArgument});
        }
        auto Connection = std::move(*Result);
        const auto Close = Connection->Close();
        const auto Drain = co_await Connection->Activity()->Drain();
        if (!Close) co_return std::unexpected(Close.error());
        if (!Drain) co_return std::unexpected(Drain.error());
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    auto RunSs2022Client(Prism::SharedTransmission Client,
                         std::array<std::uint8_t, 16> Psk)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        const Prism::Shadowsocks2022::Address Target{
            Prism::Shadowsocks2022::AddressType::Domain, "example.com", 443};
        auto Conn = std::make_shared<Prism::Shadowsocks2022::Conn<>>(
            Prism::Shadowsocks2022::ConnOptions{
                .Executor = Client->Executor(), .Psk = Psk});
        const auto HandshakeError = co_await Conn->WriteHandshake(std::move(Client), Target);
        const auto Close = Conn->Close();
        const auto Drain = co_await Conn->Activity()->Drain();
        if (HandshakeError.Failed())
        {
            co_return std::unexpected(HandshakeError);
        }
        if (!Close) co_return std::unexpected(Close.error());
        if (!Drain) co_return std::unexpected(Drain.error());
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    auto RunHttpSession(Prism::Runtime::SessionOptions Options) -> Prism::Fault::Code
    {
        Net::io_context Io;
        auto Owner = std::make_shared<ProfileSessionOwner>(Io.get_executor());
        // CONNECT 200 只能在 Dial 成功后发送；Profile 与直接接入分支
        // 共用本夹具，不能把拨号之前的响应当作候选 resolver 契约。
        const bool ExpectResponse = static_cast<bool>(Options.Services->Profile) &&
                                     !static_cast<bool>(Options.Services->AcceptProtocol);
        Prism::Fault::Code Result = Prism::Fault::Code::Success;
        auto Operation = [Owner, &Result, Options = std::move(Options), ExpectResponse]() mutable
            -> Net::awaitable<void>
        {
            Result = co_await Owner->RunHttp(std::move(Options), ExpectResponse);
        };
        DriveSessionOperation(Io, Operation());
        return Result;
    }















} // namespace
