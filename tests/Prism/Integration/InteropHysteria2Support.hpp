/**
 * @file InteropHysteria2Support.hpp
 * @brief Hysteria2 外部互操作 server translation units 的私有共享契约。
 */
#pragma once

#include <boost/asio/awaitable.hpp>
#include <boost/asio/ssl/context.hpp>

#include <exception>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

#include <Prism/Account/Authenticator.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Protocols/Http3/NativeServer.hpp>
#include <Prism/Protocols/Hysteria2/Hysteria2.hpp>
#include <Prism/Protocols/Quic/Native.hpp>
#include <TestSupport/Prism/ProviderBindings.hpp>

namespace Prism::Testing::Integration::Hysteria2::Interop
{
    namespace Net = boost::asio;

    struct Options final
    {
        std::string Address{"127.0.0.1:19088"};
        std::string Password{"hysteria2_password"};
        bool Udp{false};
    };

    struct HostPort final
    {
        std::string Host;
        std::uint16_t Port{0};
    };

    struct AuthFixture final
    {
        std::shared_ptr<Prism::Testing::ProviderAccounts> Directory;
        Prism::SharedAuthenticator Authenticator;
    };

    using SessionRunResult = std::expected<void, Prism::Fault::Failure>;
    using QuicStreamResult = std::expected<Prism::Quic::SharedStreamProvider,
                                            Prism::Fault::Failure>;

    [[nodiscard]] auto ParseOptions(int Argc, char **Argv) -> std::optional<Options>;
    [[nodiscard]] auto SplitHostPort(std::string_view Value) -> std::optional<HostPort>;

    auto CaptureDrainFailure(std::exception_ptr &FirstError, SessionRunResult Result) -> void;
    auto CaptureDrainFailure(Prism::Fault::Failure &FirstFailure,
                             SessionRunResult Result) -> void;
    auto ReportSessionRunFailure(const char *Context,
                                 const Prism::Fault::Failure &Failure) -> void;
    [[nodiscard]] auto MakeServerTls() -> std::shared_ptr<Net::ssl::context>;
    [[nodiscard]] auto MakeAuthenticator(std::string_view Password) -> AuthFixture;

    auto DrainHttp3SessionAndQuicServer(
        const std::shared_ptr<Prism::Http3::NativeServerSession> &Session,
        const std::shared_ptr<Prism::Quic::Server> &Server) -> Net::awaitable<void>;
    auto DrainQuicServer(const std::shared_ptr<Prism::Quic::Server> &Server) -> Net::awaitable<void>;
    auto WaitQuicHandshakeOrDrain(
        const std::shared_ptr<Prism::Quic::Server> &Server) -> Net::awaitable<bool>;

    auto RunTcpServer(Options OptionsValue) -> Net::awaitable<int>;
    auto RunUdpServer(Options OptionsValue) -> Net::awaitable<int>;
}
