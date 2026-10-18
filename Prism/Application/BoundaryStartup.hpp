/**
 * @file BoundaryStartup.hpp
 * @brief Prism TCP/UDP/QUIC 入口、TLS 和边界服务的冷路径装配。
 */

#pragma once

#include <Prism/Application/Application.hpp>
#include <Prism/Application/Assembly/AccountAssembly.hpp>
#include <Prism/Application/Assembly/NetworkAssembly.hpp>
#include <Prism/Application/Assembly/ProtocolAssembly.hpp>
#include <Prism/Application/Configuration/Configuration.hpp>
#include <Prism/Application/DiagnoseRuntime.hpp>
#include <Prism/Application/RuntimeState.hpp>
#include <Prism/Application/RuntimeGenerationSnapshot.hpp>
#include <Prism/Application/Startup/StartupErrors.hpp>
#include <Prism/Boundary/Contract/BoundaryDispatcher.hpp>
#include <Prism/Boundary/Datagram/DatagramClassifier.hpp>
#include <Prism/Boundary/Datagram/DatagramListener.hpp>
#include <Prism/Boundary/Quic/QuicConnectionRegistry.hpp>
#include <Prism/Boundary/Quic/QuicPacketGateway.hpp>
#include <Prism/Foundation/ByteSpan.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Net/Dns/Resolver.hpp>
#include <Prism/Protocols/Quic/Native.hpp>
#include <Prism/Protocols/Quic/StreamAdapter.hpp>
#include <Prism/Protocols/Ech/ServerKeys.hpp>
#include <Prism/Runtime/Listener.hpp>
#include <Prism/Runtime/Session.hpp>
#include <Prism/Runtime/SessionServices.hpp>
#include <Prism/Foundation/Utility/Text/Redaction.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <openssl/ssl.h>

#include <array>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <expected>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace Prism::Application::BoundaryStartup
{

    inline auto SelectNativeTlsAlpn(
        SSL *, const unsigned char **Out, unsigned char *OutLength,
        const unsigned char *In, const unsigned int InLength, void *) -> int
    {
        static constexpr unsigned char H3[] = {0x02, 'h', '3'};
        static constexpr unsigned char H2[] = {0x02, 'h', '2'};
        static constexpr unsigned char Http11[] = {0x08, 'h', 't', 't', 'p', '/', '1', '.', '1'};
        const std::array<std::span<const unsigned char>, 3> Protocols{H3, H2, Http11};
        for (const auto Protocol : Protocols)
        {
            if (SSL_select_next_proto(const_cast<unsigned char **>(Out), OutLength, Protocol.data(),
                    static_cast<unsigned int>(Protocol.size()), In, InLength) == OPENSSL_NPN_NEGOTIATED)
            {
                return SSL_TLSEXT_ERR_OK;
            }
        }
        return SSL_TLSEXT_ERR_NOACK;
    }

    using RuntimeState = Prism::Application::Application::RuntimeState;

    [[nodiscard]] inline auto MakeAddress(const std::string& Text)
        -> std::expected<Net::ip::address, StartupError>
    {
        if (Text == "localhost")
        {
            return Net::ip::address_v4::loopback();
        }
        boost::system::error_code Error;
        const auto Address = Net::ip::make_address(Text, Error);
        if (Error)
        {
            return std::unexpected(Startup::MakeStartupError(StartupErrorCode::Bind,
                "Listeners.Tcp[0].Address", "invalid TCP listen address: " + Text));
        }
        return Address;
    }

    [[nodiscard]] inline auto MakeEndpoint(const Configuration::ListenerEndpoint& Configured)
        -> std::expected<Net::ip::tcp::endpoint, StartupError>
    {
        const auto Address = MakeAddress(Configured.Address);
        if (!Address)
        {
            return std::unexpected(Address.error());
        }
        return Net::ip::tcp::endpoint(*Address, Configured.Port);
    }

    [[nodiscard]] inline auto MakeUdpEndpoint(const Configuration::ListenerEndpoint& Configured)
        -> std::expected<Net::ip::udp::endpoint, StartupError>
    {
        const auto Address = MakeAddress(Configured.Address);
        if (!Address)
        {
            auto Error = Address.error();
            Error.Path = "Listeners.Udp[0].Address";
            Error.Message = "invalid UDP listen address: " + Configured.Address;
            return std::unexpected(std::move(Error));
        }
        return Net::ip::udp::endpoint(*Address, Configured.Port);
    }

    [[nodiscard]] inline auto ResolveConfigurationPath(const std::filesystem::path& ConfigurationPath,
        const std::string& ConfiguredPath) -> std::filesystem::path
    {
        const std::filesystem::path Path(ConfiguredPath);
        if (Path.is_absolute() || ConfigurationPath.parent_path().empty())
        {
            return Path;
        }
        return ConfigurationPath.parent_path() / Path;
    }

    [[nodiscard]] inline auto MakeNativeTlsContext(
        const Configuration::PrismConfiguration& ConfigurationValue,
        const std::filesystem::path& ConfigurationPath)
        -> std::expected<std::shared_ptr<Net::ssl::context>, StartupError>
    {
        std::string CertificateFile = ConfigurationValue.NativeTls.CertificateFile;
        std::string PrivateKeyFile = ConfigurationValue.NativeTls.PrivateKeyFile;
        bool Enabled = ConfigurationValue.NativeTls.Enabled;
        if (!Enabled)
        {
            for (const auto& Carrier : ConfigurationValue.Carriers)
            {
                if (Carrier.Builtin != "native" ||
                    !std::holds_alternative<Prism::Contract::NativeTlsOptions>(Carrier.Options))
                {
                    continue;
                }
                const auto& Options = std::get<Prism::Contract::NativeTlsOptions>(Carrier.Options);
                CertificateFile = Options.CertificateFile;
                PrivateKeyFile = Options.PrivateKeyFile;
                Enabled = true;
                break;
            }
        }
        if (!Enabled)
        {
            if (ConfigurationValue.NativeTls.Ech.Enabled)
            {
                return std::unexpected(Startup::MakeStartupError(
                    StartupErrorCode::InvalidConfiguration,
                    "NativeTls.Ech",
                    "ECH server keys require a Native TLS context"));
            }
            return std::shared_ptr<Net::ssl::context>{};
        }
        const auto Certificate = ResolveConfigurationPath(ConfigurationPath, CertificateFile);
        const auto PrivateKey = ResolveConfigurationPath(ConfigurationPath, PrivateKeyFile);
        try
        {
            auto Context = std::make_shared<Net::ssl::context>(Net::ssl::context::tls_server);
            Context->set_options(Net::ssl::context::default_workarounds | Net::ssl::context::no_sslv2 |
                Net::ssl::context::no_sslv3 | Net::ssl::context::single_dh_use);
            Context->use_certificate_chain_file(Certificate.string());
            Context->use_private_key_file(PrivateKey.string(), Net::ssl::context::pem);
            if (!SSL_CTX_check_private_key(Context->native_handle()))
            {
                return std::unexpected(Startup::MakeStartupError(StartupErrorCode::InvalidConfiguration,
                    "NativeTls.PrivateKeyFile", "NativeTls certificate and private key do not match"));
            }
            if (ConfigurationValue.NativeTls.Ech.Enabled)
            {
                const auto &Ech = ConfigurationValue.NativeTls.Ech;
                auto Prepared = Prism::Ech::PrepareServerKeys(Prism::Ech::ServerKeyFiles{
                    ResolveConfigurationPath(ConfigurationPath, Ech.PrivateKeyFile),
                    ResolveConfigurationPath(ConfigurationPath, Ech.EchConfigFile)});
                if (!Prepared)
                {
                    return std::unexpected(Startup::MakeStartupError(
                        StartupErrorCode::InvalidConfiguration,
                        "NativeTls.Ech",
                        "ECH server key preparation failed (fault=" +
                            std::to_string(static_cast<std::int32_t>(Prepared.error().Code)) + ")"));
                }
                auto Installed = Prism::Ech::InstallServerKeys(
                    Context->native_handle(), std::move(*Prepared));
                if (!Installed)
                {
                    return std::unexpected(Startup::MakeStartupError(
                        StartupErrorCode::InvalidConfiguration,
                        "NativeTls.Ech",
                        "ECH server keys could not be installed (fault=" +
                            std::to_string(static_cast<std::int32_t>(Installed.error().Code)) + ")"));
                }
            }
            // QUIC requires a server-side ALPN selection callback; keep the same
            // context usable by native TCP carriers by selecting only protocols
            // actually offered by the client.
            SSL_CTX_set_alpn_select_cb(
                Context->native_handle(),
                SelectNativeTlsAlpn,
                nullptr);
            return Context;
        }
        catch (const std::exception& Error)
        {
            return std::unexpected(Startup::MakeStartupError(StartupErrorCode::InvalidConfiguration,
                "NativeTls", "NativeTls context failed: " + std::string(Error.what())));
        }
    }

    [[nodiscard]] inline auto MakeOperationsEndpoint(const std::string_view Configured)
        -> std::expected<Net::ip::tcp::endpoint, StartupError>
    {
        if (Configured.empty())
        {
            return std::unexpected(Startup::MakeStartupError(StartupErrorCode::InvalidConfiguration,
                "Operations.Endpoint", "operations Endpoint is required"));
        }

        std::string_view AddressText;
        std::string_view PortText;
        if (Configured.front() == '[')
        {
            const auto Close = Configured.find(']');
            if (Close == std::string_view::npos || Close + 2U > Configured.size() ||
                Configured[Close + 1U] != ':')
            {
                return std::unexpected(Startup::MakeStartupError(StartupErrorCode::InvalidConfiguration,
                    "Operations.Endpoint", "operations Endpoint must be address:port"));
            }
            AddressText = Configured.substr(1U, Close - 1U);
            PortText = Configured.substr(Close + 2U);
        }
        else
        {
            const auto Separator = Configured.rfind(':');
            if (Separator == std::string_view::npos || Configured.find(':') != Separator)
            {
                return std::unexpected(Startup::MakeStartupError(StartupErrorCode::InvalidConfiguration,
                    "Operations.Endpoint", "operations IPv6 endpoints must use brackets"));
            }
            AddressText = Configured.substr(0, Separator);
            PortText = Configured.substr(Separator + 1U);
        }

        const auto Address = MakeAddress(std::string(AddressText));
        if (!Address)
        {
            return std::unexpected(Startup::MakeStartupError(StartupErrorCode::InvalidConfiguration,
                "Operations.Endpoint", Address.error().Message));
        }
        if (!Address->is_loopback())
        {
            return std::unexpected(Startup::MakeStartupError(StartupErrorCode::InvalidConfiguration,
                "Operations.Endpoint", "operations listener must use a loopback address"));
        }

        std::uint32_t Port{};
        const auto [End, Error] =
            std::from_chars(PortText.data(), PortText.data() + PortText.size(), Port, 10);
        if (Error != std::errc{} || End != PortText.data() + PortText.size() || Port > 65535U)
        {
            return std::unexpected(Startup::MakeStartupError(StartupErrorCode::InvalidConfiguration,
                "Operations.Endpoint", "operations port must be between 0 and 65535"));
        }
        return Net::ip::tcp::endpoint(*Address, static_cast<std::uint16_t>(Port));
    }

    [[nodiscard]] inline auto CheckBindAvailable(const Net::ip::tcp::endpoint& Endpoint)
        -> std::expected<void, StartupError>
    {
        Net::io_context ProbeIo;
        Net::ip::tcp::acceptor Probe(ProbeIo);
        boost::system::error_code Error;
        Probe.open(Endpoint.protocol(), Error);
        if (!Error)
        {
            // 与真实 listener 保持相同选项；预检不能替代后续 listener 的实际 bind。
            Probe.set_option(Net::ip::tcp::acceptor::reuse_address(true), Error);
        }
        if (!Error)
        {
            Probe.bind(Endpoint, Error);
        }
        if (!Error)
        {
            Probe.listen(Net::socket_base::max_listen_connections, Error);
        }
        if (Error)
        {
            boost::system::error_code CloseError;
            Probe.close(CloseError);
            return std::unexpected(Startup::MakeStartupError(StartupErrorCode::Bind, "Listeners.Tcp[0]",
                "TCP listen endpoint is unavailable: " + Error.message()));
        }
        return {};
    }

    struct SessionFactoryRunner final
    {
        [[nodiscard]] auto operator()(Prism::Runtime::SessionAdmission Admission) const
            -> Prism::Runtime::SessionAdmissionResult
        {
            if (!Admission.Inbound || !Admission.Worker || !Admission.Generation)
            {
                return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            }
            const auto Snapshot = std::dynamic_pointer_cast<const RuntimeGenerationSnapshot>(
                Admission.Generation);
            if (!Snapshot || Snapshot->Id() != Admission.Generation->Id())
            {
                return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
            }
            const auto WorkerValue = Admission.Worker.Value();
            if (WorkerValue == 0U || WorkerValue > Snapshot->Services.WorkerSessions.size())
            {
                return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::ResourceUnavailable});
            }
            if (!Snapshot->Services.UseState)
            {
                return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            }
            auto GenerationUse = Snapshot->Services.UseState->Acquire();
            if (!GenerationUse)
            {
                return std::unexpected(GenerationUse.error());
            }
            try
            {
                auto Services = std::make_shared<Prism::Runtime::SessionServices>(
                    Snapshot->Services.WorkerSessions[static_cast<std::size_t>(WorkerValue - 1U)]);
                Services->Generation = Snapshot->Generation;
                Services->RuntimeSnapshotPin = Snapshot;
                Prism::Runtime::SessionOptions Options;
                Options.SourceIp = std::move(Admission.SourceIp);
                Options.Services = std::move(Services);
                auto Session = std::make_shared<Prism::Runtime::Session>(std::move(Options));
                if (!Session->SetGenerationUseLease(std::move(*GenerationUse)))
                {
                    return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
                }
                return Session;
            }
            catch (...)
            {
                return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::ResourceUnavailable});
            }
        }
    };

    [[nodiscard]] inline auto MakeSessionFactory()
        -> Prism::Runtime::TcpListener::SessionFactory
    {
        return SessionFactoryRunner{};
    }

    struct ListenerStartResult final
    {
        bool Completed{false};
        std::exception_ptr Failure;
        Prism::Fault::Code Code{Prism::Fault::Code::IoError};
    };

    [[nodiscard]] inline auto StartListener(const std::shared_ptr<Application::RuntimeState>& State,
        const Net::ip::tcp::endpoint& Endpoint) -> std::expected<void, StartupError>
    {
        ListenerStartResult Result;
        Net::co_spawn(State->Io.get_executor(), State->Listener->Start(Endpoint),
            [&Result](std::exception_ptr Failure, const Prism::Fault::Code Code)
            {
                Result.Failure = std::move(Failure);
                Result.Code = Code;
                Result.Completed = true;
            });

        while (!Result.Completed)
        {
            if (State->Io.run_one() == 0U)
            {
                State->Io.restart();
            }
        }
        if (Result.Failure)
        {
            return std::unexpected(Startup::MakeStartupError(StartupErrorCode::Bind, "Listeners.Tcp[0]",
                "TCP listener startup threw: " + Startup::DescribeException(Result.Failure)));
        }
        if (Prism::Fault::Failed(Result.Code))
        {
            return std::unexpected(Startup::MakeStartupError(StartupErrorCode::Bind, "Listeners.Tcp[0]",
                "TCP listener bind/listen failed"));
        }
        return {};
    }

    struct DatagramListenerStartResult final
    {
        bool Completed{false};
        std::exception_ptr Failure;
        Prism::Boundary::DatagramStartResult Result;
    };

    struct ActiveGenerationDatagramDispatcher final
    {
        std::weak_ptr<Application::RuntimeState> State;
        std::shared_ptr<Prism::Boundary::BoundaryDispatcher> Dispatcher;

        auto operator()(Prism::Boundary::BoundaryPacket Packet) const -> void
        {
            const auto StateValue = State.lock();
            if (!StateValue)
            {
                return;
            }
            const auto Generation = StateValue->ActiveGenerationSnapshot();
            const auto Selection = Generation ? Generation->Services.DatagramSelection
                : std::shared_ptr<const Prism::Contract::DatagramIngressSelection>{};
            Dispatcher->Dispatch(std::move(Packet), Selection);
        }
    };

    [[nodiscard]] inline auto StartDatagramListener(const std::shared_ptr<Application::RuntimeState>& State,
        const Net::ip::udp::endpoint& Endpoint) -> std::expected<void, StartupError>
    {
        if (!State->DatagramListener || !State->DatagramClassifier || !State->BoundaryDispatcher)
        {
            return std::unexpected(Startup::MakeStartupError(StartupErrorCode::Runtime, "Listeners.Udp",
                "UDP listener composition is incomplete"));
        }

        DatagramListenerStartResult Result;
        const auto WeakState = std::weak_ptr<Application::RuntimeState>(State);
        const ActiveGenerationDatagramDispatcher Handler{WeakState, State->BoundaryDispatcher};
        const auto OnError = [WeakState](const boost::system::error_code Error) noexcept
        {
            if (const auto StateValue = WeakState.lock())
            {
                const auto Message = Prism::Text::RedactSensitiveText(Error.message());
                (void)Prism::Diagnose::Error(
                    StateValue->CurrentProcessContext(), "UdpReceiveFailed Error={}", Message);
            }
        };
        Net::co_spawn(State->Io.get_executor(),
            State->DatagramListener->Start(Prism::Boundary::DatagramListener::StartRequest{Endpoint,
                State->DatagramClassifier, Handler, OnError}),
            [&Result](std::exception_ptr Failure, Prism::Boundary::DatagramStartResult Started)
            {
                Result.Failure = std::move(Failure);
                Result.Result = std::move(Started);
                Result.Completed = true;
            });

        while (!Result.Completed)
        {
            if (State->Io.run_one() == 0U)
            {
                State->Io.restart();
            }
        }
        if (Result.Failure)
        {
            return std::unexpected(Startup::MakeStartupError(StartupErrorCode::Bind, "Listeners.Udp[0]",
                "UDP listener startup threw: " + Startup::DescribeException(Result.Failure)));
        }
        if (!Result.Result.Succeeded())
        {
            const auto Message = Result.Result.Error ? Result.Result.Error.message()
                                                     : std::string("UDP listener bind/listen failed");
            return std::unexpected(
                Startup::MakeStartupError(StartupErrorCode::Bind, "Listeners.Udp[0]", Message));
        }
        return {};
    }

} // namespace Prism::Application::BoundaryStartup
