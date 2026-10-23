/**
 * @file Socks5AccountIngressCore.hpp
 * @brief SOCKS5 真实入口测试的生命周期与 typed 客户端 fixture。
 */

#pragma once

#include <Prism/Protocols/Socks5/Types.hpp>
#include <Prism/Application/Application.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/write.hpp>

#include <array>
#include <cstddef>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <stdexcept>
#include <system_error>
#include <thread>
#include <utility>

namespace Prism::Testing::Socks5AccountIngress
{

    namespace Detail
    {
        class FixtureState;
    }

    /** @brief UserPass 协商结果，区分传输失败和协议状态。 */
    struct UserPassResult final
    {
        bool TransportOk{false};
        std::uint8_t Status{0xFFU};
    };

    /** @brief 一次 SOCKS5 CONNECT 请求及其有界回复等待策略。 */
    struct ConnectAttempt final
    {
        std::string Host;
        std::uint16_t Port{0};
        std::chrono::milliseconds ReplyTimeout{std::chrono::milliseconds{1000}};
    };

    /** @brief SOCKS5 CONNECT 结果，区分传输失败和 typed reply。 */
    struct ConnectResult final
    {
        bool TransportOk{false};
        Prism::Socks5::ReplyCode Reply{
            static_cast<Prism::Socks5::ReplyCode>(0xFFU)};
        std::string Stage{"not_started"};
        std::size_t BytesWritten{0};
        std::size_t BytesReceived{0};
        std::string SocketError;
        std::string ReplyHex;
        std::chrono::milliseconds Elapsed{0};

        [[nodiscard]] auto Diagnostic() const -> std::string;
    };

    /** @brief 最近一次 Accounts/Sessions Operations 原始响应。 */
    struct OperationsSnapshot final
    {
        std::string Accounts;
        std::string Sessions;
    };

    /** @brief Operations 轮询结果，失败时保留最后一对响应用于诊断。 */
    struct OperationsWaitResult final
    {
        bool Matched{false};
        OperationsSnapshot Last;
    };

    /**
     * @class Socks5Client
     * @brief 持有单个 SOCKS5 测试连接及其 I/O 生命周期。
     * @details 所有 socket 操作都由对象自身完成，认证与 CONNECT 只接收业务输入并返回
     *          typed 结果，避免把 socket 作为跨层参数传递。
     */
    class Socks5Client final
    {
    public:
        Socks5Client();
        ~Socks5Client();

        Socks5Client(const Socks5Client &) = delete;
        auto operator=(const Socks5Client &) -> Socks5Client & = delete;

        [[nodiscard]] auto Connect(std::uint16_t Port) -> bool;
        [[nodiscard]] auto Authenticate(std::string_view User,
                                        std::string_view Password) -> UserPassResult;
        [[nodiscard]] auto ConnectTarget(ConnectAttempt Attempt) -> ConnectResult;
        [[nodiscard]] auto Write(std::string_view Bytes) -> bool;
        [[nodiscard]] auto Read(std::size_t Size) -> std::optional<std::string>;
        [[nodiscard]] auto ReadClosed() -> bool;
        auto Close() noexcept -> void;

    private:
        class State;
        std::unique_ptr<State> State_;
    };

    /**
     * @class Socks5AccountIngressFixture
     * @brief 真实 Application SOCKS5 入口、echo 源站和 Operations 观测的专属 fixture。
     */
    class Socks5AccountIngressFixture final
    {
    public:
        Socks5AccountIngressFixture();
        ~Socks5AccountIngressFixture();

        Socks5AccountIngressFixture(const Socks5AccountIngressFixture &) = delete;
        auto operator=(const Socks5AccountIngressFixture &)
            -> Socks5AccountIngressFixture & = delete;

        [[nodiscard]] auto Start() -> bool;
        auto Stop() noexcept -> void;

        [[nodiscard]] auto Port() const noexcept -> std::uint16_t;
        [[nodiscard]] auto EchoPort() const noexcept -> std::uint16_t;
        [[nodiscard]] auto RejectedPort() const noexcept -> std::uint16_t;
        [[nodiscard]] auto WaitForOperations(bool Active) -> OperationsWaitResult;
        [[nodiscard]] auto CommandOperations(std::string_view Target) -> std::string;
        [[nodiscard]] auto QueryCommandOperation(std::uint64_t Operation) -> std::string;
        [[nodiscard]] auto ExitCode() const noexcept -> int;
        [[nodiscard]] auto IsStopped() const noexcept -> bool;

    private:
        std::unique_ptr<Detail::FixtureState> State_;
    };


namespace Detail
{
/** @brief 组合 fixture 的生命周期、端口和真实 Application 访问面。 */
    class FixtureState final
    {
    public:
        FixtureState();
        ~FixtureState();

        FixtureState(const FixtureState &) = delete;
        auto operator=(const FixtureState &) -> FixtureState & = delete;

        [[nodiscard]] auto Start() -> bool;
        auto Stop() noexcept -> void;

        [[nodiscard]] auto Port() const noexcept -> std::uint16_t;
        [[nodiscard]] auto EchoPort() const noexcept -> std::uint16_t;
        [[nodiscard]] auto RejectedPort() const noexcept -> std::uint16_t;
        [[nodiscard]] auto OperationsPort() const noexcept -> std::uint16_t;
        [[nodiscard]] auto ExitCode() const noexcept -> int;
        [[nodiscard]] auto IsStopped() const noexcept -> bool;

    private:
        class Impl;
        std::unique_ptr<Impl> Impl_;
    };
}


    namespace
    {

        namespace Net = boost::asio;
        using Tcp = Net::ip::tcp;
        using Clock = std::chrono::steady_clock;

        [[nodiscard]] auto FindFreePort() -> std::uint16_t
        {
            Net::io_context Io;
            Tcp::acceptor Acceptor(Io, Tcp::endpoint(Net::ip::address_v4::loopback(), 0));
            return Acceptor.local_endpoint().port();
        }

        [[nodiscard]] auto MakeOptions(const std::filesystem::path &Path)
            -> Prism::Application::Options
        {
            Prism::Application::Options Options;
            Options.ConfigurationPath = Path;
            return Options;
        }

        class TemporaryConfiguration final
        {
        public:
            TemporaryConfiguration(const std::uint16_t TcpPort,
                                   const std::uint16_t OperationsPort)
                : Root_(std::filesystem::temp_directory_path() /
                        ("PrismSocks5AccountIngress-" +
                         std::to_string(Clock::now().time_since_epoch().count()))),
                  Path_(Root_ / "configuration.json")
            {
                std::error_code Error;
                if (!std::filesystem::create_directory(Root_, Error) || Error)
                {
                    throw std::runtime_error("failed to create SOCKS5 ingress temp root");
                }
                Created_ = true;

                std::ofstream File(Path_, std::ios::binary);
                File << R"json({
    "SchemaVersion": 1,
    "Runtime": {
        "WorkerCount": 1,
        "RequiredCapabilities": [],
        "SessionTimeout": 5000
    },
    "Listeners": {
        "Tcp": [{
            "Id": "tcp-socks5-ingress",
            "Address": "127.0.0.1",
            "Port": )json"
                     << TcpPort << R"json(,
            "Timeout": 5000
        }],
        "Udp": [],
        "Quic": [],
        "Timeout": 5000
    },
    "NativeTls": {"Enabled": false, "CertificateFile": "", "PrivateKeyFile": ""},
    "Builtins": [],
    "Protocols": [{
        "Id": "protocol-socks5",
        "Name": "socks5",
        "Builtin": "socks5",
        "Requires": []
    }],
    "Carriers": [],
    "ProtocolBindings": [],
    "Accounts": [{
        "Id": "local",
        "SecretRef": "",
        "Credential": "socks-password",
        "Credentials": {}
    }],
    "Routes": [],
    "Dns": {"Servers": ["1.1.1.1"], "Timeout": 1000},
    "Logging": {
        "Level": "Warn",
        "Directory": )json"
                     << '"' << Root_.generic_string() << R"json(",
        "FileName": "socks5-account-ingress.log",
        "RenderMode": "CompactHuman",
        "Console": false
    },
    "Statistics": {"Enabled": true, "Interval": 1000},
    "Operations": {"Enabled": true, "Endpoint": "127.0.0.1:)json"
                     << OperationsPort << R"json(", "Timeout": 1000},
    "HotReload": {"Enabled": false, "AckTimeout": 5000},
    "Shutdown": {"Timeout": 1000}
})json";
                if (!File)
                {
                    std::filesystem::remove_all(Root_, Error);
                    Created_ = false;
                    throw std::runtime_error("failed to write SOCKS5 ingress configuration");
                }
            }

            ~TemporaryConfiguration()
            {
                if (!Created_)
                {
                    return;
                }
                std::error_code Error;
                const auto Temp = std::filesystem::temp_directory_path(Error);
                if (Error)
                {
                    return;
                }
                const auto Name = Root_.filename().string();
                if (Root_.parent_path() != Temp ||
                    !Name.starts_with("PrismSocks5AccountIngress-"))
                {
                    return;
                }
                std::filesystem::remove_all(Root_, Error);
            }

            TemporaryConfiguration(const TemporaryConfiguration &) = delete;
            auto operator=(const TemporaryConfiguration &)
                -> TemporaryConfiguration & = delete;

            [[nodiscard]] auto Path() const -> const std::filesystem::path &
            {
                return Path_;
            }

        private:
            std::filesystem::path Root_;
            std::filesystem::path Path_;
            bool Created_{false};
        };

        class RunningApplication final
        {
        public:
            explicit RunningApplication(const std::filesystem::path &Path)
                : Application_(MakeOptions(Path))
            {
            }

            ~RunningApplication()
            {
                Stop();
            }

            RunningApplication(const RunningApplication &) = delete;
            auto operator=(const RunningApplication &) -> RunningApplication & = delete;

            [[nodiscard]] auto Start() -> bool
            {
                const auto Result = Application_.Start();
                if (!Result)
                {
                    return false;
                }
                Port_ = Result->Port;
                OperationsPort_ = Result->OperationsPort;
                Thread_ = std::thread([this]
                                      { ExitCode_ = Application_.Run(); });
                return true;
            }

            auto Stop() noexcept -> void
            {
                Application_.Stop();
                if (Thread_.joinable())
                {
                    Thread_.join();
                }
            }

            [[nodiscard]] auto Port() const noexcept -> std::uint16_t
            {
                return Port_;
            }

            [[nodiscard]] auto OperationsPort() const noexcept -> std::uint16_t
            {
                return OperationsPort_;
            }

            [[nodiscard]] auto ExitCode() const noexcept -> int
            {
                return ExitCode_;
            }

            [[nodiscard]] auto IsStopped() const noexcept -> bool
            {
                return Application_.IsStopped();
            }

        private:
            Prism::Application::Application Application_;
            std::thread Thread_;
            std::uint16_t Port_{0};
            std::uint16_t OperationsPort_{0};
            int ExitCode_{0};
        };

        class LoopbackEchoServer final
        {
        public:
            LoopbackEchoServer()
                : Acceptor_(Io_, Tcp::endpoint(Net::ip::address_v4::loopback(), 0))
            {
                Net::co_spawn(Io_, AcceptLoop(), Net::detached);
                Thread_ = std::thread([this]
                                      { Io_.run(); });
            }

            ~LoopbackEchoServer()
            {
                Stop();
            }

            LoopbackEchoServer(const LoopbackEchoServer &) = delete;
            auto operator=(const LoopbackEchoServer &) -> LoopbackEchoServer & = delete;

            auto Stop() noexcept -> void
            {
                Io_.stop();
                if (Thread_.joinable())
                {
                    Thread_.join();
                }
                boost::system::error_code Error;
                Acceptor_.close(Error);
            }

            [[nodiscard]] auto Port() const -> std::uint16_t
            {
                return Acceptor_.local_endpoint().port();
            }

        private:
            [[nodiscard]] auto AcceptLoop() -> Net::awaitable<void>
            {
                for (;;)
                {
                    Tcp::socket Socket(Io_);
                    boost::system::error_code Error;
                    co_await Acceptor_.async_accept(
                        Socket, Net::redirect_error(Net::use_awaitable, Error));
                    if (Error)
                    {
                        co_return;
                    }
                    Net::co_spawn(Io_, Echo(std::move(Socket)), Net::detached);
                }
            }

            [[nodiscard]] auto Echo(Tcp::socket Socket) -> Net::awaitable<void>
            {
                std::array<char, 4096> Buffer{};
                for (;;)
                {
                    boost::system::error_code Error;
                    const auto Count = co_await Socket.async_read_some(
                        Net::buffer(Buffer), Net::redirect_error(Net::use_awaitable, Error));
                    if (Error || Count == 0U)
                    {
                        co_return;
                    }
                    Error.clear();
                    co_await Net::async_write(
                        Socket, Net::buffer(Buffer.data(), Count),
                        Net::redirect_error(Net::use_awaitable, Error));
                    if (Error)
                    {
                        co_return;
                    }
                }
            }

            Net::io_context Io_;
            Tcp::acceptor Acceptor_;
            std::thread Thread_;
        };

        struct PortSelection final
        {
            PortSelection()
                : TcpPort(FindFreePort()),
                  OperationsPort(FindFreePort()),
                  RejectedPort(FindFreePort())
            {
                while (OperationsPort == TcpPort || OperationsPort == RejectedPort)
                {
                    OperationsPort = FindFreePort();
                }
                while (RejectedPort == TcpPort || RejectedPort == OperationsPort)
                {
                    RejectedPort = FindFreePort();
                }
            }

            std::uint16_t TcpPort;
            std::uint16_t OperationsPort;
            std::uint16_t RejectedPort;
        };

    } // namespace

    namespace Detail
    {

        class FixtureState::Impl final
        {
        public:
            Impl()
                : Ports(),
                  Echo(),
                  Configuration(Ports.TcpPort, Ports.OperationsPort),
                  Application(Configuration.Path())
            {
            }

            PortSelection Ports;
            LoopbackEchoServer Echo;
            TemporaryConfiguration Configuration;
            RunningApplication Application;
        };

        inline FixtureState::FixtureState()
            : Impl_(std::make_unique<Impl>())
        {
        }

        inline FixtureState::~FixtureState() = default;

        inline auto FixtureState::Start() -> bool
        {
            return Impl_ != nullptr && Impl_->Application.Start();
        }

        inline auto FixtureState::Stop() noexcept -> void
        {
            if (Impl_ != nullptr)
            {
                Impl_->Application.Stop();
            }
        }

        inline auto FixtureState::Port() const noexcept -> std::uint16_t
        {
            return Impl_ == nullptr ? 0U : Impl_->Application.Port();
        }

        inline auto FixtureState::EchoPort() const noexcept -> std::uint16_t
        {
            return Impl_ == nullptr ? 0U : Impl_->Echo.Port();
        }

        inline auto FixtureState::RejectedPort() const noexcept -> std::uint16_t
        {
            return Impl_ == nullptr ? 0U : Impl_->Ports.RejectedPort;
        }

        inline auto FixtureState::OperationsPort() const noexcept -> std::uint16_t
        {
            return Impl_ == nullptr ? 0U : Impl_->Application.OperationsPort();
        }

        inline auto FixtureState::ExitCode() const noexcept -> int
        {
            return Impl_ == nullptr ? 0 : Impl_->Application.ExitCode();
        }

        inline auto FixtureState::IsStopped() const noexcept -> bool
        {
            return Impl_ != nullptr && Impl_->Application.IsStopped();
        }

    } // namespace Detail

    inline Socks5AccountIngressFixture::Socks5AccountIngressFixture()
        : State_(std::make_unique<Detail::FixtureState>())
    {
    }

    inline Socks5AccountIngressFixture::~Socks5AccountIngressFixture()
    {
        Stop();
    }

    inline auto Socks5AccountIngressFixture::Start() -> bool
    {
        return State_ != nullptr && State_->Start();
    }

    inline auto Socks5AccountIngressFixture::Stop() noexcept -> void
    {
        if (State_ != nullptr)
        {
            State_->Stop();
        }
    }

    inline auto Socks5AccountIngressFixture::Port() const noexcept -> std::uint16_t
    {
        return State_ == nullptr ? 0U : State_->Port();
    }

    inline auto Socks5AccountIngressFixture::EchoPort() const noexcept -> std::uint16_t
    {
        return State_ == nullptr ? 0U : State_->EchoPort();
    }

    inline auto Socks5AccountIngressFixture::RejectedPort() const noexcept -> std::uint16_t
    {
        return State_ == nullptr ? 0U : State_->RejectedPort();
    }

    inline auto Socks5AccountIngressFixture::ExitCode() const noexcept -> int
    {
        return State_ == nullptr ? 0 : State_->ExitCode();
    }

    inline auto Socks5AccountIngressFixture::IsStopped() const noexcept -> bool
    {
        return State_ != nullptr && State_->IsStopped();
    }
} // namespace Prism::Testing::Socks5AccountIngress

