/**
 * @file HttpForwardApplicationFixture.hpp
 * @brief HTTP 正向代理真实入口测试的共享生命周期 fixture。
 */

#pragma once

#include <Preview/Application/Application.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/system/error_code.hpp>

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <vector>

namespace Preview::Testing::HttpForward
{

    namespace Net = boost::asio;
    using Tcp = Net::ip::tcp;

    inline constexpr std::string_view ProxyAuthorization = "Basic bG9jYWw6aHR0cC1wYXNzd29yZA==";
    inline constexpr auto IoTimeout = std::chrono::seconds(2);
    inline constexpr auto DialFailureTimeout = std::chrono::seconds(8);

    /** @brief 环回源站在写完响应后的连接策略。 */
    enum class OriginCloseMode
    {
        CloseAfterResponse,
        KeepOpen
    };

    [[nodiscard]] auto FindFreePort() -> std::uint16_t;

    /** @brief 生成单个 HTTP 真实入口测试使用的临时配置与日志目录。 */
    class TemporaryConfiguration final
    {
    public:
        TemporaryConfiguration(std::uint16_t TcpPort, std::uint16_t OperationsPort);
        ~TemporaryConfiguration();

        TemporaryConfiguration(const TemporaryConfiguration&) = delete;
        auto operator=(const TemporaryConfiguration&) -> TemporaryConfiguration& = delete;

        [[nodiscard]] auto Path() const -> const std::filesystem::path&;

    private:
        std::filesystem::path Path_;
        std::filesystem::path LogDirectory_;
    };

    /** @brief 持有真实 Application 运行线程，并负责有限生命周期内的停止与 join。 */
    class RunningApplication final
    {
    public:
        explicit RunningApplication(const std::filesystem::path& Path);
        ~RunningApplication();

        RunningApplication(const RunningApplication&) = delete;
        auto operator=(const RunningApplication&) -> RunningApplication& = delete;

        [[nodiscard]] auto Start() -> bool;
        auto Stop() -> void;

        [[nodiscard]] auto Port() const noexcept -> std::uint16_t;
        [[nodiscard]] auto OperationsPort() const noexcept -> std::uint16_t;
        [[nodiscard]] auto ExitCode() const noexcept -> int;
        [[nodiscard]] auto Error() const -> const std::string&;

    private:
        Preview::Application::Application Application_;
        std::thread Thread_;
        std::uint16_t Port_{0};
        std::uint16_t OperationsPort_{0};
        int ExitCode_{0};
        std::string Error_;
    };

    /** @brief 接收并记录代理上游请求，可选择在响应后保持连接打开。 */
    class LoopbackOrigin final
    {
    public:
        LoopbackOrigin();
        ~LoopbackOrigin();

        LoopbackOrigin(const LoopbackOrigin&) = delete;
        auto operator=(const LoopbackOrigin&) -> LoopbackOrigin& = delete;

        auto Start(std::string Expected, std::string Response,
            OriginCloseMode CloseMode = OriginCloseMode::CloseAfterResponse) -> void;
        /** @brief 配置响应写完后精确接收的 tunnel 字节，必须在 Start 前调用。 */
        auto ExpectAfterResponse(std::string Expected) -> void;
        auto Stop() -> void;

        [[nodiscard]] auto Port() const -> std::uint16_t;
        [[nodiscard]] auto WaitForAccepted(std::chrono::milliseconds Timeout) -> bool;
        [[nodiscard]] auto WaitForResponse(std::chrono::milliseconds Timeout) -> bool;
        [[nodiscard]] auto WaitForComplete(std::chrono::milliseconds Timeout) -> bool;
        [[nodiscard]] auto Captured() const -> std::string;
        [[nodiscard]] auto Extra() const -> std::string;
        /** @brief 返回响应后收到的 tunnel 字节。 */
        [[nodiscard]] auto PostResponseCaptured() const -> std::string;

    private:
        [[nodiscard]] auto Serve() -> Net::awaitable<void>;
        auto Complete() -> void;
        auto MarkResponseSent(bool Succeeded) -> void;

        Net::io_context Io_;
        Net::executor_work_guard<Net::io_context::executor_type> WorkGuard_;
        Tcp::acceptor Acceptor_;
        Net::steady_timer HoldTimer_;
        std::thread Thread_;
        std::string Expected_;
        std::string Response_;
        std::string PostResponseExpected_;
        OriginCloseMode CloseMode_{OriginCloseMode::CloseAfterResponse};
        mutable std::mutex Mutex_;
        std::condition_variable Condition_;
        std::shared_ptr<Tcp::socket> Socket_;
        bool Accepted_{false};
        bool ResponseSent_{false};
        bool Completed_{false};
        std::string Captured_;
        std::string Extra_;
        std::string PostResponseCaptured_;
    };

    [[nodiscard]] auto Connect(Tcp::socket& Socket, std::uint16_t Port,
        boost::system::error_code* Failure = nullptr) -> bool;
    [[nodiscard]] auto WriteAll(Tcp::socket& Socket, std::string_view Bytes) -> bool;

    struct ReadObservation final
    {
        std::string Bytes;
        boost::system::error_code Error;
        bool Closed{false};
        bool TimedOut{false};

        [[nodiscard]] auto Description() const -> std::string;
    };

    [[nodiscard]] auto ReadUntilClose(Tcp::socket& Socket, std::chrono::milliseconds Timeout = IoTimeout)
        -> ReadObservation;
    auto CloseSocket(Tcp::socket& Socket) -> void;

    struct OperationsQuery final
    {
        std::string Target;
        ReadObservation Read;
        boost::system::error_code Error;
        bool Connected{false};
        bool RequestWritten{false};

        [[nodiscard]] auto StatusLine() const -> std::string;
        [[nodiscard]] auto Description() const -> std::string;
    };

    struct OperationsDrainObservation final
    {
        OperationsQuery Sessions;
        OperationsQuery Accounts;
        std::optional<std::size_t> SessionItemCount;
        std::string SessionItemsState{"unknown"};
        bool AccountsItemsParsed{false};
        std::string AccountItemsState{"unknown"};
        std::vector<std::string> AccountActiveSessions;

        [[nodiscard]] auto Description() const -> std::string;
    };

    [[nodiscard]] auto ReadOperationsSessions(std::uint16_t Port) -> OperationsQuery;
    [[nodiscard]] auto ReadOperationsAccounts(std::uint16_t Port) -> OperationsQuery;
    [[nodiscard]] auto WaitForResourcesEmpty(std::uint16_t Port,
        std::chrono::milliseconds Timeout = IoTimeout, OperationsDrainObservation* Last = nullptr) -> bool;
    /** @brief 构造环回源站的 HTTP authority 文本，不拥有连接资源。 */
    [[nodiscard]] auto MakeOriginHost(std::uint16_t Port) -> std::string;

    namespace
    {
        [[nodiscard]] auto MakeApplicationOptions(const std::filesystem::path& Path)
            -> Preview::Application::Options
        {
            Preview::Application::Options Options;
            Options.ConfigurationPath = Path;
            return Options;
        }

    } // namespace

    inline auto FindFreePort() -> std::uint16_t
    {
        Net::io_context Io;
        Tcp::acceptor Acceptor(Io, Tcp::endpoint(Tcp::v4(), 0));
        return Acceptor.local_endpoint().port();
    }

    inline TemporaryConfiguration::TemporaryConfiguration(const std::uint16_t TcpPort,
                                                   const std::uint16_t OperationsPort)
        : Path_(std::filesystem::temp_directory_path() /
                ("PrismPreviewHttpIngress-" +
                 std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) +
                 ".json")),
          LogDirectory_(std::filesystem::temp_directory_path() /
                        ("PrismPreviewHttpIngressLogs-" +
                         std::to_string(std::chrono::steady_clock::now()
                                            .time_since_epoch()
                                            .count())))
    {
        std::ofstream File(Path_, std::ios::binary);
        File << R"json({
    "SchemaVersion": 1,
    "Runtime": {
        "WorkerCount": 1,
        "RequiredCapabilities": [],
        "SessionTimeout": 30000
    },
    "Listeners": {
        "Tcp": [{
            "Id": "tcp-http-ingress",
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
        "Id": "protocol-http",
        "Name": "http",
        "Builtin": "http",
        "Requires": []
    }],
    "Carriers": [],
    "ProtocolBindings": [],
    "Accounts": [{
        "Id": "local",
        "SecretRef": "",
        "Credential": "http-password",
        "Credentials": {}
    }],
    "Routes": [],
    "Dns": {"Servers": ["1.1.1.1"], "Timeout": 1000},
    "Logging": {
        "Level": "Trace",
        "Directory": ")json"
             << LogDirectory_.generic_string() << R"json(",
        "FileName": "http-ingress.log",
        "RenderMode": "CompactHuman",
        "Console": false
    },
    "Statistics": {"Enabled": true, "Interval": 1000},
    "Operations": {"Enabled": true, "Endpoint": "127.0.0.1:)json"
             << OperationsPort << R"json(", "Timeout": 1000},
    "HotReload": {"Enabled": false, "AckTimeout": 5000},
    "Shutdown": {"Timeout": 5000}
})json";
    }

    inline TemporaryConfiguration::~TemporaryConfiguration()
    {
        std::error_code Error;
        std::filesystem::remove(Path_, Error);
        std::filesystem::remove_all(LogDirectory_, Error);
    }

    inline auto TemporaryConfiguration::Path() const -> const std::filesystem::path &
    {
        return Path_;
    }

    inline RunningApplication::RunningApplication(const std::filesystem::path &Path)
        : Application_(MakeApplicationOptions(Path))
    {
    }

    inline RunningApplication::~RunningApplication()
    {
        Stop();
    }

    inline auto RunningApplication::Start() -> bool
    {
        const auto Result = Application_.Start();
        if (!Result)
        {
            Error_ = Result.error().Path + ": " + Result.error().Message;
            return false;
        }
        Port_ = Result->Port;
        OperationsPort_ = Result->OperationsPort;
        Thread_ = std::thread([this] { ExitCode_ = Application_.Run(); });
        return true;
    }

    inline auto RunningApplication::Stop() -> void
    {
        Application_.Stop();
        if (Thread_.joinable())
        {
            Thread_.join();
        }
    }

    inline auto RunningApplication::Port() const noexcept -> std::uint16_t
    {
        return Port_;
    }

    inline auto RunningApplication::OperationsPort() const noexcept -> std::uint16_t
    {
        return OperationsPort_;
    }

    inline auto RunningApplication::ExitCode() const noexcept -> int
    {
        return ExitCode_;
    }

    inline auto RunningApplication::Error() const -> const std::string &
    {
        return Error_;
    }
} // namespace Preview::Testing::HttpForward
