/**
 * @file TrustTunnelStartupTest.cpp
 * @brief TrustTunnel 协议接入启动测试。
 */

#include <Preview/Application/Application.hpp>

#include <boost/asio.hpp>
#include <gtest/gtest.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <system_error>

namespace
{

    namespace Net = boost::asio;
    using Tcp = Net::ip::tcp;

    class TemporaryConfiguration final
    {
    public:
        TemporaryConfiguration()
            : Root_(std::filesystem::temp_directory_path() /
                    ("PrismPreviewTrustTunnelStartup-" +
                     std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()))),
              ConfigurationPath_(Root_ / "configuration.json")
        {
            std::filesystem::create_directories(Root_);
            Net::io_context Io;
            Tcp::acceptor Acceptor(Io, Tcp::endpoint(Tcp::v4(), 0));
            const auto Port = Acceptor.local_endpoint().port();
            const auto Repository = std::filesystem::path{PRISM_TEST_REPO_ROOT};
            const auto Certificate = (Repository / "cert.pem").generic_string();
            const auto PrivateKey = (Repository / "key.pem").generic_string();

            std::ofstream File(ConfigurationPath_, std::ios::binary);
            File << R"json({
    "SchemaVersion": 1,
    "Runtime": {"WorkerCount": 1, "RequiredCapabilities": [], "SessionTimeout": 30000},
    "Listeners": {
        "Tcp": [{"Id": "tcp-main", "Address": "127.0.0.1", "Port": )json"
                 << Port << R"json(, "Timeout": 5000}],
        "Udp": [], "Quic": [], "Timeout": 5000
    },
    "NativeTls": {"Enabled": true, "CertificateFile": ")json"
                 << Certificate << R"json(", "PrivateKeyFile": ")json"
                 << PrivateKey << R"json("},
    "Builtins": [],
    "Protocols": [{"Id": "protocol-trusttunnel", "Name": "trusttunnel", "Builtin": "trusttunnel", "Requires": []}],
    "Carriers": [], "ProtocolBindings": [],
    "Accounts": [{"Id": "local", "SecretRef": "", "Credential": "local:trust-password"}],
    "Routes": [],
    "Dns": {"Servers": ["1.1.1.1"], "Timeout": 1000},
    "Logging": {"Level": "Info", "Directory": ")json"
                 << Root_.generic_string() << R"json(", "FileName": "trusttunnel-startup.log", "Console": false},
    "Statistics": {"Enabled": false, "Interval": 1000},
    "Operations": {"Enabled": false, "Endpoint": "127.0.0.1:0", "Timeout": 1000},
    "HotReload": {"Enabled": false, "AckTimeout": 5000},
    "Shutdown": {"Timeout": 5000}
})json";
        }

        ~TemporaryConfiguration()
        {
            std::error_code Error;
            std::filesystem::remove_all(Root_, Error);
        }

        [[nodiscard]] auto Path() const -> const std::filesystem::path &
        {
            return ConfigurationPath_;
        }

    private:
        std::filesystem::path Root_;
        std::filesystem::path ConfigurationPath_;
    };

} // namespace

TEST(PreviewApplication, StartsConfiguredTrustTunnelProtocol)
{
    TemporaryConfiguration Configuration;
    Preview::Application::Application Application(Configuration.Path());
    const auto Result = Application.Start();

    ASSERT_TRUE(Result) << (Result ? "" : Result.error().Message);
    EXPECT_TRUE(Application.IsReady());
    Application.Stop();
    EXPECT_EQ(Application.Run(), 0);
}


