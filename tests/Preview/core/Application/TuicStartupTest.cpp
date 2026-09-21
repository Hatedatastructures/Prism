/**
 * @file TuicStartupTest.cpp
 * @brief TUIC QUIC admission runtime 接线启动测试。
 */

#include <Preview/Application/Application.hpp>

#include <boost/asio.hpp>
#include <gtest/gtest.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <optional>
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
                    ("PrismPreviewTuicStartup-" +
                     std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()))),
              ConfigurationPath_(Root_ / "configuration.json")
        {
            std::filesystem::create_directories(Root_);
            Net::io_context Io;
            Tcp::acceptor Acceptor(Io, Tcp::endpoint(Tcp::v4(), 0));
            const auto TcpPort = Acceptor.local_endpoint().port();
            Acceptor.close();
            const auto QuicPort = static_cast<std::uint16_t>(TcpPort + 1U);
            const auto Repository = std::filesystem::path(__FILE__)
                                        .parent_path()
                                        .parent_path()
                                        .parent_path()
                                        .parent_path()
                                        .parent_path();
            const auto Certificate = (Repository / "cert.pem").generic_string();
            const auto PrivateKey = (Repository / "key.pem").generic_string();

            std::ofstream File(ConfigurationPath_, std::ios::binary);
            File << R"json({
    "SchemaVersion": 1,
    "Runtime": {"WorkerCount": 1, "RequiredCapabilities": [], "SessionTimeout": 30000},
    "Listeners": {
        "Tcp": [{"Id":"tcp-main","Address":"127.0.0.1","Port":)json"
                 << TcpPort << R"json(,"Timeout":5000}],
        "Udp": [],
        "Quic": [{"Id":"quic-main","Address":"127.0.0.1","Port":)json"
                 << QuicPort << R"json(,"Timeout":5000}],
        "Timeout": 5000
    },
    "NativeTls": {"Enabled": true, "CertificateFile": ")json"
                 << Certificate << R"json(", "PrivateKeyFile": ")json"
                 << PrivateKey << R"json("},
    "Builtins": [],
    "Protocols": [
        {"Id":"protocol-socks5","Name":"socks5","Builtin":"socks5","Requires":[]},
        {"Id":"protocol-tuic","Name":"tuic","Builtin":"tuic","Requires":[],"Quic":{
            "Alpn":"h3","ServerName":"quic.example","CredentialSecretRef":"secret/quic/password",
            "MaxStreams":32,"MaxDatagrams":64,"Uuid":"123e4567-e89b-12d3-a456-426614174000"}}
    ],
    "Carriers": [],
    "ProtocolBindings": [{"Id":"binding-socks5","ProtocolId":"protocol-socks5","TcpEnabled":true,"UdpEnabled":false,"MuxModes":[]}],
    "Accounts": [{"Id":"local","SecretRef":"secret/quic/password","Credential":"quic-password"}],
    "Routes": [],
    "Dns": {"Servers":["1.1.1.1"],"Timeout":1000},
    "Logging": {"Level":"Info","Directory":")json"
                 << Root_.generic_string() << R"json(","FileName":"tuic-startup.log","Console":false},
    "Statistics": {"Enabled":false,"Interval":1000},
    "Operations": {"Enabled":false,"Endpoint":"127.0.0.1:0","Timeout":1000},
    "HotReload": {"Enabled":false,"AckTimeout":5000},
    "Shutdown": {"Timeout":5000}
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

TEST(PreviewApplication, StartsConfiguredTuicQuicAdmission)
{
    TemporaryConfiguration Configuration;
    Preview::Application::Options Options;
    Options.ConfigurationPath = Configuration.Path();
    Options.SecretResolver = [](const std::string_view Reference)
        -> std::optional<std::string>
    {
        if (Reference == "secret/quic/password")
        {
            return std::string("quic-password");
        }
        return std::nullopt;
    };

    Preview::Application::Application Application(std::move(Options));
    const auto Result = Application.Start();

    ASSERT_TRUE(Result) << (Result ? "" : Result.error().Message);
    EXPECT_TRUE(Application.IsReady());
    EXPECT_TRUE(Result->QuicReady);
    EXPECT_TRUE(Result->QuicSocketReady);
    Application.Stop();
    EXPECT_EQ(Application.Run(), 0);
}
