/**
 * @file RestlsStartupTest.cpp
 * @brief Restls carrier 运行时注册启动测试。
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
                    ("PrismPreviewRestlsStartup-" +
                     std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()))),
              ConfigurationPath_(Root_ / "configuration.json")
        {
            std::filesystem::create_directories(Root_);
            Net::io_context Io;
            Tcp::acceptor Acceptor(Io, Tcp::endpoint(Tcp::v4(), 0));
            const auto Port = Acceptor.local_endpoint().port();

            std::ofstream File(ConfigurationPath_, std::ios::binary);
            File << R"json({
    "SchemaVersion": 1,
    "Runtime": {"WorkerCount": 1, "RequiredCapabilities": [], "SessionTimeout": 30000},
    "Listeners": {
        "Tcp": [{"Id":"tcp-main","Address":"127.0.0.1","Port":)json"
                 << Port << R"json(,"Timeout":5000}],
        "Udp": [], "Quic": [], "Timeout": 5000
    },
    "NativeTls": {"Enabled": false, "CertificateFile": "", "PrivateKeyFile": ""},
    "Builtins": [],
    "Protocols": [{"Id":"protocol-vless","Name":"vless","Builtin":"vless","Requires":[]}],
    "Carriers": [{
        "Id":"carrier-restls", "Name":"restls", "Builtin":"restls", "Requires":[],
        "Match":{"ServerNames":["www.example.com"],"Alpn":[],"Priority":10,"Fallback":false},
        "Options":{
            "Type":"Restls", "ServerNames":["www.example.com"],
            "Host":"www.example.com:443", "PasswordSecretRef":"secret/restls/password",
            "VersionHint":"tls13", "RestlsScript":"300?100<1", "HandshakeTimeoutMs":5000
        }
    }],
    "ProtocolBindings": [{
        "Id":"binding-vless-restls", "ProtocolId":"protocol-vless",
        "CarrierId":"carrier-restls", "TcpEnabled":true, "UdpEnabled":false,
        "MuxModes":[], "Priority":10, "Recognition":{}
    }],
    "Accounts": [{"Id":"local","SecretRef":"","Credential":"123e4567-e89b-12d3-a456-426614174000"}],
    "Routes": [],
    "Dns": {"Servers":["1.1.1.1"],"Timeout":1000},
    "Logging": {"Level":"Info","Directory":")json"
                 << Root_.generic_string() << R"json(","FileName":"restls-startup.log","Console":false},
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

TEST(PreviewApplication, StartsConfiguredRestlsCarrier)
{
    TemporaryConfiguration Configuration;
    Preview::Application::Options Options;
    Options.ConfigurationPath = Configuration.Path();
    Options.SecretResolver = [](const std::string_view Reference)
        -> std::optional<std::string>
    {
        if (Reference == "secret/restls/password")
        {
            return std::string("restls_password");
        }
        return std::nullopt;
    };

    Preview::Application::Application Application(std::move(Options));
    const auto Result = Application.Start();

    ASSERT_TRUE(Result) << (Result ? "" : Result.error().Message);
    EXPECT_TRUE(Application.IsReady());
    Application.Stop();
    EXPECT_EQ(Application.Run(), 0);
}
