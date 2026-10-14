/**
 * @file ApplicationNativeTlsTest.cpp
 * @brief 按功能拆分的 GoogleTest 行为契约。
 */

#include "ApplicationTestSupport.hpp"

#include <Preview/Application/BoundaryStartup.hpp>
#include <Preview/Application/Configuration/PreviewConfiguration.hpp>
#include <Preview/Protocols/Ech/Detail/Key.hpp>
#include <Preview/Protocols/Ech/ServerKeys.hpp>

#include <openssl/bio.h>
#include <openssl/ssl.h>

#include <cstdint>
#include <fstream>
#include <optional>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

TEST(PreviewApplication, ProtocolBindingRecognitionRoutesInnerProtocolBySni)
{
    const auto Repository = std::filesystem::path{PRISM_TEST_REPO_ROOT};
    const auto Certificate = (Repository / "cert.pem").generic_string();
    const auto PrivateKey = (Repository / "key.pem").generic_string();
    const auto Carriers = std::string(
        R"json([{"Id":"carrier-native","Name":"native","Builtin":"native","Requires":[],"Match":{"ServerNames":[],"Alpn":[],"Priority":0,"Fallback":true},"Options":{"Type":"NativeTls","CertificateFile":")json") +
        Certificate +
        R"json(","PrivateKeyFile":")json" + PrivateKey + R"json("}}])json";
    constexpr std::string_view Protocols = R"([
        {"Id":"protocol-http","Name":"http","Builtin":"http","Requires":[]},
        {"Id":"protocol-socks5","Name":"socks5","Builtin":"socks5","Requires":[]}
    ])";
    constexpr std::string_view Bindings = R"([
        {"Id":"binding-http","ProtocolId":"protocol-http","CarrierId":"carrier-native",
         "TcpEnabled":true,"UdpEnabled":false,"MuxModes":[],"Priority":100,
         "Recognition":{"Pattern":"http.example"}},
        {"Id":"binding-socks5","ProtocolId":"protocol-socks5","CarrierId":"carrier-native",
         "TcpEnabled":true,"UdpEnabled":false,"MuxModes":[],"Priority":0,
         "Recognition":{"Pattern":"socks.example"}}
    ])";
    const auto LogDirectory = std::filesystem::temp_directory_path() /
                              ("PrismPreviewProtocolSniRoute-" +
                               std::to_string(std::chrono::steady_clock::now()
                                                  .time_since_epoch()
                                                  .count()));
    const auto OperationsPort = FindFreePort();
    const auto TcpPort = FindFreePort();
    TemporaryConfiguration Configuration(
        TcpPort,
        ConfigurationShape{
            .Protocols = Protocols,
            .Carriers = Carriers,
            .Bindings = Bindings,
            .LoggingDirectory = LogDirectory.generic_string(),
            .LoggingFileName = "protocol-sni-route.log",
            .OperationsPort = OperationsPort});
    RunningApplication Application(Configuration.Path());
    ASSERT_TRUE(Application.Start());

    Net::io_context Io;
    Net::ssl::context ClientContext(Net::ssl::context::tls_client);
    ClientContext.set_verify_mode(Net::ssl::verify_none);
    Net::ssl::stream<Tcp::socket> Stream(Io, ClientContext);
    boost::system::error_code Error;
    Stream.lowest_layer().connect(
        Tcp::endpoint(Net::ip::address_v4::loopback(), Application.Port()), Error);
    ASSERT_FALSE(Error) << Error.message();
    ASSERT_EQ(SSL_set_tlsext_host_name(Stream.native_handle(), "socks.example"), 1);
    Stream.handshake(Net::ssl::stream_base::client, Error);
    ASSERT_FALSE(Error) << Error.message();

    constexpr std::array<std::uint8_t, 5> Greeting{0x05, 0x01, 0x02, '\r', '\n'};
    std::array<std::uint8_t, 2> Reply{};
    Net::write(Stream, Net::buffer(Greeting), Error);
    ASSERT_FALSE(Error) << Error.message();
    Net::read(Stream, Net::buffer(Reply), Error);
    ASSERT_FALSE(Error) << Error.message();
    EXPECT_EQ(Reply, (std::array<std::uint8_t, 2>{0x05, 0x02}));

    Stream.lowest_layer().close(Error);
    Application.Stop();
    EXPECT_EQ(Application.ExitCode(), 0);
}

TEST(PreviewApplication, NativeTlsSharedSniDispatchesInnerSocks5Protocol)
{
    const auto Repository = std::filesystem::path{PRISM_TEST_REPO_ROOT};
    const auto Certificate = (Repository / "cert.pem").generic_string();
    const auto PrivateKey = (Repository / "key.pem").generic_string();
    const auto Carriers = std::string(
        R"json([{"Id":"carrier-native","Name":"native","Builtin":"native","Requires":[],"Match":{"ServerNames":["shared.example"],"Alpn":[],"Priority":10,"Fallback":false},"Options":{"Type":"NativeTls","CertificateFile":")json") +
        Certificate +
        R"json(","PrivateKeyFile":")json" + PrivateKey + R"json("}}])json";
    constexpr std::string_view Protocols = R"([
        {"Id":"protocol-http","Name":"http","Builtin":"http","Requires":[]},
        {"Id":"protocol-socks5","Name":"socks5","Builtin":"socks5","Requires":[]}
    ])";
    constexpr std::string_view Bindings = R"([
        {"Id":"binding-http","ProtocolId":"protocol-http","CarrierId":"carrier-native",
         "TcpEnabled":true,"UdpEnabled":false,"MuxModes":[],"Priority":10,"Recognition":{}},
        {"Id":"binding-socks5","ProtocolId":"protocol-socks5","CarrierId":"carrier-native",
         "TcpEnabled":true,"UdpEnabled":false,"MuxModes":[],"Priority":10,"Recognition":{}}
    ])";
    TemporaryConfiguration Configuration(
        FindFreePort(),
        ConfigurationShape{.Protocols = Protocols,
                           .Carriers = Carriers,
                           .Bindings = Bindings,
                           .Credential = "PrismPreview-106-20260914"});
    RunningApplication Application(Configuration.Path());
    ASSERT_TRUE(Application.Start());

    Net::io_context Io;
    Net::ssl::context ClientContext(Net::ssl::context::tls_client);
    ClientContext.set_verify_mode(Net::ssl::verify_none);
    Net::ssl::stream<Tcp::socket> Stream(Io, ClientContext);
    boost::system::error_code Error;
    Stream.lowest_layer().connect(
        Tcp::endpoint(Net::ip::address_v4::loopback(), Application.Port()), Error);
    ASSERT_FALSE(Error) << Error.message();
    ASSERT_EQ(SSL_set_tlsext_host_name(Stream.native_handle(), "shared.example"), 1);
    Stream.handshake(Net::ssl::stream_base::client, Error);
    ASSERT_FALSE(Error) << Error.message();

    constexpr std::array<std::uint8_t, 3> Greeting{0x05, 0x01, 0x02};
    std::array<std::uint8_t, 2> Reply{};
    Net::write(Stream, Net::buffer(Greeting), Error);
    ASSERT_FALSE(Error) << Error.message();
    Net::read(Stream, Net::buffer(Reply), Error);
    ASSERT_FALSE(Error) << Error.message();
    EXPECT_EQ(Reply, (std::array<std::uint8_t, 2>{0x05, 0x02}));

    const std::string Password{"PrismPreview-106-20260914"};
    std::string Authentication("\x01\x05local", 7);
    Authentication.push_back(static_cast<char>(Password.size()));
    Authentication.append(Password);
    Net::write(Stream, Net::buffer(Authentication), Error);
    ASSERT_FALSE(Error) << Error.message();
    Net::read(Stream, Net::buffer(Reply), Error);
    ASSERT_FALSE(Error) << Error.message();
    EXPECT_EQ(Reply, (std::array<std::uint8_t, 2>{0x01, 0x00}));

    Stream.lowest_layer().close(Error);
    Application.Stop();
    EXPECT_EQ(Application.ExitCode(), 0);
}

TEST(PreviewApplication, GlobalNativeTlsRemainsFallbackForExplicitProtocolBindings)
{
    const auto Repository = std::filesystem::path{PRISM_TEST_REPO_ROOT};
    const auto Certificate = (Repository / "cert.pem").generic_string();
    const auto PrivateKey = (Repository / "key.pem").generic_string();
    const auto NativeTls = std::string("{\"Enabled\":true,\"CertificateFile\":\"") +
                           Certificate + "\",\"PrivateKeyFile\":\"" + PrivateKey + "\"}";
    const auto LogDirectory = std::filesystem::temp_directory_path() /
                              ("PrismPreviewNativeTlsFallback-" +
                               std::to_string(std::chrono::steady_clock::now()
                                                  .time_since_epoch()
                                                  .count()));
    const auto LogDirectoryText = LogDirectory.generic_string();
    constexpr std::string_view Bindings =
        R"([{"Id":"binding-socks5","ProtocolId":"protocol-socks5","TcpEnabled":true,"UdpEnabled":false,"MuxModes":[],"Priority":0,"Recognition":{}}])";
    TemporaryConfiguration Configuration(
        FindFreePort(),
        ConfigurationShape{.Bindings = Bindings,
                           .NativeTls = NativeTls,
                           .LoggingDirectory = LogDirectoryText,
                           .LoggingFileName = "native-fallback.log",
                           .LoggingRenderMode = "HumanWithFields"});
    RunningApplication Application(Configuration.Path());
    ASSERT_TRUE(Application.Start());

    Net::io_context Io;
    Net::ssl::context ClientContext(Net::ssl::context::tls_client);
    ClientContext.set_verify_mode(Net::ssl::verify_none);
    Net::ssl::stream<Tcp::socket> Stream(Io, ClientContext);
    boost::system::error_code Error;
    Stream.lowest_layer().connect(
        Tcp::endpoint(Net::ip::address_v4::loopback(), Application.Port()), Error);
    ASSERT_FALSE(Error);
    Stream.handshake(Net::ssl::stream_base::client, Error);
    EXPECT_FALSE(Error) << Error.message();
    const auto Method = Socks5AuthMethod(Stream);
    ASSERT_TRUE(Method.has_value());
    EXPECT_EQ(*Method, 0x02U);

    Stream.lowest_layer().close(Error);
    Application.Stop();
    EXPECT_EQ(Application.ExitCode(), 0);

    std::ifstream LogFile(LogDirectory / "native-fallback.log", std::ios::binary);
    std::stringstream LogContents;
    LogContents << LogFile.rdbuf();
    EXPECT_NE(LogContents.str().find("RecognitionAccepted Candidate=ProtocolSocks5"),
              std::string::npos);
    EXPECT_NE(LogContents.str().find("[Carrier=Native]"), std::string::npos)
        << LogContents.str();
    EXPECT_NE(LogContents.str().find("RecognitionDetails "),
              std::string::npos)
        << LogContents.str();
    EXPECT_NE(LogContents.str().find("[TlsVersion="), std::string::npos)
        << LogContents.str();
}

TEST(PreviewApplication, NativeTlsHandshakeFailureKeepsStructuredError)
{
    const auto Repository = std::filesystem::path{PRISM_TEST_REPO_ROOT};
    const auto Certificate = (Repository / "cert.pem").generic_string();
    const auto PrivateKey = (Repository / "key.pem").generic_string();
    const auto NativeTls = std::string("{\"Enabled\":true,\"CertificateFile\":\"") +
                           Certificate + "\",\"PrivateKeyFile\":\"" + PrivateKey + "\"}";
    const auto LogDirectory = std::filesystem::temp_directory_path() /
                              ("PrismPreviewNativeTlsFailure-" +
                               std::to_string(std::chrono::steady_clock::now()
                                                  .time_since_epoch()
                                                  .count()));
    const auto LogDirectoryText = LogDirectory.generic_string();
    constexpr std::string_view Bindings =
        R"([{"Id":"binding-socks5","ProtocolId":"protocol-socks5","TcpEnabled":true,"UdpEnabled":false,"MuxModes":[],"Priority":0,"Recognition":{}}])";
    TemporaryConfiguration Configuration(
        FindFreePort(),
        ConfigurationShape{.Bindings = Bindings,
                           .NativeTls = NativeTls,
                           .LoggingDirectory = LogDirectoryText,
                           .LoggingFileName = "native-tls-failure.log",
                           .LoggingRenderMode = "Structured"});
    std::string LogText;
    {
        RunningApplication Application(Configuration.Path());
        ASSERT_TRUE(Application.Start());

        Net::io_context Io;
        Tcp::socket Client(Io);
        boost::system::error_code Error;
        Client.connect(Tcp::endpoint(Net::ip::address_v4::loopback(), Application.Port()), Error);
        ASSERT_FALSE(Error) << Error.message();

        const auto ClientHello = MakeUnsupportedCipherClientHello();
        ASSERT_EQ(ClientHello.size(), 88U);
        Net::write(Client, Net::buffer(ClientHello), Error);
        ASSERT_FALSE(Error) << Error.message();

        std::array<std::uint8_t, 8> Alert{};
        std::size_t AlertBytes = 0;
        for (;;)
        {
            boost::system::error_code ReadError;
            const auto Read = Client.read_some(Net::buffer(Alert), ReadError);
            AlertBytes += Read;
            if (ReadError || Read == 0U)
            {
                break;
            }
        }
        EXPECT_GT(AlertBytes, 0U);
        Client.close(Error);
        Application.Stop();

        std::ifstream LogFile(LogDirectory / "native-tls-failure.log", std::ios::binary);
        std::stringstream LogContents;
        LogContents << LogFile.rdbuf();
        LogText = LogContents.str();
    }

    std::error_code CleanupError;
    std::filesystem::remove_all(LogDirectory, CleanupError);
    EXPECT_FALSE(CleanupError) << CleanupError.message();
    const auto FailureRecord = FindStructuredWarnRecord(LogText, "CarrierCommitFailed");
    ASSERT_TRUE(FailureRecord.has_value());
    EXPECT_EQ(FindStructuredString(*FailureRecord, "Level"), "Warn");
    EXPECT_NE(FindStructuredString(*FailureRecord, "Message").find("Outcome=TlsAlert"),
              std::string_view::npos);
    EXPECT_EQ(FindStructuredField(*FailureRecord, "Stage"), "CarrierCommit");
    EXPECT_EQ(FindStructuredField(*FailureRecord, "Status"), "TlsAlert");
    EXPECT_EQ(FindStructuredField(*FailureRecord, "FaultCode"), "TlsHsfail");
    EXPECT_FALSE(FindStructuredField(*FailureRecord, "NativeError").empty());
    EXPECT_EQ(FindStructuredField(*FailureRecord, "Carrier"), "Native");
    EXPECT_EQ(FindStructuredField(*FailureRecord, "Sni"), "example.com");
}

TEST(PreviewApplication, ConfiguredNativeTlsCarrierKeepsStructuredError)
{
    const auto Repository = std::filesystem::path{PRISM_TEST_REPO_ROOT};
    const auto Certificate = (Repository / "cert.pem").generic_string();
    const auto PrivateKey = (Repository / "key.pem").generic_string();
    const auto Carriers = std::string(
        R"json([{"Id":"carrier-native","Name":"native","Builtin":"native","Requires":[],"Match":{},"Options":{"Type":"NativeTls","CertificateFile":")json") +
        Certificate + R"json(","PrivateKeyFile":")json" + PrivateKey + R"json("}}])json";
    constexpr std::string_view Bindings =
        R"([{"Id":"binding-native","ProtocolId":"protocol-socks5","CarrierId":"carrier-native","TcpEnabled":true,"UdpEnabled":false,"MuxModes":[],"Priority":3,"Recognition":{}}])";
    const auto LogDirectory = std::filesystem::temp_directory_path() /
                              ("PrismPreviewNativeTlsCarrierFailure-" +
                               std::to_string(std::chrono::steady_clock::now()
                                                  .time_since_epoch()
                                                  .count()));
    const auto LogDirectoryText = LogDirectory.generic_string();
    auto OperationsPort = FindFreePort();
    const auto TcpPort = FindFreePort();
    while (OperationsPort == TcpPort)
    {
        OperationsPort = FindFreePort();
    }
    TemporaryConfiguration Configuration(
        TcpPort,
        ConfigurationShape{.Carriers = Carriers,
                           .Bindings = Bindings,
                           .LoggingDirectory = LogDirectoryText,
                           .LoggingFileName = "native-tls-carrier-failure.log",
                            .LoggingRenderMode = "Structured",
                           .OperationsPort = OperationsPort});
    std::string LogText;
    {
        RunningApplication Application(Configuration.Path());
        ASSERT_TRUE(Application.Start());

        Net::io_context Io;
        Tcp::socket Client(Io);
        boost::system::error_code Error;
        Client.connect(Tcp::endpoint(Net::ip::address_v4::loopback(), Application.Port()), Error);
        ASSERT_FALSE(Error) << Error.message();

        std::string OperationsResponse;
        bool SessionObserved = false;
        for (std::size_t Attempt = 0; Attempt < 100U; ++Attempt)
        {
            OperationsResponse = QueryOperationsSessions(OperationsPort);
            if (OperationsResponse.find("\"items\":[{") != std::string::npos)
            {
                SessionObserved = true;
                break;
            }
        }
        ASSERT_TRUE(SessionObserved) << OperationsResponse;

        const auto ClientHello = MakeUnsupportedCipherClientHello();
        ASSERT_EQ(ClientHello.size(), 88U);
        Net::write(Client, Net::buffer(ClientHello), Error);
        ASSERT_FALSE(Error) << Error.message();

        std::array<std::uint8_t, 8> Alert{};
        std::size_t AlertBytes = 0;
        for (;;)
        {
            boost::system::error_code ReadError;
            const auto Read = Client.read_some(Net::buffer(Alert), ReadError);
            AlertBytes += Read;
            if (ReadError || Read == 0U)
            {
                break;
            }
        }
        EXPECT_GT(AlertBytes, 0U);

        bool SessionDrained = false;
        for (std::size_t Attempt = 0; Attempt < 100U; ++Attempt)
        {
            OperationsResponse = QueryOperationsSessions(OperationsPort);
            if (OperationsResponse.find("\"items\":[]") != std::string::npos)
            {
                SessionDrained = true;
                break;
            }
        }
        ASSERT_TRUE(SessionDrained) << OperationsResponse;
        Client.close(Error);
        Application.Stop();

        std::ifstream LogFile(LogDirectory / "native-tls-carrier-failure.log", std::ios::binary);
        std::stringstream LogContents;
        LogContents << LogFile.rdbuf();
        LogText = LogContents.str();
    }

    std::error_code CleanupError;
    std::filesystem::remove_all(LogDirectory, CleanupError);
    EXPECT_FALSE(CleanupError) << CleanupError.message();
    const auto FailureRecord = FindStructuredWarnRecord(LogText, "CarrierCommitFailed");
    ASSERT_TRUE(FailureRecord.has_value());
    EXPECT_EQ(FindStructuredString(*FailureRecord, "Level"), "Warn");
    EXPECT_NE(FindStructuredString(*FailureRecord, "Message").find("Reason=TlsAlert"),
              std::string_view::npos);
    EXPECT_EQ(FindStructuredField(*FailureRecord, "Stage"), "CarrierCommit");
    EXPECT_EQ(FindStructuredField(*FailureRecord, "Status"), "TlsAlert");
    EXPECT_EQ(FindStructuredField(*FailureRecord, "FaultCode"), "TlsHsfail");
    EXPECT_FALSE(FindStructuredField(*FailureRecord, "NativeError").empty());
    EXPECT_EQ(FindStructuredField(*FailureRecord, "Carrier"), "Native");
    EXPECT_EQ(FindStructuredField(*FailureRecord, "Sni"), "example.com");
}

TEST(PreviewApplication, NativeTlsFallbackHandlesMultipleProtocolBindings)
{
    const auto Repository = std::filesystem::path{PRISM_TEST_REPO_ROOT};
    const auto Certificate = (Repository / "cert.pem").generic_string();
    const auto PrivateKey = (Repository / "key.pem").generic_string();
    const auto NativeTls = std::string("{\"Enabled\":true,\"CertificateFile\":\"") +
                           Certificate + "\",\"PrivateKeyFile\":\"" + PrivateKey + "\"}";
    const auto LogDirectory = std::filesystem::temp_directory_path() /
                              ("PrismPreviewNativeTlsMultiProtocol-" +
                               std::to_string(std::chrono::steady_clock::now()
                                                  .time_since_epoch()
                                                  .count()));
    const auto LogDirectoryText = LogDirectory.generic_string();
    constexpr std::string_view Bindings = R"([{"Id":"binding-http","ProtocolId":"protocol-http","TcpEnabled":true,"UdpEnabled":false,"MuxModes":[],"Priority":0,"Recognition":{}},{"Id":"binding-socks5","ProtocolId":"protocol-socks5","TcpEnabled":true,"UdpEnabled":false,"MuxModes":[],"Priority":0,"Recognition":{}}])";
    ConfigurationShape Shape{
        .Protocols = ValidMixedTcpProtocols,
        .Bindings = Bindings,
        .NativeTls = NativeTls,
        .LoggingDirectory = LogDirectoryText,
        .LoggingFileName = "native-multi-protocol.log"};
    const auto TcpPort = FindFreePort();
    do
    {
        Shape.OperationsPort = FindFreePort();
    } while (Shape.OperationsPort == TcpPort);
    TemporaryConfiguration Configuration(TcpPort, Shape);
    Preview::Application::Application Application(MakeOptions(Configuration.Path()));
    const auto Started = Application.Start();
    ASSERT_TRUE(Started)
        << (Started ? std::string{} : Started.error().Path + ": " + Started.error().Message);
    std::atomic<int> ExitCode{-1};
    std::thread Thread([&]
                       { ExitCode.store(Application.Run(), std::memory_order_release); });

    Net::io_context Io;
    Net::ssl::context ClientContext(Net::ssl::context::tls_client);
    ClientContext.set_verify_mode(Net::ssl::verify_none);
    Net::ssl::stream<Tcp::socket> Stream(Io, ClientContext);
    boost::system::error_code Error;
    Stream.lowest_layer().connect(
        Tcp::endpoint(Net::ip::address_v4::loopback(), Started->Port), Error);
    ASSERT_FALSE(Error);
    Stream.handshake(Net::ssl::stream_base::client, Error);
    EXPECT_FALSE(Error) << Error.message();
    const auto Method = Socks5AuthMethod(Stream);
    ASSERT_TRUE(Method.has_value());
    EXPECT_EQ(*Method, 0x02U);

    Stream.lowest_layer().close(Error);

    Tcp::socket Plain(Io);
    Plain.connect(Tcp::endpoint(Net::ip::address_v4::loopback(), Started->Port), Error);
    ASSERT_FALSE(Error);
    const auto PlainMethod = Socks5AuthMethod(Plain);
    ASSERT_TRUE(PlainMethod.has_value());
    EXPECT_EQ(*PlainMethod, 0x02U);
    Plain.close(Error);

    Application.Stop();
    Thread.join();
    EXPECT_EQ(ExitCode.load(std::memory_order_acquire), 0);
}

namespace
{
    /** @brief 为应用 TLS context 准备文件路径相对配置目录的短生命周期 ECH 密钥材料。 */
    struct TemporaryNativeEchFiles final
    {
        /** @brief 创建隔离的临时目录。 */
        TemporaryNativeEchFiles()
        {
            Directory = std::filesystem::temp_directory_path() /
                ("PrismPreviewNativeEch-" + std::to_string(
                    std::chrono::steady_clock::now().time_since_epoch().count()));
            std::error_code Error;
            Created = std::filesystem::create_directory(Directory, Error) && !Error;
        }

        /** @brief 释放本测试创建的临时文件。 */
        ~TemporaryNativeEchFiles()
        {
            std::error_code Error;
            if (Created) std::filesystem::remove_all(Directory, Error);
        }

        /** @brief 写出 BoringSSL 所需的原始私钥与单个序列化 ECHConfig。 */
        [[nodiscard]] auto Write(const Preview::Ech::Detail::EchKeypair& Keypair) const -> bool
        {
            std::ofstream Key(Directory / "server.key", std::ios::binary);
            std::ofstream Config(Directory / "server.ech", std::ios::binary);
            if (!Key || !Config) return false;
            Key.write(reinterpret_cast<const char*>(Keypair.PrivateKey.data()),
                      static_cast<std::streamsize>(Keypair.PrivateKey.size()));
            Config.write(reinterpret_cast<const char*>(Keypair.EchConfig.data()),
                         static_cast<std::streamsize>(Keypair.EchConfig.size()));
            return Key.good() && Config.good();
        }

        std::filesystem::path Directory;
        bool Created{false};
    };

    /** @brief BIO-pair ECH 握手后观察服务端 BoringSSL 的 inner SNI 与接受标记。 */
    struct NativeEchObservation final
    {
        bool EchAccepted{false};
        std::string ServerName;
    };

    /** @brief 推进一端 BIO-pair TLS 握手，并接受 Asio 非阻塞握手的 WANT 状态。 */
    [[nodiscard]] auto ProgressNativeEchHandshake(SSL* Connection, bool& Complete) -> bool
    {
        const auto Result = SSL_do_handshake(Connection);
        if (Result == 1)
        {
            Complete = true;
            return true;
        }
        const auto Error = SSL_get_error(Connection, Result);
        return Error == SSL_ERROR_WANT_READ || Error == SSL_ERROR_WANT_WRITE;
    }

    /** @brief 用应用启动生成的 SSL_CTX 完成真正的 BoringSSL ECH 握手。 */
    [[nodiscard]] auto RunNativeEchHandshake(
        SSL_CTX* ServerContext,
        const std::vector<std::uint8_t>& EchConfigList,
        const bool SendGrease = false) -> std::optional<NativeEchObservation>
    {
        SSL_CTX* ClientContext = SSL_CTX_new(TLS_method());
        if (!ClientContext) return std::nullopt;
        SSL* Client = SSL_new(ClientContext);
        SSL* Server = SSL_new(ServerContext);
        if (!Client || !Server ||
            SSL_set_tlsext_host_name(Client, SendGrease ? "outer.example" : "secret.example") != 1)
        {
            SSL_free(Client);
            SSL_free(Server);
            SSL_CTX_free(ClientContext);
            return std::nullopt;
        }
        if (SendGrease)
        {
            SSL_set_enable_ech_grease(Client, 1);
        }
        else if (SSL_set1_ech_config_list(Client, EchConfigList.data(), EchConfigList.size()) != 1)
        {
            SSL_free(Client);
            SSL_free(Server);
            SSL_CTX_free(ClientContext);
            return std::nullopt;
        }
        BIO* ClientBio = nullptr;
        BIO* ServerBio = nullptr;
        if (BIO_new_bio_pair(&ClientBio, 4096, &ServerBio, 4096) != 1)
        {
            BIO_free(ClientBio);
            BIO_free(ServerBio);
            SSL_free(Client);
            SSL_free(Server);
            SSL_CTX_free(ClientContext);
            return std::nullopt;
        }
        SSL_set_bio(Client, ClientBio, ClientBio);
        SSL_set_bio(Server, ServerBio, ServerBio);
        SSL_set_connect_state(Client);
        SSL_set_accept_state(Server);
        bool ClientComplete = false;
        bool ServerComplete = false;
        for (std::size_t Attempt = 0; Attempt < 128 && (!ClientComplete || !ServerComplete); ++Attempt)
        {
            if (!ClientComplete && !ProgressNativeEchHandshake(Client, ClientComplete)) break;
            if (!ServerComplete && !ProgressNativeEchHandshake(Server, ServerComplete)) break;
        }
        std::optional<NativeEchObservation> Result;
        if (ClientComplete && ServerComplete)
        {
            NativeEchObservation Observation;
            Observation.EchAccepted = SSL_ech_accepted(Server) == 1;
            if (const auto* ServerName = SSL_get_servername(Server, TLSEXT_NAMETYPE_host_name))
                Observation.ServerName = ServerName;
            Result = std::move(Observation);
        }
        SSL_free(Client);
        SSL_free(Server);
        SSL_CTX_free(ClientContext);
        return Result;
    }
}

TEST(PreviewApplication, NativeTlsStartupInstallsEchAndDecryptsInnerClientHello)
{
    Preview::Ech::Detail::EchKeypair Keypair;
    ASSERT_EQ(Preview::Ech::Detail::GenerateKeypair("public.example", 32, Keypair),
              Preview::Fault::Code::Success);
    TemporaryNativeEchFiles Files;
    ASSERT_TRUE(Files.Created);
    ASSERT_TRUE(Files.Write(Keypair));

    const auto Repository = std::filesystem::path{PRISM_TEST_REPO_ROOT};
    auto Configuration = Preview::Application::Configuration::PreviewConfiguration::Defaults();
    Configuration.NativeTls.Enabled = true;
    Configuration.NativeTls.CertificateFile = (Repository / "cert.pem").generic_string();
    Configuration.NativeTls.PrivateKeyFile = (Repository / "key.pem").generic_string();
    Configuration.NativeTls.Ech.Enabled = true;
    Configuration.NativeTls.Ech.PrivateKeyFile = "server.key";
    Configuration.NativeTls.Ech.EchConfigFile = "server.ech";
    const auto Context = Preview::Application::BoundaryStartup::MakeNativeTlsContext(
        Configuration, Files.Directory / "preview.json");
    ASSERT_TRUE(Context.has_value()) << Context.error().Message;

    const auto Handshake = RunNativeEchHandshake(
        (*Context)->native_handle(), Keypair.EchConfigList);
    ASSERT_TRUE(Handshake.has_value());
    EXPECT_TRUE(Handshake->EchAccepted);
    EXPECT_EQ(Handshake->ServerName, "secret.example");

    const auto Grease = RunNativeEchHandshake((*Context)->native_handle(), Keypair.EchConfigList, true);
    ASSERT_TRUE(Grease.has_value());
    EXPECT_FALSE(Grease->EchAccepted);
    EXPECT_EQ(Grease->ServerName, "outer.example");
}



