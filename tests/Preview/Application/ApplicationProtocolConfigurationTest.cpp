/**
 * @file ApplicationProtocolConfigurationTest.cpp
 * @brief 按功能拆分的 GoogleTest 行为契约。
 */

#include "ApplicationTestSupport.hpp"
#include <TestSupport/Preview/ProtocolIngressBindings.hpp>

TEST(PreviewApplication, AcceptsConfiguredSocks5Protocol)
{
    TemporaryConfiguration Configuration(19084);
    RunningApplication Application(Configuration.Path());

    ASSERT_TRUE(Application.Start());
    EXPECT_EQ(Application.Port(), 19084U);
    Application.Stop();
    EXPECT_EQ(Application.ExitCode(), 0);
}

TEST(PreviewApplication, SelectsConfiguredTcpProtocolFactory)
{
    struct ProtocolCase final
    {
        std::string_view Protocols;
        std::string_view Credential;
    };

    constexpr std::array Cases{
        ProtocolCase{ValidHttpProtocol, "local-token"},
        ProtocolCase{ValidSocks5Protocol, "local-token"},
        ProtocolCase{ValidVlessProtocol, VmessUuid},
        ProtocolCase{ValidTrojanProtocol, "local-token"},
        ProtocolCase{ValidVmessProtocol, VmessUuid},
        ProtocolCase{ValidShadowsocks2022Protocol, Shadowsocks2022Psk},
    };

    for (const auto &Case : Cases)
    {
        SCOPED_TRACE(Case.Protocols);
        TemporaryConfiguration Configuration(
            FindFreePort(), ConfigurationShape{.Protocols = Case.Protocols,
                                                .Credential = Case.Credential});
        RunningApplication Application(Configuration.Path());

        ASSERT_TRUE(Application.Start());
        Application.Stop();
        EXPECT_EQ(Application.ExitCode(), 0);
    }
}

TEST(PreviewApplication, StartsConfiguredAnyTlsProtocol)
{
    const auto Repository = std::filesystem::path{PRISM_TEST_REPO_ROOT};
    const auto Certificate = (Repository / "cert.pem").generic_string();
    const auto PrivateKey = (Repository / "key.pem").generic_string();
    const auto NativeTls = std::string("{\"Enabled\":true,\"CertificateFile\":\"") +
                           Certificate + "\",\"PrivateKeyFile\":\"" + PrivateKey + "\"}";
    TemporaryConfiguration Configuration(
        FindFreePort(),
        ConfigurationShape{.Protocols = ValidAnyTlsProtocol,
                           .NativeTls = NativeTls,
                           .Credential = "anytls-application-password"});
    RunningApplication Application(Configuration.Path());

    ASSERT_TRUE(Application.Start());
    EXPECT_NE(Application.Port(), 0U);
    Application.Stop();
    EXPECT_EQ(Application.ExitCode(), 0);
}

TEST(PreviewApplication, RejectsBareAnyTlsWithoutNativeTls)
{
    TemporaryConfiguration Configuration(
        FindFreePort(),
        ConfigurationShape{.Protocols = ValidAnyTlsProtocol,
                           .Credential = "anytls-application-password"});
    Preview::Application::Application Application(MakeOptions(Configuration.Path()));

    const auto Result = Application.Start();

    ASSERT_FALSE(Result);
    EXPECT_FALSE(Application.IsReady());
    EXPECT_EQ(Result.error().Code,
              Preview::Application::StartupErrorCode::UnsupportedService);
    EXPECT_EQ(Result.error().Path, "Protocols[0]");
    EXPECT_NE(Result.error().Message.find("NativeTls"), std::string::npos);
}

TEST(PreviewApplication, ConstructsNonSocks5ProtocolHandlers)
{
    const auto Http = Preview::Composition::Recognition::CandidateFactory::MakeHttp(
        {}, Preview::Testing::MakeHttp1Binding());
    EXPECT_EQ(Http.Spec.Name, "http");
    EXPECT_TRUE(Http.Accept);
    EXPECT_TRUE(Preview::Testing::MakeVlessIngress(Preview::Vless::ServerConfig{},
        Preview::Testing::ProtocolIngressResources{{}, Preview::Testing::MakeProtocolIngressUseState(),
            boost::asio::system_executor()}, Preview::Vless::IngressRoute{}));
    EXPECT_TRUE(Preview::Testing::MakeTrojanIngress(Preview::Trojan::ServerConfig{},
        Preview::Testing::ProtocolIngressResources{{}, Preview::Testing::MakeProtocolIngressUseState(),
            boost::asio::system_executor()}, Preview::Trojan::IngressRoute{}));
    EXPECT_TRUE(Preview::Testing::MakeVmessIngress(Preview::Vmess::ServerConfig{},
        Preview::Testing::VmessIngressResources{{}, {}, {}, Preview::Testing::MakeProtocolIngressUseState(),
            boost::asio::system_executor()}, Preview::Vmess::IngressRoute{}));
    Net::io_context BindingIo;
    const auto Config = Preview::Shadowsocks2022::ServerConfig{Preview::Testing::Ss2022FixturePsk};
    const auto Pin = Preview::Testing::ProviderPin();
    const auto Key = Config.Psk;
    const std::string Bytes(reinterpret_cast<const char *>(Key.data()), Key.size());
    auto Directory = Preview::Testing::ProviderAccount(
        Preview::Account::Credential::Psk(Bytes));
    auto Auth = Directory->Authenticator;
    auto Prepared = Preview::Shadowsocks2022::Prepare(
        {"fixture", Pin, {.TimeWindow = Config.TimeWindow}},
        {BindingIo.get_executor(), {Pin, Directory->Credentials, Auth}, {}, {}, {}});
    ASSERT_TRUE(Prepared);
    auto Bound = Preview::Shadowsocks2022::Bind(std::move(*Prepared), {});
    ASSERT_TRUE(Bound);
    auto SsBinding = std::move(*Bound);
    ASSERT_TRUE(SsBinding);
    EXPECT_FALSE(*Bound);
    const std::weak_ptr<Preview::Shadowsocks2022::Binding> Weak = SsBinding;

    // 测试自有 executor 必须由 Drain 驱动到完成后再释放唯一 owner。
    SsBinding->Close();
    bool DrainCompleted = false;
    bool DrainSucceeded = false;
    std::exception_ptr DrainFailure;
    Net::co_spawn(BindingIo, SsBinding->Drain(),
                  [&](std::exception_ptr Error,
                      std::expected<void, Preview::Fault::Failure> Result)
                  {
                      DrainFailure = std::move(Error);
                      DrainSucceeded = !DrainFailure && static_cast<bool>(Result);
                      DrainCompleted = true;
                  });
    BindingIo.run();
    ASSERT_TRUE(DrainCompleted);
    EXPECT_TRUE(DrainSucceeded);
    EXPECT_EQ(DrainFailure, nullptr);
    SsBinding.reset();
    EXPECT_TRUE(Weak.expired());
}

TEST(PreviewApplication, RejectsZeroConfiguredProtocols)
{
    TemporaryConfiguration Configuration(
        FindFreePort(), ConfigurationShape{.Protocols = "[]"});
    Preview::Application::Application Application(MakeOptions(Configuration.Path()));

    const auto Result = Application.Start();

    ASSERT_FALSE(Result);
    EXPECT_FALSE(Application.IsReady());
    EXPECT_EQ(Result.error().Code,
              Preview::Application::StartupErrorCode::InvalidConfiguration);
}

TEST(PreviewApplication, RejectsUnsupportedTcpProtocol)
{
    TemporaryConfiguration Configuration(
        FindFreePort(),
        ConfigurationShape{
            .Protocols = R"([{"Id":"protocol-hysteria2","Name":"hysteria2","Builtin":"hysteria2","Requires":[],"Quic":{"Alpn":"h3","ServerName":"quic.example","CredentialSecretRef":"secret/quic/password","MaxStreams":32,"MaxDatagrams":64}}])",
            .Quic = R"([{"Id":"quic-main","Address":"127.0.0.1","Port":19086,"Timeout":5000}])"});
    auto Options = MakeOptions(Configuration.Path());
    Options.SecretResolver = [](const std::string_view Reference) -> std::optional<std::string>
    {
        if (Reference == "secret/quic/password")
        {
            return std::string("quic-password");
        }
        return std::nullopt;
    };
    Preview::Application::Application Application(std::move(Options));

    const auto Result = Application.Start();

    ASSERT_FALSE(Result);
    EXPECT_FALSE(Application.IsReady());
    EXPECT_EQ(Result.error().Code,
              Preview::Application::StartupErrorCode::UnsupportedService);
}

TEST(PreviewApplication, RejectsTuicProtocolUntilQuicFrontIsWired)
{
    TemporaryConfiguration Configuration(
        FindFreePort(),
        ConfigurationShape{
            .Protocols = R"([{"Id":"protocol-tuic","Name":"tuic","Builtin":"tuic","Requires":[],"Quic":{"Alpn":"h3","ServerName":"quic.example","CredentialSecretRef":"secret/quic/password","MaxStreams":32,"MaxDatagrams":64,"Uuid":"123e4567-e89b-12d3-a456-426614174000"}}])",
            .Quic = R"([{"Id":"quic-main","Address":"127.0.0.1","Port":19087,"Timeout":5000}])"});
    auto Options = MakeOptions(Configuration.Path());
    Options.SecretResolver = [](const std::string_view Reference) -> std::optional<std::string>
    {
        if (Reference == "secret/quic/password")
        {
            return std::string("quic-password");
        }
        return std::nullopt;
    };
    Preview::Application::Application Application(std::move(Options));

    const auto Result = Application.Start();

    ASSERT_FALSE(Result);
    EXPECT_FALSE(Application.IsReady());
    EXPECT_EQ(Result.error().Code,
              Preview::Application::StartupErrorCode::UnsupportedService);
}

TEST(PreviewApplication, RejectsMismatchedProtocolBuiltin)
{
    TemporaryConfiguration Configuration(
        FindFreePort(),
        ConfigurationShape{
            .Protocols = R"([{"Id":"protocol-http","Name":"http","Builtin":"socks5","Requires":[]}])"});
    Preview::Application::Application Application(MakeOptions(Configuration.Path()));

    const auto Result = Application.Start();

    ASSERT_FALSE(Result);
    EXPECT_EQ(Result.error().Code,
              Preview::Application::StartupErrorCode::UnsupportedService);
}

TEST(PreviewApplication, RejectsStaticBuiltinWithoutRuntimeCallback)
{
    constexpr std::string_view Builtins =
        R"([{"Id":"builtin-socks5","Kind":"protocol","Name":"socks5","Requires":[],"Provides":[]}])";
    const auto LoggingDirectory = std::filesystem::temp_directory_path() /
                                  ("PrismPreviewBuiltinCallback-" +
                                   std::to_string(std::chrono::steady_clock::now()
                                                      .time_since_epoch()
                                                      .count()));
    TemporaryConfiguration Configuration(
        FindFreePort(),
        ConfigurationShape{.Builtins = Builtins,
                           .LoggingDirectory = LoggingDirectory.generic_string()});
    Preview::Application::Application Application(MakeOptions(Configuration.Path()));

    const auto Result = Application.Start();

    ASSERT_FALSE(Result);
    EXPECT_FALSE(Application.IsReady());
    EXPECT_EQ(Result.error().Code,
              Preview::Application::StartupErrorCode::UnsupportedService);
    EXPECT_EQ(Result.error().Path, "Builtins.builtin-socks5");
    EXPECT_NE(Result.error().Message.find("callback"), std::string::npos);
}

TEST(PreviewApplication, RejectsInvalidVlessCredentialMaterial)
{
    TemporaryConfiguration Configuration(
        FindFreePort(), ConfigurationShape{.Protocols = ValidVlessProtocol});
    Preview::Application::Application Application(MakeOptions(Configuration.Path()));

    const auto Result = Application.Start();

    ASSERT_FALSE(Result);
    EXPECT_EQ(Result.error().Code,
              Preview::Application::StartupErrorCode::InvalidConfiguration);
}

TEST(PreviewApplication, RejectsInvalidShadowsocks2022CredentialMaterial)
{
    TemporaryConfiguration Configuration(
        FindFreePort(), ConfigurationShape{.Protocols = ValidShadowsocks2022Protocol});
    Preview::Application::Application Application(MakeOptions(Configuration.Path()));

    const auto Result = Application.Start();

    ASSERT_FALSE(Result);
    EXPECT_EQ(Result.error().Code,
              Preview::Application::StartupErrorCode::InvalidConfiguration);
}

TEST(PreviewApplication, StartsMixedTrialForConfiguredTcpProtocols)
{
    TemporaryConfiguration Configuration(
        FindFreePort(),
        ConfigurationShape{
            .Protocols = ValidMixedTcpProtocols});
    RunningApplication Application(Configuration.Path());

    ASSERT_TRUE(Application.Start());
    EXPECT_NE(Application.Port(), 0U);
    Application.Stop();
    EXPECT_EQ(Application.ExitCode(), 0);
}

TEST(PreviewApplication, StartsConfiguredUdpFront)
{
    TemporaryConfiguration Configuration(
        FindFreePort(),
        ConfigurationShape{
            .Udp = R"([{"Id":"udp-main","Address":"127.0.0.1","Port":19090,"Timeout":5000}])"});
    Preview::Application::Application Application(MakeOptions(Configuration.Path()));

    const auto Result = Application.Start();

    ASSERT_TRUE(Result);
    EXPECT_EQ(Result->UdpPort, 19090U);
    EXPECT_TRUE(Result->UdpReady);
    EXPECT_FALSE(Result->QuicReady);
    Application.Stop();
    EXPECT_EQ(Application.Run(), 0);
}

TEST(PreviewApplication, StartsConfiguredQuicFrontWithHandshakePending)
{
    TemporaryConfiguration Configuration(
        FindFreePort(),
        ConfigurationShape{
            .Quic = R"([{"Id":"quic-main","Address":"127.0.0.1","Port":19091,"Timeout":5000}])"});
    Preview::Application::Application Application(MakeOptions(Configuration.Path()));

    const auto Result = Application.Start();

    ASSERT_TRUE(Result);
    EXPECT_EQ(Result->UdpPort, 19091U);
    EXPECT_TRUE(Result->UdpReady);
    EXPECT_FALSE(Result->QuicReady);
    Application.Stop();
    EXPECT_EQ(Application.Run(), 0);
}

TEST(PreviewApplication, PublishesQuicReadyAfterAdmissionContextsAreBuilt)
{
    const auto Repository = std::filesystem::path{PRISM_TEST_REPO_ROOT};
    const auto Certificate = (Repository / "cert.pem").generic_string();
    const auto PrivateKey = (Repository / "key.pem").generic_string();
    const auto NativeTls = std::string("{\"Enabled\":true,\"CertificateFile\":\"") +
                           Certificate + "\",\"PrivateKeyFile\":\"" + PrivateKey + "\"}";
    TemporaryConfiguration Configuration(
        FindFreePort(),
        ConfigurationShape{
            .Protocols = R"([{"Id":"protocol-socks5","Name":"socks5","Builtin":"socks5","Requires":[]},{"Id":"protocol-hysteria2","Name":"hysteria2","Builtin":"hysteria2","Requires":[],"Quic":{"Alpn":"h3","ServerName":"quic.example","CredentialSecretRef":"secret/quic/password","MaxStreams":32,"MaxDatagrams":64}}])",
            .Quic = R"([{"Id":"quic-main","Address":"127.0.0.1","Port":19092,"Timeout":5000}])",
            .NativeTls = NativeTls,
            .Credentials = R"({"hysteria2":"quic-password"})"});
    auto Options = MakeOptions(Configuration.Path());
    Options.SecretResolver = [](const std::string_view Reference) -> std::optional<std::string>
    {
        if (Reference == "secret/quic/password")
        {
            return std::string("quic-password");
        }
        return std::nullopt;
    };
    Preview::Application::Application Application(std::move(Options));

    const auto Result = Application.Start();

    ASSERT_TRUE(Result);
    EXPECT_EQ(Result->UdpPort, 19092U);
    EXPECT_TRUE(Result->UdpReady);
    EXPECT_TRUE(Result->QuicReady);
    Application.Stop();
    EXPECT_EQ(Application.Run(), 0);
}

TEST(PreviewApplication, StartsConfiguredNativeCarrier)
{
    const auto Repository = std::filesystem::path{PRISM_TEST_REPO_ROOT};
    const auto Certificate = (Repository / "cert.pem").generic_string();
    const auto PrivateKey = (Repository / "key.pem").generic_string();
    const auto Carriers = std::string(
        R"json([{"Id":"carrier-native","Name":"native","Builtin":"native","Requires":[],"Match":{"ServerNames":["example.com"],"Alpn":["h2"],"Priority":4,"Fallback":false},"Options":{"Type":"NativeTls","CertificateFile":")json") +
        Certificate +
        R"json(","PrivateKeyFile":")json" + PrivateKey + R"json("}}])json";
    constexpr std::string_view Bindings =
        R"([{"Id":"binding-native","ProtocolId":"protocol-socks5","CarrierId":"carrier-native","TcpEnabled":true,"UdpEnabled":false,"MuxModes":[],"Priority":3,"Recognition":{}}])";
    const auto LogDirectory = std::filesystem::temp_directory_path() /
                              ("PrismPreviewNativeCarrierSuccess-" +
                               std::to_string(std::chrono::steady_clock::now()
                                                  .time_since_epoch()
                                                  .count()));
    const auto LogDirectoryText = LogDirectory.generic_string();
    const auto TcpPort = FindFreePort();
    auto OperationsPort = FindFreePort();
    while (OperationsPort == TcpPort)
    {
        OperationsPort = FindFreePort();
    }
    TemporaryConfiguration Configuration(
        TcpPort,
        ConfigurationShape{
            .Carriers = Carriers,
            .Bindings = Bindings,
            .LoggingDirectory = LogDirectoryText,
            .LoggingFileName = "native-carrier-success.log",
            .LoggingRenderMode = "HumanWithFields",
            .OperationsPort = OperationsPort});
    std::string LogContents;
    {
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
        ASSERT_EQ(SSL_set_tlsext_host_name(Stream.native_handle(), "example.com"), 1);
        constexpr std::array<unsigned char, 3> Alpn{2U, 'h', '2'};
        ASSERT_EQ(SSL_set_alpn_protos(
                      Stream.native_handle(), Alpn.data(), static_cast<unsigned int>(Alpn.size())),
                  0);
        Stream.handshake(Net::ssl::stream_base::client, Error);
        ASSERT_FALSE(Error) << Error.message();
        const auto Method = Socks5AuthMethod(Stream);
        ASSERT_TRUE(Method.has_value());
        EXPECT_EQ(*Method, 0x02U);
        Stream.lowest_layer().close(Error);

        Application.Stop();
        EXPECT_EQ(Application.ExitCode(), 0);
        std::ifstream LogFile(LogDirectory / "native-carrier-success.log", std::ios::binary);
        std::stringstream Contents;
        Contents << LogFile.rdbuf();
        LogContents = Contents.str();
    }

    std::error_code CleanupError;
    std::filesystem::remove_all(LogDirectory, CleanupError);
    EXPECT_FALSE(CleanupError) << CleanupError.message();
    EXPECT_NE(LogContents.find("[Carrier=Native]"), std::string::npos) << LogContents;
    EXPECT_NE(LogContents.find("[Sni=example.com]"), std::string::npos) << LogContents;
    EXPECT_NE(LogContents.find("[TlsVersion="), std::string::npos) << LogContents;
}



