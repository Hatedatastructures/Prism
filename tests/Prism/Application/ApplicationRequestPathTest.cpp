/**
 * @file ApplicationRequestPathTest.cpp
 * @brief 按功能拆分的 GoogleTest 行为契约。
 */

#include "ApplicationTestSupport.hpp"

namespace
{
    /**
     * @brief 在借用的 socket 上交换一个域名目标的 SOCKS5 CONNECT 请求和回复。
     * @details Target 只借用到同步返回；I/O 失败返回 false，成功时输出 Reply。
     *          本操作不半关闭或最终关闭 socket，最终关闭者是调用测试。
     */
    [[nodiscard]] auto Socks5ConnectDomain(Tcp::socket &Socket,
        const Prism::Socks5::Address &Target, std::uint8_t &Reply) -> bool
    {
        std::string Request("\x05\x01\x00\x03", 4);
        Request.push_back(static_cast<char>(Target.Host.size()));
        Request.append(Target.Host);
        Request.push_back(static_cast<char>((Target.Port >> 8U) & 0xffU));
        Request.push_back(static_cast<char>(Target.Port & 0xffU));
        return WriteBytes(Socket, Request) && ReadSocks5Reply(Socket, Reply);
    }
}

TEST(PrismApplication, BindingMuxModeDoesNotPromoteSiblingBinding)
{
    constexpr std::string_view Protocols = R"([
        {"Id":"protocol-vless","Name":"vless","Builtin":"vless","Requires":[]},
        {"Id":"protocol-socks5","Name":"socks5","Builtin":"socks5","Requires":[]}
    ])";
    constexpr std::string_view Bindings = R"([
        {"Id":"binding-vless-mux","ProtocolId":"protocol-vless",
         "TcpEnabled":true,"UdpEnabled":false,"MuxModes":["Smux"],"Priority":0,"Recognition":{}},
        {"Id":"binding-socks5-plain","ProtocolId":"protocol-socks5",
         "TcpEnabled":true,"UdpEnabled":false,"MuxModes":[],"Priority":0,"Recognition":{}}
    ])";
    TemporaryConfiguration Configuration(
        FindFreePort(),
        ConfigurationShape{.Protocols = Protocols,
                           .Bindings = Bindings,
                           .Credential = "socks5-sibling-password",
                           .Credentials = R"({"Vless":"123e4567-e89b-12d3-a456-426614174000"})"});
    RunningApplication Application(Configuration.Path());
    ASSERT_TRUE(Application.Start());

    Net::io_context Io;
    Tcp::socket Socket(Io);
    boost::system::error_code Error;
    Socket.connect(
        Tcp::endpoint(Net::ip::address_v4::loopback(), Application.Port()), Error);
    ASSERT_FALSE(Error) << Error.message();

    std::uint8_t Status = 0xff;
    ASSERT_TRUE(Authenticate(Socket, "socks5-sibling-password", Status));
    EXPECT_EQ(Status, 0x00U);

    Socket.close(Error);
    Application.Stop();
    EXPECT_EQ(Application.ExitCode(), 0);
}

TEST(PrismApplication, RejectsGenericMuxOnAnyTlsBinding)
{
    const auto Repository = std::filesystem::path{PRISM_TEST_REPO_ROOT};
    const auto Certificate = (Repository / "cert.pem").generic_string();
    const auto PrivateKey = (Repository / "key.pem").generic_string();
    const auto NativeTls = std::string("{\"Enabled\":true,\"CertificateFile\":\"") +
                           Certificate + "\",\"PrivateKeyFile\":\"" + PrivateKey + "\"}";
    const auto Carriers = std::string(
        R"json([{"Id":"carrier-anytls","Name":"native-anytls","Builtin":"native","Requires":[],"Match":{"ServerNames":["anytls.example"],"Alpn":[],"Priority":20,"Fallback":false},"Options":{"Type":"NativeTls","CertificateFile":")json") +
        Certificate +
        R"json(","PrivateKeyFile":")json" + PrivateKey + R"json("}}])json";
    constexpr std::string_view Protocols = R"([
        {"Id":"protocol-anytls","Name":"anytls","Builtin":"anytls","Requires":[]},
        {"Id":"protocol-socks5","Name":"socks5","Builtin":"socks5","Requires":[]}
    ])";
    constexpr std::string_view Bindings = R"([
        {"Id":"binding-anytls","ProtocolId":"protocol-anytls","CarrierId":"carrier-anytls",
         "TcpEnabled":true,"UdpEnabled":false,"MuxModes":["Smux"],"Priority":20,
         "Recognition":{"Pattern":"anytls.example"}},
        {"Id":"binding-socks5-plain","ProtocolId":"protocol-socks5",
         "TcpEnabled":true,"UdpEnabled":false,"MuxModes":[],"Priority":0,"Recognition":{}}
    ])";
    TemporaryConfiguration Configuration(
        FindFreePort(),
        ConfigurationShape{.Protocols = Protocols,
                           .Carriers = Carriers,
                           .Bindings = Bindings,
                           .NativeTls = NativeTls,
                           .Credential = "local-token"});
    Prism::Application::Application Application(MakeOptions(Configuration.Path()));
    const auto Result = Application.Start();
    ASSERT_FALSE(Result);
    EXPECT_EQ(Result.error().Code,
              Prism::Application::StartupErrorCode::InvalidConfiguration);
}

TEST(PrismApplication, RejectsConfiguredRoute)
{
    TemporaryConfiguration Configuration(
        FindFreePort(),
        ConfigurationShape{
            .Routes = R"([{"Id":"route-default","Match":"*","Target":"direct","Requires":[]}])"});
    Prism::Application::Application Application(MakeOptions(Configuration.Path()));

    const auto Result = Application.Start();

    ASSERT_FALSE(Result);
    EXPECT_EQ(Result.error().Code,
              Prism::Application::StartupErrorCode::UnsupportedService);
}

TEST(PrismApplication, RejectsUnsafeSampleCredentialOnNonLoopback)
{
    TemporaryConfiguration Configuration(
        FindFreePort(), ConfigurationShape{.Address = "0.0.0.0"});
    Prism::Application::Application Application(MakeOptions(Configuration.Path()));

    const auto Result = Application.Start();

    ASSERT_FALSE(Result);
    EXPECT_FALSE(Application.IsReady());
    EXPECT_EQ(Result.error().Code,
              Prism::Application::StartupErrorCode::InvalidConfiguration);
}

TEST(PrismApplication, RejectsInvalidSocks5Credentials)
{
    TemporaryConfiguration Configuration(FindFreePort());
    RunningApplication Application(Configuration.Path());
    ASSERT_TRUE(Application.Start());

    Net::io_context Io;
    Tcp::socket Socket(Io);
    Socket.connect(Tcp::endpoint(Net::ip::address_v4::loopback(), Application.Port()));

    std::uint8_t Status = 0xff;
    ASSERT_TRUE(Authenticate(Socket, "wrong-token", Status)) << static_cast<unsigned>(Status);
    EXPECT_EQ(Status, 0x01U);
    Socket.close();
    Application.Stop();
}

TEST(PrismApplication, MapsDialFailureToConnectionRefused)
{
    TemporaryConfiguration Configuration(FindFreePort());
    RunningApplication Application(Configuration.Path());
    ASSERT_TRUE(Application.Start());

    Net::io_context Io;
    Tcp::socket Socket(Io);
    Socket.connect(Tcp::endpoint(Net::ip::address_v4::loopback(), Application.Port()));

    std::uint8_t Status = 0xff;
    ASSERT_TRUE(Authenticate(Socket, "local-token", Status)) << static_cast<unsigned>(Status);
    ASSERT_EQ(Status, 0x00U);

    std::uint8_t Reply = 0xff;
    ASSERT_TRUE(Socks5ConnectDomain(Socket,
        Prism::Socks5::Address{Prism::Socks5::AddressType::Domain, "127.0.0.1", 1}, Reply));
    EXPECT_EQ(Reply, static_cast<std::uint8_t>(Prism::Socks5::ReplyCode::ConnectionRefused));
    Socket.close();
    Application.Stop();
}

TEST(PrismApplication, RelaysAuthenticatedLoopbackEcho)
{
    LoopbackEchoServer Echo;
    TemporaryConfiguration Configuration(FindFreePort());
    RunningApplication Application(Configuration.Path());
    ASSERT_TRUE(Application.Start());

    Net::io_context Io;
    Tcp::socket Socket(Io);
    Socket.connect(Tcp::endpoint(Net::ip::address_v4::loopback(), Application.Port()));

    std::uint8_t Status = 0xff;
    ASSERT_TRUE(Authenticate(Socket, "local-token", Status)) << static_cast<unsigned>(Status);
    ASSERT_EQ(Status, 0x00U);

    std::uint8_t Reply = 0xff;
    ASSERT_TRUE(Socks5ConnectDomain(Socket,
        Prism::Socks5::Address{
            Prism::Socks5::AddressType::Domain, "127.0.0.1", Echo.Port()}, Reply));
    ASSERT_EQ(Reply, static_cast<std::uint8_t>(Prism::Socks5::ReplyCode::Success));

    constexpr std::string_view Payload = "preview-socks5-loopback";
    ASSERT_TRUE(WriteBytes(Socket, Payload));
    std::string Received(Payload.size(), '\0');
    boost::system::error_code Error;
    Net::read(Socket, Net::buffer(Received), Error);
    EXPECT_FALSE(Error);
    EXPECT_EQ(Received, Payload);

    Socket.close();
    Application.Stop();
}


