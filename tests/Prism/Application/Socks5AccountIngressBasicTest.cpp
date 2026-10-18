/**
 * @file Socks5AccountIngressBasicTest.cpp
 * @brief Application SOCKS5 UserPass、CONNECT 与账户生命周期测试。
 */
#include "Socks5AccountIngressTestSupport.hpp"
TEST(PrismSocks5AccountIngress, RelaysUserPassConnectAndDrainsOperations)
{
    Testing::Socks5AccountIngressFixture Fixture;
    ASSERT_TRUE(Fixture.Start());

    Testing::Socks5Client Client;
    ASSERT_TRUE(Client.Connect(Fixture.Port()));
    const auto Auth = Client.Authenticate("local", "socks-password");
    ASSERT_TRUE(Auth.TransportOk);
    ASSERT_EQ(Auth.Status, 0x00U);

    const auto Connect = Client.ConnectTarget(
        Testing::ConnectAttempt{"127.0.0.1", Fixture.EchoPort()});
    ASSERT_TRUE(Connect.TransportOk) << Connect.Diagnostic();
    ASSERT_EQ(Connect.Reply, Prism::Socks5::ReplyCode::Success)
        << Connect.Diagnostic();

    constexpr std::string_view Payload = "preview-socks5-account-relay";
    ASSERT_TRUE(Client.Write(Payload));
    const auto Received = Client.Read(Payload.size());
    ASSERT_TRUE(Received.has_value());
    EXPECT_EQ(*Received, Payload);

    const auto Held = Fixture.WaitForOperations(true);
    ASSERT_TRUE(Held.Matched) << OperationsFailure(Held);

    Client.Close();
    const auto Drained = Fixture.WaitForOperations(false);
    ASSERT_TRUE(Drained.Matched) << OperationsFailure(Drained);

    Fixture.Stop();
    EXPECT_TRUE(Fixture.IsStopped());
    EXPECT_EQ(Fixture.ExitCode(), 0);
}

TEST(PrismSocks5AccountIngress, RejectsInvalidUserPassAndDrainsOperations)
{
    Testing::Socks5AccountIngressFixture Fixture;
    ASSERT_TRUE(Fixture.Start());

    Testing::Socks5Client Client;
    ASSERT_TRUE(Client.Connect(Fixture.Port()));
    const auto Auth = Client.Authenticate("local", "wrong-password");
    ASSERT_TRUE(Auth.TransportOk);
    EXPECT_EQ(Auth.Status, 0x01U);

    Client.Close();
    const auto Drained = Fixture.WaitForOperations(false);
    ASSERT_TRUE(Drained.Matched) << OperationsFailure(Drained);

    Fixture.Stop();
    EXPECT_TRUE(Fixture.IsStopped());
    EXPECT_EQ(Fixture.ExitCode(), 0);
}

