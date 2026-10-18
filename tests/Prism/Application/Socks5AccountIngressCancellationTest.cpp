/**
 * @file Socks5AccountIngressCancellationTest.cpp
 * @brief Application SOCKS5 子任务取消、拒绝与排空测试。
 */
#include "Socks5AccountIngressTestSupport.hpp"
TEST(PrismSocks5AccountIngress, RejectsChildCancelWithoutCancellingRoot)
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

    const auto Held = Fixture.WaitForOperations(true);
    ASSERT_TRUE(Held.Matched) << OperationsFailure(Held);
    const auto Session = SessionIdFromOperations(Held.Last.Sessions);
    ASSERT_TRUE(Session.has_value()) << Held.Last.Sessions;

    const auto SelectorTarget = "/Operations/Sessions/" +
                                std::to_string(Session->Value()) +
                                "/Cancel?stream=7&task=9&correlation=2";
    const auto Rejected = ParseCommandObservation(Fixture.CommandOperations(SelectorTarget));
    ASSERT_TRUE(Rejected.has_value());
    EXPECT_EQ(Rejected->Status, "rejected");
    EXPECT_EQ(Rejected->Message, "target_unsupported");

    constexpr std::string_view Payload = "selector-rejection-keeps-root";
    ASSERT_TRUE(Client.Write(Payload));
    const auto Received = Client.Read(Payload.size());
    ASSERT_TRUE(Received.has_value());
    EXPECT_EQ(*Received, Payload);

    const auto RootTarget = "/Operations/Sessions/" +
                            std::to_string(Session->Value()) +
                            "/Cancel?correlation=3";
    const auto RootResult = ParseCommandObservation(Fixture.CommandOperations(RootTarget));
    ASSERT_TRUE(RootResult.has_value());
    EXPECT_EQ(RootResult->Status, "completed");
    EXPECT_TRUE(Client.ReadClosed());

    const auto Drained = Fixture.WaitForOperations(false);
    ASSERT_TRUE(Drained.Matched) << OperationsFailure(Drained);

    Fixture.Stop();
    EXPECT_TRUE(Fixture.IsStopped());
    EXPECT_EQ(Fixture.ExitCode(), 0);
}

TEST(PrismSocks5AccountIngress, MapsDialRefusalAndDrainsOperations)
{
    Testing::Socks5AccountIngressFixture Fixture;
    ASSERT_TRUE(Fixture.Start());

    Testing::Socks5Client Client;
    ASSERT_TRUE(Client.Connect(Fixture.Port()));
    const auto Auth = Client.Authenticate("local", "socks-password");
    ASSERT_TRUE(Auth.TransportOk);
    ASSERT_EQ(Auth.Status, 0x00U);

    const auto Connect = Client.ConnectTarget(Testing::ConnectAttempt{
        "127.0.0.1", Fixture.RejectedPort(), std::chrono::milliseconds{8000}});
    ASSERT_TRUE(Connect.TransportOk) << Connect.Diagnostic();
    EXPECT_EQ(Connect.Reply, Prism::Socks5::ReplyCode::ConnectionRefused)
        << Connect.Diagnostic();

    Client.Close();
    const auto Drained = Fixture.WaitForOperations(false);
    ASSERT_TRUE(Drained.Matched) << OperationsFailure(Drained);

    Fixture.Stop();
    EXPECT_TRUE(Fixture.IsStopped());
    EXPECT_EQ(Fixture.ExitCode(), 0);
}

