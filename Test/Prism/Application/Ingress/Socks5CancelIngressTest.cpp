/**
 * @file Socks5CancelIngressTest.cpp
 * @brief Application SOCKS5 子任务取消、拒绝与排空测试。
 */

#include <charconv>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>

#include <Prism/Foundation/Identifier/Id.hpp>

#include "Socks5IngressSupport.hpp"

namespace
{
    /** @brief 从 session 快照读取 canonical root-cancel path 所需的 process identity。 */
    [[nodiscard]] auto ProcessIdFromOperations(const std::string_view Response)
        -> std::optional<Prism::ProcessId>
    {
        const auto Document = ParseJsonBody(Response);
        if (!Document) return std::nullopt;
        const auto *Status = FindJsonValue(*Document, "status");
        const auto *Value = FindJsonValue(*Document, "value");
        if (Status == nullptr || !Status->is_string() || Status->get<std::string>() != "ok" ||
            Value == nullptr || !Value->is_object())
        {
            return std::nullopt;
        }
        const auto *Items = FindJsonValue(*Value, "items");
        if (Items == nullptr || !Items->is_array() || Items->get_array().size() != 1U)
        {
            return std::nullopt;
        }
        const auto *Process = FindJsonValue(Items->get_array().front(), "process");
        if (Process == nullptr || !Process->is_string()) return std::nullopt;

        const auto &Text = Process->get<std::string>();
        std::uint64_t ProcessValue{};
        const auto [End, Error] = std::from_chars(
            Text.data(), Text.data() + Text.size(), ProcessValue);
        if (Error != std::errc{} || End != Text.data() + Text.size() || ProcessValue == 0U)
        {
            return std::nullopt;
        }
        return Prism::ProcessId{ProcessValue};
    }
} // namespace

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
    const auto Process = ProcessIdFromOperations(Held.Last.Sessions);
    ASSERT_TRUE(Process.has_value()) << Held.Last.Sessions;

    const auto SessionPath = "/Operations/Processes/" +
        std::to_string(Process->Value()) + "/Sessions/" + std::to_string(Session->Value());
    const auto SelectorTarget = SessionPath +
        "/Cancel?generation=3&worker=2&stream=7&parent_task=6&task=9&correlation=2";
    const auto RejectedResponse = Fixture.CommandOperations(SelectorTarget);
    const auto FirstSpace = RejectedResponse.find(' ');
    ASSERT_NE(FirstSpace, std::string::npos) << RejectedResponse;
    const auto SecondSpace = RejectedResponse.find(' ', FirstSpace + 1U);
    ASSERT_NE(SecondSpace, std::string::npos) << RejectedResponse;
    EXPECT_EQ(RejectedResponse.substr(FirstSpace + 1U, SecondSpace - FirstSpace - 1U), "400")
        << RejectedResponse;
    const auto RejectedDocument = ParseJsonBody(RejectedResponse);
    ASSERT_TRUE(RejectedDocument.has_value()) << RejectedResponse;
    const auto *RejectedError = FindJsonValue(*RejectedDocument, "error");
    ASSERT_NE(RejectedError, nullptr) << RejectedResponse;
    ASSERT_TRUE(RejectedError->is_string()) << RejectedResponse;
    EXPECT_EQ(RejectedError->get<std::string>(), "target_unsupported") << RejectedResponse;

    constexpr std::string_view Payload = "selector-rejection-keeps-root";
    ASSERT_TRUE(Client.Write(Payload));
    const auto Received = Client.Read(Payload.size());
    ASSERT_TRUE(Received.has_value());
    EXPECT_EQ(*Received, Payload);

    const auto RootTarget = SessionPath + "/Cancel?correlation=3";
    const auto RootAccepted = ParseCommandObservation(Fixture.CommandOperations(RootTarget));
    ASSERT_TRUE(RootAccepted.has_value());
    ASSERT_EQ(RootAccepted->Status, "accepted");
    ASSERT_TRUE(RootAccepted->Operation.has_value());

    std::optional<CommandObservation> RootResult;
    const auto Deadline = std::chrono::steady_clock::now() + std::chrono::seconds{4};
    while (std::chrono::steady_clock::now() < Deadline)
    {
        RootResult = ParseCommandObservation(
            Fixture.QueryCommandOperation(*RootAccepted->Operation));
        if (RootResult && RootResult->Status != "accepted")
        {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
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

