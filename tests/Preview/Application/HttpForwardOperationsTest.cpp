/**
 * @file HttpForwardOperationsTest.cpp
 * @brief HTTP 正向代理认证、失败映射与 Operations drain 测试。
 */
#include "HttpForwardTestSupport.hpp"

#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <string>
#include <string_view>
#include <thread>

#include <Preview/Foundation/Utility/Diagnose/Facade.hpp>

#include <boost/system/errc.hpp>

namespace
{

    struct OperationsRequest final
    {
        std::uint16_t Port;
        std::string_view MethodTarget;
        std::string_view CommandToken;
        std::string_view Body;
    };

    /** @brief 通过真实管理 HTTP 端口发送请求并读取完整响应。 */
    [[nodiscard]] auto ReadOperationsResponse(const OperationsRequest &RequestValue)
        -> Preview::Testing::HttpForward::ReadObservation
    {
        Net::io_context Io;
        Tcp::socket Client(Io);
        boost::system::error_code Error;
        if (!Connect(Client, RequestValue.Port, &Error))
        {
            Preview::Testing::HttpForward::ReadObservation Result;
            Result.Error = Error;
            return Result;
        }
        auto Message = std::string(RequestValue.MethodTarget) + " HTTP/1.1\r\nHost: 127.0.0.1:" +
            std::to_string(RequestValue.Port) + "\r\nConnection: close\r\n";
        if (!RequestValue.CommandToken.empty())
        {
            Message.append("Authorization: Bearer ").append(RequestValue.CommandToken).append("\r\n");
        }
        if (RequestValue.Body.empty())
        {
            Message.append("Content-Length: 0\r\n\r\n");
        }
        else
        {
            Message.append("Content-Type: application/json\r\nContent-Length: ")
                .append(std::to_string(RequestValue.Body.size())).append("\r\n\r\n")
                .append(RequestValue.Body);
        }
        if (!WriteAll(Client, Message))
        {
            Preview::Testing::HttpForward::ReadObservation Result;
            Result.Error = boost::system::errc::make_error_code(
                boost::system::errc::io_error);
            return Result;
        }
        const auto Result = ReadUntilClose(Client, IoTimeout);
        CloseSocket(Client);
        return Result;
    }

    /** @brief 保留现有无 body 调用点，route request 内容由一个 owning value 传递。 */
    [[nodiscard]] auto ReadOperationsResponse(
        const std::uint16_t Port,
        const std::string_view MethodTarget,
        const std::string_view CommandToken = {})
        -> Preview::Testing::HttpForward::ReadObservation
    {
        return ReadOperationsResponse(OperationsRequest{Port, MethodTarget, CommandToken, {}});
    }

    [[nodiscard]] auto ReadFileText(const std::filesystem::path &Path) -> std::string
    {
        std::ifstream File(Path, std::ios::binary);
        return std::string(std::istreambuf_iterator<char>(File), std::istreambuf_iterator<char>());
    }

    [[nodiscard]] auto ReplaceOnce(
        std::string &Text,
        const std::string_view Before,
        const std::string_view After) -> bool
    {
        const auto Position = Text.find(Before);
        if (Position == std::string::npos)
        {
            return false;
        }
        Text.replace(Position, Before.size(), After);
        return true;
    }

    [[nodiscard]] auto ReadBootstrapToken(const std::string &Response)
        -> std::optional<std::string>
    {
        constexpr std::string_view Key{"\"command_token\":\""};
        const auto Begin = Response.find(Key);
        if (Begin == std::string::npos)
        {
            return std::nullopt;
        }
        const auto First = Begin + Key.size();
        const auto End = Response.find('"', First);
        if (End == std::string::npos || End - First != 64U)
        {
            return std::nullopt;
        }
        return Response.substr(First, End - First);
    }

    /** @brief 从命令 JSON 响应解析十进制 OperationId。 */
    [[nodiscard]] auto ReadOperationId(const std::string &Response)
        -> std::optional<std::uint64_t>
    {
        constexpr std::string_view Key = "\"operation\":\"";
        const auto Position = Response.find(Key);
        if (Position == std::string::npos) return {};
        const auto FirstDigit = Position + Key.size();
        const auto EndQuote = Response.find('"', FirstDigit);
        if (EndQuote == std::string::npos) return {};
        std::uint64_t Value{};
        const auto Parsed = std::from_chars(
            Response.data() + FirstDigit, Response.data() + EndQuote, Value);
        if (Parsed.ec != std::errc{} || Parsed.ptr != Response.data() + EndQuote)
        {
            return {};
        }
        return Value;
    }

    /** @brief 查找指定 operation 的真实事件对象位置。 */
    [[nodiscard]] auto FindOperationEventPosition(
        const std::string_view Response,
        const std::uint64_t Operation,
        const std::string_view Kind) -> std::size_t
    {
        const auto OperationField = "\"operation\":\"" + std::to_string(Operation) + "\"";
        const auto KindField = "\"kind\":\"" + std::string(Kind) + "\"";
        auto Search = Response.find(OperationField);
        while (Search != std::string_view::npos)
        {
            const auto Begin = Response.rfind('{', Search);
            const auto End = Response.find('}', Search);
            if (Begin != std::string_view::npos && End != std::string_view::npos &&
                Response.substr(Begin, End - Begin + 1U).find(KindField) !=
                    std::string_view::npos)
            {
                return Begin;
            }
            Search = Response.find(OperationField, Search + OperationField.size());
        }
        return std::string_view::npos;
    }

} // namespace

TEST(HttpForwardIngress, RejectsMissingCredentialsBeforeUpstreamDial)
{
    LoopbackOrigin Origin;
    Origin.Start(std::string{}, std::string{});

    const auto TcpPort = FindFreePort();
    auto OperationsPort = FindFreePort();
    while (OperationsPort == TcpPort)
    {
        OperationsPort = FindFreePort();
    }
    TemporaryConfiguration Configuration(TcpPort, OperationsPort);
    RunningApplication Application(Configuration.Path());
    ASSERT_TRUE(Application.Start()) << Application.Error();

    Net::io_context Io;
    Tcp::socket Client(Io);
    ASSERT_TRUE(Connect(Client, Application.Port()));
    const auto Request = "GET http://127.0.0.1:" + std::to_string(Origin.Port()) +
                         "/private HTTP/1.1\r\nHost: origin.example\r\n\r\n";
    ASSERT_TRUE(WriteAll(Client, Request));

    const auto Observation = ReadUntilClose(Client);
    CloseSocket(Client);
    const auto &Response = Observation.Bytes;
    ASSERT_TRUE(Observation.Closed) << Observation.Description();
    EXPECT_NE(Response.find("HTTP/1.1 407 Proxy Authentication Required"),
              std::string::npos);
    EXPECT_FALSE(Origin.WaitForAccepted(std::chrono::milliseconds(250)));
    EXPECT_TRUE(WaitForResourcesEmpty(Application.OperationsPort()));
    Application.Stop();
    EXPECT_EQ(Application.ExitCode(), 0);
}

TEST(HttpForwardIngress, RelaysConnectPayloadAndResponse)
{
    LoopbackOrigin Origin;
    constexpr std::string_view Payload = "client-tunnel-payload";
    constexpr std::string_view OriginResponse = "origin-tunnel-response";
    Origin.Start(std::string(Payload), std::string(OriginResponse));

    const auto TcpPort = FindFreePort();
    auto OperationsPort = FindFreePort();
    while (OperationsPort == TcpPort)
    {
        OperationsPort = FindFreePort();
    }
    TemporaryConfiguration Configuration(TcpPort, OperationsPort);
    RunningApplication Application(Configuration.Path());
    ASSERT_TRUE(Application.Start()) << Application.Error();

    Net::io_context Io;
    Tcp::socket Client(Io);
    ASSERT_TRUE(Connect(Client, Application.Port()));
    const auto Request = "CONNECT 127.0.0.1:" + std::to_string(Origin.Port()) +
                         " HTTP/1.1\r\nHost: 127.0.0.1:" + std::to_string(Origin.Port()) +
                         "\r\nProxy-Authorization: " + std::string(ProxyAuthorization) +
                         "\r\n\r\n" + std::string(Payload);
    ASSERT_TRUE(WriteAll(Client, Request));

    const auto Observation = ReadUntilClose(Client);
    CloseSocket(Client);
    const auto &Response = Observation.Bytes;
    ASSERT_TRUE(Observation.Closed) << Observation.Description();
    EXPECT_NE(Response.find("HTTP/1.1 200 Connection Established"), std::string::npos);
    EXPECT_TRUE(Response.ends_with(OriginResponse));
    ASSERT_TRUE(Origin.WaitForAccepted(IoTimeout));
    ASSERT_TRUE(Origin.WaitForComplete(IoTimeout));
    EXPECT_EQ(Origin.Captured(), Payload);
    EXPECT_TRUE(Origin.Extra().empty());
    EXPECT_TRUE(WaitForResourcesEmpty(Application.OperationsPort()));
    Application.Stop();
    EXPECT_EQ(Application.ExitCode(), 0);
}

TEST(HttpForwardIngress, MapsUpstreamDialFailureToBadGateway)
{
    const auto UnusedPort = FindFreePort();
    auto TcpPort = FindFreePort();
    while (TcpPort == UnusedPort)
    {
        TcpPort = FindFreePort();
    }
    auto OperationsPort = FindFreePort();
    while (OperationsPort == TcpPort || OperationsPort == UnusedPort)
    {
        OperationsPort = FindFreePort();
    }
    TemporaryConfiguration Configuration(TcpPort, OperationsPort);
    RunningApplication Application(Configuration.Path());
    ASSERT_TRUE(Application.Start()) << Application.Error();

    Net::io_context Io;
    Tcp::socket Client(Io);
    ASSERT_TRUE(Connect(Client, Application.Port()));
    const auto Request = "GET http://127.0.0.1:" + std::to_string(UnusedPort) +
                         "/unreachable HTTP/1.1\r\nHost: unreachable\r\n"
                         "Proxy-Authorization: " + std::string(ProxyAuthorization) +
                         "\r\n\r\n";
    ASSERT_TRUE(WriteAll(Client, Request));

    const auto Observation = ReadUntilClose(Client, DialFailureTimeout);
    CloseSocket(Client);
    const auto &Response = Observation.Bytes;
    EXPECT_TRUE(Observation.Closed) << Observation.Description();
    EXPECT_NE(Response.find("HTTP/1.1 502 Bad Gateway"), std::string::npos);
    OperationsDrainObservation Drain;
    EXPECT_TRUE(WaitForResourcesEmpty(Application.OperationsPort(), DialFailureTimeout, &Drain))
        << Drain.Description();
    Application.Stop();
    EXPECT_EQ(Application.ExitCode(), 0);
}

TEST(HttpForwardIngress, PropagatesUpstreamCloseAndDrainsSession)
{
    LoopbackOrigin Origin;
    const auto OriginHost = MakeOriginHost(Origin.Port());
    const auto Expected = "GET /close HTTP/1.1\r\nHost: " + OriginHost + "\r\n\r\n";
    Origin.Start(Expected, {});

    const auto TcpPort = FindFreePort();
    auto OperationsPort = FindFreePort();
    while (OperationsPort == TcpPort)
    {
        OperationsPort = FindFreePort();
    }
    TemporaryConfiguration Configuration(TcpPort, OperationsPort);
    RunningApplication Application(Configuration.Path());
    ASSERT_TRUE(Application.Start()) << Application.Error();

    Net::io_context Io;
    Tcp::socket Client(Io);
    ASSERT_TRUE(Connect(Client, Application.Port()));
    const auto Request = "GET http://" + OriginHost +
                         "/close HTTP/1.1\r\nHost: ignored.example\r\n"
                         "Proxy-Authorization: " + std::string(ProxyAuthorization) +
                         "\r\n\r\n";
    ASSERT_TRUE(WriteAll(Client, Request));

    const auto Observation = ReadUntilClose(Client);
    CloseSocket(Client);
    const auto &Response = Observation.Bytes;
    ASSERT_TRUE(Observation.Closed) << Observation.Description();
    EXPECT_TRUE(Response.empty());
    ASSERT_TRUE(Origin.WaitForAccepted(IoTimeout));
    ASSERT_TRUE(Origin.WaitForComplete(IoTimeout));
    EXPECT_EQ(Origin.Captured(), Expected);
    EXPECT_TRUE(WaitForResourcesEmpty(Application.OperationsPort()));
    Application.Stop();
    EXPECT_EQ(Application.ExitCode(), 0);
}

TEST(HttpForwardIngress, DoesNotRelayPipelinedFollowupWithoutASecondAdmission)
{
    LoopbackOrigin Origin;
    const auto OriginHost = MakeOriginHost(Origin.Port());
    const auto FirstRequest = "POST /first HTTP/1.1\r\nHost: " + OriginHost +
                               "\r\nContent-Length: 3\r\n\r\none";
    Origin.Start(FirstRequest,
                 "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nfirst");

    const auto TcpPort = FindFreePort();
    auto OperationsPort = FindFreePort();
    while (OperationsPort == TcpPort)
    {
        OperationsPort = FindFreePort();
    }
    TemporaryConfiguration Configuration(TcpPort, OperationsPort);
    RunningApplication Application(Configuration.Path());
    ASSERT_TRUE(Application.Start()) << Application.Error();

    Net::io_context Io;
    Tcp::socket Client(Io);
    ASSERT_TRUE(Connect(Client, Application.Port()));
    const auto First = "POST http://" + OriginHost +
                       "/first HTTP/1.1\r\nHost: ignored.example\r\n"
                       "Proxy-Authorization: " + std::string(ProxyAuthorization) +
                       "\r\nContent-Length: 3\r\n\r\none";
    constexpr std::string_view Followup =
        "GET /second HTTP/1.1\r\nHost: second.example\r\n\r\n";
    ASSERT_TRUE(WriteAll(Client, First + std::string(Followup)));

    const auto Observation = ReadUntilClose(Client);
    CloseSocket(Client);
    const auto &Response = Observation.Bytes;
    ASSERT_TRUE(Observation.Closed) << Observation.Description();
    const auto UpstreamAccepted = Origin.WaitForAccepted(std::chrono::milliseconds(250));
    if (UpstreamAccepted)
    {
        ASSERT_TRUE(Origin.WaitForComplete(IoTimeout));
        EXPECT_EQ(Origin.Captured(), FirstRequest);
        EXPECT_TRUE(Origin.Extra().empty());
        EXPECT_NE(Response.find("HTTP/1.1 200 OK"), std::string::npos);
    }
    else
    {
        EXPECT_TRUE(Response.empty() || Response.find("HTTP/1.1 400") != std::string::npos);
    }
    EXPECT_TRUE(WaitForResourcesEmpty(Application.OperationsPort()));
    Application.Stop();
    EXPECT_EQ(Application.ExitCode(), 0);
}

TEST(HttpForwardIngress, RejectsHttpsAbsoluteFormWithoutCleartextDial)
{
    LoopbackOrigin Origin;
    Origin.Start(std::string{}, std::string{});

    const auto TcpPort = FindFreePort();
    auto OperationsPort = FindFreePort();
    while (OperationsPort == TcpPort)
    {
        OperationsPort = FindFreePort();
    }
    TemporaryConfiguration Configuration(TcpPort, OperationsPort);
    RunningApplication Application(Configuration.Path());
    ASSERT_TRUE(Application.Start()) << Application.Error();

    Net::io_context Io;
    Tcp::socket Client(Io);
    ASSERT_TRUE(Connect(Client, Application.Port()));
    const auto Request = "GET https://127.0.0.1:" + std::to_string(Origin.Port()) +
                         "/secure HTTP/1.1\r\nHost: ignored.example\r\n"
                         "Proxy-Authorization: " + std::string(ProxyAuthorization) +
                         "\r\n\r\n";
    ASSERT_TRUE(WriteAll(Client, Request));

    const auto Observation = ReadUntilClose(Client);
    CloseSocket(Client);
    const auto &Response = Observation.Bytes;
    ASSERT_TRUE(Observation.Closed) << Observation.Description();
    EXPECT_NE(Response.find("HTTP/1.1 400"), std::string::npos);
    EXPECT_FALSE(Origin.WaitForAccepted(std::chrono::milliseconds(250)));
    EXPECT_TRUE(WaitForResourcesEmpty(Application.OperationsPort()));
    Application.Stop();
    EXPECT_EQ(Application.ExitCode(), 0);
}

TEST(HttpForwardOperations, WorkerDrainReturnsOperationIdAndTrueTerminalReceipt)
{
    const auto TcpPort = FindFreePort();
    auto OperationsPort = FindFreePort();
    while (OperationsPort == TcpPort)
    {
        OperationsPort = FindFreePort();
    }
    TemporaryConfiguration Configuration(TcpPort, OperationsPort);
    RunningApplication Application(Configuration.Path());
    ASSERT_TRUE(Application.Start()) << Application.Error();

    const auto Bootstrap = ReadOperationsResponse(
        Application.OperationsPort(), "GET /Operations/Bootstrap");
    ASSERT_TRUE(Bootstrap.Closed) << Bootstrap.Description();
    const auto Token = ReadBootstrapToken(Bootstrap.Bytes);
    ASSERT_TRUE(Token);
    const auto Accepted = ReadOperationsResponse(
        Application.OperationsPort(),
        "POST /Operations/Drain?worker=1&force=false&correlation=701", *Token);
    ASSERT_TRUE(Accepted.Closed) << Accepted.Description();
    ASSERT_NE(Accepted.Bytes.find("HTTP/1.1 202"), std::string::npos);
    ASSERT_NE(Accepted.Bytes.find("\"status\":\"accepted\""), std::string::npos);
    EXPECT_NE(Accepted.Bytes.find("\"worker\":\"1\""), std::string::npos);
    const auto Operation = ReadOperationId(Accepted.Bytes);
    ASSERT_TRUE(Operation);
    ASSERT_NE(*Operation, 0U);

    bool TerminalCompleted = false;
    const auto Deadline = std::chrono::steady_clock::now() + IoTimeout;
    while (std::chrono::steady_clock::now() < Deadline && !TerminalCompleted)
    {
        const auto Status = ReadOperationsResponse(
            Application.OperationsPort(),
            "GET /Operations/Operations/" + std::to_string(*Operation) + "?correlation=702");
        const auto StatusOperation = ReadOperationId(Status.Bytes);
        TerminalCompleted = Status.Closed &&
            StatusOperation && *StatusOperation == *Operation &&
            Status.Bytes.find("\"status\":\"completed\"") != std::string::npos;
        if (!TerminalCompleted)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    }
    EXPECT_TRUE(TerminalCompleted);

    auto AcceptedEvent = std::string_view::npos;
    auto TerminalEvent = std::string_view::npos;
    while (std::chrono::steady_clock::now() < Deadline &&
        (AcceptedEvent == std::string_view::npos || TerminalEvent == std::string_view::npos))
    {
        const auto Events = ReadOperationsResponse(
            Application.OperationsPort(), "GET /Operations/Events?correlation=704");
        if (Events.Closed)
        {
            AcceptedEvent = FindOperationEventPosition(
                Events.Bytes, *Operation, "operation_accepted");
            TerminalEvent = FindOperationEventPosition(
                Events.Bytes, *Operation, "operation_completed");
        }
        if (AcceptedEvent == std::string_view::npos || TerminalEvent == std::string_view::npos)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    }
    ASSERT_NE(AcceptedEvent, std::string_view::npos);
    ASSERT_NE(TerminalEvent, std::string_view::npos);
    EXPECT_LT(AcceptedEvent, TerminalEvent);

    const auto Workers = ReadOperationsResponse(
        Application.OperationsPort(), "GET /Operations/Workers?id=1&correlation=703");
    ASSERT_TRUE(Workers.Closed) << Workers.Description();
    EXPECT_NE(Workers.Bytes.find("\"accepting\":false"), std::string::npos);
    EXPECT_NE(Workers.Bytes.find("\"active_tasks\":\"0\""), std::string::npos);
    Application.Stop();
    EXPECT_EQ(Application.ExitCode(), 0);
}

TEST(HttpForwardOperations, HotReloadPublishesNewDiagnoseRenderEpoch)
{
    const auto TcpPort = FindFreePort();
    auto OperationsPort = FindFreePort();
    while (OperationsPort == TcpPort)
    {
        OperationsPort = FindFreePort();
    }
    const auto LogDirectory = (std::filesystem::temp_directory_path() /
        ("PrismPreviewDiagnoseReload-" + std::to_string(
            std::chrono::steady_clock::now().time_since_epoch().count()))).generic_string();
    TemporaryConfiguration Configuration(
        TcpPort, OperationsPort,
        TemporaryConfigurationOptions{
            .LogDirectory = LogDirectory,
            .LogFileName = "preview.log"});
    RunningApplication Application(Configuration.Path());
    ASSERT_TRUE(Application.Start()) << Application.Error();

    const auto OldContext = Preview::Diagnose::CaptureCurrentContext();
    const auto Before = Preview::Diagnose::Info(OldContext, "A5ReloadHumanMarker");
    ASSERT_EQ(Before.Status, Preview::Diagnose::SubmissionStatus::Accepted);

    const auto Bootstrap = ReadOperationsResponse(
        Application.OperationsPort(), "GET /Operations/Bootstrap");
    ASSERT_TRUE(Bootstrap.Closed) << Bootstrap.Description();
    const auto Token = ReadBootstrapToken(Bootstrap.Bytes);
    ASSERT_TRUE(Token);

    auto CandidateConfiguration = ReadFileText(Configuration.Path());
    ASSERT_FALSE(CandidateConfiguration.empty());
    ASSERT_TRUE(ReplaceOnce(CandidateConfiguration, "\"Level\": \"Trace\"",
        "\"Level\":\"Error\""));
    ASSERT_TRUE(ReplaceOnce(CandidateConfiguration, "\"FileName\": \"preview.log\"",
        "\"FileName\":\"reload-preview.log\""));
    ASSERT_TRUE(ReplaceOnce(CandidateConfiguration, "\"RenderMode\": \"CompactHuman\"",
        "\"RenderMode\":\"Structured\""));
    const auto Body = std::string(
        "{\"mode\":\"apply\",\"base_generation\":\"1\",\"configuration\":") +
        CandidateConfiguration + "}";
    const auto Accepted = ReadOperationsResponse(OperationsRequest{
        Application.OperationsPort(), "POST /Operations/Reload?correlation=811", *Token, Body});
    ASSERT_TRUE(Accepted.Closed) << Accepted.Description();
    ASSERT_NE(Accepted.Bytes.find("HTTP/1.1 202"), std::string::npos);
    ASSERT_NE(Accepted.Bytes.find("\"status\":\"accepted\""), std::string::npos);
    const auto Operation = ReadOperationId(Accepted.Bytes);
    ASSERT_TRUE(Operation);

    bool Completed = false;
    const auto Deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(5000);
    while (std::chrono::steady_clock::now() < Deadline && !Completed)
    {
        const auto Status = ReadOperationsResponse(
            Application.OperationsPort(),
            "GET /Operations/Operations/" + std::to_string(*Operation) + "?correlation=812");
        const auto StatusOperation = ReadOperationId(Status.Bytes);
        Completed = Status.Closed && StatusOperation && *StatusOperation == *Operation &&
            Status.Bytes.find("\"status\":\"completed\"") != std::string::npos;
        if (!Completed)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    }
    ASSERT_TRUE(Completed);

    const auto Retained = Preview::Diagnose::Error(OldContext, "A5ReloadRetainedHumanMarker");
    ASSERT_EQ(Retained.Status, Preview::Diagnose::SubmissionStatus::Accepted);
    const auto After = Preview::Diagnose::Error(
        Preview::Diagnose::ContextState::Empty(), "A5ReloadStructuredMarker");
    ASSERT_EQ(After.Status, Preview::Diagnose::SubmissionStatus::Accepted);
    Application.Stop();
    ASSERT_EQ(Application.ExitCode(), 0);

    std::size_t HumanMarkerFiles = 0;
    std::size_t StructuredMarkerFiles = 0;
    for (const auto &Entry : std::filesystem::directory_iterator(LogDirectory))
    {
        if (!Entry.is_regular_file())
        {
            continue;
        }
        const auto Contents = ReadFileText(Entry.path());
        if (Contents.find("A5ReloadHumanMarker") != std::string::npos ||
            Contents.find("A5ReloadRetainedHumanMarker") != std::string::npos)
        {
            ++HumanMarkerFiles;
            EXPECT_NE(Contents.find("A5ReloadHumanMarker"), std::string::npos);
            EXPECT_NE(Contents.find("A5ReloadRetainedHumanMarker"), std::string::npos);
            EXPECT_EQ(Contents.find("\"Message\""), std::string::npos);
            EXPECT_EQ(Contents.find("A5ReloadStructuredMarker"), std::string::npos);
        }
        if (Contents.find("A5ReloadStructuredMarker") != std::string::npos)
        {
            ++StructuredMarkerFiles;
            EXPECT_NE(Contents.find("\"Message\":\"A5ReloadStructuredMarker\""),
                std::string::npos);
            EXPECT_EQ(Contents.find("A5ReloadHumanMarker"), std::string::npos);
        }
    }
    EXPECT_EQ(HumanMarkerFiles, 1U);
    EXPECT_EQ(StructuredMarkerFiles, 1U);
    const auto OldSink = ReadFileText(std::filesystem::path(LogDirectory) / "preview.log");
    const auto NewSink = ReadFileText(std::filesystem::path(LogDirectory) / "reload-preview.log");
    EXPECT_NE(OldSink.find("A5ReloadHumanMarker"), std::string::npos);
    EXPECT_NE(OldSink.find("A5ReloadRetainedHumanMarker"), std::string::npos);
    EXPECT_EQ(OldSink.find("A5ReloadStructuredMarker"), std::string::npos);
    EXPECT_NE(NewSink.find("A5ReloadStructuredMarker"), std::string::npos);
    EXPECT_EQ(NewSink.find("A5ReloadHumanMarker"), std::string::npos);
}

