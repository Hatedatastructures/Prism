/**
 * @file SessionAuditTest.cpp
 * @brief Session 关闭审计事件集成测试。
 */
#include <gtest/gtest.h>

#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <string>
#include <string_view>

#include <Preview/Foundation/Utility/Diagnose/Facade.hpp>
#include <Preview/Foundation/Fault/Code.hpp>
#include <Preview/Foundation/Utility/Diagnose/FieldKey.hpp>
#include <Preview/Foundation/Utility/Diagnose/ContextState.hpp>
#include <Preview/Lifecycle/TaskState.hpp>
#include <Preview/Runtime/Middleware/Context.hpp>
#include <Preview/Runtime/Session.hpp>
#include <Preview/Runtime/SessionServices.hpp>
#include <Preview/Transport/MemoryStream.hpp>
#include <Preview/Transport/Transmission.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>
#include <TestSupport/Preview/DiagnoseTestEnvironment.hpp>

namespace
{

    namespace Net = boost::asio;

    auto MakeSharedPair(Net::io_context &Ioc)
        -> std::pair<std::shared_ptr<Preview::MemoryStream>,
                     std::shared_ptr<Preview::MemoryStream>>
    {
        auto [First, Second] = Preview::MakeMemoryPair(Ioc.get_executor());
        return {std::make_shared<Preview::MemoryStream>(std::move(First)),
                std::make_shared<Preview::MemoryStream>(std::move(Second))};
    }

    auto EmptyOperation() -> Net::awaitable<void>
    {
        co_return;
    }

    auto MakeSessionControl(Net::any_io_executor Executor)
        -> std::shared_ptr<Preview::Runtime::SessionControl>
    {
        auto Control = std::make_shared<Preview::Runtime::SessionControl>(std::move(Executor));
        Preview::Lifecycle::TaskRequest Request;
        Request.Identity.TaskId = Preview::TaskId{7001};
        Request.Identity.SessionId = Preview::SessionId{8002};
        Request.Identity.WorkerId = Preview::WorkerId{9003};
        Request.Identity.Generation = Preview::GenerationId{10004};
        if (!Control->Start(std::move(Request), EmptyOperation()))
        {
            return {};
        }
        return Control;
    }

    auto CountText(const std::string_view Text, const std::string_view Needle) -> std::size_t
    {
        std::size_t Count = 0U;
        std::size_t Offset = 0U;
        while ((Offset = Text.find(Needle, Offset)) != std::string_view::npos)
        {
            ++Count;
            Offset += Needle.size();
        }
        return Count;
    }

    TEST(SessionAudit, CloseEventIsSubmittedExactlyOnce)
    {
        Preview::TestSupport::DiagnoseTestEnvironment Environment{"session-audit"};
        Environment.Configuration().Mode = Preview::Diagnose::RenderMode::Structured;
        ASSERT_TRUE(Environment.Install().has_value());

        Net::io_context Ioc;
        auto [Client, Inbound] = MakeSharedPair(Ioc);
        auto Services = std::make_shared<Preview::Runtime::SessionServices>();
        Services->ProcessContext = Preview::Diagnose::ContextState::Empty()
                                       .With(Preview::Diagnose::Fields::Process,
                                             Preview::ProcessId{6000})
                                       .With(Preview::Diagnose::Fields::Generation,
                                             Preview::GenerationId{10004});
        auto Control = MakeSessionControl(Ioc.get_executor());
        ASSERT_NE(Control, nullptr);

        Preview::Recognition::ProfileSpec ProfileSpec;
        ProfileSpec.Mode = Preview::Recognition::RecognitionMode::Configured;
        ProfileSpec.ConfiguredCandidate = 7;
        Preview::Recognition::CandidateSpec Candidate;
        Candidate.Id = 7;
        Candidate.Name = "safe-candidate";
        Candidate.Protocol = Preview::Recognition::ProtocolType::Http;
        Candidate.FirstBytes = {0xA1};
        Candidate.MinimumBytes = 5U;
        Candidate.Inspect = [](const Preview::Recognition::ProbeSnapshot &)
        {
            return Preview::Recognition::MatchState::Rejected;
        };
        Candidate.Commit = [](Preview::Recognition::CommitContext Context)
            -> Net::awaitable<Preview::Recognition::CommitResult>
        {
            Preview::Recognition::CommitResult Result;
            Result.Candidate = Context.Candidate;
            Result.Status = Preview::Recognition::RecognitionStatus::NoMatch;
            co_return Result;
        };
        ProfileSpec.Candidates.push_back(std::move(Candidate));
        const auto CompiledProfile =
            Preview::Recognition::Profile::Compile(std::move(ProfileSpec));
        ASSERT_TRUE(CompiledProfile.has_value());

        Preview::Runtime::SessionOptions Options;
        Options.Services = Services;
        Options.Control = Control;
        Options.Profile = *CompiledProfile;
        Preview::Runtime::Session Session(std::move(Options));

        auto Result = Preview::Fault::Code::Success;
        Preview::Testing::RunCoro(
            Ioc,
            [&]() -> Net::awaitable<void>
            {
                const std::array<std::byte, 5> Payload{
                    std::byte{0xA1}, std::byte{0xB2}, std::byte{0xC3},
                    std::byte{0xD4}, std::byte{0xE5}};
                std::error_code Error;
                co_await Client->async_write_some(Payload, Error);
                Client->Close();
                Result = co_await Session.Run(Inbound);
            });

        EXPECT_EQ(Result, Preview::Fault::Code::ProtocolError);
        EXPECT_EQ(Control->Metrics().CloseCalls, 1U);
        EXPECT_EQ(Environment.Runtime().Shutdown().Status,
                  Preview::Diagnose::SubmissionStatus::Accepted);

        const auto LogPath = Environment.Configuration().Logging.Directory /
                             Environment.Configuration().Logging.FileName;
        std::ifstream Input(LogPath, std::ios::binary);
        ASSERT_TRUE(Input.is_open());
        const std::string Contents{std::istreambuf_iterator<char>{Input},
                                   std::istreambuf_iterator<char>{}};
        EXPECT_EQ(CountText(Contents, "\"Message\":\"SessionClosed"), 1U);
        EXPECT_NE(Contents.find("\"Level\":\"Access\""), std::string::npos);
        EXPECT_NE(Contents.find("\"Kind\":\"Audit\""), std::string::npos);
        EXPECT_NE(Contents.find("\"Worker\":9003"), std::string::npos);
        EXPECT_NE(Contents.find("\"Session\":8002"), std::string::npos);
        EXPECT_NE(Contents.find("\"Process\":6000"), std::string::npos);
        EXPECT_NE(Contents.find("\"Task\":7001"), std::string::npos);
    }

    TEST(SessionLogging, InfoContainsOnlyAuthenticationAndTargetRequest)
    {
        Preview::TestSupport::DiagnoseTestEnvironment Environment{"session-request-log"};
        Environment.Configuration().Logging.Level = Preview::Diagnose::LogLevel::Info;
        ASSERT_TRUE(Environment.Install().has_value());

        Net::io_context Ioc;
        auto [Client, Inbound] = MakeSharedPair(Ioc);
        auto [Upstream, Outbound] = MakeSharedPair(Ioc);
        Upstream->Close();

        Preview::Runtime::SessionOptions Options;
        Options.SourceIp = "192.0.2.8";
        Options.AcceptProtocol = [](Preview::SharedTransmission &,
                                    Preview::Middleware::Context &Context)
            -> Net::awaitable<Preview::Fault::Code>
        {
            Context.Target.Host = "example.com";
            Context.Target.Port = "443";
            Context.Target.Positive = true;
            Context.AccountId = Preview::AccountId{9004};
            Context.DisplayIdentity = "Alice";
            Context.ProtocolAuthenticated = true;
            co_return Preview::Fault::Code::Success;
        };
        Options.Dial = [Outbound](const Preview::Network::Target &)
            -> Net::awaitable<std::pair<Preview::Fault::Code, Preview::SharedTransmission>>
        {
            co_return std::pair{Preview::Fault::Code::Success, Outbound};
        };
        Preview::Runtime::Session Session(std::move(Options));

        auto Result = Preview::Fault::Code::GenericError;
        Preview::Testing::RunCoro(
            Ioc,
            [&]() -> Net::awaitable<void>
            {
                const std::array<std::byte, 5> Payload{
                    std::byte{0xA1}, std::byte{0xB2}, std::byte{0xC3},
                    std::byte{0xD4}, std::byte{0xE5}};
                std::error_code Error;
                (void)co_await Client->async_write_some(Payload, Error);
                Client->Close();
                Result = co_await Session.Run(Inbound);
            });

        EXPECT_NE(Result, Preview::Fault::Code::AuthFailed);
        EXPECT_EQ(Environment.Runtime().Shutdown().Status,
                  Preview::Diagnose::SubmissionStatus::Accepted);

        const auto LogPath = Environment.Configuration().Logging.Directory /
                             Environment.Configuration().Logging.FileName;
        std::ifstream Input(LogPath, std::ios::binary);
        ASSERT_TRUE(Input.is_open());
        const std::string Contents{std::istreambuf_iterator<char>{Input},
                                   std::istreambuf_iterator<char>{}};
        EXPECT_EQ(CountText(Contents,
                            "AuthenticationSucceeded SourceIp=192.0.2.8 User=Alice"),
                  1U);
        EXPECT_EQ(CountText(Contents,
                            "Request SourceIp=192.0.2.8 Target=example.com:443 User=Alice"),
                  1U);
        EXPECT_EQ(Contents.find("SessionStarted"), std::string::npos);
        EXPECT_EQ(Contents.find("DialStarted"), std::string::npos);
    }

} // namespace
