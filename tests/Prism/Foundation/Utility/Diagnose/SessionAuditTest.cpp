/**
 * @file SessionAuditTest.cpp
 * @brief Session 关闭审计事件集成测试。
 */
#include <gtest/gtest.h>
#include <TestSupport/Fixtures/StreamFactory.hpp>

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

#include <Prism/Foundation/Utility/Diagnose/Facade.hpp>
#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Foundation/Utility/Diagnose/FieldKey.hpp>
#include <Prism/Foundation/Utility/Diagnose/ContextState.hpp>
#include <Prism/Lifecycle/TaskState.hpp>
#include <Prism/Runtime/Middleware/Context.hpp>
#include <Prism/Runtime/Session.hpp>
#include <Prism/Runtime/SessionServices.hpp>
#include <Prism/Transport/MemoryStream.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>
#include <TestSupport/Fixtures/TaskRegistryAccess.hpp>
#include <TestSupport/Prism/DiagnoseTestEnvironment.hpp>

namespace
{

    namespace Net = boost::asio;

    auto MakeSharedPair(Net::io_context &Ioc)
        -> std::pair<std::shared_ptr<Prism::MemoryStream>,
                     std::shared_ptr<Prism::MemoryStream>>
    {
        auto [First, Second] = Prism::MakeMemoryPair(Ioc.get_executor());
        return {std::make_shared<Prism::MemoryStream>(std::move(First)),
                std::make_shared<Prism::MemoryStream>(std::move(Second))};
    }

    auto EmptyOperation() -> Net::awaitable<void>
    {
        co_return;
    }

    auto MakeSessionControl(Net::any_io_executor Executor)
        -> std::shared_ptr<Prism::Runtime::SessionControl>
    {
        auto Control = std::make_shared<Prism::Runtime::SessionControl>(std::move(Executor));
        Prism::Lifecycle::TaskRequest Request;
        Request.Context.SessionId = Prism::SessionId{8002};
        Request.Context.WorkerId = Prism::WorkerId{9003};
        Request.Context.Generation = Prism::GenerationId{10004};
        if (!Control->Start(std::move(Request), EmptyOperation()))
        {
            return {};
        }
        return Control;
    }

    /** @brief 复用原场景的五字节输入，传输 owner 保活到会话返回。 */
    auto RunSessionRequest(Prism::Runtime::Session& Session,
        std::pair<std::shared_ptr<Prism::MemoryStream>, std::shared_ptr<Prism::MemoryStream>> Pair)
        -> Net::awaitable<Prism::Fault::Failure>
    {
        const std::array<std::byte, 5> Payload{
            std::byte{0xA1}, std::byte{0xB2}, std::byte{0xC3}, std::byte{0xD4}, std::byte{0xE5}};
        std::error_code Error;
        const auto Write = co_await Pair.first->WriteSome(Payload);
        Error = Prism::Fault::ToNative(Write.Failure);
        (void)Pair.first->Close();
        co_return co_await Session.Run(std::move(Pair.second));
    }

    /** @brief 原认证场景的正式结果，保持目标、身份和认证输入。 */
    auto AcceptAuthenticatedTarget(Prism::Contract::StreamAcceptInput Input)
        -> Net::awaitable<Prism::Contract::AcceptOutcome>
    {
        (void)Input.Metadata;
        Prism::Contract::ProtocolDataPlane Plane;
        Plane.Root = Prism::Contract::StreamDataPlane{std::move(Input.Inbound)};
        Plane.Protocol = Prism::Contract::ProtocolType::Http;
        Plane.Target.Host = *Prism::Network::ParseHost("example.com");
        Plane.Target.Port = 443;
        Plane.Target.Route = Prism::Network::RouteKind::Forward;
        Plane.AccountId = Prism::AccountId{9004};
        Plane.DisplayIdentity = "Alice";
        Plane.ProtocolAuthenticated = true;
        co_return Plane;
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
        Prism::TestSupport::DiagnoseTestEnvironment Environment{"session-audit"};
        Environment.Configuration().Mode = Prism::Diagnose::RenderMode::Structured;
        ASSERT_TRUE(Environment.Install().has_value());

        Net::io_context Ioc;
        auto [Client, Inbound] = MakeSharedPair(Ioc);
        auto Services = std::make_shared<Prism::Runtime::SessionServices>();
        Services->Bytes = std::make_shared<Prism::Memory::BytePool>(
            Prism::Memory::BytePoolOptions{.BlockCount = 8U});
        Services->ProcessContext = Prism::Diagnose::ContextState::Empty()
                                       .With(Prism::Diagnose::Fields::Process,
                                             Prism::ProcessId{6000})
                                       .With(Prism::Diagnose::Fields::Generation,
                                             Prism::GenerationId{10004});
        const auto SavedNextTaskId = Prism::Lifecycle::TaskRegistryTestAccess::ExchangeNextId(7001U);
        auto Control = MakeSessionControl(Ioc.get_executor());
        ASSERT_NE(Control, nullptr);

        Prism::Recognition::ProfileSpec ProfileSpec;
        ProfileSpec.Mode = Prism::Recognition::RecognitionMode::Configured;
        ProfileSpec.ConfiguredCandidate = 7;
        Prism::Recognition::CandidateSpec Candidate;
        Candidate.Id = 7;
        Candidate.Name = "safe-candidate";
        Candidate.Protocol = Prism::Contract::ProtocolType::Http;
        Candidate.FirstBytes = {0xA1};
        Candidate.MinimumBytes = 5U;
        Candidate.Inspect = [](const Prism::Recognition::ProbeSnapshot &)
        {
            return Prism::Recognition::MatchState::Rejected;
        };
        Candidate.Commit = [](Prism::Recognition::CommitContext Context)
            -> Net::awaitable<Prism::Recognition::CommitResult>
        {
            Prism::Recognition::CommitResult Result;
            Result.Candidate = Context.Candidate;
            Result.Status = Prism::Recognition::RecognitionStatus::NoMatch;
            co_return Result;
        };
        ProfileSpec.Candidates.push_back(std::move(Candidate));
        const auto CompiledProfile =
            Prism::Recognition::Profile::Compile(std::move(ProfileSpec));
        ASSERT_TRUE(CompiledProfile.has_value());

        Prism::Runtime::SessionOptions Options;
        Options.Services = Services;
        Options.Control = Control;
        Options.Services->Profile = *CompiledProfile;
        Prism::Runtime::Session Session(std::move(Options));

        Prism::Fault::Failure Result{};
        std::expected<void, Prism::Fault::Failure> Drained =
            std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::GenericError});
        Prism::Testing::RunCoro(
            Ioc,
            [&]() -> Net::awaitable<void>
            {
                Result = co_await RunSessionRequest(Session, {Client, Inbound});
                Drained = co_await Control->Drain();
            });

        if (Drained)
        {
            (void)Prism::Lifecycle::TaskRegistryTestAccess::ExchangeNextId(SavedNextTaskId);
        }
        EXPECT_TRUE(Drained.has_value());
        EXPECT_EQ(Result.Code, Prism::Fault::Code::ProtocolError);
        EXPECT_EQ(Control->Metrics().CloseCalls, 1U);
        EXPECT_EQ(Environment.Runtime().Shutdown().Status,
                  Prism::Diagnose::SubmissionStatus::Closed);

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
        Prism::TestSupport::DiagnoseTestEnvironment Environment{"session-request-log"};
        Environment.Configuration().Logging.Level = Prism::Diagnose::LogLevel::Info;
        ASSERT_TRUE(Environment.Install().has_value());

        Net::io_context Ioc;
        auto [Client, Inbound] = MakeSharedPair(Ioc);
        auto [Upstream, Outbound] = MakeSharedPair(Ioc);
        (void)Upstream->Close();

        Prism::Runtime::SessionOptions Options;
        Options.SourceIp = "192.0.2.8";
        Options.Services->AcceptProtocol =
            std::make_shared<Prism::Testing::StreamFactory>(&AcceptAuthenticatedTarget);
        Options.Services->Dial = [Outbound](const Prism::Network::Target &)
            -> Net::awaitable<std::expected<Prism::SharedTransmission, Prism::Fault::Failure>>
        {
            co_return Outbound;
        };
        Prism::Runtime::Session Session(std::move(Options));

        Prism::Fault::Failure Result{Prism::Fault::Code::GenericError, {}};
        Prism::Testing::RunCoro(
            Ioc,
            [&]() -> Net::awaitable<void>
            {
                Result = co_await RunSessionRequest(Session, {Client, Inbound});
            });

        EXPECT_NE(Result.Code, Prism::Fault::Code::AuthFailed);
        EXPECT_EQ(Environment.Runtime().Shutdown().Status,
                  Prism::Diagnose::SubmissionStatus::Closed);

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
