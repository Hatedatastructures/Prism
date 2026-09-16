/**
 * @file SessionOrchestrationTest.cpp
 * @brief 会话编排测试（T4-2）
 * @details 覆盖：
 *          - 识别成功 → 装配 → 管线 → 数据转发（echo 往返）
 *          - 未知协议 / 识别失败 → protocol_error
 *          - 认证中途拒绝 → auth_failed 管线终止
 *          - relay 结束 → traffic sink 收到按 identity 聚合的流量
 *          - Prepare 回调装配 Target → Dial 拿到正确目标
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <string>
#include <string_view>

#include <Preview/Foundation/Authenticator.hpp>
#include <Preview/Foundation/Fault/Code.hpp>
#include <Preview/Foundation/Fault/Handling.hpp>
#include <Preview/Foundation/Utility/Diagnose/Logger.hpp>
#include <Preview/Lifecycle/TaskState.hpp>
#include <Preview/Runtime/Middleware/Context.hpp>
#include <Preview/Runtime/Session.hpp>
#include <Preview/Transport/MemoryStream.hpp>
#include <Preview/Transport/Transmission.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>

namespace
{

    namespace Net = boost::asio;
    using Preview::MakeMemoryPair;
    using Preview::MemoryStream;
    using Preview::SharedTransmission;

    using Preview::Testing::RunCoro; // 公共样板（见 <TestSupport/Fixtures/RuntimeTestHelpers.hpp>）

    using CompletionChannel = Net::experimental::channel<void(boost::system::error_code)>;

    auto SpawnAndSignal(Net::any_io_executor Executor, Net::awaitable<void> Task)
        -> std::shared_ptr<CompletionChannel>
    {
        auto Done = std::make_shared<CompletionChannel>(Executor, 1);
        Net::co_spawn(Executor, std::move(Task),
                      [Done](std::exception_ptr Failure)
                      {
                          boost::system::error_code ErrorCode;
                          if (Failure)
                          {
                              ErrorCode = boost::system::errc::make_error_code(
                                  boost::system::errc::io_error);
                          }
                          Done->try_send(ErrorCode);
                      });
        return Done;
    }

    auto SpawnAndSignal(Net::any_io_executor Executor,
                        Net::awaitable<Preview::Fault::Code> Task)
        -> std::shared_ptr<CompletionChannel>
    {
        auto Done = std::make_shared<CompletionChannel>(Executor, 1);
        Net::co_spawn(Executor, std::move(Task),
                      [Done](std::exception_ptr Failure, Preview::Fault::Code)
                      {
                          boost::system::error_code ErrorCode;
                          if (Failure)
                          {
                              ErrorCode = boost::system::errc::make_error_code(
                                  boost::system::errc::io_error);
                          }
                          Done->try_send(ErrorCode);
                      });
        return Done;
    }

    /// 测试流量统计 sink
    class test_traffic_sink final : public Preview::Middleware::Context::TrafficSink
    {
    public:
        void Report(std::string_view identity, std::size_t up, std::size_t down) override
        {
            last_identity = std::string(identity);
            total_up += up;
            total_down += down;
            ++calls;
        }
        std::string last_identity;
        std::size_t total_up{0};
        std::size_t total_down{0};
        int calls{0};
    };

    /// 回显上游：读到的数据原样写回（detached 运行，直至 EOF）
    auto echo_upstream(SharedTransmission client_side) -> Net::awaitable<void>
    {
        std::array<std::byte, 4096> buf{};
        std::error_code ec;
        while (true)
        {
            const auto n = co_await client_side->async_read_some(std::span<std::byte>(buf), ec);
            if (ec || n == 0)
            {
                break;
            }
            co_await client_side->async_write_some(std::span<const std::byte>(buf.data(), n), ec);
            if (ec)
            {
                break;
            }
        }
        client_side->Close();
    }

    auto consume_upstream(SharedTransmission upstream) -> Net::awaitable<void>
    {
        std::array<std::byte, 64> Buffer{};
        std::error_code ReadEc;
        (void)co_await upstream->async_read_some(Buffer, ReadEc);
        upstream->Close();
    }

    /// 构造可识别的首包（socks5 Greeting：0x05 0x01 0x00）
    auto socks5_greeting() -> std::string
    {
        return std::string("\x05\x01\x00", 3);
    }

    /// 内存流对 → shared 包装
    auto make_pair_shared(Net::io_context &ioc)
        -> std::pair<std::shared_ptr<MemoryStream>, std::shared_ptr<MemoryStream>>
    {
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        return {std::make_shared<MemoryStream>(std::move(a)),
                std::make_shared<MemoryStream>(std::move(b))};
    }

    auto EmptySessionOperation() -> Net::awaitable<void>
    {
        co_return;
    }

    auto MakeDiagnosticControl(Net::any_io_executor Executor)
        -> std::shared_ptr<Preview::Runtime::SessionControl>
    {
        auto Control = std::make_shared<Preview::Runtime::SessionControl>(std::move(Executor));
        Preview::Lifecycle::TaskRequest Request;
        Request.Identity.TaskId = Preview::TaskId{7001};
        Request.Identity.SessionId = Preview::SessionId{8002};
        Request.Identity.WorkerId = Preview::WorkerId{9003};
        Request.Identity.Generation = Preview::GenerationId{10004};
        if (!Control->Start(std::move(Request), EmptySessionOperation()))
        {
            return {};
        }
        return Control;
    }

    auto MakeSessionLogDirectory() -> std::filesystem::path
    {
        static std::uint64_t Index = 0;
        const auto Directory = std::filesystem::temp_directory_path() /
                               ("prism_preview_session_log_" + std::to_string(++Index));
        std::error_code Error;
        std::filesystem::remove_all(Directory, Error);
        return Directory;
    }

    auto ReadSessionLog(const std::filesystem::path &Directory) -> std::string
    {
        std::ifstream Input(Directory / "preview.log", std::ios::binary);
        return {std::istreambuf_iterator<char>(Input), std::istreambuf_iterator<char>()};
    }

    auto CountText(std::string_view Text, std::string_view Needle) -> std::size_t
    {
        std::size_t Count = 0;
        std::size_t Offset = 0;
        while ((Offset = Text.find(Needle, Offset)) != std::string_view::npos)
        {
            ++Count;
            Offset += Needle.size();
        }
        return Count;
    }

    /// 基础会话选项：识别 socks5 + Prepare 装配 + Dial 注入出站
    auto base_options(std::shared_ptr<MemoryStream> outbound_s,
                      std::chrono::milliseconds idle = std::chrono::seconds(60))
        -> Preview::Runtime::SessionOptions
    {
        Preview::Runtime::SessionOptions opts;
        opts.RelayIdleTimeout = idle;
        opts.Prepare = [](const Preview::Recognition::RecognizeResult &,
                          Preview::Middleware::Context &ctx) -> Net::awaitable<Preview::Fault::Code>
        {
            ctx.Target.Positive = true;
            ctx.Target.Host = "upstream.test";
            ctx.Target.Port = "8080";
            co_return Preview::Fault::Code::Success;
        };
        opts.Dial = [outbound_s](const Preview::Network::Target &) -> Net::awaitable<
            std::pair<Preview::Fault::Code, Preview::SharedTransmission>>
        {
            co_return std::pair{Preview::Fault::Code::Success, outbound_s};
        };
        return opts;
    }

    TEST(SessionOrchestration, RecognizeAndRelay)
    {
        Net::io_context ioc;
        auto [client_s, inbound_s] = make_pair_shared(ioc);
        auto [outbound_s, upstream_s] = make_pair_shared(ioc);

        Preview::Runtime::Session Session(base_options(outbound_s));

        RunCoro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto session_done = SpawnAndSignal(ioc.get_executor(), Session.Run(inbound_s));
                     auto echo_done = SpawnAndSignal(ioc.get_executor(), echo_upstream(upstream_s));

                     // 客户端发 socks5 首包
                     std::error_code wec;
                     const auto payload = socks5_greeting();
                     co_await client_s->async_write_some(
                         std::span<const std::byte>(reinterpret_cast<const std::byte *>(payload.data()),
                                                    payload.size()),
                         wec);

                     // 上游回显 → 客户端收到
                     std::array<std::byte, 64> rbuf{};
                     std::error_code rec;
                     const auto rn = co_await client_s->async_read_some(std::span<std::byte>(rbuf), rec);
                     EXPECT_EQ(std::string_view(reinterpret_cast<const char *>(rbuf.data()), rn), payload);

                     client_s->Close();
                     inbound_s->Close();
                     upstream_s->Close();
                     outbound_s->Close();
                     boost::system::error_code session_ec;
                     boost::system::error_code echo_ec;
                     co_await session_done->async_receive(
                         Net::redirect_error(Net::use_awaitable, session_ec));
                     co_await echo_done->async_receive(
                         Net::redirect_error(Net::use_awaitable, echo_ec));
                     EXPECT_FALSE(session_ec);
                     EXPECT_FALSE(echo_ec);
                 });
    }

    TEST(SessionOrchestration, UnknownProtocolRejected)
    {
        Net::io_context ioc;
        auto [client_s, inbound_s] = make_pair_shared(ioc);

        Preview::Runtime::SessionOptions opts;
        Preview::Runtime::Session Session(opts);

        Preview::Fault::Code rc = Preview::Fault::Code::Success;
        RunCoro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     // 垃圾首包（不可识别）
                     const std::string garbage = "\xff\xfe\xfd\xfc\xfb";
                     std::error_code wec;
                     co_await client_s->async_write_some(
                         std::span<const std::byte>(reinterpret_cast<const std::byte *>(garbage.data()),
                                                    garbage.size()),
                         wec);
                     client_s->Close();
                     rc = co_await Session.Run(inbound_s);
                 });
        EXPECT_EQ(rc, Preview::Fault::Code::ProtocolError);
        EXPECT_FALSE(inbound_s->IsOpen());
    }

    TEST(SessionOrchestration, DialFailureClosesInbound)
    {
        Net::io_context ioc;
        auto [client_s, inbound_s] = make_pair_shared(ioc);

        Preview::Runtime::SessionOptions opts;
        opts.AcceptProtocol = [](Preview::SharedTransmission &, Preview::Middleware::Context &)
            -> Net::awaitable<Preview::Fault::Code>
        {
            co_return Preview::Fault::Code::Success;
        };
        opts.Dial = [](const Preview::Network::Target &)
            -> Net::awaitable<std::pair<Preview::Fault::Code, Preview::SharedTransmission>>
        {
            co_return std::pair{Preview::Fault::Code::BadGateway, Preview::SharedTransmission{}};
        };
        Preview::Runtime::Session Session(opts);

        Preview::Fault::Code rc = Preview::Fault::Code::Success;
        RunCoro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     const auto Greeting = socks5_greeting();
                     std::error_code wec;
                     co_await client_s->async_write_some(
                         std::span<const std::byte>(reinterpret_cast<const std::byte *>(Greeting.data()),
                                                    Greeting.size()),
                         wec);
                     rc = co_await Session.Run(inbound_s);
                     client_s->Close();
                 });

        EXPECT_EQ(rc, Preview::Fault::Code::BadGateway);
        EXPECT_FALSE(inbound_s->IsOpen());
    }

    TEST(SessionOrchestration, NullDialResultClosesInbound)
    {
        Net::io_context ioc;
        auto [client_s, inbound_s] = make_pair_shared(ioc);

        Preview::Runtime::SessionOptions opts;
        opts.AcceptProtocol = [](Preview::SharedTransmission &, Preview::Middleware::Context &)
            -> Net::awaitable<Preview::Fault::Code>
        {
            co_return Preview::Fault::Code::Success;
        };
        opts.Dial = [](const Preview::Network::Target &)
            -> Net::awaitable<std::pair<Preview::Fault::Code, Preview::SharedTransmission>>
        {
            co_return std::pair{Preview::Fault::Code::Success, Preview::SharedTransmission{}};
        };
        Preview::Runtime::Session Session(opts);

        Preview::Fault::Code rc = Preview::Fault::Code::Success;
        RunCoro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     const auto Greeting = socks5_greeting();
                     std::error_code wec;
                     co_await client_s->async_write_some(
                         std::span<const std::byte>(reinterpret_cast<const std::byte *>(Greeting.data()),
                                                    Greeting.size()),
                         wec);
                     rc = co_await Session.Run(inbound_s);
                     client_s->Close();
                 });

        EXPECT_EQ(rc, Preview::Fault::Code::BadGateway);
        EXPECT_FALSE(inbound_s->IsOpen());
    }

    TEST(SessionOrchestration, AuthRejectedMidway)
    {
        Net::io_context ioc;
        auto [client_s, inbound_s] = make_pair_shared(ioc);

        Preview::Runtime::SessionOptions opts;
        opts.Auth = std::make_shared<Preview::RejectAuthenticator>();
        opts.Prepare = [](const Preview::Recognition::RecognizeResult &,
                          Preview::Middleware::Context &ctx) -> Net::awaitable<Preview::Fault::Code>
        {
            ctx.RawIdentity = "alice";
            ctx.SetCredential(Preview::Account::Credential::Password("bad"));
            co_return Preview::Fault::Code::Success;
        };
        Preview::Runtime::Session Session(opts);

        Preview::Fault::Code rc = Preview::Fault::Code::Success;
        RunCoro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     std::error_code wec;
                     const auto payload = socks5_greeting();
                     co_await client_s->async_write_some(
                         std::span<const std::byte>(reinterpret_cast<const std::byte *>(payload.data()),
                                                    payload.size()),
                         wec);
                     rc = co_await Session.Run(inbound_s);
                 });
        EXPECT_EQ(rc, Preview::Fault::Code::AuthFailed);
    }

    TEST(SessionOrchestration, TrafficReportedOnRelayEnd)
    {
        Net::io_context ioc;
        auto [client_s, inbound_s] = make_pair_shared(ioc);
        auto [outbound_s, upstream_s] = make_pair_shared(ioc);

        test_traffic_sink sink;
        auto opts = base_options(outbound_s, std::chrono::milliseconds(50));
        opts.Auth = std::make_shared<Preview::StaticAuthenticator>("alice", "pw");
        opts.traffic = &sink;
        opts.Prepare = [](const Preview::Recognition::RecognizeResult &,
                          Preview::Middleware::Context &ctx) -> Net::awaitable<Preview::Fault::Code>
        {
            ctx.Target.Positive = true;
            ctx.RawIdentity = "alice";
            ctx.SetCredential(Preview::Account::Credential::Password("pw"));
            co_return Preview::Fault::Code::Success;
        };
        Preview::Runtime::Session Session(opts);

        RunCoro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto session_done = SpawnAndSignal(ioc.get_executor(), Session.Run(inbound_s));
                     auto echo_done = SpawnAndSignal(ioc.get_executor(), echo_upstream(upstream_s));

                     std::error_code wec;
                     const auto payload = socks5_greeting();
                     co_await client_s->async_write_some(
                         std::span<const std::byte>(reinterpret_cast<const std::byte *>(payload.data()),
                                                    payload.size()),
                         wec);
                     // 等回显（relay 转发 → echo → 回显）
                     std::array<std::byte, 64> buf{};
                     std::error_code sec;
                     const auto n = co_await client_s->async_read_some(std::span<std::byte>(buf), sec);
                     EXPECT_EQ(std::string_view(reinterpret_cast<const char *>(buf.data()), n), payload);

                     // 空闲 50ms → relay 超时关闭 → 会话结束 → 上报
                     Net::steady_timer t(ioc);
                     t.expires_after(std::chrono::milliseconds(300));
                     co_await t.async_wait(Net::use_awaitable);
                     client_s->Close();
                     inbound_s->Close();
                     upstream_s->Close();
                     outbound_s->Close();
                     boost::system::error_code session_ec;
                     boost::system::error_code echo_ec;
                     co_await session_done->async_receive(
                         Net::redirect_error(Net::use_awaitable, session_ec));
                     co_await echo_done->async_receive(
                         Net::redirect_error(Net::use_awaitable, echo_ec));
                     EXPECT_FALSE(session_ec);
                     EXPECT_FALSE(echo_ec);
                 });
        EXPECT_GT(sink.calls, 0);
        EXPECT_GE(sink.total_up, socks5_greeting().size());
        EXPECT_EQ(sink.last_identity, "alice");
    }

    TEST(SessionOrchestration, PrepareSetsTargetForDial)
    {
        Net::io_context ioc;
        auto [client_s, inbound_s] = make_pair_shared(ioc);
        auto [outbound_s, upstream_s] = make_pair_shared(ioc);

        std::string dialed_host;
        std::string dialed_port;
        Preview::Runtime::SessionOptions opts;
        opts.Prepare = [](const Preview::Recognition::RecognizeResult &,
                          Preview::Middleware::Context &ctx) -> Net::awaitable<Preview::Fault::Code>
        {
            ctx.Target.Positive = true;
            ctx.Target.Host = "Target.test";
            ctx.Target.Port = "443";
            co_return Preview::Fault::Code::Success;
        };
        opts.Dial = [&](const Preview::Network::Target &t) -> Net::awaitable<
            std::pair<Preview::Fault::Code, Preview::SharedTransmission>>
        {
            dialed_host = t.Host;
            dialed_port = t.Port;
            co_return std::pair{Preview::Fault::Code::Success, outbound_s};
        };
        Preview::Runtime::Session Session(opts);

        Preview::Fault::Code rc = Preview::Fault::Code::Success;
        RunCoro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto echo_done = SpawnAndSignal(ioc.get_executor(), consume_upstream(upstream_s));

                     std::error_code wec;
                     const auto payload = socks5_greeting();
                     co_await client_s->async_write_some(
                         std::span<const std::byte>(reinterpret_cast<const std::byte *>(payload.data()),
                                                    payload.size()),
                         wec);
                     client_s->Close(); // EOF → relay 立即结束
                     rc = co_await Session.Run(inbound_s);
                     boost::system::error_code echo_ec;
                     co_await echo_done->async_receive(
                         Net::redirect_error(Net::use_awaitable, echo_ec));
                     EXPECT_FALSE(echo_ec);
                 });
        EXPECT_EQ(rc, Preview::Fault::Code::Success);
        EXPECT_EQ(dialed_host, "Target.test");
        EXPECT_EQ(dialed_port, "443");
    }

    TEST(SessionDiagnostics, FailureRecordContainsSafeRecognitionMetadataAndClosesOnce)
    {
        Net::io_context Ioc;
        auto [Client, Inbound] = make_pair_shared(Ioc);
        const auto Directory = MakeSessionLogDirectory();

        Preview::Diagnose::LoggerOptions LoggerOptions;
        LoggerOptions.Directory = Directory;
        LoggerOptions.FileName = "preview.log";
        auto Created = Preview::Diagnose::Logger::Create(std::move(LoggerOptions));
        ASSERT_TRUE(Created.has_value()) << Created.error().Message;
        auto Logger = std::move(*Created);

        auto Services = std::make_shared<Preview::Runtime::SessionServices>();
        Services->Logger = Logger;
        auto Control = MakeDiagnosticControl(Ioc.get_executor());
        ASSERT_NE(Control, nullptr);

        Preview::Recognition::ProfileSpec ProfileSpec;
        ProfileSpec.Mode = Preview::Recognition::RecognitionMode::Configured;
        ProfileSpec.ConfiguredCandidate = 7;
        Preview::Recognition::CandidateSpec Candidate;
        Candidate.Id = 7;
        Candidate.Name = "safe-candidate";
        Candidate.Protocol = Preview::Recognition::ProtocolType::Http;
        Candidate.FirstBytes = {0xA1};
        Candidate.MinimumBytes = 5;
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
        auto CompiledProfile = Preview::Recognition::Profile::Compile(std::move(ProfileSpec));
        ASSERT_TRUE(CompiledProfile.has_value());
        ASSERT_EQ((*CompiledProfile)->CandidateCount(), 1U);
        EXPECT_EQ((*CompiledProfile)->CandidateIdAt(0), 7U);
        EXPECT_EQ((*CompiledProfile)->CandidateName(7), "safe-candidate");
        EXPECT_EQ((*CompiledProfile)->CandidateProtocol(7),
                  Preview::Recognition::ProtocolType::Http);

        Preview::Runtime::SessionOptions Options;
        Options.Services = Services;
        Options.Control = Control;
        Options.Profile = *CompiledProfile;
        Preview::Runtime::Session Session(std::move(Options));

        Preview::Fault::Code Result = Preview::Fault::Code::Success;
        RunCoro(Ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     const std::array<std::byte, 5> Payload{
                         std::byte{0xA1}, std::byte{0xB2}, std::byte{0xC3}, std::byte{0xD4}, std::byte{0xE5}};
                     std::error_code Error;
                     co_await Client->async_write_some(Payload, Error);
                     Client->Close();
                     Result = co_await Session.Run(Inbound);
                 });

        EXPECT_EQ(Result, Preview::Fault::Code::ProtocolError);
        Logger->Stop();
        const auto Contents = ReadSessionLog(Directory);
        EXPECT_NE(Contents.find("stage=recognition"), std::string::npos);
        EXPECT_NE(Contents.find("status=no_match"), std::string::npos);
        EXPECT_NE(Contents.find("candidate_id=7"), std::string::npos);
        EXPECT_NE(Contents.find("candidate_name=safe-candidate"), std::string::npos);
        EXPECT_NE(Contents.find("detected=http"), std::string::npos);
        EXPECT_NE(Contents.find("probe_bytes=5"), std::string::npos);
        EXPECT_NE(Contents.find("crypto_trials=0"), std::string::npos);
        EXPECT_NE(Contents.find("probe_first_byte=0xA1"), std::string::npos);
        EXPECT_NE(Contents.find("probe_length=5"), std::string::npos);
        EXPECT_NE(Contents.find("error_code=none"), std::string::npos);
        EXPECT_NE(Contents.find("fault_code=protocol_error"), std::string::npos);
        EXPECT_NE(Contents.find("[Correlation=7001]"), std::string::npos);
        EXPECT_NE(Contents.find("[Worker=9003]"), std::string::npos);
        EXPECT_NE(Contents.find("[Session=8002]"), std::string::npos);
        EXPECT_NE(Contents.find("generation_id=10004"), std::string::npos);
        EXPECT_EQ(Contents.find("A1B2C3D4E5"), std::string::npos);
        EXPECT_EQ(Contents.find("secret-token"), std::string::npos);
        EXPECT_EQ(CountText(Contents, "stage=close"), 1U);
        EXPECT_EQ(Control->Metrics().CloseCalls, 1U);

        Services->Logger.reset();
        Logger.reset();
        std::error_code CleanupError;
        std::filesystem::remove_all(Directory, CleanupError);
        EXPECT_FALSE(CleanupError);
    }

    TEST(SessionDiagnostics, SuccessRecordsOrderedLifecycleStages)
    {
        Net::io_context Ioc;
        auto [Client, Inbound] = make_pair_shared(Ioc);
        auto [Outbound, Upstream] = make_pair_shared(Ioc);
        const auto Directory = MakeSessionLogDirectory();

        Preview::Diagnose::LoggerOptions LoggerOptions;
        LoggerOptions.Directory = Directory;
        LoggerOptions.FileName = "preview.log";
        auto Created = Preview::Diagnose::Logger::Create(std::move(LoggerOptions));
        ASSERT_TRUE(Created.has_value()) << Created.error().Message;
        auto Logger = std::move(*Created);

        auto Options = base_options(Outbound, std::chrono::milliseconds(50));
        auto Services = std::make_shared<Preview::Runtime::SessionServices>();
        Services->Logger = Logger;
        Services->RelayIdleTimeout = Options.RelayIdleTimeout;
        Services->Prepare = Options.Prepare;
        Services->Dial = Options.Dial;
        Options.Services = Services;
        Options.Control = MakeDiagnosticControl(Ioc.get_executor());
        ASSERT_NE(Options.Control, nullptr);
        Preview::Runtime::Session Session(std::move(Options));

        RunCoro(Ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto SessionDone = SpawnAndSignal(Ioc.get_executor(), Session.Run(Inbound));
                     auto EchoDone = SpawnAndSignal(Ioc.get_executor(), echo_upstream(Upstream));
                     const auto Payload = socks5_greeting();
                     std::error_code Error;
                     co_await Client->async_write_some(
                         std::span<const std::byte>(reinterpret_cast<const std::byte *>(Payload.data()),
                                                    Payload.size()),
                         Error);
                     std::array<std::byte, 64> Reply{};
                     co_await Client->async_read_some(Reply, Error);
                     Client->Close();
                     Inbound->Close();
                     Upstream->Close();
                     Outbound->Close();
                     boost::system::error_code SessionError;
                     boost::system::error_code EchoError;
                     co_await SessionDone->async_receive(Net::redirect_error(Net::use_awaitable, SessionError));
                     co_await EchoDone->async_receive(Net::redirect_error(Net::use_awaitable, EchoError));
                     EXPECT_FALSE(SessionError);
                     EXPECT_FALSE(EchoError);
                 });

        Logger->Stop();
        const auto Contents = ReadSessionLog(Directory);
        EXPECT_NE(Contents.find("phase_sequence=recognition>accept>auth>dial>relay>close"),
                  std::string::npos);
        EXPECT_EQ(CountText(Contents, "stage=close"), 1U);

        Services->Logger.reset();
        Logger.reset();
        std::error_code CleanupError;
        std::filesystem::remove_all(Directory, CleanupError);
        EXPECT_FALSE(CleanupError);
    }

} // namespace
