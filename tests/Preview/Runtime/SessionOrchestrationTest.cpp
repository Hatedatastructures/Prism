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
#include <TestSupport/Preview/ProviderBindings.hpp>

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
#include <memory>
#include <string>
#include <string_view>
#include <utility>

#include <Preview/Account/Authenticator.hpp>
#include <Preview/Foundation/Fault/Code.hpp>
#include <Preview/Foundation/Fault/Handling.hpp>
#include <Preview/Foundation/Memory/BytePool.hpp>
#include <Preview/Lifecycle/TaskState.hpp>
#include <Preview/Runtime/Middleware/Context.hpp>
#include <Preview/Runtime/Session.hpp>
#include <Preview/Transport/MemoryStream.hpp>
#include <Preview/Transport/Transmission.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>
#include <TestSupport/Fixtures/StreamFactory.hpp>

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
                        Net::awaitable<Preview::Fault::Failure> Task)
        -> std::shared_ptr<CompletionChannel>
    {
        auto Done = std::make_shared<CompletionChannel>(Executor, 1);
        Net::co_spawn(Executor, std::move(Task),
                      [Done](std::exception_ptr Failure, Preview::Fault::Failure)
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
    class TestTrafficSink final : public Preview::Foundation::TrafficSink
    {
    public:
        void Report(Preview::Foundation::TrafficEvent Event) noexcept override
        {
            LastAccount = Event.Account;
            TotalUp += Event.Up;
            TotalDown += Event.Down;
            if (Event.Kind == Preview::Foundation::TrafficEventKind::Completed) ++Calls;
        }
        auto Retire(Preview::Foundation::TrafficRetirement Owner)
            -> boost::asio::awaitable<std::expected<void, Preview::Fault::Failure>> override
        { (void)Owner; co_return std::expected<void, Preview::Fault::Failure>{}; }
        Preview::AccountId LastAccount{};
        std::size_t TotalUp{0};
        std::size_t TotalDown{0};
        int Calls{0};
    };

    /// 回显上游：读到的数据原样写回（detached 运行，直至 EOF）
    auto EchoUpstream(SharedTransmission ClientSide) -> Net::awaitable<void>
    {
        std::array<std::byte, 4096> Buffer{};
        std::error_code Error;
        while (true)
        {
            const auto Read = co_await ClientSide->ReadSome(std::span<std::byte>(Buffer));
            Error = Preview::Fault::ToNative(Read.Failure);
            const auto BytesRead = Read.Bytes;
            if (Error || BytesRead == 0)
            {
                break;
            }
            const auto Write = co_await ClientSide->WriteSome(
                std::span<const std::byte>(Buffer.data(), BytesRead));
            Error = Preview::Fault::ToNative(Write.Failure);
            if (Error)
            {
                break;
            }
        }
        (void)ClientSide->Close();
    }

    auto ConsumeUpstream(SharedTransmission Upstream) -> Net::awaitable<void>
    {
        std::array<std::byte, 64> Buffer{};
        std::error_code Error;
        const auto Read = co_await Upstream->ReadSome(Buffer);
        Error = Preview::Fault::ToNative(Read.Failure);
        (void)Upstream->Close();
    }

    /// 构造可识别的首包（socks5 Greeting：0x05 0x01 0x00）
    auto Socks5Greeting() -> std::string
    {
        return std::string("\x05\x01\x00", 3);
    }

    /// 内存流对 → shared 包装
    auto MakePairShared(Net::io_context &Ioc)
        -> std::pair<std::shared_ptr<MemoryStream>, std::shared_ptr<MemoryStream>>
    {
        auto [First, Second] = MakeMemoryPair(Ioc.get_executor());
        return {std::make_shared<MemoryStream>(std::move(First)),
                std::make_shared<MemoryStream>(std::move(Second))};
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
        Request.Context.SessionId = Preview::SessionId{8002};
        Request.Context.WorkerId = Preview::WorkerId{9003};
        Request.Context.Generation = Preview::GenerationId{10004};
        if (!Control->Start(std::move(Request), EmptySessionOperation()))
        {
            return {};
        }
        if (!Control->CurrentIdentity().TaskId)
        {
            return {};
        }
        return Control;
    }

    auto MakeSessionOptions(Net::any_io_executor Executor)
        -> Preview::Runtime::SessionOptions
    {
        Preview::Runtime::SessionOptions Options;
        Options.Services->Bytes = std::make_shared<Preview::Memory::BytePool>();
        Options.Control = std::make_shared<Preview::Runtime::SessionControl>(
            std::move(Executor));
        return Options;
    }

    /// 基础会话选项：识别 socks5 + Prepare 装配 + Dial 注入出站
    auto BaseOptions(Net::any_io_executor Executor,
                     std::shared_ptr<MemoryStream> Outbound,
                     std::chrono::milliseconds Idle = std::chrono::seconds(60))
        -> Preview::Runtime::SessionOptions
    {
        auto Options = MakeSessionOptions(std::move(Executor));
        Options.Services->RelayIdleTimeout = Idle;
        Options.Services->AcceptProtocol = std::make_shared<Preview::Testing::StreamFactory>([](Preview::Contract::StreamAcceptInput Input) -> Net::awaitable<Preview::Contract::AcceptOutcome>
        {
            Preview::Contract::ProtocolDataPlane Plane;
            Plane.Root = Preview::Contract::StreamDataPlane{std::move(Input.Inbound)};
            Plane.Target.Route = Preview::Network::RouteKind::Forward;
            Plane.Target.Host = *Preview::Network::ParseHost("upstream.test");
            Plane.Target.Port = 8080;
            co_return Plane;
        });
        Options.Services->Dial = [Outbound](const Preview::Network::Target &) -> Net::awaitable<
            std::expected<Preview::SharedTransmission, Preview::Fault::Failure>>
        {
            co_return Outbound;
        };
        return Options;
    }

    struct RecognizeAndRelayRequest final
    {
        std::shared_ptr<Preview::Runtime::Session> Session;
        SharedTransmission Client;
        SharedTransmission Inbound;
        SharedTransmission Outbound;
        SharedTransmission Upstream;
    };

    auto RunRecognizeAndRelay(RecognizeAndRelayRequest Request) -> Net::awaitable<void>
    {
        auto SessionDone = SpawnAndSignal(
            Request.Inbound->Executor(), Request.Session->Run(Request.Inbound));
        auto EchoDone = SpawnAndSignal(
            Request.Upstream->Executor(), EchoUpstream(Request.Upstream));

        std::error_code WriteError;
        const auto Payload = Socks5Greeting();
        const auto Write = co_await Request.Client->WriteSome(
            std::span<const std::byte>(reinterpret_cast<const std::byte *>(Payload.data()),
                                       Payload.size()));
        WriteError = Preview::Fault::ToNative(Write.Failure);

        std::array<std::byte, 64> Reply{};
        std::error_code ReadError;
        const auto Read = co_await Request.Client->ReadSome(
            std::span<std::byte>(Reply));
        ReadError = Preview::Fault::ToNative(Read.Failure);
        const auto BytesRead = Read.Bytes;
        EXPECT_EQ(std::string_view(reinterpret_cast<const char *>(Reply.data()), BytesRead),
                  Payload);

        (void)Request.Client->Close();
        (void)Request.Inbound->Close();
        (void)Request.Upstream->Close();
        (void)Request.Outbound->Close();
        boost::system::error_code SessionError;
        boost::system::error_code EchoError;
        co_await SessionDone->async_receive(
            Net::redirect_error(Net::use_awaitable, SessionError));
        co_await EchoDone->async_receive(
            Net::redirect_error(Net::use_awaitable, EchoError));
        EXPECT_FALSE(SessionError);
        EXPECT_FALSE(EchoError);
    }

    struct SessionResult final
    {
        Preview::Fault::Code Value{Preview::Fault::Code::Success};
    };

    struct UnknownProtocolRequest final
    {
        std::shared_ptr<Preview::Runtime::Session> Session;
        SharedTransmission Client;
        SharedTransmission Inbound;
        std::shared_ptr<SessionResult> Result;
    };

    auto RunUnknownProtocol(UnknownProtocolRequest Request) -> Net::awaitable<void>
    {
        const std::string Garbage = "\xff\xfe\xfd\xfc\xfb";
        std::error_code WriteError;
        const auto Write = co_await Request.Client->WriteSome(
            std::span<const std::byte>(reinterpret_cast<const std::byte *>(Garbage.data()),
                                       Garbage.size()));
        WriteError = Preview::Fault::ToNative(Write.Failure);
        (void)Request.Client->Close();
        Request.Result->Value = (co_await Request.Session->Run(Request.Inbound)).Code;
    }

    struct DialFailureRequest final
    {
        std::shared_ptr<Preview::Runtime::Session> Session;
        SharedTransmission Client;
        SharedTransmission Inbound;
        std::shared_ptr<SessionResult> Result;
    };

    auto RunDialFailure(DialFailureRequest Request) -> Net::awaitable<void>
    {
        const auto Greeting = Socks5Greeting();
        std::error_code WriteError;
        const auto Write = co_await Request.Client->WriteSome(
            std::span<const std::byte>(reinterpret_cast<const std::byte *>(Greeting.data()),
                                       Greeting.size()));
        WriteError = Preview::Fault::ToNative(Write.Failure);
        Request.Result->Value = (co_await Request.Session->Run(Request.Inbound)).Code;
        (void)Request.Client->Close();
    }

    struct NullDialRequest final
    {
        std::shared_ptr<Preview::Runtime::Session> Session;
        SharedTransmission Client;
        SharedTransmission Inbound;
        std::shared_ptr<SessionResult> Result;
    };

    auto RunNullDial(NullDialRequest Request) -> Net::awaitable<void>
    {
        const auto Greeting = Socks5Greeting();
        std::error_code WriteError;
        const auto Write = co_await Request.Client->WriteSome(
            std::span<const std::byte>(reinterpret_cast<const std::byte *>(Greeting.data()),
                                       Greeting.size()));
        WriteError = Preview::Fault::ToNative(Write.Failure);
        Request.Result->Value = (co_await Request.Session->Run(Request.Inbound)).Code;
        (void)Request.Client->Close();
    }

    auto AcceptRejectedAuthentication(
        std::shared_ptr<Preview::RejectAuthenticator> Authenticator,
        Preview::Contract::StreamAcceptInput Input)
        -> Net::awaitable<Preview::Contract::AcceptOutcome>
    {
        Preview::Contract::ProtocolDataPlane Plane;
        Plane.Root = Preview::Contract::StreamDataPlane{std::move(Input.Inbound)};
        auto Credential = Preview::Account::Credential::Password("bad");
        auto Authentication = Authenticator->Authenticate(Preview::AuthenticationRequest{
            .Identity = "alice", .Credential = Credential.View(), .Rate = {}});
        if (!Authentication)
        {
            co_return std::unexpected(Preview::Contract::FailureFromProtocolError(Preview::Error::BadAuth));
        }
        auto Lease = std::move(*Authentication);
        Plane.ProtocolAuthenticated = true;
        Plane.Identity = Lease.Identity();
        Plane.DisplayIdentity = Lease.DisplayIdentity();
        Plane.AccountId = Lease.AccountId();
        Plane.AccountLease = std::move(Lease);
        co_return Plane;
    }

    struct RejectedAuthenticationFactory final
    {
        std::shared_ptr<Preview::RejectAuthenticator> Authenticator;

        auto operator()(Preview::Contract::StreamAcceptInput Input) const
            -> Net::awaitable<Preview::Contract::AcceptOutcome>
        {
            return AcceptRejectedAuthentication(Authenticator, std::move(Input));
        }
    };

    struct AuthRejectedRequest final
    {
        std::shared_ptr<Preview::Runtime::Session> Session;
        SharedTransmission Client;
        SharedTransmission Inbound;
        std::shared_ptr<SessionResult> Result;
    };

    auto RunAuthRejected(AuthRejectedRequest Request) -> Net::awaitable<void>
    {
        std::error_code WriteError;
        const auto Payload = Socks5Greeting();
        const auto Write = co_await Request.Client->WriteSome(
            std::span<const std::byte>(reinterpret_cast<const std::byte *>(Payload.data()),
                                       Payload.size()));
        WriteError = Preview::Fault::ToNative(Write.Failure);
        Request.Result->Value = (co_await Request.Session->Run(Request.Inbound)).Code;
    }

    auto AcceptAuthenticatedTraffic(
        Preview::SharedAuthenticator Authenticator,
        Preview::Contract::StreamAcceptInput Input)
        -> Net::awaitable<Preview::Contract::AcceptOutcome>
    {
        Preview::Contract::ProtocolDataPlane Plane;
        Plane.Root = Preview::Contract::StreamDataPlane{std::move(Input.Inbound)};
        Plane.Target.Route = Preview::Network::RouteKind::Forward;
        auto Credential = Preview::Account::Credential::Password("pw");
        auto Authentication = Authenticator->Authenticate(Preview::AuthenticationRequest{
            .Identity = "alice", .Credential = Credential.View(), .Rate = {}});
        if (!Authentication)
        {
            co_return std::unexpected(Preview::Contract::FailureFromProtocolError(Preview::Error::BadAuth));
        }
        auto Lease = std::move(*Authentication);
        Plane.ProtocolAuthenticated = true;
        Plane.Identity = Lease.Identity();
        Plane.DisplayIdentity = Lease.DisplayIdentity();
        Plane.AccountId = Lease.AccountId();
        Plane.AccountLease = std::move(Lease);
        co_return Plane;
    }

    struct AuthenticatedTrafficFactory final
    {
        Preview::SharedAuthenticator Authenticator;

        auto operator()(Preview::Contract::StreamAcceptInput Input) const
            -> Net::awaitable<Preview::Contract::AcceptOutcome>
        {
            return AcceptAuthenticatedTraffic(Authenticator, std::move(Input));
        }
    };

    struct TrafficRelayRequest final
    {
        std::shared_ptr<Preview::Runtime::Session> Session;
        SharedTransmission Client;
        SharedTransmission Inbound;
        SharedTransmission Outbound;
        SharedTransmission Upstream;
    };

    auto RunTrafficRelay(TrafficRelayRequest Request) -> Net::awaitable<void>
    {
        auto SessionDone = SpawnAndSignal(
            Request.Inbound->Executor(), Request.Session->Run(Request.Inbound));
        auto EchoDone = SpawnAndSignal(
            Request.Upstream->Executor(), EchoUpstream(Request.Upstream));

        std::error_code WriteError;
        const auto Payload = Socks5Greeting();
        const auto Write = co_await Request.Client->WriteSome(
            std::span<const std::byte>(reinterpret_cast<const std::byte *>(Payload.data()),
                                       Payload.size()));
        WriteError = Preview::Fault::ToNative(Write.Failure);
        std::array<std::byte, 64> Reply{};
        std::error_code ReadError;
        const auto Read = co_await Request.Client->ReadSome(
            std::span<std::byte>(Reply));
        ReadError = Preview::Fault::ToNative(Read.Failure);
        const auto BytesRead = Read.Bytes;
        EXPECT_EQ(std::string_view(reinterpret_cast<const char *>(Reply.data()), BytesRead),
                  Payload);

        // 保留原有 300ms 等待，覆盖 idle timeout 后的 relay 收口。
        Net::steady_timer Timer(Request.Inbound->Executor());
        Timer.expires_after(std::chrono::milliseconds(300));
        co_await Timer.async_wait(Net::use_awaitable);
        (void)Request.Client->Close();
        (void)Request.Inbound->Close();
        (void)Request.Upstream->Close();
        (void)Request.Outbound->Close();
        boost::system::error_code SessionError;
        boost::system::error_code EchoError;
        co_await SessionDone->async_receive(
            Net::redirect_error(Net::use_awaitable, SessionError));
        co_await EchoDone->async_receive(
            Net::redirect_error(Net::use_awaitable, EchoError));
        EXPECT_FALSE(SessionError);
        EXPECT_FALSE(EchoError);
    }

    struct FactoryTargetState final
    {
        Preview::Fault::Code Result{Preview::Fault::Code::Success};
        Preview::Network::Host DialedHost;
        std::uint16_t DialedPort{0};
    };

    struct FactoryTargetRequest final
    {
        std::shared_ptr<Preview::Runtime::Session> Session;
        SharedTransmission Client;
        SharedTransmission Inbound;
        SharedTransmission Outbound;
        SharedTransmission Upstream;
        std::shared_ptr<FactoryTargetState> State;
    };

    auto RunFactoryTarget(FactoryTargetRequest Request) -> Net::awaitable<void>
    {
        auto EchoDone = SpawnAndSignal(
            Request.Upstream->Executor(), ConsumeUpstream(Request.Upstream));
        std::error_code WriteError;
        const auto Payload = Socks5Greeting();
        const auto Write = co_await Request.Client->WriteSome(
            std::span<const std::byte>(reinterpret_cast<const std::byte *>(Payload.data()),
                                       Payload.size()));
        WriteError = Preview::Fault::ToNative(Write.Failure);
        (void)Request.Client->Close();
        Request.State->Result = (co_await Request.Session->Run(Request.Inbound)).Code;
        boost::system::error_code EchoError;
        co_await EchoDone->async_receive(
            Net::redirect_error(Net::use_awaitable, EchoError));
        EXPECT_FALSE(EchoError);
    }

    struct MissingBackendShutdownRequest final
    {
        std::shared_ptr<Preview::Runtime::Session> Session;
        SharedTransmission Client;
        SharedTransmission Inbound;
        SharedTransmission Outbound;
        SharedTransmission Upstream;
    };

    auto RunMissingBackendShutdown(
        MissingBackendShutdownRequest Request) -> Net::awaitable<void>
    {
        auto SessionDone = SpawnAndSignal(
            Request.Inbound->Executor(), Request.Session->Run(Request.Inbound));
        auto EchoDone = SpawnAndSignal(
            Request.Upstream->Executor(), EchoUpstream(Request.Upstream));
        const auto Payload = Socks5Greeting();
        std::error_code WriteError;
        const auto Write = co_await Request.Client->WriteSome(
            std::span<const std::byte>(reinterpret_cast<const std::byte *>(Payload.data()),
                                       Payload.size()));
        WriteError = Preview::Fault::ToNative(Write.Failure);
        std::array<std::byte, 64> Reply{};
        std::error_code ReadError;
        const auto Read = co_await Request.Client->ReadSome(Reply);
        ReadError = Preview::Fault::ToNative(Read.Failure);
        (void)Request.Client->Close();
        (void)Request.Inbound->Close();
        (void)Request.Upstream->Close();
        (void)Request.Outbound->Close();
        boost::system::error_code SessionError;
        boost::system::error_code EchoError;
        co_await SessionDone->async_receive(
            Net::redirect_error(Net::use_awaitable, SessionError));
        co_await EchoDone->async_receive(
            Net::redirect_error(Net::use_awaitable, EchoError));
        EXPECT_FALSE(SessionError);
        EXPECT_FALSE(EchoError);
    }

    TEST(SessionOrchestration, RecognizeAndRelay)
    {
        Net::io_context Ioc;
        auto [Client, Inbound] = MakePairShared(Ioc);
        auto [Outbound, Upstream] = MakePairShared(Ioc);
        auto Session = std::make_shared<Preview::Runtime::Session>(
            BaseOptions(Ioc.get_executor(), Outbound));

        RunCoro(Ioc, RunRecognizeAndRelay(RecognizeAndRelayRequest{
                            Session, Client, Inbound, Outbound, Upstream}));
    }

    TEST(SessionOrchestration, UnknownProtocolRejected)
    {
        Net::io_context Ioc;
        auto [Client, Inbound] = MakePairShared(Ioc);
        auto Session = std::make_shared<Preview::Runtime::Session>(
            MakeSessionOptions(Ioc.get_executor()));
        auto Result = std::make_shared<SessionResult>();

        RunCoro(Ioc, RunUnknownProtocol(UnknownProtocolRequest{
                            Session, Client, Inbound, Result}));
        EXPECT_EQ(Result->Value, Preview::Fault::Code::ProtocolError);
        EXPECT_FALSE(Inbound->IsOpen());
    }

    TEST(SessionOrchestration, DialFailureClosesInbound)
    {
        Net::io_context Ioc;
        auto [Client, Inbound] = MakePairShared(Ioc);

        auto Options = MakeSessionOptions(Ioc.get_executor());
        Options.Services->AcceptProtocol = std::make_shared<Preview::Testing::StreamFactory>([](Preview::Contract::StreamAcceptInput Input)
            -> Net::awaitable<Preview::Contract::AcceptOutcome>
        {
            Preview::Contract::ProtocolDataPlane Plane;
            Plane.Root = Preview::Contract::StreamDataPlane{std::move(Input.Inbound)};
            co_return Plane;
        });
        Options.Services->Dial = [](const Preview::Network::Target &)
            -> Net::awaitable<std::expected<Preview::SharedTransmission, Preview::Fault::Failure>>
        {
            co_return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::BadGateway});
        };
        auto Session = std::make_shared<Preview::Runtime::Session>(std::move(Options));
        auto Result = std::make_shared<SessionResult>();

        RunCoro(Ioc, RunDialFailure(DialFailureRequest{
                            Session, Client, Inbound, Result}));
        EXPECT_EQ(Result->Value, Preview::Fault::Code::BadGateway);
        EXPECT_FALSE(Inbound->IsOpen());
    }

    TEST(SessionOrchestration, NullDialResultClosesInbound)
    {
        Net::io_context Ioc;
        auto [Client, Inbound] = MakePairShared(Ioc);

        auto Options = MakeSessionOptions(Ioc.get_executor());
        Options.Services->AcceptProtocol = std::make_shared<Preview::Testing::StreamFactory>([](Preview::Contract::StreamAcceptInput Input)
            -> Net::awaitable<Preview::Contract::AcceptOutcome>
        {
            Preview::Contract::ProtocolDataPlane Plane;
            Plane.Root = Preview::Contract::StreamDataPlane{std::move(Input.Inbound)};
            co_return Plane;
        });
        Options.Services->Dial = [](const Preview::Network::Target &)
            -> Net::awaitable<std::expected<Preview::SharedTransmission, Preview::Fault::Failure>>
        {
            co_return Preview::SharedTransmission{};
        };
        auto Session = std::make_shared<Preview::Runtime::Session>(std::move(Options));
        auto Result = std::make_shared<SessionResult>();

        RunCoro(Ioc, RunNullDial(NullDialRequest{
                            Session, Client, Inbound, Result}));
        EXPECT_EQ(Result->Value, Preview::Fault::Code::BadGateway);
        EXPECT_FALSE(Inbound->IsOpen());
    }

    TEST(SessionOrchestration, AuthRejectedMidway)
    {
        Net::io_context Ioc;
        auto [Client, Inbound] = MakePairShared(Ioc);

        auto Options = MakeSessionOptions(Ioc.get_executor());
        auto Authenticator = std::make_shared<Preview::RejectAuthenticator>();
        Options.Services->AcceptProtocol = std::make_shared<Preview::Testing::StreamFactory>(
            RejectedAuthenticationFactory{Authenticator});
        auto Session = std::make_shared<Preview::Runtime::Session>(std::move(Options));
        auto Result = std::make_shared<SessionResult>();

        RunCoro(Ioc, RunAuthRejected(AuthRejectedRequest{
                            Session, Client, Inbound, Result}));
        EXPECT_EQ(Result->Value, Preview::Fault::Code::AuthFailed);
    }

    TEST(SessionOrchestration, TrafficReportedOnRelayEnd)
    {
        Net::io_context Ioc;
        auto [Client, Inbound] = MakePairShared(Ioc);
        auto [Outbound, Upstream] = MakePairShared(Ioc);

        auto SinkOwner = std::make_shared<TestTrafficSink>();
        auto Options = BaseOptions(
            Ioc.get_executor(), Outbound, std::chrono::milliseconds(50));
        auto Authenticator = Preview::Testing::ProviderAccount(Preview::Testing::ProviderAccountInput{Preview::AccountId{1U}, Preview::Account::Credential::Password("pw"), "alice", "alice", {}})->Authenticator;
        Options.Services->Traffic = SinkOwner;
        Options.Services->AcceptProtocol = std::make_shared<Preview::Testing::StreamFactory>(
            AuthenticatedTrafficFactory{Authenticator});
        auto Session = std::make_shared<Preview::Runtime::Session>(std::move(Options));

        RunCoro(Ioc, RunTrafficRelay(TrafficRelayRequest{
                            Session, Client, Inbound, Outbound, Upstream}));
        EXPECT_GT(SinkOwner->Calls, 0);
        EXPECT_GE(SinkOwner->TotalUp, Socks5Greeting().size());
        EXPECT_EQ(SinkOwner->LastAccount, Preview::AccountId{1});
    }

    TEST(SessionOrchestration, FactorySetsTargetForDial)
    {
        Net::io_context Ioc;
        auto [Client, Inbound] = MakePairShared(Ioc);
        auto [Outbound, Upstream] = MakePairShared(Ioc);

        auto State = std::make_shared<FactoryTargetState>();
        auto Options = MakeSessionOptions(Ioc.get_executor());
        Options.Services->AcceptProtocol = std::make_shared<Preview::Testing::StreamFactory>([](Preview::Contract::StreamAcceptInput Input) -> Net::awaitable<Preview::Contract::AcceptOutcome>
        {
            Preview::Contract::ProtocolDataPlane Plane;
            Plane.Root = Preview::Contract::StreamDataPlane{std::move(Input.Inbound)};
            Plane.Target.Route = Preview::Network::RouteKind::Forward;
            Plane.Target.Host = *Preview::Network::ParseHost("Target.test");
            Plane.Target.Port = 443;
            co_return Plane;
        });
        Options.Services->Dial = [State, Outbound](const Preview::Network::Target &Target) -> Net::awaitable<
            std::expected<Preview::SharedTransmission, Preview::Fault::Failure>>
        {
            State->DialedHost = Target.Host;
            State->DialedPort = Target.Port;
            co_return Outbound;
        };
        auto Session = std::make_shared<Preview::Runtime::Session>(std::move(Options));

        RunCoro(Ioc, RunFactoryTarget(FactoryTargetRequest{
                            Session, Client, Inbound, Outbound, Upstream, State}));
        EXPECT_EQ(State->Result, Preview::Fault::Code::Success);
        EXPECT_EQ(State->DialedHost, *Preview::Network::ParseHost("Target.test"));
        EXPECT_EQ(State->DialedPort, 443);
    }

    TEST(G2Log, MissingBackendDoesNotChangeFailureResultOrCloseCount)
    {
        Net::io_context Ioc;
        auto [Client, Inbound] = MakePairShared(Ioc);

        auto Services = std::make_shared<Preview::Runtime::SessionServices>();
        Services->Bytes = std::make_shared<Preview::Memory::BytePool>();
        auto Control = MakeDiagnosticControl(Ioc.get_executor());
        ASSERT_NE(Control, nullptr);

        Preview::Recognition::ProfileSpec ProfileSpec;
        ProfileSpec.Mode = Preview::Recognition::RecognitionMode::Configured;
        ProfileSpec.ConfiguredCandidate = 7;
        Preview::Recognition::CandidateSpec Candidate;
        Candidate.Id = 7;
        Candidate.Name = "safe-candidate";
        Candidate.Protocol = Preview::Contract::ProtocolType::Http;
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
                  Preview::Contract::ProtocolType::Http);

        Preview::Runtime::SessionOptions Options;
        Options.Services = Services;
        Options.Control = Control;
        Options.Services->Profile = *CompiledProfile;
        auto Session = std::make_shared<Preview::Runtime::Session>(std::move(Options));

        Preview::Fault::Code Result = Preview::Fault::Code::Success;
        // RunCoro 返回前完整等待，以下引用只借用本测试调用期间的 owner。
        RunCoro(Ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     const std::array<std::byte, 5> Payload{
                         std::byte{0xA1}, std::byte{0xB2}, std::byte{0xC3}, std::byte{0xD4}, std::byte{0xE5}};
                     std::error_code Error;
                     const auto Write = co_await Client->WriteSome(Payload);
                     Error = Preview::Fault::ToNative(Write.Failure);
                     (void)Client->Close();
                      Result = (co_await Session->Run(Inbound)).Code;
                 });

        EXPECT_EQ(Result, Preview::Fault::Code::ProtocolError);
        EXPECT_EQ(Control->Metrics().CloseCalls, 1U);
    }

    TEST(G2Log, MissingBackendDoesNotPreventSessionShutdown)
    {
        Net::io_context Ioc;
        auto [Client, Inbound] = MakePairShared(Ioc);
        auto [Outbound, Upstream] = MakePairShared(Ioc);

        auto Options = BaseOptions(
            Ioc.get_executor(), Outbound, std::chrono::milliseconds(50));
        auto Services = std::make_shared<Preview::Runtime::SessionServices>();
        Services->Bytes = Options.Services->Bytes;
        Services->RelayIdleTimeout = Options.Services->RelayIdleTimeout;
        Services->AcceptProtocol = Options.Services->AcceptProtocol;
        Services->Dial = Options.Services->Dial;
        Options.Services = Services;
        auto Control = MakeDiagnosticControl(Ioc.get_executor());
        ASSERT_NE(Control, nullptr);
        Options.Control = Control;
        auto Session = std::make_shared<Preview::Runtime::Session>(std::move(Options));

        RunCoro(Ioc, RunMissingBackendShutdown(MissingBackendShutdownRequest{
                            Session, Client, Inbound, Outbound, Upstream}));

        EXPECT_EQ(Control->Metrics().CloseCalls, 1U);
    }

} // namespace
