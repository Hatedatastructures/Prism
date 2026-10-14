#include <TestSupport/Preview/ProviderBindings.hpp>
/**
 * @file PostDialReplyFailureTest.cpp
 * @brief PostDial 回执写失败与原始错误优先级回归测试。
 * @details 通过当前 CandidateFactory、ProtocolAdapter、受控接入/拨号/装饰器
 *          和 Session::Run 注入确定性的回执写失败，覆盖成功拨号与四条原始
 *          失败出口，验证不得进入 relay，并验证传输、账户租约和会话注册收口。
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <expected>
#include <functional>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <Preview/Account/Account.hpp>
#include <Preview/Account/Authenticator.hpp>
#include <Preview/Composition/Recognition/CandidateFactory.hpp>
#include <Preview/Foundation/Fault/Code.hpp>
#include <Preview/Foundation/Executor/ClosingStorage.hpp>
#include <Preview/Foundation/Executor/ContextOwner.hpp>
#include <Preview/Foundation/Memory/BytePool.hpp>
#include <Preview/Protocols/Http1/Conn.hpp>
#include <Preview/Protocols/Socks5/Socks5.hpp>
#include <Preview/Runtime/Session.hpp>
#include <Preview/Runtime/SessionRegistry.hpp>
#include <Preview/Transport/Detail/IoCompletion.hpp>
#include <Preview/Transport/Transmission.hpp>
#include <TestSupport/Fixtures/StreamFactory.hpp>
#include <TestSupport/Preview/PreviewMockTransport.hpp>
#include "../../../Transport/TransportResources.hpp"

namespace
{

    namespace Net = boost::asio;
    namespace Composition = Preview::Composition::Recognition;
    namespace Runtime = Preview::Runtime;

    using MockTransport = Preview::PreviewMockTransport;
    using SharedAccountBinding = std::shared_ptr<const Preview::Account::AccountBinding>;
    using SharedTransmission = Preview::SharedTransmission;
    using FaultCode = Preview::Fault::Code;

    /** @brief 按 fixture 选项创建可由测试持有的出站传输 owner。 */
    auto MakeOptionalOutbound(Net::any_io_executor Executor, bool Provide)
        -> std::shared_ptr<MockTransport>
    {
        if (!Provide) return {};
        return std::make_shared<MockTransport>(std::move(Executor));
    }

    /** @brief 持有测试原生关闭的首错与唯一一次物理关闭状态。 */
    struct NativeCloseRetryState final
    {
        explicit NativeCloseRetryState(std::error_code Failure) : NativeFailure(std::move(Failure)) {}
        const std::error_code NativeFailure;
        std::atomic<std::size_t> CloseAttempts{0};
        std::atomic<bool> NativeClosed{false};
    };

    /** @brief 首次 OnClose 返回 native cause，显式同域重试后才确认物理关闭。 */
    class NativeCloseRetryTransmission final : public Preview::Transmission
    {
    public:
        NativeCloseRetryTransmission(Net::any_io_executor Executor,
                                     std::shared_ptr<NativeCloseRetryState> State)
            : Preview::Transmission(Executor), Executor_(std::move(Executor)), State_(std::move(State))
        {
        }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor override { return Executor_; }
        [[nodiscard]] auto IsOpen() const -> bool override
        { return !State_->NativeClosed.load(std::memory_order_acquire); }

    protected:
        auto StartRead(std::span<std::byte>, Completion Handler) -> void override
        {
            Preview::Transport::Detail::PostResult(
                Executor_, std::move(Handler), {0, {FaultCode::Eof}});
        }

        auto StartWrite(std::span<const std::byte>, Completion Handler) -> void override
        {
            Preview::Transport::Detail::PostResult(Executor_, std::move(Handler), {});
        }

        auto StartWriteShutdown(Completion Handler) -> void override
        {
            Preview::Transport::Detail::PostResult(Executor_, std::move(Handler), {});
        }

        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            const auto Attempt = State_->CloseAttempts.fetch_add(1, std::memory_order_acq_rel) + 1U;
            if (Attempt == 1U)
                return std::unexpected(Preview::Fault::FromNative(State_->NativeFailure));
            State_->NativeClosed.store(true, std::memory_order_release);
            return {};
        }

        [[nodiscard]] auto OnCancel() -> ControlResult override { return {}; }

    private:
        Net::any_io_executor Executor_;
        std::shared_ptr<NativeCloseRetryState> State_;
    };

    auto MakeAccountRecord(Preview::AccountId AccountIdValue, std::string_view Password)
        -> std::shared_ptr<Preview::Testing::ProviderAccounts>
    {
        return Preview::Testing::ProviderAccount(
            Preview::Account::Credential::Password(Password), AccountIdValue,
            {.MaxConnections = 1});
    }

    auto MakeSessionInfo(std::uint64_t Id, Preview::AccountId AccountIdValue)
        -> Runtime::SessionInfo
    {
        Runtime::SessionInfo Info;
        Info.Id = Id;
        Info.AccountId = AccountIdValue;
        Info.identity = "account";
        Info.peer = "127.0.0.1";
        Info.Target = "example.com:443";
        Info.Protocol = 1;
        return Info;
    }

    auto MakeSocks5UserPassConnect() -> std::vector<std::uint8_t>
    {
        constexpr std::string_view User = "account";
        constexpr std::string_view Password = "socks-password";
        constexpr std::string_view Host = "example.com";

        std::vector<std::uint8_t> Wire{0x05, 0x01, 0x02};
        Wire.push_back(0x01);
        Wire.push_back(static_cast<std::uint8_t>(User.size()));
        Wire.insert(Wire.end(), User.begin(), User.end());
        Wire.push_back(static_cast<std::uint8_t>(Password.size()));
        Wire.insert(Wire.end(), Password.begin(), Password.end());
        Wire.insert(Wire.end(), {0x05, 0x01, 0x00, 0x03,
                                 static_cast<std::uint8_t>(Host.size())});
        Wire.insert(Wire.end(), Host.begin(), Host.end());
        Wire.insert(Wire.end(), {0x01, 0xbb});
        return Wire;
    }

    auto MakeHttpConnect() -> std::vector<std::uint8_t>
    {
        constexpr std::string_view Request =
            "CONNECT example.com:443 HTTP/1.1\r\n"
            "Host: example.com:443\r\n"
            "Proxy-Authorization: Basic YTpi\r\n"
            "\r\n";
        return std::vector<std::uint8_t>(Request.begin(), Request.end());
    }

    struct SessionFixtureOptions final
    {
        std::uint64_t SessionId{0};
        Preview::AccountId AccountIdValue{};
        std::string Password{"socks-password"};
        std::vector<std::uint8_t> Request;
        std::size_t WriteFailAt{1};
        bool ProvideOutbound{false};
    };

    class PostDialFailureFixture final
    {
    public:
        explicit PostDialFailureFixture(SessionFixtureOptions Options)
            : SessionId_(Options.SessionId), AccountId_(Options.AccountIdValue),
              Password_(std::move(Options.Password)), Inbound_(std::make_shared<MockTransport>(Io_.get_executor())),
              Outbound_(MakeOptionalOutbound(Io_.get_executor(), Options.ProvideOutbound)),
              Directory_(MakeAccountRecord(AccountId_, Password_)),
              Account_(Directory_->Store->FindById(AccountId_)),
              Control_(std::make_shared<Runtime::SessionControl>(Io_.get_executor()))
        {
            Inbound_->ToRead = std::move(Options.Request);
            Inbound_->EofOnDrain = true;
            Inbound_->WriteFailAt = Options.WriteFailAt;
            if (Outbound_)
            {
                Outbound_->EofOnDrain = true;
            }
            AccountInstalled_ = static_cast<bool>(Account_);
            auto Info = MakeSessionInfo(SessionId_, AccountId_);
            if (Account_)
            {
                Info.AccountRuntime = Account_->Runtime()->RuntimeIdentity();
            }
            Registration_ = Registry_.Register(std::move(Info), Control_);
        }

        [[nodiscard]] auto AccountInstalled() const noexcept -> bool
        {
            return AccountInstalled_.load(std::memory_order_acquire);
        }

        [[nodiscard]] auto RegistrationActive() const noexcept -> bool
        {
            return static_cast<bool>(Registration_);
        }

        [[nodiscard]] auto RegistrySize() const -> std::size_t
        {
            return Registry_.Size();
        }

        [[nodiscard]] auto Inbound() const -> std::shared_ptr<MockTransport>
        {
            return Inbound_;
        }

        [[nodiscard]] auto Outbound() const -> std::shared_ptr<MockTransport>
        {
            return Outbound_;
        }

        [[nodiscard]] auto Account() const -> SharedAccountBinding
        {
            return Account_;
        }

        [[nodiscard]] auto Directory() const
            -> std::shared_ptr<Preview::Testing::ProviderAccounts>
        {
            return Directory_;
        }

        [[nodiscard]] auto PostDialCalls() const noexcept -> std::uint32_t
        {
            return PostDialCalls_.load(std::memory_order_acquire);
        }

        [[nodiscard]] auto PostDialStatus() const noexcept -> FaultCode
        {
            return PostDialStatus_.load(std::memory_order_acquire);
        }

        [[nodiscard]] auto PostDialReplyStatus() const noexcept -> FaultCode
        {
            return PostDialReplyStatus_.load(std::memory_order_acquire);
        }

        [[nodiscard]] auto PostDialCallbackStatus() const noexcept -> FaultCode
        {
            return PostDialCallbackStatus_.load(std::memory_order_acquire);
        }

        [[nodiscard]] auto DialCalled() const noexcept -> bool
        {
            return DialCalled_.load(std::memory_order_acquire);
        }

        [[nodiscard]] auto LeaseHeldAtDial() const noexcept -> bool
        {
            return LeaseHeldAtDial_.load(std::memory_order_acquire);
        }

        [[nodiscard]] auto OutboundDecoratorCalled() const noexcept -> bool
        {
            return OutboundDecoratorCalled_.load(std::memory_order_acquire);
        }

        [[nodiscard]] auto OutboundWasTransferred() const noexcept -> bool
        {
            return OutboundTransferred_.load(std::memory_order_acquire);
        }

        [[nodiscard]] auto UntransferredOutboundClosed() const noexcept -> bool
        {
            return UntransferredOutboundClose_.Succeeded();
        }

        [[nodiscard]] auto LastOutcome() const noexcept -> Preview::Fault::Failure
        {
            return LastOutcome_;
        }

        auto SetDialOutbound(SharedTransmission Value) -> void
        {
            DialOutbound_ = std::move(Value);
        }

        auto ReleaseDialOutbound() noexcept -> void
        {
            DialOutbound_.reset();
        }

        auto RetryStoredOwners() -> void
        {
            Io_.restart();
            Storage_->Retry();
            Io_.run();
            Storage_->Collect();
        }

        [[nodiscard]] auto PendingOwners() const noexcept -> std::size_t
        {
            return Storage_->Pending();
        }

        auto MakeAcceptForAuthenticationFailure() -> std::shared_ptr<Preview::Contract::StreamFactory>
        {
            return std::make_shared<Preview::Testing::StreamFactory>(
                [this](Preview::Contract::StreamAcceptInput Input)
                { return AcceptAuthenticationFailure(std::move(Input.Inbound)); });
        }

        auto MakeAcceptForStream(const bool IncludeOutboundDecorator)
            -> std::shared_ptr<Preview::Contract::StreamFactory>
        {
            return std::make_shared<Preview::Testing::StreamFactory>(
                [this, IncludeOutboundDecorator](Preview::Contract::StreamAcceptInput Input)
                { return AcceptStream(std::move(Input.Inbound), IncludeOutboundDecorator); });
        }

        auto MakeDialFailure(const FaultCode Code)
            -> Preview::Middleware::Builtin::DialMiddleware::DialFn
        {
            return [this, Code](const Preview::Network::Target &)
                       -> Net::awaitable<std::expected<SharedTransmission, Preview::Fault::Failure>>
            {
                DialCalled_.store(true, std::memory_order_release);
                LeaseHeldAtDial_.store(Account_->Runtime()->ActiveConnections() == 1U,
                                       std::memory_order_release);
                co_return std::unexpected(Preview::Fault::Failure{Code});
            };
        }

        auto MakeDialSuccess() -> Preview::Middleware::Builtin::DialMiddleware::DialFn
        {
            return [this](const Preview::Network::Target &)
                       -> Net::awaitable<std::expected<SharedTransmission, Preview::Fault::Failure>>
            {
                DialCalled_.store(true, std::memory_order_release);
                LeaseHeldAtDial_.store(Account_->Runtime()->ActiveConnections() == 1U,
                                       std::memory_order_release);
                OutboundTransferred_.store(true, std::memory_order_release);
                if (DialOutbound_) co_return DialOutbound_;
                co_return Outbound_;
            };
        }

        auto MakeAcceptForMuxFailure() -> std::shared_ptr<Preview::Contract::StreamFactory>
        {
            return std::make_shared<Preview::Testing::StreamFactory>(
                [this](Preview::Contract::StreamAcceptInput Input)
                    -> Net::awaitable<Preview::Contract::AcceptOutcome>
                { co_return co_await AcceptMuxFailure(std::move(Input.Inbound)); });
        }

        [[nodiscard]] auto Run(Runtime::SessionOptions Options) -> FaultCode
        {
            Options.Control = Control_;
            Options.Services->Bytes = std::make_shared<Preview::Memory::BytePool>(
                Preview::Memory::BytePoolOptions{.BlockCount=8});
            Runtime::Session Session(std::move(Options));
            FaultCode Result = FaultCode::Success;
            bool Completed = false;
            std::exception_ptr Failure;
            Net::co_spawn(Io_, Session.Run(Inbound_),
                [&](std::exception_ptr Error, Preview::Fault::Failure Outcome)
                {
                    Failure = std::move(Error);
                    LastOutcome_ = Outcome;
                    if (!Failure) Result = Outcome.Code;
                    Completed = true;
                    Io_.stop();
                });
            Io_.run();
            if (Outbound_ && !OutboundTransferred_.load(std::memory_order_acquire))
                UntransferredOutboundClose_ = Preview::Testing::DriveClose(Io_, Outbound_);
            if (Failure) std::rethrow_exception(Failure);
            if (!Completed) throw std::runtime_error("session task returned without completion");
            return Result;
        }

        auto ResetRegistration() noexcept -> void
        {
            Registration_.Reset();
        }

        auto OverridePostDialReturnForDecorator(const FaultCode Code) noexcept -> void
        {
            PostDialReturnOverride_.store(Code, std::memory_order_release);
        }

    private:
        using PostDialFn = std::function<Net::awaitable<FaultCode>(FaultCode)>;

        auto AcceptAuthenticationFailure(SharedTransmission Inbound)
            -> Net::awaitable<Preview::Contract::AcceptOutcome>
        {
            const auto Credential = Preview::Account::Credential::Password("wrong-password");
            auto Result = Preview::DirectoryAuthenticator(Directory_->Credentials).Authenticate(
                Preview::AuthenticationRequest{.Identity = "account", .Credential = Credential.View(), .Rate = {}});
            EXPECT_FALSE(static_cast<bool>(Result));
            (void)co_await MakePostDial(Inbound)(FaultCode::AuthFailed);
            Inbound->Close();
            co_return std::unexpected(Preview::Contract::FailureFromProtocolError(Preview::Error::BadAuth));
        }

        auto AcceptStream(SharedTransmission Inbound, const bool IncludeOutboundDecorator)
            -> Net::awaitable<Preview::Contract::AcceptOutcome>
        {
            const auto Credential = Preview::Account::Credential::Password(Password_);
            auto Result = Preview::DirectoryAuthenticator(Directory_->Credentials).Authenticate(
                Preview::AuthenticationRequest{.Identity = "account", .Credential = Credential.View(), .Rate = {}});
            if (!Result) co_return std::unexpected(Preview::Contract::FailureFromProtocolError(Preview::Error::BadAuth));
            Preview::Contract::ProtocolDataPlane Plane;
            Plane.Root = Preview::Contract::StreamDataPlane{Inbound};
            if (IncludeOutboundDecorator)
            {
                Plane.Stream()->OutboundDecorator = [this](SharedTransmission) -> SharedTransmission
                {
                    OutboundDecoratorCalled_.store(true, std::memory_order_release);
                    return {};
                };
            }
            Plane.Target.Host = *Preview::Network::ParseHost("example.com");
            Plane.Target.Port = 443;
            Plane.Identity = "account";
            Plane.DisplayIdentity = "account";
            Plane.AccountId = Result->AccountId();
            Plane.AccountLease = std::move(*Result);
            Plane.ProtocolAuthenticated = true;
            Plane.PostDial = MakePostDial(Inbound);
            co_return Plane;
        }

        auto AcceptMuxFailure(SharedTransmission Inbound)->Net::awaitable<Preview::Contract::AcceptOutcome>
        {
            auto Accepted=co_await AcceptStream(Inbound,false);
            if(!Accepted)co_return std::move(Accepted);
            auto Owner=std::make_shared<Preview::Testing::MuxSession>(Inbound,
                [this,Inbound](Preview::Contract::MuxRootRequest)->Net::awaitable<FaultCode>
                {
                    (void)co_await MakePostDial(Inbound)(FaultCode::BadGateway);
                    co_return FaultCode::BadGateway;
                });
            Accepted->Root=Preview::Contract::MuxRootDataPlane{std::move(Inbound),std::move(Owner)};
            Accepted->PostDial={};co_return std::move(Accepted);
        }

        auto RunPostDial(const SharedTransmission &Client, const FaultCode Status)
            -> Net::awaitable<FaultCode>
        {
            PostDialCalls_.fetch_add(1U, std::memory_order_acq_rel);
            PostDialStatus_.store(Status, std::memory_order_release);
            auto Response = Preview::Http11::Status::Ok;
            if (Preview::Fault::Failed(Status)) Response = Preview::Http11::Status::BadGateway;
            const auto ReplyStatus = co_await Preview::Http11::SendResponse(Client, Response);
            PostDialReplyStatus_.store(ReplyStatus, std::memory_order_release);
            const auto Override = PostDialReturnOverride_.load(std::memory_order_acquire);
            auto CallbackStatus = ReplyStatus;
            if (Override != FaultCode::Success) CallbackStatus = Override;
            PostDialCallbackStatus_.store(CallbackStatus, std::memory_order_release);
            co_return CallbackStatus;
        }

        auto MakePostDial(const SharedTransmission &Client) -> PostDialFn
        {
            return [this, Client](const FaultCode Status) -> Net::awaitable<FaultCode>
            {
                co_return co_await RunPostDial(Client, Status);
            };
        }

        std::uint64_t SessionId_;
        Preview::AccountId AccountId_;
        std::string Password_;
         std::shared_ptr<Preview::Executor::ClosingStorage> Storage_{
             std::make_shared<Preview::Executor::ClosingStorage>()};
         std::shared_ptr<Preview::Executor::ContextOwner> Context_{
             Preview::Executor::ContextOwner::Create(Storage_)};
         Net::io_context& Io_{Context_->Io};
        std::shared_ptr<MockTransport> Inbound_;
        std::shared_ptr<MockTransport> Outbound_;
         SharedTransmission DialOutbound_;
        std::shared_ptr<Preview::Testing::ProviderAccounts> Directory_;
        SharedAccountBinding Account_;
        std::shared_ptr<Runtime::SessionControl> Control_;
        Runtime::SessionRegistry Registry_;
        Runtime::SessionRegistry::Registration Registration_;
        std::atomic<bool> AccountInstalled_{false};
        std::atomic<std::uint32_t> PostDialCalls_{0};
        std::atomic<FaultCode> PostDialStatus_{FaultCode::Success};
        std::atomic<FaultCode> PostDialReplyStatus_{FaultCode::Success};
        std::atomic<FaultCode> PostDialCallbackStatus_{FaultCode::Success};
        std::atomic<FaultCode> PostDialReturnOverride_{FaultCode::Success};
        std::atomic<bool> DialCalled_{false};
        std::atomic<bool> LeaseHeldAtDial_{false};
        std::atomic<bool> OutboundDecoratorCalled_{false};
        std::atomic<bool> OutboundTransferred_{false};
         Preview::Fault::Failure LastOutcome_;
        Preview::Testing::FixtureCloseReceipt UntransferredOutboundClose_;
    };

} // namespace

TEST(PostDialReplyFailure, Socks5UserPassDeferredReplyWriteFailureStopsRelay)
{
    PostDialFailureFixture Fixture(SessionFixtureOptions{
        .SessionId = 9401,
        .AccountIdValue = Preview::AccountId{9401},
        .Password = "socks-password",
        .Request = MakeSocks5UserPassConnect(),
        .WriteFailAt = 3,
        .ProvideOutbound = true});
    ASSERT_TRUE(Fixture.AccountInstalled());
    ASSERT_TRUE(Fixture.RegistrationActive());
    ASSERT_EQ(Fixture.RegistrySize(), 1U);

    Preview::Socks5::ServerConfig Config;
    Config.EnableTcp = true;
    Config.EnableUdp = false;
    Config.EnableAuth = true;
    Config.DeferConnectReply = true;
    Config.Authenticator =
        std::make_shared<Preview::DirectoryAuthenticator>(Fixture.Directory()->Credentials);
    auto Binding = Composition::CandidateFactory::MakeSocks5(
        Composition::CandidateOptions{}, Preview::Testing::MakeSocks5Binding(std::move(Config)));
    ASSERT_TRUE(Binding.Accept);

    Runtime::SessionOptions Options;
    Options.Services->AcceptProtocol = std::move(Binding.Accept);
    Options.Services->Dial = Fixture.MakeDialSuccess();
    const auto Result = Fixture.Run(std::move(Options));

    EXPECT_TRUE(Fixture.DialCalled());
    EXPECT_TRUE(Fixture.LeaseHeldAtDial());
    EXPECT_NE(Result, Preview::Fault::Code::Success);
    EXPECT_TRUE(Fixture.Inbound()->IsClosed());
    EXPECT_TRUE(Fixture.Outbound()->IsClosed());
    EXPECT_EQ(Fixture.Outbound()->ReadsDone, 0U);
    EXPECT_EQ(Fixture.Inbound()->WritesDone, 3U);
    EXPECT_EQ(Fixture.Account()->Runtime()->ActiveConnections(), 0U);

    // Run 返回前 registration 仍由 owner 持有；此处才模拟 Listener::RunSession 的 Reset。
    EXPECT_EQ(Fixture.RegistrySize(), 1U);
    Fixture.ResetRegistration();
    EXPECT_EQ(Fixture.RegistrySize(), 0U);
}

TEST(PostDialReplyFailure, HttpConnectDeferredReplyWriteFailureStopsRelay)
{
    PostDialFailureFixture Fixture(SessionFixtureOptions{
        .SessionId = 9402,
        .AccountIdValue = Preview::AccountId{9402},
        .Password = "b",
        .Request = MakeHttpConnect(),
        .ProvideOutbound = true});
    ASSERT_TRUE(Fixture.AccountInstalled());
    ASSERT_TRUE(Fixture.RegistrationActive());
    ASSERT_EQ(Fixture.RegistrySize(), 1U);

    Preview::Http11::IngressOptions Config;
    Config.RequireAuth = true;
    Config.Authenticator =
        std::make_shared<Preview::DirectoryAuthenticator>(Fixture.Directory()->Credentials);
    auto Binding = Composition::CandidateFactory::MakeHttp(
        Composition::CandidateOptions{}, std::move(Config));
    ASSERT_TRUE(Binding.Accept);

    Runtime::SessionOptions Options;
    Options.Services->AcceptProtocol = std::move(Binding.Accept);
    Options.Services->Dial = Fixture.MakeDialSuccess();
    const auto Result = Fixture.Run(std::move(Options));

    EXPECT_TRUE(Fixture.DialCalled());
    EXPECT_TRUE(Fixture.LeaseHeldAtDial());
    EXPECT_NE(Result, Preview::Fault::Code::Success);
    EXPECT_TRUE(Fixture.Inbound()->IsClosed());
    EXPECT_TRUE(Fixture.Outbound()->IsClosed());
    EXPECT_EQ(Fixture.Outbound()->ReadsDone, 0U);
    EXPECT_EQ(Fixture.Inbound()->WritesDone, 1U);
    EXPECT_EQ(Fixture.Account()->Runtime()->ActiveConnections(), 0U);

    EXPECT_EQ(Fixture.RegistrySize(), 1U);
    Fixture.ResetRegistration();
    EXPECT_EQ(Fixture.RegistrySize(), 0U);
}

TEST(PostDialReplyFailure, AuthenticationFailureKeepsOriginalErrorWhenReplyFails)
{
    PostDialFailureFixture Fixture(SessionFixtureOptions{
        .SessionId = 9501,
        .AccountIdValue = Preview::AccountId{9501},
        .Request = MakeHttpConnect()});
    ASSERT_TRUE(Fixture.AccountInstalled());
    ASSERT_TRUE(Fixture.RegistrationActive());
    ASSERT_EQ(Fixture.RegistrySize(), 1U);

    Runtime::SessionOptions Options;
    Options.Services->AcceptProtocol = Fixture.MakeAcceptForAuthenticationFailure();
    Options.Services->Dial = Fixture.MakeDialFailure(FaultCode::ConnectionRefused);

    const auto Result = Fixture.Run(std::move(Options));

    EXPECT_EQ(Result, FaultCode::AuthFailed);
    EXPECT_EQ(Fixture.PostDialCalls(), 1U);
    EXPECT_EQ(Fixture.PostDialStatus(), FaultCode::AuthFailed);
    EXPECT_EQ(Fixture.PostDialReplyStatus(), FaultCode::IoError);
    EXPECT_FALSE(Fixture.DialCalled());
    EXPECT_TRUE(Fixture.Inbound()->IsClosed());
    EXPECT_EQ(Fixture.Inbound()->WritesDone, 1U);
    EXPECT_FALSE(Fixture.Outbound());
    EXPECT_EQ(Fixture.Account()->Runtime()->ActiveConnections(), 0U);
    EXPECT_EQ(Fixture.RegistrySize(), 1U);

    Fixture.ResetRegistration();
    EXPECT_EQ(Fixture.RegistrySize(), 0U);
}

TEST(PostDialReplyFailure, MuxOwnerFailureKeepsOriginalErrorWhenReplyFails)
{
    PostDialFailureFixture Fixture(SessionFixtureOptions{
        .SessionId = 9502,
        .AccountIdValue = Preview::AccountId{9502},
        .Request = MakeHttpConnect()});
    ASSERT_TRUE(Fixture.AccountInstalled());
    ASSERT_TRUE(Fixture.RegistrationActive());
    ASSERT_EQ(Fixture.RegistrySize(), 1U);

    Runtime::SessionOptions Options;
    Options.Services->AcceptProtocol = Fixture.MakeAcceptForMuxFailure();
    Options.Services->Dial = Fixture.MakeDialFailure(FaultCode::ConnectionRefused);

    const auto Result = Fixture.Run(std::move(Options));

    EXPECT_EQ(Result, FaultCode::BadGateway);
    EXPECT_EQ(Fixture.PostDialCalls(), 1U);
    EXPECT_EQ(Fixture.PostDialStatus(), FaultCode::BadGateway);
    EXPECT_EQ(Fixture.PostDialReplyStatus(), FaultCode::IoError);
    EXPECT_FALSE(Fixture.DialCalled());
    EXPECT_TRUE(Fixture.Inbound()->IsClosed());
    EXPECT_EQ(Fixture.Inbound()->WritesDone, 1U);
    EXPECT_FALSE(Fixture.Outbound());
    EXPECT_EQ(Fixture.Account()->Runtime()->ActiveConnections(), 0U);
    EXPECT_EQ(Fixture.RegistrySize(), 1U);

    Fixture.ResetRegistration();
    EXPECT_EQ(Fixture.RegistrySize(), 0U);
}

TEST(PostDialReplyFailure, DialFailureKeepsOriginalErrorWhenReplyFails)
{
    PostDialFailureFixture Fixture(SessionFixtureOptions{
        .SessionId = 9503,
        .AccountIdValue = Preview::AccountId{9503},
        .Request = MakeHttpConnect(),
        .ProvideOutbound = true});
    ASSERT_TRUE(Fixture.AccountInstalled());
    ASSERT_TRUE(Fixture.RegistrationActive());
    ASSERT_EQ(Fixture.RegistrySize(), 1U);
    ASSERT_TRUE(Fixture.Outbound());

    Runtime::SessionOptions Options;
    Options.Services->AcceptProtocol = Fixture.MakeAcceptForStream(false);
    Options.Services->Dial = Fixture.MakeDialFailure(FaultCode::ConnectionRefused);

    const auto Result = Fixture.Run(std::move(Options));

    EXPECT_EQ(Result, FaultCode::ConnectionRefused);
    EXPECT_EQ(Fixture.PostDialCalls(), 1U);
    EXPECT_EQ(Fixture.PostDialStatus(), FaultCode::ConnectionRefused);
    EXPECT_EQ(Fixture.PostDialReplyStatus(), FaultCode::IoError);
    EXPECT_TRUE(Fixture.DialCalled());
    EXPECT_TRUE(Fixture.LeaseHeldAtDial());
    EXPECT_FALSE(Fixture.OutboundWasTransferred());
    EXPECT_TRUE(Fixture.UntransferredOutboundClosed());
    EXPECT_TRUE(Fixture.Inbound()->IsClosed());
    EXPECT_TRUE(Fixture.Outbound()->IsClosed());
    EXPECT_EQ(Fixture.Outbound()->ReadsDone, 0U);
    EXPECT_EQ(Fixture.Inbound()->WritesDone, 1U);
    EXPECT_EQ(Fixture.Account()->Runtime()->ActiveConnections(), 0U);
    EXPECT_EQ(Fixture.RegistrySize(), 1U);

    Fixture.ResetRegistration();
    EXPECT_EQ(Fixture.RegistrySize(), 0U);
}

TEST(PostDialReplyFailure, OutboundDecoratorFailureKeepsOriginalErrorWhenReplyFails)
{
    PostDialFailureFixture Fixture(SessionFixtureOptions{
        .SessionId = 9504,
        .AccountIdValue = Preview::AccountId{9504},
        .Request = MakeHttpConnect(),
        .ProvideOutbound = true});
    ASSERT_TRUE(Fixture.AccountInstalled());
    ASSERT_TRUE(Fixture.RegistrationActive());
    ASSERT_EQ(Fixture.RegistrySize(), 1U);
    ASSERT_TRUE(Fixture.Outbound());

    Runtime::SessionOptions Options;
    Options.Services->AcceptProtocol = Fixture.MakeAcceptForStream(true);
    Options.Services->Dial = Fixture.MakeDialSuccess();
    Fixture.OverridePostDialReturnForDecorator(FaultCode::ConnectionRefused);

    const auto Result = Fixture.Run(std::move(Options));

    EXPECT_EQ(Result, FaultCode::IoError);
    EXPECT_EQ(Fixture.PostDialCalls(), 1U);
    EXPECT_EQ(Fixture.PostDialStatus(), FaultCode::IoError);
    EXPECT_EQ(Fixture.PostDialReplyStatus(), FaultCode::IoError);
    EXPECT_EQ(Fixture.PostDialCallbackStatus(), FaultCode::ConnectionRefused);
    EXPECT_TRUE(Fixture.DialCalled());
    EXPECT_TRUE(Fixture.LeaseHeldAtDial());
    EXPECT_TRUE(Fixture.OutboundDecoratorCalled());
    EXPECT_TRUE(Fixture.Inbound()->IsClosed());
    EXPECT_TRUE(Fixture.Outbound()->IsClosed());
    EXPECT_EQ(Fixture.Outbound()->ReadsDone, 0U);
    EXPECT_EQ(Fixture.Inbound()->WritesDone, 1U);
    EXPECT_EQ(Fixture.Account()->Runtime()->ActiveConnections(), 0U);
    EXPECT_EQ(Fixture.RegistrySize(), 1U);

    Fixture.ResetRegistration();
    EXPECT_EQ(Fixture.RegistrySize(), 0U);
}

 TEST(PostDialReplyFailure, OutboundDecoratorNativeCloseFailureStaysOwnedUntilRetry)
 {
     PostDialFailureFixture Fixture(SessionFixtureOptions{
         .SessionId = 9505,
         .AccountIdValue = Preview::AccountId{9505},
         .Request = MakeHttpConnect(),
         .ProvideOutbound = true});
     ASSERT_TRUE(Fixture.AccountInstalled());
     ASSERT_TRUE(Fixture.RegistrationActive());
     ASSERT_EQ(Fixture.RegistrySize(), 1U);

     const auto NativeError = std::make_error_code(std::errc::connection_reset);
     auto State = std::make_shared<NativeCloseRetryState>(NativeError);
     auto Outbound = std::make_shared<NativeCloseRetryTransmission>(
         Fixture.Outbound()->Executor(), State);
     std::weak_ptr<NativeCloseRetryTransmission> WeakOutbound = Outbound;
     Fixture.SetDialOutbound(Outbound);
     Outbound.reset();

     Runtime::SessionOptions Options;
     Options.Services->AcceptProtocol = Fixture.MakeAcceptForStream(true);
     Options.Services->Dial = Fixture.MakeDialSuccess();
     Fixture.OverridePostDialReturnForDecorator(FaultCode::ConnectionRefused);

     const auto Result = Fixture.Run(std::move(Options));
     const auto Outcome = Fixture.LastOutcome();

     EXPECT_EQ(Result, Preview::Fault::FromNative(NativeError).Code);
     EXPECT_EQ(Outcome.Code, Preview::Fault::FromNative(NativeError).Code);
     EXPECT_EQ(Outcome.Native, NativeError);
     EXPECT_EQ(Fixture.PostDialStatus(), FaultCode::IoError);
     EXPECT_EQ(Fixture.PostDialReplyStatus(), FaultCode::IoError);
     EXPECT_EQ(Fixture.PostDialCallbackStatus(), FaultCode::ConnectionRefused);
     EXPECT_TRUE(Fixture.OutboundDecoratorCalled());
     EXPECT_GE(State->CloseAttempts.load(std::memory_order_relaxed), 1U);
     EXPECT_FALSE(State->NativeClosed.load(std::memory_order_acquire));
     EXPECT_GT(Fixture.PendingOwners(), 0U);

     Fixture.ReleaseDialOutbound();
     EXPECT_FALSE(WeakOutbound.expired());
     Fixture.RetryStoredOwners();
     Fixture.RetryStoredOwners();

     EXPECT_GE(State->CloseAttempts.load(std::memory_order_relaxed), 2U);
     EXPECT_TRUE(State->NativeClosed.load(std::memory_order_acquire));
     EXPECT_EQ(Fixture.PendingOwners(), 0U);
     EXPECT_TRUE(WeakOutbound.expired());
     EXPECT_EQ(Fixture.Account()->Runtime()->ActiveConnections(), 0U);
     Fixture.ResetRegistration();
     EXPECT_EQ(Fixture.RegistrySize(), 0U);
 }
