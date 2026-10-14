/**
 * @file Hysteria2AdmissionTest.cpp
 * @brief Hysteria2 admission、stream 子 owner 与 datagram 子 owner 生命周期测试。
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <Preview/Account/Account.hpp>
#include <Preview/Account/Authenticator.hpp>
#include <Preview/Protocols/Hysteria2/Admission.hpp>
#include <Preview/Protocols/Hysteria2/Codec.hpp>
#include <Preview/Protocols/Hysteria2/DatagramSession.hpp>
#include <Preview/Protocols/Hysteria2/Http3Auth.hpp>
#include <Preview/Protocols/Hysteria2/StreamSession.hpp>
#include <TestSupport/Preview/ProviderBindings.hpp>
#include <TestSupport/Preview/QuicStreamProviderActivity.hpp>
#include <Preview/Transport/MemoryStream.hpp>

namespace
{

    namespace Net = boost::asio;

    class ScriptedStreamProvider final : public Preview::Quic::StreamProvider
    {
    public:
        ScriptedStreamProvider(Net::any_io_executor Executor, std::vector<std::byte> Wire)
            : Executor_(std::move(Executor)), Chunks_{std::move(Wire)},
              Activity_(std::make_shared<Preview::Testing::Quic::StreamProviderActivity>(Executor_))
        {
        }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            return Executor_;
        }

        [[nodiscard]] auto Activity() const noexcept
            -> std::shared_ptr<Preview::Contract::CarrierActivity> override
        {
            return Activity_;
        }

        [[nodiscard]] auto Read(
            std::span<std::byte> Buffer,
            std::error_code &Error) -> Net::awaitable<std::size_t> override
        {
            Error.clear();
            if (Chunks_.empty() || Closed_)
            {
                co_return 0;
            }
            const auto Operation = Activity_->BeginOperation();
            if (!Operation)
            {
                Error = std::make_error_code(std::errc::operation_canceled);
                co_return 0;
            }
            const auto Count = (std::min)(Buffer.size(), Chunks_.front().size());
            std::copy_n(Chunks_.front().begin(), Count, Buffer.begin());
            Chunks_.front().erase(
                Chunks_.front().begin(),
                Chunks_.front().begin() + static_cast<std::ptrdiff_t>(Count));
            if (Chunks_.front().empty())
            {
                Chunks_.erase(Chunks_.begin());
            }
            co_return Count;
        }

        [[nodiscard]] auto Write(
            std::span<const std::byte> Buffer,
            std::error_code &Error) -> Net::awaitable<std::size_t> override
        {
            Error.clear();
            const auto Operation = Activity_->BeginOperation();
            if (!Operation)
            {
                Error = std::make_error_code(std::errc::operation_canceled);
                co_return 0;
            }
            Writes_.emplace_back(Buffer.begin(), Buffer.end());
            co_return Buffer.size();
        }

        [[nodiscard]] auto Close() -> Preview::Quic::StreamProvider::ControlResult override
        {
            Closed_ = true;
            Activity_->CompleteClose();
            return {};
        }
        auto ShutdownWrite()
            -> Net::awaitable<Preview::Quic::StreamProvider::ShutdownResult> override
        {
            const auto Operation = Activity_->BeginOperation();
            if (!Operation)
            {
                co_return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::Canceled});
            }
            WriteShutdown_ = true;
            co_return Preview::Quic::StreamProvider::ShutdownResult{};
        }
        auto WaitForWriteAcknowledgement()
            -> Net::awaitable<Preview::Quic::StreamProvider::ShutdownResult> override
        {
            const auto Operation = Activity_->BeginOperation();
            if (!Operation)
            {
                co_return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::Canceled});
            }
            if (!WriteShutdown_)
            {
                co_return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument});
            }
            co_return Preview::Quic::StreamProvider::ShutdownResult{};
        }

        [[nodiscard]] auto StreamId() const noexcept -> std::int64_t override
        {
            return StreamId_;
        }

        [[nodiscard]] auto IsClosed() const noexcept -> bool override
        {
            return Closed_;
        }

        std::int64_t StreamId_{1};
        bool Closed_{false};
        bool WriteShutdown_{false};
        std::vector<std::vector<std::byte>> Writes_;

    private:
        Net::any_io_executor Executor_;
        std::vector<std::vector<std::byte>> Chunks_;
        std::shared_ptr<Preview::Testing::Quic::StreamProviderActivity> Activity_;
    };

    class ScriptedDatagramProvider final : public Preview::Quic::DatagramProvider
    {
    public:
        explicit ScriptedDatagramProvider(Net::any_io_executor Executor)
            : Executor_(std::move(Executor))
        {
        }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            return Executor_;
        }

        [[nodiscard]] auto Receive(
            std::span<std::byte> Buffer,
            std::error_code &Error) -> Net::awaitable<std::size_t> override
        {
            Error.clear();
            if (Closed_ || Chunks_.empty())
            {
                co_return 0;
            }
            const auto Count = (std::min)(Buffer.size(), Chunks_.front().size());
            std::copy_n(Chunks_.front().begin(), Count, Buffer.begin());
            Chunks_.front().erase(
                Chunks_.front().begin(),
                Chunks_.front().begin() + static_cast<std::ptrdiff_t>(Count));
            if (Chunks_.front().empty())
            {
                Chunks_.erase(Chunks_.begin());
            }
            co_return Count;
        }

        [[nodiscard]] auto Send(
            std::span<const std::byte> Buffer,
            std::error_code &Error) -> Net::awaitable<std::size_t> override
        {
            Error.clear();
            Sends_.emplace_back(Buffer.begin(), Buffer.end());
            co_return Buffer.size();
        }

        auto Close() -> void override { Closed_ = true; }
        auto Cancel() -> void override { Canceled_ = true; }

        [[nodiscard]] auto IsClosed() const noexcept -> bool override
        {
            return Closed_;
        }

        Net::any_io_executor Executor_;
        std::vector<std::vector<std::byte>> Chunks_;
        std::vector<std::vector<std::byte>> Sends_;
        bool Closed_{false};
        bool Canceled_{false};
    };

    struct AuthFixture final
    {
        std::shared_ptr<Preview::Testing::ProviderAccounts> Directory;
        std::shared_ptr<Preview::Hysteria2::Http3AuthSession> Session;
        std::shared_ptr<const Preview::Account::AccountBinding> Record;
    };

    auto MakeAuthFixture(Net::any_io_executor Executor) -> AuthFixture
    {
        auto Directory = Preview::Testing::ProviderAccount(
            Preview::Account::Credential::Token("secret"), Preview::AccountId{42},
            {.MaxConnections = 1, .MaxStreams = 1});
        auto Record = Directory->Store->FindById(Preview::AccountId{42});
        EXPECT_TRUE(Record);
        auto Authenticator = Directory->Authenticator;
        return {
            Directory,
            std::make_shared<Preview::Hysteria2::Http3AuthSession>(
                Preview::Hysteria2::Http3AuthSessionOptions{Executor, Authenticator}),
            Record};
    }

    auto MakeAuthRequest(
        std::string_view Secret = "secret",
        const bool Fin = true) -> Preview::Http3::RequestEvent
    {
        auto Owner = std::make_shared<Preview::Memory::SessionResource<>>();
        Preview::Http3::HeaderBlock Headers(Owner);
        Headers.Fields.push_back({":method", "POST"});
        Headers.Fields.push_back({":scheme", "https"});
        Headers.Fields.push_back({":authority", "hysteria"});
        Headers.Fields.push_back({":path", "/auth"});
        Headers.Fields.push_back({"hysteria-auth", std::string(Secret)});
        Headers.Fields.push_back({"hysteria-cc-rx", "0"});
        return Preview::Http3::RequestEvent{
            0, Preview::Http3::RequestHead{std::move(Headers), Fin}};
    }

    auto AppendVarint(std::vector<std::byte> &Output, const std::uint64_t Value) -> void
    {
        if (Value <= 63)
        {
            Output.push_back(static_cast<std::byte>(Value));
            return;
        }
        Output.push_back(static_cast<std::byte>((Value >> 8U) | 0x40U));
        Output.push_back(static_cast<std::byte>(Value));
    }

    auto MakeRawRequest(std::span<const std::byte> Trailing) -> std::vector<std::byte>
    {
        constexpr std::string_view Target{"example.com:443"};
        std::vector<std::byte> Wire;
        AppendVarint(Wire, 0x401);
        AppendVarint(Wire, Target.size());
        for (const auto Character : Target)
        {
            Wire.push_back(static_cast<std::byte>(static_cast<unsigned char>(Character)));
        }
        AppendVarint(Wire, 0);
        Wire.insert(Wire.end(), Trailing.begin(), Trailing.end());
        return Wire;
    }

    template <typename Operation>
    auto RunIo(Net::io_context &Io, Operation OperationValue) -> void
    {
        std::exception_ptr Failure;
        Io.restart();
        Net::co_spawn(
            Io,
            std::move(OperationValue),
            [&Failure](std::exception_ptr Error) { Failure = std::move(Error); });
        Io.run();
        if (Failure)
        {
            std::rethrow_exception(Failure);
        }
    }

    /** @brief 等待 admission 子任务退栈并断言 typed drain 成功。 */
    auto DrainAdmission(
        const std::shared_ptr<Preview::Hysteria2::ConnectionAdmission> &Admission)
        -> Net::awaitable<void>
    {
        const auto Result = co_await Admission->Drain();
        EXPECT_TRUE(Result.has_value());
        co_return;
    }

    struct RawAdmissionRequest final
    {
        std::shared_ptr<Preview::Hysteria2::ConnectionAdmission> Admission;
        std::shared_ptr<ScriptedStreamProvider> Provider;
    };

    /** @brief 驱动认证 raw stream 接入并等待 admission child。 */
    auto RunRawAdmission(RawAdmissionRequest Request) -> Net::awaitable<void>
    {
        auto AuthAction = co_await Request.Admission->HandleEvent(MakeAuthRequest());
        const auto HasResponse = AuthAction.Response.has_value();
        EXPECT_TRUE(HasResponse);
        if (!HasResponse)
        {
            co_return;
        }
        auto RawAction = co_await Request.Admission->HandleEvent(
            Preview::Http3::RawStreamEvent{
                1, Preview::Http3::StreamDirection::Inbound, Request.Provider});
        EXPECT_EQ(RawAction.Mode, Preview::Http3::StreamMode::Opaque);
    }

    /** @brief 驱动仅 header 认证并发送后续空 FIN。 */
    auto RunHeadersOnly(
        std::shared_ptr<Preview::Hysteria2::ConnectionAdmission> Admission)
        -> Net::awaitable<void>
    {
        auto AuthAction = co_await Admission->HandleEvent(
            MakeAuthRequest("secret", false));
        EXPECT_TRUE(AuthAction.Response.has_value());
        if (!AuthAction.Response)
        {
            co_return;
        }
        EXPECT_FALSE(AuthAction.Response->Fin);
        EXPECT_TRUE(Admission->Authenticated());
        auto EmptyFin = co_await Admission->HandleEvent(
            Preview::Http3::DataEvent{0, {}, true});
        EXPECT_FALSE(EmptyFin.Response.has_value());
        EXPECT_FALSE(Admission->LastError().has_value());
    }

    /** @brief 驱动错误凭据并验证 unauthorized response。 */
    auto RunBadCredential(
        std::shared_ptr<Preview::Hysteria2::ConnectionAdmission> Admission)
        -> Net::awaitable<void>
    {
        auto Action = co_await Admission->HandleEvent(
            MakeAuthRequest("wrong", false));
        EXPECT_TRUE(Action.Response.has_value());
        if (Action.Response)
        {
            EXPECT_EQ(Action.Response->Status, 401);
            EXPECT_TRUE(Action.Response->Fin);
        }
        EXPECT_FALSE(Admission->Authenticated());
        EXPECT_EQ(Admission->LastError(),
                  std::optional<Preview::Hysteria2::AdmissionError>{
                      Preview::Hysteria2::AdmissionError::AuthenticationRequired});
    }

    TEST(Hysteria2Admission, AuthLeaseAndStreamQuotaReleaseOnClose)
    {
        Net::io_context Io;
        auto Fixture = MakeAuthFixture(Io.get_executor());
        ASSERT_TRUE(Fixture.Session->HandleRequest(MakeAuthRequest()).has_value());

        auto First = Fixture.Session->AcquireStream();
        ASSERT_TRUE(First.has_value());
        auto Rejected = Fixture.Session->AcquireStream();
        ASSERT_FALSE(Rejected.has_value());
        EXPECT_EQ(Rejected.error(), Preview::Hysteria2::AuthError::StreamQuota);
        First->Release();
        auto Reopened = Fixture.Session->AcquireStream();
        ASSERT_TRUE(Reopened.has_value());
        Reopened->Release();
        EXPECT_EQ(Fixture.Record->Runtime()->ActiveConnections(), 1U);
        Fixture.Session->Close();
        EXPECT_EQ(Fixture.Record->Runtime()->ActiveConnections(), 0U);
    }

    TEST(Hysteria2Admission, RetainsFirstRejectedOwnerCloseReceiptUntilRetryAccepted)
    {
        Net::io_context Io;
        auto Fixture=MakeAuthFixture(Io.get_executor());
        const Preview::Fault::Failure OriginalFailure{
            Preview::Fault::Code::Blocked,
            std::make_error_code(std::errc::operation_not_permitted)};
        const Preview::Fault::Failure LaterFailure{
            Preview::Fault::Code::IoError,
            std::make_error_code(std::errc::io_error)};
        std::size_t CloseCalls=0;
        auto Options=Preview::Hysteria2::AdmissionOptions{
            Io.get_executor(),Fixture.Session,4U,1U,{}};
        Options.CloseOwner=[&CloseCalls,OriginalFailure,LaterFailure]()
            ->std::expected<void,Preview::Fault::Failure>
        {
            ++CloseCalls;
            if(CloseCalls==1U)return std::unexpected(OriginalFailure);
            if(CloseCalls==2U)return std::unexpected(LaterFailure);
            return {};
        };
        auto Created=Preview::Hysteria2::ConnectionAdmission::Create(
            std::move(Options),Preview::Hysteria2::AdmissionServices{});
        ASSERT_TRUE(Created);
        auto Admission=std::move(*Created);
        Admission->Close();
        Io.run();
        ASSERT_EQ(CloseCalls,1U);

        std::optional<Preview::Fault::Failure> DrainFailure;
        std::exception_ptr DrainException;
        Io.restart();
        Net::co_spawn(Io,Admission->Drain(),
            [&DrainFailure,&DrainException](std::exception_ptr Error,
                std::expected<void,Preview::Fault::Failure> Result)
            {
                DrainException=std::move(Error);
                if(!DrainException && !Result)DrainFailure=Result.error();
            });
        Io.run();
        ASSERT_FALSE(DrainException);
        ASSERT_TRUE(DrainFailure);
        EXPECT_EQ(DrainFailure->Code,OriginalFailure.Code);
        EXPECT_EQ(DrainFailure->Native,OriginalFailure.Native);
        EXPECT_EQ(CloseCalls,2U);

        Io.restart();
        bool RetrySucceeded=false;
        Net::co_spawn(Io,Admission->Drain(),
            [&RetrySucceeded](std::exception_ptr Error,
                std::expected<void,Preview::Fault::Failure> Result)
            {RetrySucceeded=!Error && static_cast<bool>(Result);});
        Io.run();
        EXPECT_TRUE(RetrySucceeded);
        EXPECT_EQ(CloseCalls,3U);
    }

    TEST(Hysteria2Admission, AuthRawAdmissionClosesChildrenBeforeOwner)
    {
        Net::io_context Io;
        auto Fixture = MakeAuthFixture(Io.get_executor());
        auto CloseCalls = std::make_shared<std::size_t>(0);
        auto StreamReports = std::make_shared<std::size_t>(0);
        Preview::Hysteria2::AdmissionServices Services;
        Services.ReportStream = [StreamReports](Preview::Hysteria2::StreamReport)
        {
            ++*StreamReports;
        };
        auto Admission = Preview::Hysteria2::ConnectionAdmission::Create(
            Preview::Hysteria2::AdmissionOptions{
                Io.get_executor(), Fixture.Session, 4, 1,
                [CloseCalls]
                {
                    ++*CloseCalls;
                    return std::expected<void, Preview::Fault::Failure>{};
                }},
            std::move(Services));
        ASSERT_TRUE(Admission);
        auto Owner = std::move(*Admission);

        auto Provider = std::make_shared<ScriptedStreamProvider>(
            Io.get_executor(), std::vector<std::byte>{});
        RunIo(Io, RunRawAdmission(RawAdmissionRequest{Owner, Provider}));
        EXPECT_EQ(*StreamReports, 1U);
        Owner->Close();
        RunIo(Io, DrainAdmission(Owner));
        EXPECT_EQ(*CloseCalls, 1U);
        EXPECT_EQ(Fixture.Record->Runtime()->ActiveConnections(), 0U);
    }

    TEST(Hysteria2Admission, HeadersOnlyAuthCompletesOnFollowingEmptyFin)
    {
        Net::io_context Io;
        auto Fixture = MakeAuthFixture(Io.get_executor());
        auto Admission = Preview::Hysteria2::ConnectionAdmission::Create(
            Preview::Hysteria2::AdmissionOptions{Io.get_executor(), Fixture.Session, 4, 1, {}},
            Preview::Hysteria2::AdmissionServices{});
        ASSERT_TRUE(Admission);
        auto Owner = std::move(*Admission);

        RunIo(Io, RunHeadersOnly(Owner));
        Owner->Close();
        RunIo(Io, DrainAdmission(Owner));
    }

    TEST(Hysteria2Admission, BadCredentialReturnsUnauthorizedResponse)
    {
        Net::io_context Io;
        auto Fixture = MakeAuthFixture(Io.get_executor());
        auto Admission = Preview::Hysteria2::ConnectionAdmission::Create(
            Preview::Hysteria2::AdmissionOptions{Io.get_executor(), Fixture.Session, 4, 1, {}},
            Preview::Hysteria2::AdmissionServices{});
        ASSERT_TRUE(Admission);
        auto Owner = std::move(*Admission);

        RunIo(Io, RunBadCredential(Owner));
        Owner->Close();
        RunIo(Io, DrainAdmission(Owner));
    }

    TEST(Hysteria2Admission, StreamSessionParsesTrailingPayloadAndReportsOnce)
    {
        Net::io_context Io;
        auto Fixture = MakeAuthFixture(Io.get_executor());
        ASSERT_TRUE(Fixture.Session->HandleRequest(MakeAuthRequest()).has_value());
        auto Lease = Fixture.Session->AcquireStream();
        ASSERT_TRUE(Lease.has_value());

        const std::array<std::byte, 4> Tail{
            std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04}};
        auto Provider = std::make_shared<ScriptedStreamProvider>(
            Io.get_executor(), MakeRawRequest(Tail));
        auto MemoryPair = Preview::MakeMemoryPair(Io.get_executor());
        auto OutboundB = std::move(MemoryPair.second);
        auto Outbound = std::make_shared<Preview::MemoryStream>(std::move(OutboundB));
        auto Reports = std::make_shared<std::size_t>(0);
        auto PayloadSize = std::make_shared<std::size_t>(0);
        std::size_t CompletionCalls = 0;
        auto CompletionStatus = Preview::Fault::Code::Success;
        auto Relay = [PayloadSize](Preview::Hysteria2::StreamRelayRequest Request)
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
        {
            *PayloadSize = Request.InitialPayload.size();
            EXPECT_TRUE(Request.Lease);
            co_return std::expected<void, Preview::Fault::Failure>{};
        };
        Preview::Hysteria2::AdmissionServices Services;
        Services.Dial = [Outbound](
                            Preview::Hysteria2::DialRequest)
            -> Net::awaitable<std::expected<Preview::SharedTransmission,
                Preview::Fault::Failure>>
        {
            co_return Preview::SharedTransmission{Outbound};
        };
        Services.RelayStream = std::move(Relay);
        Services.ReportStream = [Reports](Preview::Hysteria2::StreamReport)
        {
            ++*Reports;
        };
        auto Child = Preview::Hysteria2::StreamSession::Create({
            Io.get_executor(),
            1,
            Provider,
            Fixture.Session->AccountId(),
            std::string(Fixture.Session->Identity()),
            std::move(*Lease),
            std::move(Services),
            [&CompletionCalls, &CompletionStatus](
                std::uint64_t, Preview::Fault::Code Status)
            {
                ++CompletionCalls;
                CompletionStatus = Status;
            }});
        ASSERT_TRUE(Child);
        Child->Start();
        RunIo(Io, []() -> Net::awaitable<void> { co_return; });
        Child->Close();
        EXPECT_EQ(*PayloadSize, Tail.size());
        EXPECT_EQ(*Reports, 1U);
        EXPECT_TRUE(Provider->Closed_);
        EXPECT_EQ(CompletionCalls, 1U);
        EXPECT_EQ(CompletionStatus, Preview::Fault::Code::Success);
        EXPECT_EQ(Fixture.Record->Runtime()->ActiveStreams(), 0U);
        RunIo(Io, [Outbound]() -> Net::awaitable<void>
        {
            const auto DrainResult = co_await Outbound->Activity()->Drain();
            EXPECT_TRUE(DrainResult.has_value());
            co_return;
        });
        Fixture.Session->Close();
        EXPECT_EQ(Fixture.Record->Runtime()->ActiveConnections(), 0U);
    }

    TEST(Hysteria2Admission, DatagramReportsValidMalformedDropAndBytesOnce)
    {
        Net::io_context Io;
        auto Fixture = MakeAuthFixture(Io.get_executor());
        ASSERT_TRUE(Fixture.Session->HandleRequest(MakeAuthRequest()).has_value());
        auto Lease = Fixture.Session->AcquireStream();
        ASSERT_TRUE(Lease.has_value());

        const std::string EndpointText = "example.com:443";
        std::vector<std::byte> Valid{
            std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0},
            std::byte{0}, std::byte{0}, std::byte{0}, std::byte{1}};
        Valid.push_back(static_cast<std::byte>(EndpointText.size()));
        for (const auto Character : EndpointText)
        {
            Valid.push_back(static_cast<std::byte>(
                static_cast<unsigned char>(Character)));
        }
        auto Provider = std::make_shared<ScriptedDatagramProvider>(Io.get_executor());
        Provider->Chunks_.push_back({std::byte{0xFF}});
        Provider->Chunks_.push_back(Valid);
        auto Reports = std::make_shared<std::vector<Preview::Hysteria2::DatagramSessionReport>>();
        std::uint64_t ByteUploaded = 0;
        std::uint64_t ByteDownloaded = 0;
        bool Completed = false;
        std::exception_ptr CompletionError;
        Preview::Hysteria2::AdmissionServices Services;
        Services.Resolve = [](Preview::Hysteria2::ResolveRequest Request)
            -> Net::awaitable<Preview::Hysteria2::ResolveResult>
        {
            co_return Preview::Hysteria2::ResolveResult{
                Preview::Fault::Code::Success, {Request.Target}};
        };
        Services.ExchangeDatagram = [](Preview::Hysteria2::DatagramRequest Request)
            -> Net::awaitable<Preview::Hysteria2::DatagramResult>
        {
            co_return Preview::Hysteria2::DatagramResult{
                Preview::Fault::Code::Success,
                Request.Target,
                {std::uint8_t{0xAA}},
                Request.Payload.size(),
                1};
        };
        Services.ReportDatagram = [Reports, &ByteUploaded, &ByteDownloaded](
                                      Preview::Hysteria2::DatagramSessionReport Report)
        {
            if (Report.Kind == Preview::Foundation::TrafficEventKind::Bytes) { ByteUploaded += Report.UploadedBytes; ByteDownloaded += Report.DownloadedBytes; } else { Reports->push_back(Report); }
        };
        auto Child = Preview::Hysteria2::DatagramSession::Create({
            Io.get_executor(), Provider, std::move(*Lease), Fixture.Session->AccountId(),
            std::move(Services), [&Completed, &CompletionError](std::exception_ptr Error)
            {
                Completed = true;
                CompletionError = std::move(Error);
            }});
        ASSERT_TRUE(Child);
        Child->Start();
        RunIo(Io, []() -> Net::awaitable<void> { co_return; });
        Child->Close();
        RunIo(Io, []() -> Net::awaitable<void> { co_return; });
        EXPECT_TRUE(Completed);
        EXPECT_FALSE(CompletionError);
        ASSERT_EQ(Reports->size(), 1U);
        EXPECT_EQ((*Reports)[0].Kind, Preview::Foundation::TrafficEventKind::Completed);
        EXPECT_EQ((*Reports)[0].ValidDatagrams, 1U);
        EXPECT_EQ((*Reports)[0].MalformedDatagrams, 1U);
        EXPECT_EQ((*Reports)[0].UploadedBytes, 0U);
        EXPECT_EQ((*Reports)[0].DownloadedBytes, 1U);
        EXPECT_EQ(ByteUploaded, 0U);
        EXPECT_EQ(ByteDownloaded, 1U);
        ASSERT_EQ(Provider->Sends_.size(), 1U);
        ASSERT_GE(Provider->Sends_[0].size(), 8U);
        EXPECT_EQ(Provider->Sends_[0][6], std::byte{0});
        EXPECT_EQ(Provider->Sends_[0][7], std::byte{1});
        Fixture.Session->Close();
        EXPECT_EQ(Fixture.Record->Runtime()->ActiveConnections(), 0U);
    }

} // namespace
