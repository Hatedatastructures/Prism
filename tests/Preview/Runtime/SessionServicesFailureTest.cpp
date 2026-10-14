/**
 * @file SessionServicesFailureTest.cpp
 * @brief 验证会话数据面保留原生失败并在拒绝复用入口后等待真实活动排空。
 */

#include "SessionLifecycleTestSupport.hpp"

#include <Preview/Foundation/Memory/BytePool.hpp>
#include <Preview/Contract/Ingress/InboundAdmission.hpp>
#include <Preview/Protocols/Common/ProtocolActivity.hpp>
#include <Preview/Runtime/GenerationPublication.hpp>

#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <system_error>
#include <utility>

namespace
{    class RejectedMuxProbe final : public Preview::Contract::MuxSession
    {
    public:
        RejectedMuxProbe(Preview::SharedTransmission Transport,
            std::shared_ptr<ByteChannel> Closed)
            : Activity_(std::make_shared<Preview::Protocols::ProtocolActivity>(
                  Transport->Executor())),
              Closed_(std::move(Closed))
        {
        }

        auto Run(Preview::Contract::MuxRootRequest)
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>> override
        {
            RunCalled = true;
            co_return std::expected<void, Preview::Fault::Failure>{};
        }

        [[nodiscard]] auto Activity() const
            -> std::shared_ptr<Preview::Contract::CarrierActivity> override
        {
            return Activity_;
        }

        [[nodiscard]] auto IsRetired() const noexcept -> bool override
        {
            return Activity_->IsRetired();
        }

        auto Cancel() noexcept -> void override { CancelCalled = true; Activity_->Seal(); }

        auto Close() noexcept -> void override
        {
            CloseCalled = true;
            Activity_->Seal();
            (void)Closed_->try_send(boost::system::error_code{});
        }

        bool RunCalled{false};
        bool CancelCalled{false};
        bool CloseCalled{false};
        std::shared_ptr<Preview::Protocols::ProtocolActivity> Activity_;

    private:
        std::shared_ptr<ByteChannel> Closed_;
    };

    struct RejectedMuxAdmissionState final
    {
        std::shared_ptr<Preview::MemoryStream> Client;
        std::shared_ptr<Preview::MemoryStream> Inbound;
        std::shared_ptr<RejectedMuxProbe> Mux;
        std::shared_ptr<Preview::Runtime::GenerationPublication> Publisher;
        std::shared_ptr<ByteChannel> Closed;
        std::shared_ptr<ByteChannel> Finished;
        std::shared_ptr<Preview::Account::AccountRuntime> Runtime;
        std::optional<Preview::Protocols::ProtocolActivity::Reservation> Reservation;
        Preview::Contract::ProtocolDataPlane Plane;
        std::optional<Preview::Contract::AcceptOutcome> Outcome;
        Preview::Fault::Failure PrepareFailure;
        std::uint32_t ActiveDuringDrain{0};
        std::uint32_t ActiveAfterDrain{0};
        bool SetupReady{false};
        bool Prepared{false};
        bool ReservationReady{false};
        bool InboundOpenDuringDrain{false};
        bool InboundOpenAfterDrain{true};
    };

    auto RunRejectedMuxAdmission(std::shared_ptr<RejectedMuxAdmissionState> State)
        -> Net::awaitable<void>
    {
        auto Prepared = co_await Preview::Contract::InboundAdmission::Prepare(State->Inbound);
        if (!Prepared)
        {
            State->PrepareFailure = Prepared.error();
            (void)State->Closed->try_send(boost::system::error_code{});
        }
        else
        {
            State->Prepared = true;
            auto Admission = std::move(*Prepared);
            State->Outcome = co_await Admission.Admit(std::move(State->Plane));
        }
        (void)State->Finished->try_send(boost::system::error_code{});
    }

    auto RunRejectedMuxAdmissionScenario(Net::io_context &Io,
        std::shared_ptr<RejectedMuxAdmissionState> State) -> Net::awaitable<void>
    {
        auto [Client, Inbound] = Preview::MakeMemoryPair(Io.get_executor());
        State->Client = std::make_shared<Preview::MemoryStream>(std::move(Client));
        State->Inbound = std::make_shared<Preview::MemoryStream>(std::move(Inbound));
        State->Closed = MakeReleaseChannel(Io.get_executor());
        State->Finished = MakeReleaseChannel(Io.get_executor());
        State->Mux = std::make_shared<RejectedMuxProbe>(State->Inbound, State->Closed);

        auto Directory = Preview::Testing::ProviderAccount(
            Preview::Account::Credential::Password("rejected-mux"), Preview::AccountId{7111},
            {.MaxConnections = 1});
        const auto Record = Directory->Store->FindById(Preview::AccountId{7111});
        if (!Record) co_return;
        State->Runtime = Record->Runtime();
        State->Publisher = Directory->Publication;
        if (!State->Publisher) co_return;
        auto AuthResult = Directory->Authenticator->Authenticate(Preview::AuthenticationRequest{
            .AccountId = {},
            .Identity = {},
            .Credential = Preview::Account::CredentialView::Password("rejected-mux"),
            .Rate = {}});
        if (!AuthResult || !*AuthResult) co_return;

        State->Plane.ProtocolAuthenticated = true;
        State->Plane.AccountLease = std::move(*AuthResult);
        // 缺少 AccountId 是本用例刻意构造的 typed plane 违规，触发正式 Admission 拒绝。
        State->Plane.Root = Preview::Contract::MuxRootDataPlane{State->Inbound, State->Mux};
        auto Reservation = State->Mux->Activity_->TryBegin();
        if (Reservation)
        {
            State->ReservationReady = true;
            State->Reservation.emplace(std::move(*Reservation));
        }
        State->SetupReady = true;

        Net::co_spawn(Io, RunRejectedMuxAdmission(State), Net::detached);
        boost::system::error_code Error;
        co_await State->Closed->async_receive(Net::redirect_error(Net::use_awaitable, Error));
        State->ActiveDuringDrain = State->Runtime->ActiveConnections();
        State->InboundOpenDuringDrain = State->Inbound->IsOpen();
        if (State->Reservation)
        {
            State->Reservation->Complete();
            State->Reservation.reset();
        }
        Error.clear();
        co_await State->Finished->async_receive(Net::redirect_error(Net::use_awaitable, Error));
        State->ActiveAfterDrain = State->Runtime->ActiveConnections();
        State->InboundOpenAfterDrain = State->Inbound->IsOpen();
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

    auto AcceptTypedDatagram(
        std::shared_ptr<bool> ServiceCalled,
        std::shared_ptr<Preview::Fault::Failure> RunFailure,
        Preview::SharedTransmission Inbound)
        -> Net::awaitable<Preview::Contract::AcceptOutcome>
    {
        Preview::Contract::DatagramDataPlane Datagram;
        Datagram.Transport = Inbound;
        Datagram.Session = std::make_shared<Preview::Testing::DatagramSession>(
            Inbound,
            [ServiceCalled, RunFailure]()
                -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
            {
                *ServiceCalled = true;
                if (RunFailure && RunFailure->Failed())
                {
                    co_return std::unexpected(*RunFailure);
                }
                co_return std::expected<void, Preview::Fault::Failure>{};
            });
        Preview::Contract::ProtocolDataPlane Plane;
        Plane.Root = std::move(Datagram);
        auto Prepared = co_await Preview::Contract::InboundAdmission::Prepare(std::move(Inbound));
        if (!Prepared)
        {
            co_return std::unexpected(Prepared.error());
        }
        co_return co_await Prepared->Admit(std::move(Plane));
    }

    struct TypedDatagramFactory final
    {
        std::shared_ptr<bool> ServiceCalled;
        std::shared_ptr<Preview::Fault::Failure> RunFailure;

        auto operator()(Preview::Contract::StreamAcceptInput Input) const
            -> Net::awaitable<Preview::Contract::AcceptOutcome>
        {
            return AcceptTypedDatagram(ServiceCalled, RunFailure, std::move(Input.Inbound));
        }
    };

    struct TypedDatagramRequest final
    {
        std::shared_ptr<Preview::Runtime::Session> Session;
        std::shared_ptr<Preview::MemoryStream> Client;
        std::shared_ptr<Preview::MemoryStream> Server;
        std::shared_ptr<Preview::Fault::Failure> Result;
    };

    auto RunTypedDatagram(TypedDatagramRequest Request) -> Net::awaitable<void>
    {
        const std::string Greeting("\x05\x01\x00", 3);
        std::error_code ErrorCode;
        const auto Write = co_await Request.Client->WriteSome(
            std::span<const std::byte>(
                reinterpret_cast<const std::byte *>(Greeting.data()), Greeting.size()));
        ErrorCode = Preview::Fault::ToNative(Write.Failure);
        EXPECT_FALSE(ErrorCode);
        *Request.Result = co_await Request.Session->Run(Request.Server);
    }
}

TEST(SessionDataPlane, DatagramRunPreservesNativeFailure)
    {
        Net::io_context Ioc;
        auto [ClientRaw, ServerRaw] = Preview::MakeMemoryPair(Ioc.get_executor());
        auto Client = std::make_shared<Preview::MemoryStream>(std::move(ClientRaw));
        auto Server = std::make_shared<Preview::MemoryStream>(std::move(ServerRaw));
        auto ServiceCalled = std::make_shared<bool>(false);
        const auto Native = std::make_error_code(std::errc::connection_reset);
        auto RunFailure = std::make_shared<Preview::Fault::Failure>(
            Preview::Fault::Code::ConnectionReset, Native);
        auto Result = std::make_shared<Preview::Fault::Failure>();

        auto Options = MakeSessionOptions(Ioc.get_executor());
        Options.Services->AcceptProtocol = std::make_shared<Preview::Testing::StreamFactory>(
            TypedDatagramFactory{ServiceCalled, RunFailure});
        auto Session = std::make_shared<Preview::Runtime::Session>(std::move(Options));

        Preview::Testing::RunCoro(Ioc, RunTypedDatagram(
            TypedDatagramRequest{Session, Client, Server, Result}));

        EXPECT_TRUE(*ServiceCalled);
        EXPECT_EQ(Result->Code, Preview::Fault::Code::ConnectionReset);
        EXPECT_EQ(Result->Native, Native);
    }

TEST(SessionDataPlane, RejectedMuxDoesNotRunAndRetainsLeaseUntilActivityDrain)
{
    Net::io_context Io;
    auto State = std::make_shared<RejectedMuxAdmissionState>();
    RunCoro(Io, RunRejectedMuxAdmissionScenario(Io, State));

    ASSERT_TRUE(State->SetupReady);
    EXPECT_TRUE(State->Prepared);
    EXPECT_TRUE(State->ReservationReady);
    EXPECT_TRUE(State->Mux->CancelCalled);
    EXPECT_TRUE(State->Mux->CloseCalled);
    EXPECT_FALSE(State->Mux->RunCalled);
    EXPECT_EQ(State->ActiveDuringDrain, 1U);
    EXPECT_TRUE(State->InboundOpenDuringDrain);
    ASSERT_TRUE(State->Outcome);
    ASSERT_FALSE(*State->Outcome);
    EXPECT_EQ(State->Outcome->error().Code, Preview::Fault::Code::AuthFailed);
    EXPECT_EQ(State->ActiveAfterDrain, 0U);
    EXPECT_FALSE(State->InboundOpenAfterDrain);
}
