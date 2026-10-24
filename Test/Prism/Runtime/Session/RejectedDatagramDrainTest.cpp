#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <expected>
#include <memory>
#include <optional>
#include <system_error>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <Prism/Contract/Ingress/DatagramSession.hpp>
#include <Prism/Contract/Ingress/DataPlane.hpp>
#include <Prism/Contract/Ingress/InboundAdmission.hpp>
#include <Prism/Foundation/Executor/ClosingStorage.hpp>
#include <Prism/Foundation/Executor/ContextOwner.hpp>
#include <Prism/Protocols/Common/ProtocolActivity.hpp>
#include <Prism/Runtime/ActiveTransports.hpp>
#include <Prism/Runtime/CarrierDomain.hpp>
#include <Prism/Runtime/ListenerConnectionDrain.hpp>
#include <Prism/Transport/MemoryStream.hpp>
#include <TestSupport/Prism/PrismMockTransport.hpp>
#include <TestSupport/Prism/ProviderBindings.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>

namespace
{

    namespace Net = boost::asio;
    using Failure = Prism::Fault::Failure;

    using ByteChannel = Net::experimental::channel<void(boost::system::error_code)>;

    auto MakeReleaseChannel(Net::any_io_executor Executor) -> std::shared_ptr<ByteChannel>
    {
        return std::make_shared<ByteChannel>(std::move(Executor), 1);
    }

    /** @brief 仅用于验证 Store 拒绝 Executor 与真实 Activity 不一致的 carrier。 */

    class RejectedDatagramActivity final : public Prism::Contract::CarrierActivity
    {
    public:
        explicit RejectedDatagramActivity(std::shared_ptr<Prism::MemoryStream> Inbound)
            : Inbound_(std::move(Inbound)),
              RunActivity_(std::make_shared<Prism::Protocols::ProtocolActivity>(Inbound_->Executor())),
              InboundActivity_(Inbound_->Activity())
        {
        }

        [[nodiscard]] auto TryBegin()
            -> std::expected<Prism::Protocols::ProtocolActivity::Reservation, Failure>
        {
            return RunActivity_->TryBegin();
        }

        auto Seal() noexcept -> void override { RunActivity_->Seal(); }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            return RunActivity_->Executor();
        }

        [[nodiscard]] auto IsRetired() const noexcept -> bool override
        {
            return RunActivity_->IsRetired() && !Inbound_->IsOpen() &&
                InboundActivity_ && InboundActivity_->IsRetired();
        }

        [[nodiscard]] auto Drain()
            -> Net::awaitable<std::expected<void, Failure>> override
        {
            const auto RunDrained = co_await RunActivity_->Drain();
            if (!RunDrained) co_return std::unexpected(RunDrained.error());
            const auto Closed = Inbound_->Close();
            if (!Closed) co_return std::unexpected(Closed.error());
            InboundActivity_->Seal();
            const auto CarrierDrained = co_await InboundActivity_->Drain();
            if (!CarrierDrained) co_return std::unexpected(CarrierDrained.error());
            if (!InboundActivity_->IsRetired())
                co_return std::unexpected(Failure{Prism::Fault::Code::Blocked});
            co_return std::expected<void, Failure>{};
        }

    private:
        std::shared_ptr<Prism::MemoryStream> Inbound_;
        std::shared_ptr<Prism::Protocols::ProtocolActivity> RunActivity_;
        std::shared_ptr<Prism::Contract::CarrierActivity> InboundActivity_;
    };

    /** @brief 验证拒绝的数据报根只 Cancel/Close/Drain，不进入 Run。 */
    class RejectedDatagramProbe final : public Prism::Contract::DatagramSession
    {
    public:
        RejectedDatagramProbe(std::shared_ptr<Prism::MemoryStream> Inbound,
                              std::shared_ptr<ByteChannel> Closed)
            : Activity_(std::make_shared<RejectedDatagramActivity>(std::move(Inbound))),
              Closed_(std::move(Closed))
        {
        }

        auto Run() -> Net::awaitable<std::expected<void, Failure>> override
        {
            RunCalled = true;
            co_return std::expected<void, Failure>{};
        }

        [[nodiscard]] auto Activity() const
            -> std::shared_ptr<Prism::Contract::CarrierActivity> override
        {
            return Activity_;
        }

        auto Cancel() noexcept -> void override
        {
            CancelCalled = true;
            Activity_->Seal();
        }

        auto Close() noexcept -> void override
        {
            CloseCalled = true;
            Activity_->Seal();
            (void)Closed_->try_send(boost::system::error_code{});
        }

        bool RunCalled{false};
        bool CancelCalled{false};
        bool CloseCalled{false};
        [[nodiscard]] auto TryBegin()
            -> std::expected<Prism::Protocols::ProtocolActivity::Reservation, Failure>
        {
            return Activity_->TryBegin();
        }
        std::shared_ptr<RejectedDatagramActivity> Activity_;

    private:
        std::shared_ptr<ByteChannel> Closed_;
    };

    struct RejectedDatagramState final
    {
        std::shared_ptr<Prism::MemoryStream> Client;
        std::shared_ptr<Prism::MemoryStream> Inbound;
        std::shared_ptr<RejectedDatagramProbe> Datagram;
        std::shared_ptr<ByteChannel> Closed;
        std::shared_ptr<ByteChannel> Finished;
        std::shared_ptr<Prism::Account::AccountRuntime> Runtime;
        std::optional<Prism::Protocols::ProtocolActivity::Reservation> Reservation;
        Prism::Contract::ProtocolDataPlane Plane;
        std::optional<Prism::Contract::AcceptOutcome> Outcome;
        std::uint32_t ActiveDuringDrain{0};
        std::uint32_t ActiveAfterDrain{0};
        bool ReservationReady{false};
        bool InboundOpenDuringDrain{false};
        bool InboundOpenAfterDrain{true};
        bool PlaneLeaseHeldAfterAdmission{false};
        bool AdmissionOwnerFound{false};
        bool AdmissionRetiredAfterDrain{false};
        bool AdmissionDispatchUnavailableAfterDrain{false};
        bool SessionActivityRetiredAfterDrain{false};
        bool InboundActivityRetiredAfterDrain{false};
    };

    auto RunRejectedDatagram(std::shared_ptr<RejectedDatagramState> State)
        -> Net::awaitable<void>
    {
        auto Prepared = co_await Prism::Contract::InboundAdmission::Prepare(State->Inbound);
        if (!Prepared)
        {
            (void)State->Closed->try_send(boost::system::error_code{});
        }
        else
        {
            auto Admission = std::move(*Prepared);
            State->Outcome = co_await Admission.Admit(std::move(State->Plane));
            State->PlaneLeaseHeldAfterAdmission = static_cast<bool>(State->Plane.AccountLease);
            const auto Owner = std::dynamic_pointer_cast<Prism::Executor::ClosingResource>(
                Admission.RootCreateOwner());
            State->AdmissionOwnerFound = static_cast<bool>(Owner);
            State->AdmissionRetiredAfterDrain = Owner && Owner->IsRetired();
            State->AdmissionDispatchUnavailableAfterDrain = Owner && Owner->IsDispatchUnavailable();
        }
        (void)State->Finished->try_send(boost::system::error_code{});
    }

    auto RunRejectedDatagramAdmission(Net::io_context &Io,
        std::shared_ptr<RejectedDatagramState> State) -> Net::awaitable<void>
    {
        auto [Client, Inbound] = Prism::MakeMemoryPair(Io.get_executor());
        State->Client = std::make_shared<Prism::MemoryStream>(std::move(Client));
        State->Inbound = std::make_shared<Prism::MemoryStream>(std::move(Inbound));
        State->Closed = MakeReleaseChannel(Io.get_executor());
        State->Finished = MakeReleaseChannel(Io.get_executor());
        State->Datagram = std::make_shared<RejectedDatagramProbe>(
            State->Inbound, State->Closed);

        auto Directory = Prism::Testing::ProviderAccount(
            Prism::Account::Credential::Password("rejected-datagram"),
            Prism::AccountId{7112}, {.MaxConnections = 1});
        const auto Record = Directory->Store->FindById(Prism::AccountId{7112});
        if (!Record) co_return;
        State->Runtime = Record->Runtime();
        auto AuthResult = Directory->Authenticator->Authenticate(Prism::AuthenticationRequest{
            .AccountId = {},
            .Identity = {},
            .Credential = Prism::Account::CredentialView::Password("rejected-datagram"),
            .Rate = {}});
        if (!AuthResult || !*AuthResult) co_return;

        State->Plane.ProtocolAuthenticated = true;
        State->Plane.AccountLease = std::move(*AuthResult);
        State->Plane.Root = Prism::Contract::DatagramDataPlane{
            State->Inbound, State->Datagram};
        auto Reservation = State->Datagram->TryBegin();
        if (Reservation)
        {
            State->ReservationReady = true;
            State->Reservation.emplace(std::move(*Reservation));
        }

        Net::co_spawn(Io, RunRejectedDatagram(State), Net::detached);
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
        State->SessionActivityRetiredAfterDrain = State->Datagram->Activity_->IsRetired();
        const auto InboundActivity = State->Inbound->Activity();
        State->InboundActivityRetiredAfterDrain = InboundActivity && InboundActivity->IsRetired();
    }


    TEST(ActiveTransports, RejectedDatagramDrainsWithoutRunAndRetainsLease)
    {
        Net::io_context Io;
        auto State = std::make_shared<RejectedDatagramState>();
        Prism::Testing::RunCoro(Io, RunRejectedDatagramAdmission(Io, State));

        ASSERT_TRUE(State->ReservationReady);
        EXPECT_TRUE(State->Datagram->CancelCalled);
        EXPECT_TRUE(State->Datagram->CloseCalled);
        EXPECT_FALSE(State->Datagram->RunCalled);
        EXPECT_EQ(State->ActiveDuringDrain, 1U);
        EXPECT_TRUE(State->InboundOpenDuringDrain);
        ASSERT_TRUE(State->Outcome);
        ASSERT_FALSE(*State->Outcome);
        EXPECT_EQ(State->Outcome->error().Code, Prism::Fault::Code::AuthFailed);
        EXPECT_FALSE(State->Outcome->error().Native);
        EXPECT_FALSE(State->PlaneLeaseHeldAfterAdmission);
        EXPECT_TRUE(State->AdmissionOwnerFound);
        EXPECT_TRUE(State->AdmissionRetiredAfterDrain);
        EXPECT_FALSE(State->AdmissionDispatchUnavailableAfterDrain);
        EXPECT_TRUE(State->SessionActivityRetiredAfterDrain);
        EXPECT_TRUE(State->InboundActivityRetiredAfterDrain);
        EXPECT_EQ(State->ActiveAfterDrain, 0U);
        EXPECT_FALSE(State->InboundOpenAfterDrain);
    }

} // namespace
