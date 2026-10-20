/** @file Dialer.cpp @brief TCP 拨号与阶段观察的非模板实现。 */
#include <Prism/Net/Dialer/Dialer.hpp>
#include <Prism/Net/Dialer/Detail/AttemptRetirement.hpp>
#include <Prism/Net/Services/StreamEgress.hpp>
#include <Prism/Net/Services/WorkerDialService.hpp>

#include <boost/asio/bind_cancellation_slot.hpp>
#include <boost/asio/cancellation_signal.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/errc.hpp>
#include <boost/system/error_code.hpp>

#include <cstdint>
#include <exception>
#include <utility>
#include <variant>

namespace Prism::Network::Dialer
{
    Dialer::Attempt::Attempt(Net::any_io_executor Executor)
        : Socket(std::move(Executor))
    {
    }

    StageObservation::StageObservation(
        const ObservationOwner &Owner,
        const Prism::Foundation::NetworkLatencyStage Stage)
        : Sink_(Owner.Sink.lock()), Worker_(Owner.Worker), Stage_(Stage)
    {
        if (Sink_) Started_ = std::chrono::steady_clock::now();
    }

    StageObservation::~StageObservation()
    {
        Complete(Prism::Fault::Failure{Prism::Fault::Code::Canceled});
    }

    auto StageObservation::Complete(Prism::Fault::Failure Failure) noexcept -> void
    {
        if (!Sink_) return;
        auto Sink = std::move(Sink_);
        const auto Elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - Started_).count();
        Prism::Foundation::TrafficEvent Event;
        Event.Worker = Worker_;
        Event.Kind = Prism::Foundation::TrafficEventKind::NetworkLatency;
        Event.DurationMicroseconds = Elapsed > 0 ? static_cast<std::uint64_t>(Elapsed) : 0U;
        Event.Failure = Failure;
        Event.NetworkStage = Stage_;
        Sink->Report(Event);
    }
    auto Dialer::ResolveCandidates(const DialOptions &Options, const Prism::Network::Target &Target)
        -> Net::awaitable<std::expected<std::vector<Tcp::endpoint>, Prism::Fault::Failure>>
    {
        std::vector<Tcp::endpoint> Candidates;
        if (const auto Literal = Prism::Network::IpAddress(Target.Host))
        {
            if (Literal->is_v6() && !Options.EnableIpv6)
            {
                co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::NotSupported, {}});
            }
            Candidates.emplace_back(*Literal, Target.Port);
            co_return Candidates;
        }
        const auto *Domain = std::get_if<Prism::Network::DomainName>(&Target.Host.Get());
        if (Domain == nullptr || !Options.Resolver)
        {
            co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::DnsFailed, {}});
        }
        StageObservation Observation(Options.Observation, Prism::Foundation::NetworkLatencyStage::DnsResolution);
        const auto Addresses = co_await Options.Resolver->AsyncResolve(Domain->View());
        Observation.Complete(Addresses ? Prism::Fault::Failure{} : Addresses.error());
        if (!Addresses)
        {
            co_return std::unexpected(Addresses.error());
        }
        for (const auto &Address : *Addresses)
        {
            if (Address.is_v6() && !Options.EnableIpv6)
            {
                continue;
            }
            Candidates.emplace_back(Address, Target.Port);
        }
        if (Candidates.empty())
        {
            co_return std::unexpected(Prism::Fault::Failure{
                Prism::Fault::Code::DnsFailed, {}});
        }
        co_return Candidates;
    }

    auto Dialer::RunAttempt(std::shared_ptr<Race> State, const std::size_t Index) -> Net::awaitable<void>
    {
        auto &Value = *State->Attempts[Index];
        StageObservation Observation(State->Observation, Prism::Foundation::NetworkLatencyStage::TcpConnect);
        boost::system::error_code ConnectError;
        if (State->Connect)
        {
            ConnectError = co_await State->Connect(
                {Value.Socket, State->Candidates[Index]}, Value.Signal.slot());
        }
        else
        {
            co_await Value.Socket.async_connect(
                State->Candidates[Index],
                Net::bind_cancellation_slot(
                    Value.Signal.slot(), Net::redirect_error(Net::use_awaitable, ConnectError)));
        }
        Observation.Complete(ConnectError ? Prism::Fault::Failure{Prism::Fault::ToCode(ConnectError), ConnectError}
            : Prism::Fault::Failure{});
        boost::system::error_code SendError;
        co_await State->Events->async_send(boost::system::error_code{}, RaceEvent{Index, ConnectError, false},
            Net::redirect_error(Net::use_awaitable, SendError));
    }

    auto Dialer::WatchDeadline(std::shared_ptr<Race> State, const std::chrono::milliseconds Timeout)
        -> Net::awaitable<void>
    {
        Net::steady_timer Timer(co_await Net::this_coro::executor);
        Timer.expires_after(Timeout);
        boost::system::error_code WaitError;
        co_await Timer.async_wait(Net::redirect_error(Net::use_awaitable, WaitError));
        if (WaitError)
        {
            co_return;
        }
        for (const auto &Value : State->Attempts)
        {
            Value->Signal.emit(Net::cancellation_type::all);
        }
        boost::system::error_code SendError;
        co_await State->Events->async_send(boost::system::error_code{},
            RaceEvent{State->Attempts.size(), {}, true},
            Net::redirect_error(Net::use_awaitable, SendError));
    }

    auto Dialer::CloseAttempts(const Race &State, const std::optional<std::size_t> Keep) -> void
    {
        for (std::size_t Index = 0; Index < State.Attempts.size(); ++Index)
        {
            if (Keep && Index == *Keep)
            {
                continue;
            }
            boost::system::error_code CloseError;
            State.Attempts[Index]->Socket.close(CloseError);
        }
    }

    auto Dialer::CompleteAttempt(std::shared_ptr<Race> State,
                                 const std::size_t Index,
                                 const bool Failed) -> void
    {
        if (Failed)
        {
            (void)State->Events->try_send(boost::system::error_code{}, RaceEvent{Index,
                boost::system::errc::make_error_code(boost::system::errc::io_error), false});
        }
        const auto Retired = State->Retired.fetch_add(1, std::memory_order_acq_rel) + 1U;
        if (Retired == State->Attempts.size())
        {
            (void)State->Events->try_send(boost::system::error_code{},
                RaceEvent{State->Attempts.size(), {}, false, true});
        }
    }

    auto Dialer::RunRace(std::shared_ptr<Race> State, const std::chrono::milliseconds Timeout)
        -> Net::awaitable<RaceOutcome>
    {
        State->Events = std::make_shared<EventChannel>(State->Executor, State->Candidates.size() + 2U);
        State->Watch = std::make_shared<Net::cancellation_signal>();
        for (std::size_t Index = 0; Index < State->Candidates.size(); ++Index)
        {
            State->Attempts.push_back(std::make_shared<Attempt>(State->Executor));
            Net::co_spawn(State->Executor, RunAttempt(State, Index), [State, Index]
                (std::exception_ptr Exception)
                {
                    CompleteAttempt(State, Index, static_cast<bool>(Exception));
                });
        }
        Net::co_spawn(State->Executor, WatchDeadline(State, Timeout),
            Net::bind_cancellation_slot(State->Watch->slot(), Net::detached));

        std::size_t Reported = 0;
        RaceOutcome Outcome;
        bool AllRetired = false;
        while (Reported < State->Attempts.size())
        {
            boost::system::error_code ReceiveError;
            const auto Event = co_await State->Events->async_receive(
                Net::redirect_error(Net::use_awaitable, ReceiveError));
            if (ReceiveError)
            {
                Outcome.Aborted = true;
                State->Watch->emit(Net::cancellation_type::all);
                for (const auto &AttemptValue : State->Attempts)
                {
                    AttemptValue->Signal.emit(Net::cancellation_type::all);
                }
                CloseAttempts(*State, std::nullopt);
                co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
                continue;
            }
            if (Event.Expired)
            {
                Outcome.Expired = true;
                continue;
            }
            ++Reported;
            if (Event.Error)
            {
                Outcome.LastError = Event.Error;
                continue;
            }
            if (Outcome.Winner)
            {
                continue;
            }
            Outcome.Winner = Event.Index;
            for (std::size_t Index = 0; Index < State->Attempts.size(); ++Index)
            {
                if (Index != Event.Index)
                {
                    State->Attempts[Index]->Signal.emit(Net::cancellation_type::all);
                }
            }
        }

        if (!Outcome.Aborted)
        {
            State->Watch->emit(Net::cancellation_type::all);
            CloseAttempts(*State, Outcome.Winner);
        }
        while (!AllRetired)
        {
            boost::system::error_code ReceiveError;
            (void)co_await Detail::WaitUntilAttemptRetired(
                *State->Events, Net::redirect_error(Net::use_awaitable, ReceiveError));
            if (ReceiveError)
            {
                if (!Outcome.Aborted)
                {
                    Outcome.Aborted = true;
                    for (const auto &AttemptValue : State->Attempts)
                    {
                        AttemptValue->Signal.emit(Net::cancellation_type::all);
                    }
                    CloseAttempts(*State, std::nullopt);
                    co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
                }
                continue;
            }
            AllRetired = true;
        }
        co_return Outcome;
    }

    auto Dialer::Connect(Prism::Network::Target Target)
        -> Net::awaitable<std::expected<Prism::SharedTransmission, Prism::Fault::Failure>>
    {
        if (Target.Host.Empty() || Target.Port == 0)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument, {}});
        }

        auto Candidates = co_await ResolveCandidates(Options_, Target);
        if (!Candidates)
        {
            co_return std::unexpected(Candidates.error());
        }

        auto State = std::make_shared<Race>(Executor_);
        State->Observation = Options_.Observation;
        State->Connect = Options_.Connect;
        State->Candidates = std::move(*Candidates);
        auto Outcome = co_await RunRace(State, Options_.Timeout);
        if (Outcome.Aborted)
        {
            co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Canceled, {}});
        }
        if (!Outcome.Winner)
        {
            if (Outcome.Expired)
            {
                co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Timeout, {}});
            }
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::ToCode(Outcome.LastError), Outcome.LastError});
        }
        auto Socket = std::move(State->Attempts[*Outcome.Winner]->Socket);
        co_return std::make_shared<Prism::Transport::Reliable>(std::move(Socket));
    }

}

namespace Prism::Network::Services
{
    WorkerDialService::WorkerDialService(WorkerDialOptions Options)
        : Resolver_(std::make_shared<Prism::Network::Dns::Resolver>(Options.Executor, Options.Dns)),
          Dialer_(Options.Executor,
              Prism::Network::Dialer::DialOptions{
                  Options.Timeout, Options.EnableIpv6, Resolver_, Options.Observation})
    {
    }

    auto WorkerDialService::Connect(Prism::Network::Target Target)
        -> Net::awaitable<std::expected<Prism::SharedTransmission, Prism::Fault::Failure>>
    {
        if (Stopping_.load(std::memory_order_acquire))
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::Canceled});
        }
        co_return co_await Dialer_.Connect(std::move(Target));
    }

    auto WorkerDialService::Shutdown()
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
        Stopping_.store(true, std::memory_order_release);
        if (!Resolver_)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        }
        co_return co_await Resolver_->Shutdown();
    }
}

namespace Prism::Network
{
    StreamEgress::StreamEgress(StreamEgressOptions Options)
        : Dialer_(Options.Executor,
              Prism::Network::Dialer::DialOptions{Options.Timeout, true, std::move(Options.Resolver)})
    {
    }

    auto StreamEgress::Connect(Prism::Network::Target Target)
        -> boost::asio::awaitable<std::expected<Prism::SharedTransmission, Prism::Fault::Failure>>
    {
        co_return co_await Dialer_.Connect(std::move(Target));
    }
}
