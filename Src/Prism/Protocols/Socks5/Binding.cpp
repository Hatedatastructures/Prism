/** @file Binding.cpp @brief SOCKS5 prepared binding 与 service 接线实现。 */
#include <Prism/Protocols/Socks5/Binding.hpp>
#include <Prism/Contract/Ingress/MuxRootCreateRequest.hpp>
#include <Prism/Contract/Services/Datagram.hpp>
#include <Prism/Protocols/Common/Datagram/Binding.hpp>
#include <Prism/Protocols/Socks5/Reply.hpp>

#include "Detail/Target.hpp"

#include <exception>
#include <memory>
#include <string>
#include <utility>

namespace Prism::Socks5
{
    namespace
    {
        [[nodiscard]] auto ResolveDatagramTarget(
            const Prism::Contract::DatagramServices& Services,
            const Address& Target)
            -> Net::awaitable<std::expected<Net::ip::udp::endpoint,
                Prism::Fault::Failure>>
        {
            const auto Value = Detail::ToNetworkTarget(Target);
            if (!Value)
            {
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::BadMessage});
            }
            co_return co_await Prism::Protocols::ResolveDatagram(
                Services, std::move(*Value));
        }
    }

    auto Prepare(Preparation Input, BindingServices Services)
        -> std::expected<Prepared, Prism::Contract::ProviderFailure>
    {
        using Error = Prism::Contract::ProviderError;
        const auto Fail = [&Input](Error Code, std::string Path)
        {
            return std::unexpected(
                Prism::Contract::ProviderFailure{Code, Input.Instance, std::move(Path)});
        };
        if (Input.Instance.empty() || !Services.Executor ||
            (!Input.Config.EnableTcp && !Input.Config.EnableUdp))
        {
            return Fail(Error::InvalidConfiguration, "Options");
        }
        if (!Services.Authentication.Matches(Input.Generation))
        {
            return Fail(Error::GenerationMismatch, "Generation");
        }
        if (Input.Config.EnableAuth &&
            (!Services.Authentication.Authenticator || !Services.Authentication.Credentials))
        {
            return Fail(Error::MissingAuthentication, "Authentication");
        }
        if (Input.Config.EnableUdp && !Services.Datagrams.Resolve)
        {
            return Fail(Error::MissingResolver, "Datagrams.Resolve");
        }
        Input.Config.Authenticator = Services.Authentication.Authenticator;
        Input.Config.DeferConnectReply = true;
        return Prepared(std::move(Input), std::move(Services));
    }

    auto Binding::AcceptPrepared(Prism::Contract::StreamAcceptInput Input,
        Prism::Contract::InboundAdmission Admission)
        -> Net::awaitable<Prism::Contract::AcceptOutcome>
    {
        if (!Input.Inbound || !Input.Bytes)
        {
            co_return co_await Admission.Reject(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        const auto Value = State_->Material.load();
        if (!Value || State_->Lifetime->Closed())
        {
            co_return co_await Admission.Reject(
                Prism::Fault::Failure{Prism::Fault::Code::Canceled});
        }
        auto Activity = State_->Lifetime->Enter(Input.Inbound);
        if (!Activity || State_->Lifetime->Closed())
        {
            co_return co_await Admission.Reject(
                Prism::Fault::Failure{Prism::Fault::Code::Canceled});
        }
        auto Carrier = std::make_shared<Prism::Protocols::BoundTransmission>(Activity);
        if (const auto Tracked = Admission.Track(Carrier); !Tracked)
        {
            co_return co_await Admission.Reject(Tracked.error());
        }
        auto Config = Value->Input.Config;
        Config.EnableUdp = UdpEnabled_;
        auto Accepted = co_await Prism::Socks5::Accept(Carrier, Config);
        if (!Accepted)
        {
            co_return co_await Admission.Reject(Accepted.error());
        }
        auto Request = std::move(Accepted->RequestValue);
        auto Connection = std::move(Accepted->Connection);
        if (const auto Tracked = Admission.Track(Connection); !Tracked)
        {
            co_return co_await Admission.Reject(Tracked.error());
        }
        Prism::Contract::ProtocolDataPlane Plane;
        Plane.Protocol = Prism::Contract::ProtocolType::Socks5;
        auto Target = Detail::ToNetworkTarget(Request.Target);
        if (!Target)
        {
            co_return co_await Admission.Reject(
                Prism::Contract::FailureFromProtocolError(Prism::Error::BadAddress));
        }
        Plane.Target = std::move(*Target);
        Plane.AccountId = Connection->AccountId();
        Plane.Identity = std::string(Connection->Identity());
        Plane.AccountLease = Connection->TakeAuthLease();
        Plane.DisplayIdentity = std::string(Connection->DisplayIdentity());
        Plane.ProtocolAuthenticated = Config.EnableAuth;
        co_return co_await CompleteAccepted(AcceptedCommand{
            std::move(Value), std::move(Admission), std::move(Request),
            std::move(Connection), std::move(Plane), std::move(Input.Metadata)});
    }

    [[nodiscard]] auto PrepareAccountCredential(std::string_view Value)
        ->Prism::Account::Credential
    {
        return Prism::Account::Credential::Password(Value);
    }

    BindingState::BindingState(Prepared Value):Material(std::make_shared<const Prepared>(std::move(Value))),
        Lifetime(std::make_shared<Prism::Protocols::BindingLifetime>(Material.load()->Services.Executor,Material.load()->Input.Generation))
    {}

    BindingState::~BindingState()
    {Close();}

    auto BindingState::Close() noexcept->void
    {Lifetime->Close();for(const auto& Factory:MuxFactories)Factory->Close();}

    [[nodiscard]] auto BindingState::IsRetired() const noexcept -> bool
    {
        if (!Lifetime->IsRetired())
        {
            return false;
        }
        for (const auto& Factory : MuxFactories)
        {
            if (!Factory->IsRetired())
            {
                return false;
            }
        }
        return true;
    }

    auto BindingState::Drain()
        ->Net::awaitable<std::expected<void,Prism::Fault::Failure>>
    {
        auto Factories=MuxFactories;
        Close();
        auto FirstFailure=std::expected<void,Prism::Fault::Failure>{};
        for(const auto& Factory:Factories)
        {
            const auto Result=co_await Factory->Drain();
            if(!Result && FirstFailure)FirstFailure=std::unexpected(Result.error());
        }
        const auto ActivityDrain=co_await Lifetime->Drain();
        if(!ActivityDrain && FirstFailure)FirstFailure=std::unexpected(ActivityDrain.error());
        if(!FirstFailure)
        {
            if (IsRetired())
            {
                Material.store({});
                MuxFactories.clear();
            }
            co_return std::unexpected(FirstFailure.error());
        }
        Material.store({});
        MuxFactories.clear();
        co_return std::expected<void,Prism::Fault::Failure>{};
    }

    auto BindingState::Add(std::shared_ptr<Prism::Mux::RootBinding> Factory)->bool
    {if(!Factory||Lifetime->Closed())return false;MuxFactories.push_back(std::move(Factory));return true;}

    Binding::Binding(Prepared Value)
        :UdpEnabled_(Value.Input.Config.EnableUdp),State_(std::make_shared<BindingState>(std::move(Value)))
    {}

    Binding::Binding(std::shared_ptr<BindingState> State, AdmissionPolicy Policy)
        :UdpEnabled_(Policy.UdpEnabled.value_or(false)),State_(std::move(State)),Mux_(std::move(Policy.Mux))
    {}

    [[nodiscard]] auto Binding::WithAdmission(AdmissionPolicy Policy)->std::shared_ptr<Binding>
    {
        if (!Policy.UdpEnabled)
        {
            Policy.UdpEnabled=UdpEnabled_;
        }
        if(State_->Lifetime->Closed() || (Policy.Mux && !State_->Add(Policy.Mux)))return {};
        return std::shared_ptr<Binding>(new Binding(State_,std::move(Policy)));
    }

    auto Binding::Accept(Prism::Contract::StreamAcceptInput Input)
        -> Net::awaitable<Prism::Contract::AcceptOutcome>
    {
        auto PreparedAdmission =
            co_await Prism::Contract::InboundAdmission::Prepare(Input.Inbound);
        if (!PreparedAdmission)
        {
            co_return std::unexpected(PreparedAdmission.error());
        }
        co_return co_await AcceptPrepared(
            std::move(Input), std::move(*PreparedAdmission));
    }

    auto Binding::Close() noexcept -> void
    {State_->Close();}

    auto Binding::Drain()->Net::awaitable<std::expected<void,Prism::Fault::Failure>>
    {co_return co_await State_->Drain();}

    auto Binding::CompleteAccepted(Binding::AcceptedCommand Accepted)
        -> Net::awaitable<Prism::Contract::AcceptOutcome>
    {
        auto &Plane = Accepted.Plane;
        auto &Admission = Accepted.Admission;
        const auto &Connection = Accepted.Connection;
        if (Accepted.Request.Cmd == Command::UdpAssociate)
        {
            Prism::Protocols::DatagramBinding Services{Accepted.Material->Services.Datagrams,
                Prism::Protocols::DatagramObservation{.Request = std::move(Accepted.Metadata),
                    .Identity = Plane.Identity, .DisplayIdentity = Plane.DisplayIdentity,
                    .Protocol = Plane.Protocol, .AccountId = Plane.AccountId}};
            std::shared_ptr<UdpAssoc> Association;
            Prism::Fault::Failure BindFailure;
            std::exception_ptr BindException;
            try
            {
                Association = MakeDatagramSession(Connection, std::move(Services));
                const auto Status = co_await Association->BindAndReply();
                if (!Status)
                {
                    BindFailure = Status.error().Transport;
                    if (!BindFailure.Failed())
                    {
                        BindFailure = Prism::Contract::FailureFromProtocolError(
                            Status.error().Protocol);
                    }
                }
            }
            catch (...)
            {
                BindException = std::current_exception();
            }
            if (BindFailure.Failed() || BindException)
            {
                if (Association)
                {
                    Plane.Root = Prism::Contract::DatagramDataPlane{
                        Connection, std::move(Association)};
                }
                auto Failure = BindFailure;
                if (BindException)
                {
                    Failure = Prism::Contract::InboundAdmission::ExceptionFailure(BindException);
                }
                co_return co_await Admission.Reject(
                    std::move(Plane), Failure);
            }
            Plane.Root = Prism::Contract::DatagramDataPlane{
                Connection, std::move(Association)};
        }
        else if(Mux_)
        {
            Plane.Root = Prism::Contract::MuxRootDataPlane{Connection, {}};
            const auto UseState = Mux_->GenerationUseState();
            if (!UseState)
            {
                co_return co_await Admission.Reject(
                    std::move(Plane),
                    Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
            }
            auto Request = Prism::Contract::MuxRootCreateRequest::Prepare(
                Admission.RootCreateOwner(), UseState, std::move(Plane));
            if (!Request)
            {
                if (Plane.HasTransport())
                    co_return co_await Admission.Reject(std::move(Plane), Request.error());
                co_return std::unexpected(Request.error());
            }
            auto Created = Mux_->Create(std::move(*Request));
            if (!Created) co_return std::unexpected(Created.error());
            Plane = std::move(Created->Plane);
            const auto Reply = co_await SendConnectDeferredReply(
                Connection, Accepted.Metadata.Trace, Prism::Fault::Failure{});
            if (Reply.Failed())
            {
                co_return co_await Admission.Reject(
                    std::move(Plane), Reply);
            }
        }
        else
        {
            Plane.Root = Prism::Contract::StreamDataPlane{Connection};
            Plane.PostDial = [Connection, Trace = Accepted.Metadata.Trace](
                Prism::Fault::Failure Status)
                -> Net::awaitable<Prism::Fault::Failure>
            {
                co_return co_await SendConnectDeferredReply(Connection, Trace, Status);
            };
        }
        co_return co_await Admission.Admit(std::move(Plane));
    }

    auto Bind(Prepared Value, std::stop_token Stop)
        -> std::expected<std::shared_ptr<Binding>, Prism::Contract::ProviderFailure>
    {
        if (Stop.stop_requested())
        {
            return std::unexpected(Prism::Contract::ProviderFailure{
                Prism::Contract::ProviderError::Cancelled, Value.Input.Instance, "Bind"});
        }
        auto Verified = Prepare(std::move(Value.Input), std::move(Value.Services));
        if (!Verified)
        {
            return std::unexpected(Verified.error());
        }
        auto Result = std::shared_ptr<Binding>(new Binding(std::move(*Verified)));
        if (Stop.stop_requested())
        {
            Result->Close();
            return std::unexpected(Prism::Contract::ProviderFailure{
                Prism::Contract::ProviderError::Cancelled, {}, "Bind"});
        }
        return Result;
    }

    auto MakeDatagramSession(std::shared_ptr<Conn<>> Carrier,
        Prism::Protocols::DatagramBinding Binding) -> std::shared_ptr<UdpAssoc>
    {
        UdpAssocOptions Options;
        Options.IdleTimeout = Binding.Services.IdleTimeout;
        Options.Traffic = std::move(Binding.Services.Traffic);
        Options.TaskIdentity = Binding.Observation.Request.TaskIdentity;
        Options.AccountId = Binding.Observation.AccountId;
        Options.OnFirstTarget = [Observation = Binding.Observation](const Address& Target)
        {
            const auto Value = Detail::ToNetworkTarget(Target);
            if (Value)
            {
                Observation.FirstTarget(*Value);
            }
        };
        Options.OnSessionEnd = [Observation = std::move(Binding.Observation)](
            const Prism::Protocols::DatagramSummary& Summary)
        {
            Observation.Finish({Summary.Datagrams, Summary.UpBytes, Summary.DownBytes});
        };
        Options.Resolve = [Services = std::move(Binding.Services)](const Address& Target)
            -> Net::awaitable<std::expected<Net::ip::udp::endpoint,
                Prism::Fault::Failure>>
        {
            return ResolveDatagramTarget(Services, Target);
        };
        const auto Executor = Carrier->Executor();
        return std::make_shared<UdpAssoc>(Executor, std::move(Carrier), std::move(Options));
    }

} // namespace Prism::Socks5
