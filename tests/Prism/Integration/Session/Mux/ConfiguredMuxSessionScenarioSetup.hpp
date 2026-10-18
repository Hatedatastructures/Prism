/** @file ConfiguredMuxSessionScenarioSetup.hpp @brief 配置化 Mux 场景的冷装配与启动。 */
#pragma once

#include "ConfiguredMuxSessionScenarioFlow.hpp"
#include <Prism/Composition/Protocol/ProtocolCatalog.hpp>

namespace
{
    [[nodiscard]] auto MakeMaxStreamDirectory(
        const std::shared_ptr<const Prism::Account::AccountBinding>& Source)
        -> std::shared_ptr<Prism::Testing::ProviderAccounts>
    {
        if (!Source) return {};
        const auto& Material = Source->Materials()->Credentials().front();
        return Prism::Testing::ProviderAccount(
            Prism::Testing::ProviderAccountInput{Source->AccountId(),
                Prism::Account::Credential(Material.Credential.Kind(),
                    Prism::Account::SecureBytes(Material.Credential.View().Bytes())),
                Material.Identity, std::string(Source->Materials()->DisplayIdentity()),
                {.MaxConnections = 1, .MaxStreams = 1, .MaxBytes = 0}},
            Prism::Testing::ProviderPin());
    }

    auto PrepareScenarioAccounts(
        const std::shared_ptr<ScenarioState>& State,
        Application::Startup::GenerationPhase::Result& Phase) -> bool
    {
        const auto Name = ProtocolName(State->Family);
        const auto Descriptor = Prism::Composition::Protocol::ProtocolCatalog::Find(Name);
        if (!Descriptor || Descriptor->Kind != Prism::Composition::Protocol::DescriptorKind::Protocol)
        {
            State->FailureMessage = std::string(Name) + " static protocol was not recognized";
            return false;
        }
        auto Published = Prism::Testing::PublishConfiguredAccountCatalog(
            Phase.Accounts, Phase.Generation);
        if (!Published)
        {
            State->FailureMessage = "configured account authority publish failed: " +
                Prism::Fault::ToNative(Published.error()).message();
            return false;
        }
        State->AdmissionPublication = std::move(*Published);
        const auto Authentication = Phase.Accounts.Find("mux-" + std::string(Name));
        if (!Authentication)
        {
            State->FailureMessage = "configured account services were not published";
            return false;
        }
        if (State->Family == ProtocolFamily::Socks5)
        {
            const auto Credential = Prism::Account::CredentialView::Password(
                "task4-provider-password");
            const auto Indexed = Authentication->Credentials.InspectCredential(Credential);
            if (!Indexed || !*Indexed)
            {
                State->FailureMessage = "configured SOCKS5 password is absent from its account scope";
                return false;
            }
            const auto Probe = Authentication->Authenticator->Authenticate(
                Prism::AuthenticationRequest{.Identity = "configured-account",
                    .Credential = Credential});
            if (!Probe)
            {
                State->FailureMessage = "configured SOCKS5 account preflight failed: " +
                    Prism::Fault::ToNative(Probe.error()).message();
                return false;
            }
        }

        auto Accounts = std::make_shared<Prism::Testing::ProviderAccounts>(
            Prism::Testing::ProviderAccounts{Phase.Accounts.Store, Authentication->Credentials,
                Authentication->Authenticator});
        if (State->Kind == ScenarioKind::QuotaSecond || State->Kind == ScenarioKind::Replacement)
        {
            Accounts = MakeMaxStreamDirectory(
                Phase.Accounts.Store->FindById(Prism::AccountId{1}));
            if (!Accounts)
            {
                State->FailureMessage = "quota scenario could not publish its MaxStreams=1 account";
                return false;
            }
            const auto LimitedRecord = Accounts->Store->FindById(Prism::AccountId{1});
            if (!LimitedRecord)
            {
                State->FailureMessage = "quota fixture account was not published";
                return false;
            }
            const auto& Material = LimitedRecord->Materials()->Credentials().front();
            const auto Probe = Accounts->Authenticator->Authenticate(
                Prism::AuthenticationRequest{.Identity = Material.Identity,
                    .Credential = Material.Credential.View()});
            if (!Probe)
            {
                State->FailureMessage = "quota fixture credential preflight failed: " +
                    Prism::Fault::ToNative(Probe.error()).message();
                return false;
            }
        }
        State->Directory = Accounts;
        State->UseState = std::make_shared<Prism::Foundation::GenerationUseState>();
        return true;
    }

    auto PrepareScenarioProvider(
        const std::shared_ptr<ScenarioState>& State,
        const Application::Startup::GenerationPhase::Result& Phase) -> bool
    {
        const auto Name = ProtocolName(State->Family);
        Provider::ConfigurationInput Input{
            Phase.Generation, State->UseState, Phase.Generation->Configuration().Protocols,
            Phase.Generation->Configuration().ProtocolBindings, {}};
        Input.Authentication.emplace("mux-" + std::string(Name),
            Prism::Contract::AuthenticationServices{Phase.Generation,
                State->Directory->Credentials, State->Directory->Authenticator});
        Provider::BindingServices ProviderServices{State->Executor, {}, {}, {}};
        ProviderServices.Streams.Egress = State->Egress;
        ProviderServices.Streams.Bytes = State->Bytes;
        auto Prepared = Provider::Compile(std::move(Input), std::move(ProviderServices));
        if (!Prepared)
        {
            State->FailureMessage = "provider compile failed";
            return false;
        }
        auto Frozen = Prepared->Freeze();
        if (!Frozen)
        {
            State->FailureMessage = "provider freeze failed";
            return false;
        }
        auto Bound = Frozen->Bind({});
        if (!Bound)
        {
            State->FailureMessage = "provider bind failed";
            return false;
        }

        Application::ProtocolProfile::ProtocolFactoryContext Context{
            Phase.Generation->Configuration(), *Phase.Generation,
            Phase.Accounts, {}, {}, &*Bound, {}, {.Egress = State->Egress, .Bytes = State->Bytes}};
        auto Profile = Application::ProtocolProfile::MakeTcpProfile(Context);
        if (!Profile || Profile->Profile->CandidateCount() != 1U ||
            Phase.Generation->Configuration().ProtocolBindings.front().MuxModes.front() != "Smux")
        {
            State->FailureMessage = "configured SOCKS5 profile did not select one Smux mode";
            return false;
        }
        State->Factory = Profile->Resolver(Profile->Profile->CandidateIdAt(0));
        if (!State->Factory || !State->Directory)
        {
            State->FailureMessage = "configured SOCKS5 profile did not publish a factory and directory";
            return false;
        }

        State->Metadata.SourceIp = "127.0.0.1";
        State->Metadata.TaskIdentity.SessionId = Prism::SessionId{3003};
        State->Metadata.TaskIdentity.TaskId = Prism::TaskId{3004};
        State->Bound = std::make_shared<Provider::BoundCatalog>(std::move(*Bound));
        return true;
    }

    auto Scenario(const ProtocolFamily Family, const ScenarioKind Kind)
        -> std::shared_ptr<ScenarioState>
    {
        const auto RootPath = std::filesystem::path{PRISM_TEST_REPO_ROOT};
        const auto Name = ProtocolName(Family);
        auto State = std::make_shared<ScenarioState>(Family, Kind);
        State->Egress = std::make_shared<LocalEgress>(State);
        auto Phase = Application::Startup::GenerationPhase::Build({
            RootPath / "tests/TestSupport/Prism/ConfiguredMux" / (std::string(Name) + ".json"), {}});
        if (!Phase)
        {
            State->FailureMessage = Phase.error().Path + ": " + Phase.error().Message;
            return State;
        }
        if (!PrepareScenarioAccounts(State, *Phase) || !PrepareScenarioProvider(State, *Phase))
            return State;

        Net::co_spawn(State->Io, RunScenario(State),
            [State](std::exception_ptr Error) { if (Error) { State->Failure = Error; State->Stop(); } });
        Net::co_spawn(State->Io, RunWatchdog(State),
            [State](std::exception_ptr Error) { if (Error) { State->Failure = Error; State->Stop(); } });
        State->Io.run();
        return State;
    }
} // namespace
