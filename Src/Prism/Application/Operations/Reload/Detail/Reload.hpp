/**
 * @file Reload.hpp
 * @brief Operations Reload 命令的候选编译、worker 准备与唯一发布 owner。
 */
#pragma once

#include <Prism/Application/Configuration/ConfigurationParser.hpp>
#include <Prism/Application/Operations/Configuration/Detail/Persistence.hpp>
#include <Prism/Application/Operations/Configuration.hpp>
#include <Prism/Application/Configuration/Command/Detail/Outcome.hpp>
#include <Prism/Application/Reload/RestartPolicy.hpp>
#include <Prism/Application/Configuration/ReloadCoordinator.hpp>
#include <Prism/Application/RuntimeGenerationSnapshot.hpp>
#include <Prism/Application/Startup/Detail/RuntimeState.hpp>
#include <Prism/Application/Reload/Candidate/Detail/Preparation.hpp>
#include <Prism/Application/Reload/Transaction/Detail/Generation.hpp>
#include <Prism/Application/Reload/Transaction/Detail/Publication.hpp>
#include <Prism/Application/Operations/Detail/CommandOwner.hpp>
#include <Prism/Operations/Models.hpp>
#include <Prism/Operations/Models.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace Prism::Application::OperationsReload
{

    namespace Net = boost::asio;
    namespace Configuration = Prism::Application::Configuration;
    using RuntimeState = Prism::Application::Application::RuntimeState;
    using RuntimeSnapshot = Prism::Application::RuntimeGenerationSnapshot;
    using SharedRuntimeSnapshot = Prism::Application::SharedRuntimeGenerationSnapshot;
    using Failure = Prism::Fault::Failure;
    using Outcome = Prism::Application::CommandOperationOwner::ShutdownOutcome;

    using ReloadWork = Prism::Application::Reload::ReloadWork;

    struct ConfigurationPersistenceLease final
    {
        explicit ConfigurationPersistenceLease(std::shared_ptr<RuntimeState> Value) : State(std::move(Value)) {}
        ~ConfigurationPersistenceLease()
        {
            if (State) State->ConfigurationPersistenceActive.store(false, std::memory_order_release);
        }
        std::shared_ptr<RuntimeState> State;
    };

    /** @brief 持有候选 reload 与唯一持久化 lease 的异步操作。 */
    struct PersistedReloadRequest final
    {
        ReloadWork Work;
        std::shared_ptr<RuntimeState> State;
        std::uint64_t Operation;
        std::shared_ptr<ConfigurationPersistenceLease> PersistenceLease;
    };








    [[nodiscard]] inline auto ParseCandidate(
        const std::shared_ptr<const RuntimeSnapshot> &Current,
        const Prism::Operations::ReloadCommand &Command)
        -> std::expected<Configuration::SharedConfigurationGeneration, Configuration::ConfigurationError>
    {
        auto Parsed = Configuration::ConfigurationParser::ParseForOperationsReload(
            Command.ConfigurationJson);
        if (!Parsed)
        {
            return std::unexpected(Parsed.error());
        }
        Prism::Application::OperationsConfiguration::MergeExistingSecretSources(
            Current->Generation->Configuration(), *Parsed);

        Configuration::ReloadRequest Request;
        Request.BaseGeneration = Command.BaseGeneration;
        Request.Configuration = std::move(*Parsed);
        Request.Builtins = Current->Generation->Builtins();
        Request.AvailableCapabilities = Current->Generation->AvailableCapabilities();
        const auto Generation = Current->Generation;
        Request.SecretResolver = [Generation](const std::string_view Reference)
            -> std::optional<std::string>
        {
            const auto Secret = Generation->LookupSecret(Reference);
            if (Secret.empty())
            {
                return std::nullopt;
            }
            return std::string(reinterpret_cast<const char *>(Secret.data()), Secret.size());
        };

        Configuration::ReloadCoordinator Coordinator;
        const auto Prepared = Coordinator.Prepare(Current->Generation, std::move(Request));
        if (!Prepared)
        {
            return std::unexpected(Prepared.error());
        }
        return *Prepared;
    }

    [[nodiscard]] inline auto RunPreparedReload(ReloadWork Work,
        std::shared_ptr<RuntimeState> State) -> Net::awaitable<Outcome>
    {
        const auto Prepared = co_await Prism::Application::Reload::PrepareGenerationReload(
            State, Work);
        if (!Prepared)
        {
            co_return co_await Prism::Application::Reload::PublicationTransaction::Abort(
                State, std::move(Work.Candidate), Prepared.error());
        }
        co_return co_await Prism::Application::Reload::PublicationTransaction::PublishPreparedReload(
            State, std::move(*Prepared));
    }

    [[nodiscard]] auto RunPersistedReload(PersistedReloadRequest Request)
        -> Net::awaitable<Outcome>;

    [[nodiscard]] inline auto StartReload(
        const std::shared_ptr<RuntimeState> &State,
        const Prism::Operations::ReloadCommand &Command,
        const Prism::Operations::OperationCompletion &Completion)
        -> Prism::Operations::CommandResult
    {
        const auto Current = State ? State->ActiveGenerationSnapshot() : SharedRuntimeSnapshot{};
        if (!State || !Current || !State->Process)
        {
            return Prism::Operations::CommandResult::Unavailable(Command.Correlation);
        }
        if (Command.BaseGeneration != Current->Id())
        {
            return Prism::Operations::CommandResult::Conflict(Command.Correlation, Current->Id());
        }
        if (!Current->Generation->Configuration().HotReload.Enabled)
        {
            return Prism::Operations::CommandResult::Rejected(Command.Correlation);
        }
        auto Generation = ParseCandidate(Current, Command);
        if (!Generation)
        {
            return Prism::Application::ConfigurationCommandOutcome::Invalid(
                Command.Correlation, Generation.error());
        }
        auto RestartFields = Prism::Application::Reload::RestartPolicy::RestartRequiredFields(
            {Current->Generation->Configuration(), (*Generation)->Configuration()});
        if (!RestartFields.empty())
        {
            auto Result = Prism::Operations::CommandResult::RestartRequired(
                Command.Correlation, Current->Id());
            Result.RestartRequiredFields = std::move(RestartFields);
            return Result;
        }
        std::shared_ptr<ConfigurationPersistenceLease> PersistenceLease;
        if (Command.Mode == Prism::Operations::ReloadMode::ApplyAndPersist)
        {
            if (State->ConfigurationPath.empty())
            {
                auto Rejected = Prism::Operations::CommandResult::Rejected(Command.Correlation);
                Rejected.Message = "configuration_path_unavailable";
                return Rejected;
            }
            bool Expected = false;
            if (!State->ConfigurationPersistenceActive.compare_exchange_strong(
                    Expected, true, std::memory_order_acq_rel))
            {
                auto Rejected = Prism::Operations::CommandResult::Rejected(Command.Correlation);
                Rejected.Message = "configuration_persistence_busy";
                return Rejected;
            }
            try { PersistenceLease = std::make_shared<ConfigurationPersistenceLease>(State); }
            catch (...)
            {
                State->ConfigurationPersistenceActive.store(false, std::memory_order_release);
                return Prism::Operations::CommandResult::Unavailable(Command.Correlation);
            }
        }
        auto Candidate = ReloadGenerationPreparation::MakeCandidateSnapshot(State, Current, std::move(*Generation));
        if (!Candidate)
        {
            return Prism::Operations::CommandResult::FromFailure(
                Command.Correlation, Candidate.error());
        }
        const auto AckTimeout = std::chrono::milliseconds(
            Current->Generation->Configuration().HotReload.AckTimeout);
        const auto Deadline = std::chrono::steady_clock::now() + AckTimeout;
        if (Command.Mode == Prism::Operations::ReloadMode::ValidateOnly)
        {
            return Prism::Application::CommandOperationOwner::StartScopedCommand(
                Prism::Application::CommandOperationOwner::ScopedCommandRequest{
                    State, Completion, Command.Correlation, Deadline,
                    Prism::Operations::CommandTargetScope{
                        Prism::Operations::ProcessTargetScope{State->Process->Id()}},
                    Prism::Application::Reload::PublicationTransaction::DrainValidated(
                        State, std::move(*Candidate)), Current->Id()});
        }
        const auto ResultGeneration = (*Candidate)->Id();
        if (PersistenceLease)
        {
            return Prism::Application::CommandOperationOwner::StartScopedCommand(
                Prism::Application::CommandOperationOwner::ScopedCommandRequest{
                    State, Completion, Command.Correlation, Deadline,
                    Prism::Operations::CommandTargetScope{
                        Prism::Operations::ProcessTargetScope{State->Process->Id()}},
                    RunPersistedReload(PersistedReloadRequest{
                        ReloadWork{
                            std::move(*Candidate), Current->Id(), Command.Correlation, Deadline},
                        State, Completion.Id().Value(), std::move(PersistenceLease)}),
                    ResultGeneration});
        }
        return Prism::Application::CommandOperationOwner::StartScopedCommand(
            Prism::Application::CommandOperationOwner::ScopedCommandRequest{
                State, Completion, Command.Correlation, Deadline,
                Prism::Operations::CommandTargetScope{
                    Prism::Operations::ProcessTargetScope{State->Process->Id()}},
                RunPreparedReload(ReloadWork{
                    std::move(*Candidate), Current->Id(), Command.Correlation, Deadline}, State),
                ResultGeneration});
    }

} // namespace Prism::Application::OperationsReload
