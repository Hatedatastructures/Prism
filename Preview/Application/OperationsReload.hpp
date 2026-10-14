/**
 * @file OperationsReload.hpp
 * @brief Operations Reload 命令的候选编译、worker 准备与唯一发布 owner。
 */
#pragma once

#include <Preview/Application/Configuration/ConfigurationParser.hpp>
#include <Preview/Application/OperationsConfiguration.hpp>
#include <Preview/Application/ConfigurationCommandOutcome.hpp>
#include <Preview/Application/Reload/ConfigurationDifference.hpp>
#include <Preview/Application/Configuration/ReloadCoordinator.hpp>
#include <Preview/Application/RuntimeGenerationSnapshot.hpp>
#include <Preview/Application/RuntimeState.hpp>
#include <Preview/Application/ReloadGenerationPreparation.hpp>
#include <Preview/Application/Reload/CandidateOwner.hpp>
#include <Preview/Application/Reload/GenerationPreparation.hpp>
#include <Preview/Application/Reload/PublicationTransaction.hpp>
#include <Preview/Application/CommandOperationOwner.hpp>
#include <Preview/Operations/CommandTargetScope.hpp>
#include <Preview/Operations/Models.hpp>

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

namespace Preview::Application::OperationsReload
{

    namespace Net = boost::asio;
    namespace Configuration = Preview::Application::Configuration;
    using RuntimeState = Preview::Application::Application::RuntimeState;
    using RuntimeSnapshot = Preview::Application::RuntimeGenerationSnapshot;
    using SharedRuntimeSnapshot = Preview::Application::SharedRuntimeGenerationSnapshot;
    using Failure = Preview::Fault::Failure;
    using Outcome = Preview::Application::CommandOperationOwner::ShutdownOutcome;

    using ReloadWork = Preview::Application::Reload::ReloadWork;









    [[nodiscard]] inline auto ParseCandidate(
        const std::shared_ptr<const RuntimeSnapshot> &Current,
        const Preview::Operations::ReloadCommand &Command)
        -> std::expected<Configuration::SharedConfigurationGeneration, Configuration::ConfigurationError>
    {
        auto Parsed = Configuration::ConfigurationParser::ParseForOperationsReload(
            Command.ConfigurationJson);
        if (!Parsed)
        {
            return std::unexpected(Parsed.error());
        }
        Preview::Application::OperationsConfiguration::MergeExistingSecretSources(
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
        const std::shared_ptr<RuntimeState> &State) -> Net::awaitable<Outcome>
    {
        const auto Prepared = co_await Preview::Application::Reload::PrepareGenerationReload(
            State, Work);
        if (!Prepared)
        {
            co_return co_await Preview::Application::Reload::CandidateOwner::Abort(
                State, std::move(Work.Candidate), Prepared.error());
        }
        co_return co_await Preview::Application::Reload::PublicationTransaction::PublishPreparedReload(
            State, std::move(*Prepared));
    }

    [[nodiscard]] inline auto StartReload(
        const std::shared_ptr<RuntimeState> &State,
        const Preview::Operations::ReloadCommand &Command,
        const Preview::Operations::OperationCompletion &Completion)
        -> Preview::Operations::CommandResult
    {
        const auto Current = State ? State->ActiveGenerationSnapshot() : SharedRuntimeSnapshot{};
        if (!State || !Current || !State->Process)
        {
            return Preview::Operations::CommandResult::Unavailable(Command.Correlation);
        }
        if (Command.BaseGeneration != Current->Id())
        {
            return Preview::Operations::CommandResult::Conflict(Command.Correlation, Current->Id());
        }
        if (!Current->Generation->Configuration().HotReload.Enabled)
        {
            return Preview::Operations::CommandResult::Rejected(Command.Correlation);
        }
        auto Generation = ParseCandidate(Current, Command);
        if (!Generation)
        {
            return Preview::Application::ConfigurationCommandOutcome::Invalid(
                Command.Correlation, Generation.error());
        }
        auto RestartFields = Preview::Application::Reload::ConfigurationDifference::RestartRequiredFields(
            {Current->Generation->Configuration(), (*Generation)->Configuration()});
        if (!RestartFields.empty())
        {
            auto Result = Preview::Operations::CommandResult::RestartRequired(
                Command.Correlation, Current->Id());
            Result.RestartRequiredFields = std::move(RestartFields);
            return Result;
        }
        auto Candidate = ReloadGenerationPreparation::MakeCandidateSnapshot(State, Current, std::move(*Generation));
        if (!Candidate)
        {
            return Preview::Operations::CommandResult::FromFailure(
                Command.Correlation, Candidate.error());
        }
        const auto AckTimeout = std::chrono::milliseconds(
            Current->Generation->Configuration().HotReload.AckTimeout);
        const auto Deadline = std::chrono::steady_clock::now() + AckTimeout;
        if (Command.Mode == Preview::Operations::ReloadMode::ValidateOnly)
        {
            return Preview::Application::CommandOperationOwner::StartScopedCommand(
                Preview::Application::CommandOperationOwner::ScopedCommandRequest{
                    State, Completion, Command.Correlation, Deadline,
                    Preview::Operations::CommandTargetScope{
                        Preview::Operations::ProcessTargetScope{State->Process->Id()}},
                    Preview::Application::Reload::CandidateOwner::DrainValidated(
                        State, std::move(*Candidate)), Current->Id()});
        }
        const auto ResultGeneration = (*Candidate)->Id();
        return Preview::Application::CommandOperationOwner::StartScopedCommand(
            Preview::Application::CommandOperationOwner::ScopedCommandRequest{
                State, Completion, Command.Correlation, Deadline,
                Preview::Operations::CommandTargetScope{
                    Preview::Operations::ProcessTargetScope{State->Process->Id()}},
                RunPreparedReload(ReloadWork{
                    std::move(*Candidate), Current->Id(), Command.Correlation, Deadline}, State),
                ResultGeneration});
    }

} // namespace Preview::Application::OperationsReload
