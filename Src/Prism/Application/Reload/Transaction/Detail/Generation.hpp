/**
 * @file Generation.hpp
 * @brief 准备 Reload generation、worker ACK 与账户身份事务，不发布 live 状态。
 */
#pragma once

#include <Prism/Application/Account/IdentityRegistry.hpp>
#include <Prism/Application/Operations/Detail/CommandOwner.hpp>
#include <Prism/Application/RuntimeGenerationSnapshot.hpp>
#include <Prism/Application/Startup/Detail/RuntimeState.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Utility/Diagnose/ContextState.hpp>
#include <Prism/Runtime/GenerationPublication.hpp>
#include <Prism/Runtime/WorkerGroup.hpp>

#include <boost/asio/awaitable.hpp>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <exception>
#include <memory>
#include <utility>
#include <vector>

namespace Prism::Application::Reload
{

    namespace Net = boost::asio;
    using RuntimeState = Prism::Application::Application::RuntimeState;
    using RuntimeSnapshot = Prism::Application::RuntimeGenerationSnapshot;
    using SharedRuntimeSnapshot = Prism::Application::SharedRuntimeGenerationSnapshot;
    using Failure = Prism::Fault::Failure;
    using ContextState = Prism::Diagnose::ContextState;
    using PublicationToken = Prism::Runtime::GenerationPublication::PrepareToken;
    using IdentityPreparation = Prism::Application::AccountIdentityPreparation;

    /** @brief 进入 Reload 命令后由同一个协程 owner 持有的候选工作。 */
    struct ReloadWork final
    {
        SharedRuntimeSnapshot Candidate;
        Prism::GenerationId Base{};
        Prism::RequestId Correlation{};
        std::chrono::steady_clock::time_point Deadline;
    };

    /** @brief worker 与发布器共同确认后可交给唯一 CAS 发布者的完整事务。 */
    struct PreparedGenerationReload final
    {
        SharedRuntimeSnapshot Candidate;
        SharedRuntimeSnapshot Current;
        PublicationToken Token;
        std::shared_ptr<IdentityPreparation> Identity;
        std::vector<ContextState> WorkerContexts;
        std::chrono::steady_clock::time_point Deadline;
    };

    /** @brief 只含一次 worker prepare 所需的 generation 与命令 deadline。 */
    struct WorkerPreparationRequest final
    {
        Prism::GenerationId Base{};
        SharedRuntimeSnapshot Candidate;
        std::chrono::steady_clock::time_point Deadline;
    };

    /** @brief 为发布器固定同一当前 generation 与完整候选账户成员集合。 */
    struct PublicationPreparationRequest final
    {
        SharedRuntimeSnapshot Current;
        SharedRuntimeSnapshot Candidate;
    };

    /** @brief 将发布器的准备错误映射为稳定的管理接口失败。 */
    [[nodiscard]] inline auto MapPublicationPrepareError(
        const Prism::Runtime::GenerationPublication::PrepareError Error) noexcept -> Failure
    {
        if (Error == Prism::Runtime::GenerationPublication::PrepareError::RetentionLimit ||
            Error == Prism::Runtime::GenerationPublication::PrepareError::AccountLimit ||
            Error == Prism::Runtime::GenerationPublication::PrepareError::RevocationLimit)
        {
            return Failure{Prism::Fault::Code::ResourceUnavailable};
        }
        if (Error == Prism::Runtime::GenerationPublication::PrepareError::Closed)
        {
            return Failure{Prism::Fault::Code::Canceled};
        }
        return Failure{Prism::Fault::Code::InvalidArgument};
    }

    /** @brief 准备单次 publication token；该步骤只构造候选状态、不改变 live publication。 */
    [[nodiscard]] inline auto PreparePublication(
        const std::shared_ptr<RuntimeState> &State,
        const PublicationPreparationRequest &Request) -> std::expected<PublicationToken, Failure>
    {
        if (!State || !State->GenerationPublisher || !Request.Current || !Request.Candidate ||
            !Request.Candidate->Accounts.Store)
        {
            return std::unexpected(Failure{Prism::Fault::Code::Blocked});
        }
        const Prism::Foundation::GenerationPin CurrentPin = Request.Current;
        const Prism::Foundation::GenerationPin CandidatePin = Request.Candidate;
        const auto Token = State->GenerationPublisher->Prepare(
            CurrentPin, CandidatePin, Request.Candidate->Accounts.Store->AccountIds());
        if (!Token)
        {
            return std::unexpected(MapPublicationPrepareError(Token.error()));
        }
        return *Token;
    }

    /** @brief 验证 worker prepare 回执集合精确对应本次候选及每个 worker 身份。 */
    [[nodiscard]] inline auto ValidateWorkerAcknowledgements(
        const WorkerPreparationRequest &Request,
        const std::vector<Prism::Runtime::GenerationPrepareAck> &Acknowledgements)
        -> std::expected<void, Failure>
    {
        for (std::size_t Index = 0; Index < Acknowledgements.size(); ++Index)
        {
            const auto ExpectedWorker =
                Prism::WorkerId{static_cast<std::uint64_t>(Index + 1U)};
            const auto &Ack = Acknowledgements[Index];
            if (Ack.Worker != ExpectedWorker || Ack.Base != Request.Base ||
                Ack.Candidate != Request.Candidate->Id() ||
                Ack.Status != Prism::Runtime::GenerationPrepareStatus::Prepared)
            {
                return std::unexpected(Failure{Prism::Fault::Code::ResourceUnavailable});
            }
        }
        return {};
    }

    /** @brief 收集并核验 typed worker ACK；任何不完整回执都阻止候选进入发布阶段。 */
    [[nodiscard]] inline auto PrepareWorkers(
        const std::shared_ptr<RuntimeState> &State,
        const WorkerPreparationRequest &Request) -> Net::awaitable<std::expected<void, Failure>>
    {
        if (!State || !State->Process || !Request.Candidate)
        {
            co_return std::unexpected(Failure{Prism::Fault::Code::Blocked});
        }
        const Prism::Foundation::GenerationPin CandidatePin = Request.Candidate;
        const auto Acknowledgements = co_await State->Process->Workers().PrepareGeneration(
            Request.Base, CandidatePin);
        if (!Acknowledgements)
        {
            co_return std::unexpected(Acknowledgements.error());
        }
        if (State->Phase.load(std::memory_order_acquire) != RuntimePhase::Ready)
        {
            co_return std::unexpected(Failure{Prism::Fault::Code::Canceled});
        }
        if (std::chrono::steady_clock::now() >= Request.Deadline)
        {
            co_return std::unexpected(Failure{Prism::Fault::Code::Timeout});
        }
        co_return ValidateWorkerAcknowledgements(Request, *Acknowledgements);
    }

    /** @brief 预留退休快照容量并冻结身份事务，保证 CAS 后的收尾不再分配。 */
    [[nodiscard]] inline auto StageIdentityAndRetirement(
        const std::shared_ptr<RuntimeState> &State,
        const SharedRuntimeSnapshot &Candidate)
        -> std::expected<std::shared_ptr<IdentityPreparation>, Failure>
    {
        if (!State || !Candidate)
        {
            return std::unexpected(Failure{Prism::Fault::Code::Blocked});
        }
        try
        {
            State->RetiredGenerationSnapshots.reserve(
                State->RetiredGenerationSnapshots.size() + 1U);
        }
        catch (...)
        {
            return std::unexpected(Prism::Application::CommandOperationOwner::FailureFromException(
                std::current_exception()));
        }
        if (State->Phase.load(std::memory_order_acquire) != RuntimePhase::Ready)
        {
            return std::unexpected(Failure{Prism::Fault::Code::Canceled});
        }
        auto Identity = Candidate->Accounts.IdentityPreparation;
        if (!Identity)
        {
            return std::unexpected(Failure{Prism::Fault::Code::Blocked});
        }
        const auto Staged = Identity->StageCommit();
        if (!Staged)
        {
            return std::unexpected(Staged.error());
        }
        if (!Candidate->Accounts.RuntimeTransaction)
        {
            return std::unexpected(Failure{Prism::Fault::Code::Blocked});
        }
        return Identity;
    }

    /** @brief CAS 前固定候选代的 worker Diagnose context，避免提交后分配或派生字段。 */
    [[nodiscard]] inline auto PrepareWorkerContexts(
        const std::shared_ptr<RuntimeState> &State,
        const SharedRuntimeSnapshot &Candidate) -> std::expected<std::vector<ContextState>, Failure>
    {
        if (!State || !State->Process || !Candidate || !Candidate->Services.Session ||
            !Candidate->Services.UseState ||
            Candidate->Services.Session->GenerationUseState != Candidate->Services.UseState ||
            Candidate->Services.WorkerSessions.size() != State->Process->Workers().Size())
        {
            return std::unexpected(Failure{Prism::Fault::Code::Blocked});
        }
        const auto Epoch = Candidate->Services.Session->ProcessContext.RenderEpoch();
        if (!Epoch || Candidate->Services.Session->ProcessContext.Failed())
        {
            return std::unexpected(Failure{Prism::Fault::Code::ResourceUnavailable});
        }
        std::vector<ContextState> Contexts;
        try
        {
            Contexts.reserve(Candidate->Services.WorkerSessions.size());
            for (const auto &Worker : Candidate->Services.WorkerSessions)
            {
                if (Worker.GenerationUseState != Candidate->Services.UseState ||
                    Worker.ProcessContext.Failed() || Worker.ProcessContext.RenderEpoch() != Epoch)
                {
                    return std::unexpected(Failure{Prism::Fault::Code::Blocked});
                }
                Contexts.push_back(Worker.ProcessContext);
            }
        }
        catch (...)
        {
            return std::unexpected(Prism::Application::CommandOperationOwner::FailureFromException(
                std::current_exception()));
        }
        return Contexts;
    }

    /** @brief 运行完整 prepare 闭包；成功后仅返回可发布事务，不写 live publication。 */
    [[nodiscard]] inline auto PrepareGenerationReload(
        const std::shared_ptr<RuntimeState> &State,
        ReloadWork &Work) -> Net::awaitable<std::expected<PreparedGenerationReload, Failure>>
    {
        if (!State || !State->Process || !State->GenerationPublisher || !Work.Candidate)
        {
            co_return std::unexpected(Failure{Prism::Fault::Code::Blocked});
        }
        if (State->Phase.load(std::memory_order_acquire) != RuntimePhase::Ready)
        {
            co_return std::unexpected(Failure{Prism::Fault::Code::Canceled});
        }
        const auto Current = State->ActiveGenerationSnapshot();
        if (!Current || Current->Id() != Work.Base)
        {
            co_return std::unexpected(Failure{Prism::Fault::Code::InvalidArgument});
        }
        const auto Token = PreparePublication(State,
            PublicationPreparationRequest{Current, Work.Candidate});
        if (!Token)
        {
            co_return std::unexpected(Token.error());
        }
        const auto Workers = co_await PrepareWorkers(State,
            WorkerPreparationRequest{Work.Base, Work.Candidate, Work.Deadline});
        if (!Workers)
        {
            co_return std::unexpected(Workers.error());
        }
        const auto WorkerContexts = PrepareWorkerContexts(State, Work.Candidate);
        if (!WorkerContexts)
        {
            co_return std::unexpected(WorkerContexts.error());
        }
        const auto Identity = StageIdentityAndRetirement(State, Work.Candidate);
        if (!Identity)
        {
            co_return std::unexpected(Identity.error());
        }
        co_return PreparedGenerationReload{
            std::move(Work.Candidate), Current, *Token, *Identity,
            std::move(*WorkerContexts), Work.Deadline};
    }

} // namespace Prism::Application::Reload
