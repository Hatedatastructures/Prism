/**
 * @file GenerationPreparation.hpp
 * @brief 准备 Reload generation、worker ACK 与账户身份事务，不发布 live 状态。
 */
#pragma once

#include <Preview/Application/Account/IdentityRegistry.hpp>
#include <Preview/Application/CommandOperationOwner.hpp>
#include <Preview/Application/RuntimeGenerationSnapshot.hpp>
#include <Preview/Application/RuntimeState.hpp>
#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Foundation/Utility/Diagnose/ContextState.hpp>
#include <Preview/Runtime/GenerationPublication.hpp>

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

namespace Preview::Application::Reload
{

    namespace Net = boost::asio;
    using RuntimeState = Preview::Application::Application::RuntimeState;
    using RuntimeSnapshot = Preview::Application::RuntimeGenerationSnapshot;
    using SharedRuntimeSnapshot = Preview::Application::SharedRuntimeGenerationSnapshot;
    using Failure = Preview::Fault::Failure;
    using ContextState = Preview::Diagnose::ContextState;
    using PublicationToken = Preview::Runtime::GenerationPublication::PrepareToken;
    using IdentityPreparation = Preview::Application::AccountIdentityPreparation;

    /** @brief 进入 Reload 命令后由同一个协程 owner 持有的候选工作。 */
    struct ReloadWork final
    {
        SharedRuntimeSnapshot Candidate;
        Preview::GenerationId Base{};
        Preview::RequestId Correlation{};
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
        Preview::GenerationId Base{};
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
        const Preview::Runtime::GenerationPublication::PrepareError Error) noexcept -> Failure
    {
        if (Error == Preview::Runtime::GenerationPublication::PrepareError::RetentionLimit ||
            Error == Preview::Runtime::GenerationPublication::PrepareError::AccountLimit ||
            Error == Preview::Runtime::GenerationPublication::PrepareError::RevocationLimit)
        {
            return Failure{Preview::Fault::Code::ResourceUnavailable};
        }
        if (Error == Preview::Runtime::GenerationPublication::PrepareError::Closed)
        {
            return Failure{Preview::Fault::Code::Canceled};
        }
        return Failure{Preview::Fault::Code::InvalidArgument};
    }

    /** @brief 准备单次 publication token；该步骤只构造候选状态、不改变 live publication。 */
    [[nodiscard]] inline auto PreparePublication(
        const std::shared_ptr<RuntimeState> &State,
        const PublicationPreparationRequest &Request) -> std::expected<PublicationToken, Failure>
    {
        if (!State || !State->GenerationPublisher || !Request.Current || !Request.Candidate ||
            !Request.Candidate->Accounts.Store)
        {
            return std::unexpected(Failure{Preview::Fault::Code::Blocked});
        }
        const Preview::Foundation::GenerationPin CurrentPin = Request.Current;
        const Preview::Foundation::GenerationPin CandidatePin = Request.Candidate;
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
        const std::vector<Preview::Runtime::GenerationPrepareAck> &Acknowledgements)
        -> std::expected<void, Failure>
    {
        for (std::size_t Index = 0; Index < Acknowledgements.size(); ++Index)
        {
            const auto ExpectedWorker =
                Preview::WorkerId{static_cast<std::uint64_t>(Index + 1U)};
            const auto &Ack = Acknowledgements[Index];
            if (Ack.Worker != ExpectedWorker || Ack.Base != Request.Base ||
                Ack.Candidate != Request.Candidate->Id() ||
                Ack.Status != Preview::Runtime::GenerationPrepareStatus::Prepared)
            {
                return std::unexpected(Failure{Preview::Fault::Code::ResourceUnavailable});
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
            co_return std::unexpected(Failure{Preview::Fault::Code::Blocked});
        }
        const Preview::Foundation::GenerationPin CandidatePin = Request.Candidate;
        const auto Acknowledgements = co_await State->Process->Workers().PrepareGeneration(
            Request.Base, CandidatePin);
        if (!Acknowledgements)
        {
            co_return std::unexpected(Acknowledgements.error());
        }
        if (State->Phase.load(std::memory_order_acquire) != RuntimePhase::Ready)
        {
            co_return std::unexpected(Failure{Preview::Fault::Code::Canceled});
        }
        if (std::chrono::steady_clock::now() >= Request.Deadline)
        {
            co_return std::unexpected(Failure{Preview::Fault::Code::Timeout});
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
            return std::unexpected(Failure{Preview::Fault::Code::Blocked});
        }
        try
        {
            State->RetiredGenerationSnapshots.reserve(
                State->RetiredGenerationSnapshots.size() + 1U);
        }
        catch (...)
        {
            return std::unexpected(Preview::Application::CommandOperationOwner::FailureFromException(
                std::current_exception()));
        }
        if (State->Phase.load(std::memory_order_acquire) != RuntimePhase::Ready)
        {
            return std::unexpected(Failure{Preview::Fault::Code::Canceled});
        }
        auto Identity = Candidate->Accounts.IdentityPreparation;
        if (!Identity)
        {
            return std::unexpected(Failure{Preview::Fault::Code::Blocked});
        }
        const auto Staged = Identity->StageCommit();
        if (!Staged)
        {
            return std::unexpected(Staged.error());
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
            return std::unexpected(Failure{Preview::Fault::Code::Blocked});
        }
        const auto Epoch = Candidate->Services.Session->ProcessContext.RenderEpoch();
        if (!Epoch || Candidate->Services.Session->ProcessContext.Failed())
        {
            return std::unexpected(Failure{Preview::Fault::Code::ResourceUnavailable});
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
                    return std::unexpected(Failure{Preview::Fault::Code::Blocked});
                }
                Contexts.push_back(Worker.ProcessContext);
            }
        }
        catch (...)
        {
            return std::unexpected(Preview::Application::CommandOperationOwner::FailureFromException(
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
            co_return std::unexpected(Failure{Preview::Fault::Code::Blocked});
        }
        if (State->Phase.load(std::memory_order_acquire) != RuntimePhase::Ready)
        {
            co_return std::unexpected(Failure{Preview::Fault::Code::Canceled});
        }
        const auto Current = State->ActiveGenerationSnapshot();
        if (!Current || Current->Id() != Work.Base)
        {
            co_return std::unexpected(Failure{Preview::Fault::Code::InvalidArgument});
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

} // namespace Preview::Application::Reload
