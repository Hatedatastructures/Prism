/**
 * @file PublicationTransaction.hpp
 * @brief 通过单次 generation CAS 提交 Reload 并接管旧 snapshot retirement。
 */
#pragma once

#include <Preview/Application/Reload/CandidateOwner.hpp>
#include <Preview/Application/Reload/GenerationPreparation.hpp>
#include <Preview/Application/Shutdown.hpp>
#include <Preview/Application/RuntimeState.hpp>
#include <Preview/Foundation/Fault/Failure.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <chrono>
#include <expected>
#include <memory>
#include <system_error>
#include <utility>

namespace Preview::Application::Reload::PublicationTransaction
{

    namespace Net = boost::asio;
    using RuntimeState = Preview::Application::Application::RuntimeState;
    using Failure = Preview::Fault::Failure;
    using Outcome = std::expected<void, Failure>;
    using PreparedReload = Preview::Application::Reload::PreparedGenerationReload;

    /** @brief CAS 后本地收尾失败时保留首因并停止已不一致的运行时。 */
    [[nodiscard]] inline auto FailCommittedReload(
        const std::shared_ptr<RuntimeState> &State,
        const Failure Cause) -> Outcome
    {
        if (!State)
        {
            return std::unexpected(Cause);
        }
        const auto Recorded = State->RecordShutdownFailure(Cause);
        State->StopForFatal();
        return std::unexpected(Recorded);
    }

    /** @brief 只重试 publication gate 的瞬时竞争；所有等待共享原始命令 deadline。 */
    [[nodiscard]] inline auto PublishUntilDeadline(
        const std::shared_ptr<RuntimeState> &State,
        PreparedReload &Prepared) -> Net::awaitable<Outcome>
    {
        if (!State || !State->GenerationPublisher)
        {
            co_return std::unexpected(Failure{Preview::Fault::Code::Blocked});
        }
        for (;;)
        {
            const auto Published = State->GenerationPublisher->Publish(Prepared.Token);
            if (Published)
            {
                co_return Outcome{};
            }
            if (Published.error() !=
                Preview::Runtime::GenerationPublication::PublishError::AdmissionBusy)
            {
                co_return std::unexpected(Failure{Preview::Fault::Code::InvalidArgument});
            }
            if (std::chrono::steady_clock::now() >= Prepared.Deadline)
            {
                co_return std::unexpected(Failure{Preview::Fault::Code::Timeout});
            }
            Net::steady_timer Retry(co_await Net::this_coro::executor);
            Retry.expires_after(std::chrono::milliseconds(1));
            boost::system::error_code WaitError;
            co_await Retry.async_wait(Net::redirect_error(Net::use_awaitable, WaitError));
            if (WaitError)
            {
                co_return std::unexpected(
                    Preview::Fault::FromNative(static_cast<std::error_code>(WaitError)));
            }
            if (State->Phase.load(std::memory_order_acquire) != RuntimePhase::Ready)
            {
                co_return std::unexpected(Failure{Preview::Fault::Code::Canceled});
            }
        }
    }

    /** @brief CAS 成功后提交已冻结身份映射并登记旧代 snapshot 的 retirement owner。 */
    [[nodiscard]] inline auto FinishCommittedReload(
        const std::shared_ptr<RuntimeState> &State,
        PreparedReload &Prepared) -> Outcome
    {
        if (!State || !Prepared.Current)
        {
            return FailCommittedReload(State, Failure{Preview::Fault::Code::Blocked});
        }
        if (!Prepared.Identity || !Prepared.Candidate || !Prepared.Candidate->Services.Session ||
            !Prepared.Candidate->Services.UseState ||
            Prepared.Candidate->Services.Session->GenerationUseState !=
                Prepared.Candidate->Services.UseState || !State->Diagnose)
        {
            return FailCommittedReload(State, Failure{Preview::Fault::Code::Blocked});
        }
        const auto IdentityCommitted = Prepared.Identity->Commit();
        if (!IdentityCommitted)
        {
            return FailCommittedReload(State, IdentityCommitted.error());
        }
        const auto &CandidateSession = Prepared.Candidate->Services.Session;
        const auto Epoch = CandidateSession->ProcessContext.RenderEpoch();
        const auto EpochPublished = Epoch &&
            Prepared.WorkerContexts.size() == Prepared.Candidate->Services.WorkerSessions.size() &&
            State->Diagnose->PublishEpoch(Epoch);
        State->RetiredGenerationSnapshots.push_back(Prepared.Current);
        if (!EpochPublished)
        {
            return FailCommittedReload(State, Failure{Preview::Fault::Code::Blocked});
        }
        State->ReleaseInitialContextPins();
        State->Services = CandidateSession;
        State->ProviderBindings = Prepared.Candidate->Services.Providers;
        State->Generation = Prepared.Candidate->Generation;
        State->Accounts = Prepared.Candidate->Accounts;
        State->DiagnoseFlushInterval = std::chrono::milliseconds{Epoch->Value().Settings.FlushIntervalMs};
        try
        {
            Preview::Application::Shutdown::ArmDiagnoseFlush(State);
        }
        catch (...)
        {
            return FailCommittedReload(State,
                Preview::Application::CommandOperationOwner::FailureFromException(
                    std::current_exception()));
        }
        return {};
    }

    /** @brief 完成一次 Reload publication；失败候选仍由同一 owner 真实 Drain。 */
    [[nodiscard]] inline auto PublishPreparedReload(
        const std::shared_ptr<RuntimeState> &State,
        PreparedReload Prepared) -> Net::awaitable<Outcome>
    {
        if (!State || !Prepared.Candidate || !Prepared.Current || !Prepared.Identity)
        {
            co_return co_await Preview::Application::Reload::CandidateOwner::Abort(
                State, std::move(Prepared.Candidate), Failure{Preview::Fault::Code::Blocked});
        }
        const auto Published = co_await PublishUntilDeadline(State, Prepared);
        if (!Published)
        {
            co_return co_await Preview::Application::Reload::CandidateOwner::Abort(
                State, std::move(Prepared.Candidate), Published.error());
        }
        co_return FinishCommittedReload(State, Prepared);
    }

} // namespace Preview::Application::Reload::PublicationTransaction
