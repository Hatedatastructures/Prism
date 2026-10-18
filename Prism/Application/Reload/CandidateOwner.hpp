/**
 * @file CandidateOwner.hpp
 * @brief Reload 候选 generation 的验证关闭与失败回收 owner。
 */
#pragma once

#include <Prism/Application/RuntimeGenerationSnapshot.hpp>
#include <Prism/Application/RuntimeState.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>

#include <boost/asio/awaitable.hpp>

#include <atomic>
#include <memory>
#include <utility>

namespace Prism::Application::Reload::CandidateOwner
{

    namespace Net = boost::asio;
    using RuntimeState = Prism::Application::Application::RuntimeState;
    using SharedRuntimeSnapshot = Prism::Application::SharedRuntimeGenerationSnapshot;
    using Failure = Prism::Fault::Failure;
    using Outcome = std::expected<void, Failure>;

    /** @brief 候选失败时关闭完整服务图；Drain 失败则由 RuntimeState 保留 owner 重试。 */
    [[nodiscard]] inline auto Abort(
        const std::shared_ptr<RuntimeState> &State,
        SharedRuntimeSnapshot Candidate,
        const Failure Cause) -> Net::awaitable<Outcome>
    {
        if (Candidate)
        {
            const auto Retired = co_await Candidate->DrainOwnedServices();
            if (!Retired && State)
            {
                State->RetiredGenerationSnapshots.push_back(std::move(Candidate));
                State->ObservationFailures.fetch_add(1, std::memory_order_relaxed);
            }
        }
        co_return std::unexpected(Cause);
    }

    /** @brief ValidateOnly 关闭同一完整候选服务图后才返回成功终态。 */
    [[nodiscard]] inline auto DrainValidated(
        const std::shared_ptr<RuntimeState> &State,
        SharedRuntimeSnapshot Candidate) -> Net::awaitable<Outcome>
    {
        if (!Candidate)
        {
            co_return std::unexpected(Failure{Prism::Fault::Code::Blocked});
        }
        const auto Result = co_await Candidate->DrainOwnedServices();
        if (!Result && State)
        {
            State->RetiredGenerationSnapshots.push_back(std::move(Candidate));
            State->ObservationFailures.fetch_add(1, std::memory_order_relaxed);
            co_return std::unexpected(Result.error());
        }
        co_return Outcome{};
    }

} // namespace Prism::Application::Reload::CandidateOwner
