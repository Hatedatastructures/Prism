/** @file RootRetirement.hpp @brief mux root 的 engine/carrier 物理退休回执。 */
#pragma once
#include <Prism/Protocols/Mux/Detail/Root/RootState.hpp>
#include <exception>
#include <expected>
#include <memory>

namespace Prism::Mux::Detail
{
    struct RootEngineDrainReceipt final
    {
        bool Retired{true};
        bool H2Retired{false};
        Prism::Fault::Failure Failure;
    };
    struct RootCarrierDrainReceipt final
    {
        bool Retired{false};
        Prism::Fault::Failure Failure;
    };
    auto PreserveRootDrainFailure(
        Prism::Fault::Failure &Primary,
        const Prism::Fault::Failure &Next) noexcept -> void;
    template<class Server>
    [[nodiscard]] inline auto DrainMuxServerTasks(
        const std::shared_ptr<RootState> &State,
        const std::shared_ptr<Server> &ServerValue)
        -> Net::awaitable<RootEngineDrainReceipt>
    {
        RootEngineDrainReceipt Receipt;
        Receipt.Retired = false;
        if (!State || !ServerValue)
        {
            Receipt.Failure = {Prism::Fault::Code::Blocked};
            co_return Receipt;
        }
        const auto Session = ServerValue->Session();
        if (!Session)
        {
            Receipt.Failure = {Prism::Fault::Code::Blocked};
            co_return Receipt;
        }
        try
        {
            co_await Session->Close();
        }
        catch (...)
        {
            PreserveRootDrainFailure(
                Receipt.Failure, ControlFailureFromException(std::current_exception()));
        }
        const auto Tasks = Session->Tasks();
        if (!Tasks)
        {
            if (!Receipt.Failure.Failed())
                Receipt.Failure = {Prism::Fault::Code::Blocked};
            co_return Receipt;
        }
        std::expected<void, Prism::Fault::Failure> Drained;
        try { Drained = co_await Tasks->Drain(); }
        catch (...) { Drained = std::unexpected(ControlFailureFromException(std::current_exception())); }
        const auto Stats = Tasks->Stats();
        Receipt.Retired = Stats.Active == 0U && !Stats.DrainBlocked;
        if (State->IsExpectedRetirementCancellation(Receipt.Failure, Receipt.Retired))
        {
            Receipt.Failure = {};
        }
        const bool ExpectedCancellation = !Drained &&
            State->IsExpectedRetirementCancellation(Drained.error(), Receipt.Retired);
        if (!Drained && !ExpectedCancellation)
            PreserveRootDrainFailure(Receipt.Failure, Drained.error());
        if (!Receipt.Retired && !Receipt.Failure.Failed())
            Receipt.Failure = {Prism::Fault::Code::Blocked};
        co_return Receipt;
    }

    /** @brief 等待 engine 自身正式 Drain，并独立读取其物理退休回执。 */
    auto DrainRootEngine(const std::shared_ptr<RootState> &State)
        -> Net::awaitable<RootEngineDrainReceipt>;

    /** @brief H2 物理 receipt 未覆盖时排空 root 原始 carrier Activity。 */
    auto DrainRootCarrier(
        const std::shared_ptr<RootState> &State,
        bool CoveredByEngine)
        -> Net::awaitable<RootCarrierDrainReceipt>;

    /** @brief Run 退出后释放最后资源，并把失败记录进 root 的单一终态。 */
    auto FinalizeRootRunResources(
        std::shared_ptr<RootState> State,
        std::expected<void, Prism::Fault::Failure> Result)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;
}
