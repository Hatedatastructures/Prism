/** @file RootRetirement.hpp @brief mux root 的 engine/carrier 物理退休回执。 */
#pragma once
#include <Preview/Protocols/Mux/Detail/Root/RootChild.hpp>

namespace Preview::Mux::Detail
{
    struct RootEngineDrainReceipt final
    {
        bool Retired{true};
        bool H2Retired{false};
        Preview::Fault::Failure Failure;
    };
    struct RootCarrierDrainReceipt final
    {
        bool Retired{false};
        Preview::Fault::Failure Failure;
    };
    template<class Server>
    [[nodiscard]] inline auto DrainMuxServerTasks(
        const std::shared_ptr<Server> &ServerValue)
        -> Net::awaitable<RootEngineDrainReceipt>
    {
        RootEngineDrainReceipt Receipt;
        Receipt.Retired = false;
        if (!ServerValue)
        {
            Receipt.Failure = {Preview::Fault::Code::Blocked};
            co_return Receipt;
        }
        const auto Session = ServerValue->Session();
        if (!Session)
        {
            Receipt.Failure = {Preview::Fault::Code::Blocked};
            co_return Receipt;
        }
        try
        {
            co_await Session->Close();
        }
        catch (...)
        {
            Receipt.Failure = ControlFailureFromException(std::current_exception());
        }
        const auto Tasks = Session->Tasks();
        if (!Tasks)
        {
            if (!Receipt.Failure.Failed())
                Receipt.Failure = {Preview::Fault::Code::Blocked};
            co_return Receipt;
        }
        std::expected<void, Preview::Fault::Failure> Drained;
        try { Drained = co_await Tasks->Drain(); }
        catch (...) { Drained = std::unexpected(ControlFailureFromException(std::current_exception())); }
        if (!Drained && !Receipt.Failure.Failed()) Receipt.Failure = Drained.error();
        const auto Stats = Tasks->Stats();
        Receipt.Retired = Stats.Active == 0U && !Stats.DrainBlocked;
        if (!Receipt.Retired && !Receipt.Failure.Failed())
            Receipt.Failure = {Preview::Fault::Code::Blocked};
        co_return Receipt;
    }

    /** @brief 等待 engine 自身正式 Drain，并独立读取其物理退休回执。 */
    inline auto DrainRootEngine(const std::shared_ptr<RootState> &State)
        -> Net::awaitable<RootEngineDrainReceipt>
    {
        RootEngineDrainReceipt Receipt;
        if (!State->EngineControl) co_return Receipt;
        try
        {
            const auto Drained = co_await State->EngineControl->Drain();
            Receipt.Retired = State->EngineControl->IsRetired();
            if (!Drained) Receipt.Failure = Drained.error();
            else if (!Receipt.Retired)
                Receipt.Failure = {Preview::Fault::Code::Blocked};
        }
        catch (...)
        {
            Receipt.Failure = ControlFailureFromException(std::current_exception());
            Receipt.Retired = State->EngineControl->IsRetired();
        }
        Receipt.H2Retired = State->SelectedWire == Mode::H2Mux && Receipt.Retired;
        if (Receipt.Failure.Failed()) State->RecordTerminalFailure(Receipt.Failure);
        co_return Receipt;
    }

    /** @brief H2 物理 receipt 未覆盖时排空 root 原始 carrier Activity。 */
    inline auto DrainRootCarrier(
        const std::shared_ptr<RootState> &State,
        bool CoveredByEngine)
        -> Net::awaitable<RootCarrierDrainReceipt>
    {
        RootCarrierDrainReceipt Receipt;
        if (CoveredByEngine)
        {
            Receipt.Retired = true;
            co_return Receipt;
        }
        const auto Carrier = State->Inbound->Activity();
        if (!Carrier)
        {
            Receipt.Failure = {Preview::Fault::Code::Blocked};
            co_return Receipt;
        }
        Carrier->Seal();
        try
        {
            const auto Drained = co_await Carrier->Drain();
            if (!Drained) Receipt.Failure = Drained.error();
        }
        catch (...)
        {
            Receipt.Failure = ControlFailureFromException(std::current_exception());
        }
        Receipt.Retired = Carrier->IsRetired();
        if (!Receipt.Retired && !Receipt.Failure.Failed())
            Receipt.Failure = {Preview::Fault::Code::Blocked};
        co_return Receipt;
    }
}
