/** @file Relay.hpp @brief Runtime 与协议共用的有界可靠中继 owner。 */
#pragma once
#include <Preview/Net/Relay/Pump.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

namespace Preview::Network::Relay
{
    /** @brief 准入失败仍退休已移交载体；交付失败保留底层正式 Control owner 并返回真实原因。 */
    inline auto Reject(Request Input, Fault::Failure Failure) -> Net::awaitable<Result>
    {
        co_await Net::this_coro::throw_if_cancelled(false);
        co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
        Result Output{.Failure = Failure};
        std::array<SharedTransmission, 2> Carriers{std::move(Input.Inbound), std::move(Input.Outbound)};
        for (std::size_t Direction = 0; Direction < Carriers.size(); ++Direction)
        {
            const auto& Carrier = Carriers[Direction];
            if (!Carrier) continue;
            const auto Close = Carrier->Close();
            if (!Close) { Output.DirectionFailure[Direction] = Close.error(); Output.Failure = Close.error(); continue; }
            auto Activity = Carrier->Activity();
            if (!Activity)
            { Output.DirectionFailure[Direction] = {Fault::Code::Blocked}; Output.Failure = {Fault::Code::Blocked}; continue; }
            const auto Drain = co_await Activity->Drain();
            if (!Drain) { Output.DirectionFailure[Direction] = Drain.error(); Output.Failure = Drain.error(); }
        }
        co_return Output;
    }
    /** @brief 原 strand 等全部 pump 与监视任务结束，然后等待两端真实活动退休。 */
    inline auto RunOnExecutor(std::shared_ptr<State> Owner) -> Net::awaitable<Result>
    {
        co_await Net::this_coro::throw_if_cancelled(false);
        Owner->Touch();
        using Net::experimental::awaitable_operators::operator&&;
        auto Upload = Net::co_spawn(Owner->Executor, Pump(Owner, 0), Net::use_awaitable);
        auto Download = Net::co_spawn(Owner->Executor, Pump(Owner, 1), Net::use_awaitable);
        if (Owner->Input.IdleTimeout.count() > 0)
        {
            auto Idle = Net::co_spawn(Owner->Executor, WaitIdle(Owner), Net::use_awaitable);
            co_await (std::move(Upload) && std::move(Download) && std::move(Idle));
        }
        else co_await (std::move(Upload) && std::move(Download));
        Owner->Close();
        co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
        const auto First = co_await Owner->Input.Inbound->Activity()->Drain();
        if (!First) Owner->Record(0, First.error());
        const auto Second = co_await Owner->Input.Outbound->Activity()->Drain();
        if (!Second) Owner->Record(1, Second.error());
        co_return std::move(Owner->Output);
    }
    /**
     * @brief 接管两端；预算拒绝不取得块，成功保活存储和载体至实际退出。
     * @return 完整领域/原生错误及成功字节；普通取消关闭不抛异常。
     * @details 输入载体归此 owner 最终关闭，工作在入站原 executor 的串行域。
     */
    [[nodiscard]] inline auto Run(Request Input) -> Net::awaitable<Result>
    {
        co_await Net::this_coro::throw_if_cancelled(false);
        if (!Input.Inbound || !Input.Outbound)
            co_return co_await Reject(std::move(Input), {Fault::Code::BadGateway});
        if (!Input.Bytes) co_return co_await Reject(std::move(Input), {Fault::Code::ResourceUnavailable});
        if (Input.BufferSize < 2 || Input.BufferSize > Input.Bytes->BlockSize())
            co_return co_await Reject(std::move(Input), {Fault::Code::InvalidArgument});
        auto Upload = Input.Bytes->TryAcquire(Input.BufferSize);
        if (!Upload) co_return co_await Reject(std::move(Input), Upload.error());
        auto Download = Input.Bytes->TryAcquire(Input.BufferSize);
        if (!Download) co_return co_await Reject(std::move(Input), Download.error());
        std::array<Memory::OwnedBytes, 2> Buffers{std::move(*Upload), std::move(*Download)};
        auto Owner = std::make_shared<State>(std::move(Input), std::move(Buffers));
        co_return co_await Net::co_spawn(Owner->Executor, RunOnExecutor(Owner), Net::use_awaitable);
    }
}
