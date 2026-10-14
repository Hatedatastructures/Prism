/** @file State.hpp @brief 有界双向中继的输入、值结果和唯一资源 owner。 */
#pragma once
#include <Preview/Transport/Transmission.hpp>
#include <Preview/Foundation/Memory/BytePool.hpp>
#include <Preview/Foundation/Utility/TrafficSink.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/steady_timer.hpp>
#include <array>
#include <chrono>

namespace Preview::Network::Relay
{
    namespace Net = boost::asio;
    /**
     * @brief 移交两端、共享 worker 字节池和冻结策略。
     * @details 每方向借用一个独占块至 pump 返回；零 idle 禁用监视任务。
     *          本 owner 在原 executor 请求最终关闭，Drain 等待实际操作退出。
     */
    struct Request final
    {
        SharedTransmission Inbound, Outbound;
        std::size_t BufferSize{16 * 1024};
        std::chrono::milliseconds IdleTimeout{0};
        Foundation::TrafficObservation Observation{};
        std::shared_ptr<Memory::BytePool> Bytes;
    };
    /** @brief 实际成功写出字节与领域/原生原因；EOF 半关闭不算业务失败。 */
    struct Result final
    {
        Fault::Failure Failure;
        std::array<std::size_t, 2> Total{};
        std::array<Fault::Failure, 2> DirectionFailure{};
    };
    /** @brief 所有状态由本 strand 串行更新，不借用外层协程帧。 */
    struct State final
    {
        State(Request Value, std::array<Memory::OwnedBytes, 2> Storage)
            : Input(std::move(Value)), Buffers(std::move(Storage)),
              Executor(Net::make_strand(Input.Inbound->Executor())), Idle(Executor) {}
        auto Record(std::size_t Direction, Fault::Failure Failure) noexcept -> void
        {
            if (Failure.Succeeded()) return;
            if (Output.DirectionFailure[Direction].Succeeded()) Output.DirectionFailure[Direction] = Failure;
            if (Output.Failure.Succeeded() || Output.Failure.Code == Fault::Code::Canceled)
                Output.Failure = Failure;
        }
        /** @brief 值关闭只证明命令交付；已拥有的缓冲区保留到全部 pump 退栈。 */
        auto Close() -> void
        {
            if (Closed) return;
            Closed = true;
            CloseCarrier(Input.Inbound, 0);
            CloseCarrier(Input.Outbound, 1);
            // Boost.Asio 1.89 removed the error_code overload for timers.
            // The throwing overload keeps cancellation failure on this
            // non-noexcept lifecycle boundary instead of silently losing it.
            (void)Idle.cancel();
        }
        auto FinishPump() -> void
        {
            ++Completed;
            if (Completed != 2) return;
            (void)Idle.cancel();
        }
        auto Touch() -> void
        { if (Input.IdleTimeout.count() > 0) Idle.expires_after(Input.IdleTimeout); }
        [[nodiscard]] auto Source(std::size_t Direction) const -> SharedTransmission
        { if (Direction == 0) return Input.Inbound; return Input.Outbound; }
        [[nodiscard]] auto Destination(std::size_t Direction) const -> SharedTransmission
        { if (Direction == 0) return Input.Outbound; return Input.Inbound; }
        Request Input;
        std::array<Memory::OwnedBytes, 2> Buffers;
        Net::strand<Net::any_io_executor> Executor;
        Net::steady_timer Idle;
        Result Output;
        std::size_t Completed{0};
        bool Closed{false};
    private:
        auto CloseCarrier(const SharedTransmission& Carrier, std::size_t Direction) -> void
        {
            const auto Cancel = Carrier->Cancel();
            if (!Cancel) Record(Direction, Cancel.error());
            const auto Close = Carrier->Close();
            if (!Close) Record(Direction, Close.error());
        }
    };
}
