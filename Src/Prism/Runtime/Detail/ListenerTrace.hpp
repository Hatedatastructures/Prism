/** @file ListenerTrace.hpp @brief TCP listener 接入时钟和初始轨迹事件 owner。 */
#pragma once

#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Runtime/Session/Trace/Ring.hpp>
#include <Prism/Runtime/Worker.hpp>

#include <chrono>
#include <memory>

namespace Prism::Runtime::Detail
{
    struct ListenerSessionTraceTiming final
    {
        std::chrono::system_clock::time_point AcceptedWall{};
        std::chrono::steady_clock::time_point AcceptedMonotonic{};
        std::chrono::system_clock::time_point DispatchWall{};
        std::chrono::steady_clock::time_point DispatchMonotonic{};
    };

    /** @brief 在 worker executor 上创建 writer，并按实际接入时刻写入 accept 与 dispatch。 */
    template <typename Admission>
    [[nodiscard]] inline auto MakeListenerSessionTraceWriter(
        const Admission &Request,
        Worker *WorkerValue) noexcept -> std::shared_ptr<SessionTraceWriter>
    {
        if (!WorkerValue || Request.Info.Id == 0U)
        {
            return {};
        }
        try
        {
            const SessionTraceIdentity Identity{
                WorkerValue->Process(), Request.Generation(),
                Prism::SessionId{Request.Info.Id}, WorkerValue->Id()};
            auto Trace = std::make_shared<SessionTraceWriter>(
                WorkerValue->TraceRing(), Identity,
                Request.TraceTiming.AcceptedMonotonic);
            Trace->RecordAt(SessionTraceWriter::SessionTraceRecordRequest{
                .Stage = SessionTraceStage::TcpAccepted,
                .Outcome = SessionTraceOutcome::Succeeded,
                .Failure = Prism::Fault::Code::Success,
                .Wall = Request.TraceTiming.AcceptedWall,
                .Monotonic = Request.TraceTiming.AcceptedMonotonic});
            Trace->RecordAt(SessionTraceWriter::SessionTraceRecordRequest{
                .Stage = SessionTraceStage::WorkerDispatchAccepted,
                .Outcome = SessionTraceOutcome::Succeeded,
                .Failure = Prism::Fault::Code::Success,
                .Wall = Request.TraceTiming.DispatchWall,
                .Monotonic = Request.TraceTiming.DispatchMonotonic});
            return Trace;
        }
        catch (...)
        {
            return {};
        }
    }
}
