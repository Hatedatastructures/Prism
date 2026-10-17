/** @file ListenerTrace.hpp @brief TCP listener 接入时钟和初始轨迹事件 owner。 */
#pragma once

#include <Preview/Runtime/SessionTraceRing.hpp>
#include <Preview/Runtime/Worker.hpp>

#include <chrono>
#include <memory>

namespace Preview::Runtime::Detail
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
                Preview::SessionId{Request.Info.Id}, WorkerValue->Id()};
            auto Trace = std::make_shared<SessionTraceWriter>(
                WorkerValue->TraceRing(), Identity,
                Request.TraceTiming.AcceptedMonotonic);
            Trace->RecordAt(SessionTraceStage::TcpAccepted,
                SessionTraceOutcome::Succeeded, Preview::Fault::Code::Success,
                Request.TraceTiming.AcceptedWall, Request.TraceTiming.AcceptedMonotonic);
            Trace->RecordAt(SessionTraceStage::WorkerDispatchAccepted,
                SessionTraceOutcome::Succeeded, Preview::Fault::Code::Success,
                Request.TraceTiming.DispatchWall, Request.TraceTiming.DispatchMonotonic);
            return Trace;
        }
        catch (...)
        {
            return {};
        }
    }
}
