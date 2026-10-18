/** @file Observation.hpp @brief 网络阶段 owner 的真实时长观察，不拥有会话或配置代次。 */
#pragma once
#include <Prism/Foundation/Utility/TrafficSink.hpp>
#include <chrono>
#include <memory>
#include <utility>

namespace Prism::Network::Dialer
{
    struct ObservationOwner final
    {
        std::weak_ptr<Prism::Foundation::TrafficSink> Sink;
        Prism::WorkerId Worker;
    };

    /** @brief 每次 DNS 或 socket connect 的局部阶段；退出而未完成时记录取消。 */
    class StageObservation final
    {
    public:
        StageObservation(const ObservationOwner &Owner, Prism::Foundation::NetworkLatencyStage Stage)
            : Sink_(Owner.Sink.lock()), Worker_(Owner.Worker), Stage_(Stage)
        { if (Sink_) Started_ = std::chrono::steady_clock::now(); }
        StageObservation(const StageObservation &) = delete;
        auto operator=(const StageObservation &) -> StageObservation & = delete;
        ~StageObservation() { Complete(Prism::Fault::Failure{Prism::Fault::Code::Canceled}); }

        auto Complete(Prism::Fault::Failure Failure = {}) noexcept -> void
        {
            if (!Sink_) return;
            auto Sink = std::move(Sink_);
            const auto Elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - Started_).count();
            Prism::Foundation::TrafficEvent Event;
            Event.Worker = Worker_;
            Event.Kind = Prism::Foundation::TrafficEventKind::NetworkLatency;
            Event.DurationMicroseconds = Elapsed > 0 ? static_cast<std::uint64_t>(Elapsed) : 0U;
            Event.Failure = Failure; Event.NetworkStage = Stage_;
            Sink->Report(Event);
        }

    private:
        std::shared_ptr<Prism::Foundation::TrafficSink> Sink_;
        Prism::WorkerId Worker_;
        Prism::Foundation::NetworkLatencyStage Stage_;
        std::chrono::steady_clock::time_point Started_{};
    };
}
