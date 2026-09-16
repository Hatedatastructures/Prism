/**
 * @file SchedulerBenchmark.cpp
 * @brief FairScheduler / PriorityScheduler 固定槽位热路径基准
 * @details 输出吞吐、单次调度纳秒数、平均服务字节和 ready 峰值；测试不创建
 *          线程或外部进程，scheduler 本身也不在 warmup 后进行通用分配。
 */

#include <Preview/Scheduler/Scheduler.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <iostream>

namespace
{

    struct Metrics final
    {
        std::uint64_t Operations{0};
        std::uint64_t Bytes{0};
        std::size_t PeakReady{0};
        std::size_t QueueFull{0};
        double NanosecondsPerOperation{0};
    };

    auto MakeRequest(const std::uint64_t RequestValue,
                     const std::uint64_t AccountValue,
                     const std::uint64_t StreamValue) -> Preview::Scheduler::Request
    {
        Preview::Scheduler::Request RequestData;
        RequestData.RequestId = Preview::RequestId{RequestValue};
        RequestData.AccountId = Preview::AccountId{AccountValue};
        RequestData.StreamId = Preview::StreamId{StreamValue};
        RequestData.WorkerId = Preview::WorkerId{1};
        RequestData.RemainingBytes = 1'000'000'000;
        RequestData.Weight = 1;
        RequestData.QuantumBytes = 1024;
        RequestData.MaxBurstBytes = 4096;
        RequestData.MaxConsecutiveTurns = 1;
        RequestData.Priority = Preview::Scheduler::PriorityBand::Bulk;
        return RequestData;
    }

    auto RunFair(const std::size_t Iterations) -> Metrics
    {
        Preview::Scheduler::Budget BudgetValue;
        BudgetValue.WorkerId = Preview::WorkerId{1};
        BudgetValue.MaxQueueSize = 64;
        BudgetValue.AccountQuantumBytes = 1024;
        Preview::Scheduler::FairScheduler SchedulerValue(BudgetValue);
        std::array<Preview::Scheduler::Request, 32> Requests{};
        for (std::size_t Index = 0; Index < Requests.size(); ++Index)
        {
            Requests[Index] = MakeRequest(Index + 1, Index % 8 + 1, Index + 100);
            if (SchedulerValue.Submit(Requests[Index]).Status ==
                Preview::Scheduler::ResultStatus::QueueFull)
            {
                return Metrics{.QueueFull = 1};
            }
        }
        SchedulerValue.Warmup();

        Metrics ResultValue;
        const auto Start = std::chrono::steady_clock::now();
        for (std::size_t Index = 0; Index < Iterations; ++Index)
        {
            auto Turn = SchedulerValue.Next(Index);
            if (Turn.Status != Preview::Scheduler::ResultStatus::Ready)
            {
                continue;
            }
            ++ResultValue.Operations;
            ResultValue.Bytes += Turn.GrantedBytes;
            (void)SchedulerValue.Requeue(Turn);
            ResultValue.PeakReady = (std::max)(ResultValue.PeakReady, SchedulerValue.ReadyCount());
        }
        const auto Elapsed = std::chrono::duration<double, std::nano>(
            std::chrono::steady_clock::now() - Start);
        ResultValue.NanosecondsPerOperation =
            ResultValue.Operations == 0
                ? 0.0
                : Elapsed.count() / static_cast<double>(ResultValue.Operations);
        return ResultValue;
    }

    auto RunPriority(const std::size_t Iterations) -> Metrics
    {
        Preview::Scheduler::Budget BudgetValue;
        BudgetValue.WorkerId = Preview::WorkerId{1};
        BudgetValue.MaxQueueSize = 64;
        BudgetValue.AgingInterval = 1000;
        BudgetValue.StarvationDeadline = 10000;
        BudgetValue.MinimumServiceBytes = 512;
        BudgetValue.MaxBurstBytes = 4096;
        Preview::Scheduler::PriorityScheduler SchedulerValue(BudgetValue);
        std::array<Preview::Scheduler::Request, 32> Requests{};
        for (std::size_t Index = 0; Index < Requests.size(); ++Index)
        {
            Requests[Index] = MakeRequest(Index + 1000, Index % 8 + 1, Index + 200);
            Requests[Index].Priority = Index % 4 == 0
                                           ? Preview::Scheduler::PriorityBand::Control
                                           : Preview::Scheduler::PriorityBand::Bulk;
            Requests[Index].EnqueuedAt = 0;
            if (SchedulerValue.Submit(Requests[Index]).Status ==
                Preview::Scheduler::ResultStatus::QueueFull)
            {
                return Metrics{.QueueFull = 1};
            }
        }
        SchedulerValue.Warmup();

        Metrics ResultValue;
        const auto Start = std::chrono::steady_clock::now();
        for (std::size_t Index = 0; Index < Iterations; ++Index)
        {
            auto Turn = SchedulerValue.Next(Index);
            if (Turn.Status != Preview::Scheduler::ResultStatus::Ready)
            {
                continue;
            }
            ++ResultValue.Operations;
            ResultValue.Bytes += Turn.GrantedBytes;
            (void)SchedulerValue.Requeue(Turn);
            ResultValue.PeakReady = (std::max)(ResultValue.PeakReady, SchedulerValue.ReadyCount());
        }
        const auto Elapsed = std::chrono::duration<double, std::nano>(
            std::chrono::steady_clock::now() - Start);
        ResultValue.NanosecondsPerOperation =
            ResultValue.Operations == 0
                ? 0.0
                : Elapsed.count() / static_cast<double>(ResultValue.Operations);
        return ResultValue;
    }

    auto PrintMetrics(const char *Name, const Metrics &Value) -> void
    {
        std::cout << Name << ".operations=" << Value.Operations << '\n'
                  << Name << ".bytes=" << Value.Bytes << '\n'
                  << Name << ".ns_per_operation=" << Value.NanosecondsPerOperation << '\n'
                  << Name << ".peak_ready=" << Value.PeakReady << '\n'
                  << Name << ".queue_full=" << Value.QueueFull << '\n';
    }

} // namespace

auto main() -> int
{
    constexpr std::size_t Iterations{200'000};
    const auto Fair = RunFair(Iterations);
    const auto Priority = RunPriority(Iterations);
    PrintMetrics("fair", Fair);
    PrintMetrics("priority", Priority);
    return Fair.Operations != 0 && Priority.Operations != 0 && Fair.QueueFull == 0 &&
                   Priority.QueueFull == 0
               ? 0
               : 1;
}
