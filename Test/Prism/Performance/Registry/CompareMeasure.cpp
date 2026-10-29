/**
 * @file CompareMeasure.cpp
 * @brief 会话注册表对照实验编排。
 */

#include "CompareCorrect.hpp"
#include "CompareModels.hpp"
#include "CompareSampling.hpp"
#include "CompareTrace.hpp"

#include <array>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <new>

#if defined(_WIN32)
#    include <malloc.h>
#endif

namespace Prism::Runtime::Perf
{

    auto Allocate(std::size_t Size) -> void *;
    auto AllocateAligned(std::size_t Size, std::size_t Alignment) -> void *;
    auto ValidateAllocationInstrumentation() -> void;
    auto ValidateSamplingLifecycle() -> void;
    auto ValidateShardedCowFailureConcurrency() -> void;
    auto ValidateExecutorTableFailureConcurrency() -> void;
    auto ValidateExecutorStartupRollback() -> void;
    auto MakeTrace(const Options &Settings) -> Trace;
    auto MakeModel(ModelKind Kind, std::size_t Executors) -> std::unique_ptr<IModel>;
    auto RunProbe(IModel &Model, const Trace &TraceValue, std::size_t MaxSessions)
        -> ProbeResult;
    auto RunDirectedContracts(IModel &Model) -> ProbeResult;
    auto RunSample(const SampleRequest &Request) -> Sample;
    auto ModelName(ModelKind Kind) -> const char *;
    auto InvalidReasonName(InvalidReason Reason) -> const char *;
    auto PrintSample(const Sample &Result, const Options &Settings) -> void;

    namespace
    {

        auto PrintValidationFailure(const ModelKind Kind, const char *Stage,
                                    const ProbeResult &Result) -> void
        {
            std::size_t ReasonIndex = InvalidReasonCount;
            for (std::size_t Index = 0; Index < InvalidReasonCount; ++Index)
            {
                if (Result.InvalidReasons[Index] != 0)
                {
                    ReasonIndex = Index;
                    break;
                }
            }
            const auto ReasonName = ReasonIndex == InvalidReasonCount
                                        ? "none"
                                        : InvalidReasonName(
                                              static_cast<InvalidReason>(ReasonIndex));
            const auto ReasonCount = ReasonIndex == InvalidReasonCount
                                         ? std::uint64_t{0}
                                         : Result.InvalidReasons[ReasonIndex];
            std::fprintf(stderr,
                         "[FAIL] semantic %s failed for %s invalid_reason=%s invalid_reason_count=%llu hook_errors=%llu hook_metrics=%llu\n",
                         Stage, ModelName(Kind), ReasonName,
                         static_cast<unsigned long long>(ReasonCount),
                         static_cast<unsigned long long>(Result.Hooks.Errors),
                         static_cast<unsigned long long>(Result.Hooks.Metrics));
        }

        auto ValidateModels(const Options &Settings, const Trace &TraceValue) -> bool
        {
            for (const auto Kind : {ModelKind::CurrentCow, ModelKind::ShardedCow,
                                    ModelKind::ExecutorTable})
            {
                auto TraceModel = MakeModel(Kind, Settings.Executors);
                const auto TraceResult =
                    RunProbe(*TraceModel, TraceValue, Settings.ActiveSessions);
                if (!TraceResult.Valid)
                {
                    PrintValidationFailure(Kind, "trace", TraceResult);
                    return false;
                }

                auto ContractModel = MakeModel(Kind, Settings.Executors);
                const auto ContractResult = RunDirectedContracts(*ContractModel);
                if (!ContractResult.Valid)
                {
                    PrintValidationFailure(Kind, "contract", ContractResult);
                    return false;
                }
            }
            return true;
        }

        auto RunOneKind(const Options &Settings, const Trace &TraceValue,
                        const ModelKind Kind) -> bool
        {
            for (std::size_t Round = 0; Round < Settings.Rounds; ++Round)
            {
                const auto Result = RunSample(SampleRequest{Settings, TraceValue, Kind,
                                                             Round + 1});
                PrintSample(Result, Settings);
                if (Result.Invalid)
                {
                    return false;
                }
            }
            return true;
        }

    } // namespace

    auto Run(const Options &Settings) -> int
    {
        ValidateAllocationInstrumentation();
        ValidateSamplingLifecycle();
        std::puts("sampling_lifecycle_preflight=pass");
        ValidateShardedCowFailureConcurrency();
        std::puts("registry_sharded_failure_concurrency_preflight=pass");
        ValidateExecutorTableFailureConcurrency();
        std::puts("registry_executor_failure_concurrency_preflight=pass");
        ValidateExecutorStartupRollback();
        std::puts("executor_startup_rollback_preflight=pass");
        const auto TraceValue = MakeTrace(Settings);
        std::printf("trace_hash=%016llx probe_operations=%zu work_operations=%zu\n",
                    static_cast<unsigned long long>(TraceValue.Hash), TraceValue.Probe.size(),
                    TraceValue.Work.size());
        std::puts("memory_boundary=timed ordinary and aligned process-wide operator new/new[] calls, reported by kind and requested bytes; setup, trace storage, allocator retention and other malloc/native DLL callers are excluded");
        std::puts("rss_boundary=working set and commit sampled immediately before Start and immediately after Finish; sampler peak is restricted to the timed window");
        std::puts("c_boundary=caller-to-owner queue, wait and result transfer are included; the candidate does not claim to be an async production API");
        std::puts("c_deadlock_boundary=owner-thread Invoke runs inline; external callers wait on one result future and owner commands never wait on a future; this avoids nested owner self-wait but does not model coroutine cancellation or executor shutdown races");
        std::puts("affinity_boundary=caller worker is lane%executors; C owner is Id%executors and the generated Id/lane offset makes this matrix cross-owner worst-case; B uses direct shard COW without queue transfer, so these numbers do not choose a production affinity strategy");
        std::puts("hash_boundary=correctness_hash is quiescent final-state only; observation_hash includes mid-run checks and hook counts and is schedule-dependent when executors exceed one, so it is diagnostic rather than an equality gate");
        std::puts("fault_contract=all models inject failure after publication and modeled ErrorHook installation, before MetricsHook installation; failure must leave no successful token and no active record");
        std::puts("hook_failure_window=post-failure ErrorHook dispatch is exercised through the retained test control; the narrower concurrent InstallHooks-to-RetireRecord window has no production test seam and is unverified");
        std::puts("inflight_hook_contract=hook passing the Removed check may finish after Reset; hooks beginning after logical removal are suppressed");
        std::puts("shutdown_boundary=only synchronous BeginShutdown cancellation is modeled; async SessionControl Drain and Registry Shutdown clear are unverified");
        std::puts("non_equivalent=async Cancel/Drain and real Listener/Operations integration are outside this harness; replacement_gate=reject_until_those_contracts_are_verified");
        if (!ValidateModels(Settings, TraceValue))
        {
            return 1;
        }
        if (Settings.ValidateOnly)
        {
            std::puts("semantic_preflight=pass");
            return 0;
        }

        if (Settings.Model == ModelKind::All)
        {
            const std::array<ModelKind, 3> Order0{ModelKind::CurrentCow,
                                                   ModelKind::ShardedCow,
                                                   ModelKind::ExecutorTable};
            const std::array<ModelKind, 3> Order1{ModelKind::ExecutorTable,
                                                   ModelKind::ShardedCow,
                                                   ModelKind::CurrentCow};
            const std::array<ModelKind, 3> Order2{ModelKind::ShardedCow,
                                                   ModelKind::CurrentCow,
                                                   ModelKind::ExecutorTable};
            const std::array<ModelKind, 3> Order3{ModelKind::CurrentCow,
                                                   ModelKind::ExecutorTable,
                                                   ModelKind::ShardedCow};
            const std::array<ModelKind, 3> Order4{ModelKind::ShardedCow,
                                                   ModelKind::ExecutorTable,
                                                   ModelKind::CurrentCow};
            const std::array<std::array<ModelKind, 3>, 5> Orders{
                {Order0, Order1, Order2, Order3, Order4}};
            for (std::size_t Round = 0; Round < Settings.Rounds; ++Round)
            {
                const auto &Order = Orders[Round % Orders.size()];
                for (const auto Kind : Order)
                {
                    const auto Result = RunSample(SampleRequest{Settings, TraceValue, Kind,
                                                                 Round + 1});
                    PrintSample(Result, Settings);
                    if (Result.Invalid)
                    {
                        return 1;
                    }
                }
            }
            return 0;
        }
        return RunOneKind(Settings, TraceValue, Settings.Model) ? 0 : 1;
    }

} // namespace Prism::Runtime::Perf

void *operator new(const std::size_t Size)
{
    return Prism::Runtime::Perf::Allocate(Size);
}

void *operator new[](const std::size_t Size)
{
    return Prism::Runtime::Perf::Allocate(Size);
}

void *operator new(const std::size_t Size, const std::nothrow_t &) noexcept
{
    try
    {
        return ::operator new(Size);
    }
    catch (...)
    {
        return nullptr;
    }
}

void *operator new[](const std::size_t Size, const std::nothrow_t &) noexcept
{
    try
    {
        return ::operator new[](Size);
    }
    catch (...)
    {
        return nullptr;
    }
}

void *operator new(const std::size_t Size, const std::align_val_t Alignment)
{
    return Prism::Runtime::Perf::AllocateAligned(
        Size, static_cast<std::size_t>(Alignment));
}

void *operator new[](const std::size_t Size, const std::align_val_t Alignment)
{
    return Prism::Runtime::Perf::AllocateAligned(
        Size, static_cast<std::size_t>(Alignment));
}

void *operator new(const std::size_t Size, const std::align_val_t Alignment,
                   const std::nothrow_t &) noexcept
{
    try
    {
        return ::operator new(Size, Alignment);
    }
    catch (...)
    {
        return nullptr;
    }
}

void *operator new[](const std::size_t Size, const std::align_val_t Alignment,
                    const std::nothrow_t &) noexcept
{
    try
    {
        return ::operator new[](Size, Alignment);
    }
    catch (...)
    {
        return nullptr;
    }
}

void operator delete(void *Memory) noexcept { std::free(Memory); }
void operator delete[](void *Memory) noexcept { std::free(Memory); }
void operator delete(void *Memory, const std::size_t) noexcept { std::free(Memory); }
void operator delete[](void *Memory, const std::size_t) noexcept { std::free(Memory); }
void operator delete(void *Memory, const std::nothrow_t &) noexcept { std::free(Memory); }
void operator delete[](void *Memory, const std::nothrow_t &) noexcept { std::free(Memory); }

void operator delete(void *Memory, const std::align_val_t) noexcept
{
#if defined(_WIN32)
    _aligned_free(Memory);
#else
    std::free(Memory);
#endif
}

void operator delete[](void *Memory, const std::align_val_t Alignment) noexcept
{
    ::operator delete(Memory, Alignment);
}

void operator delete(void *Memory, const std::size_t, const std::align_val_t Alignment) noexcept
{
    ::operator delete(Memory, Alignment);
}

void operator delete[](void *Memory, const std::size_t, const std::align_val_t Alignment) noexcept
{
    ::operator delete[](Memory, Alignment);
}

void operator delete(void *Memory, const std::nothrow_t &, const std::align_val_t Alignment) noexcept
{
    ::operator delete(Memory, Alignment);
}

void operator delete[](void *Memory, const std::nothrow_t &, const std::align_val_t Alignment) noexcept
{
    ::operator delete[](Memory, Alignment);
}
