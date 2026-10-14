/**
 * @file DnsPerfCoalescerMetrics.cpp
 * @brief DNS coalescer 的平台进程采样与计时窗口指标所有者。
 */

#include "DnsPerfCoalescer.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cctype>
#include <future>
#include <functional>
#include <memory>
#include <thread>

#ifdef _WIN32
#    if !defined(NOMINMAX)
#        define NOMINMAX
#    endif
#    include <windows.h>
#    include <psapi.h>
#endif

namespace DnsPerf
{
    /** @brief 按 nearest-rank 计算实际样本分位数；空样本没有测量结果。 */
    [[nodiscard]] auto PercentileNs(std::vector<std::uint64_t> Values, std::size_t Percent)
        -> std::uint64_t
    {
        if (Values.empty()) return 0;
        std::sort(Values.begin(), Values.end());
        Percent = std::min(Percent, std::size_t{100});
        const auto Rank = (Values.size() * Percent + 99U) / 100U;
        return Values[Rank == 0U ? 0U : Rank - 1U];
    }

    /** @brief 错误字段保留真实内容，将空白转为可解析的单个日志 token。 */
    [[nodiscard]] auto ErrorToken(std::string Value) -> std::string
    {
        if (Value.empty()) return "none";
        for (auto &Character : Value)
        {
            if (std::isspace(static_cast<unsigned char>(Character))) Character = '_';
        }
        return Value;
    }

    struct DnsProcessSamplerState final
    {
        std::shared_ptr<GateChannel> Begin;
        std::shared_ptr<ReadySignal> Ready;
        std::shared_ptr<ReadySignal> Done;
        std::shared_ptr<Net::steady_timer> Timer;
        std::atomic<bool> End{false};
        std::atomic<std::uint64_t> EndNs{0};
        std::size_t Samples{0};
        std::size_t PeakWorkingSet{0};
        std::size_t PeakPrivateUsage{0};
        bool Valid{true};
    };

    struct DnsSamplerRuntime final
    {
        Net::io_context IoContext;
        std::shared_ptr<DnsProcessSamplerState> State;
        std::thread Thread;
        std::future<bool> Done;
    };

    auto CompleteSamplerStart(const std::shared_ptr<DnsProcessSamplerState> &State,
                              std::exception_ptr Failure) -> void
    {
        if (Failure)
        {
            State->Ready->Publish(false);
            State->Done->Publish(false);
        }
    }

#ifdef _WIN32
    [[nodiscard]] auto SampleDnsProcess() -> DnsProcessSample
    {
        DnsProcessSample Result;
        FILETIME CreateTime{}, ExitTime{}, KernelTime{}, UserTime{};
        const auto TimesAvailable = GetProcessTimes(
            GetCurrentProcess(), &CreateTime, &ExitTime, &KernelTime, &UserTime) != FALSE;
        if (TimesAvailable)
        {
            ULARGE_INTEGER User{}, Kernel{};
            User.LowPart = UserTime.dwLowDateTime;
            User.HighPart = UserTime.dwHighDateTime;
            Kernel.LowPart = KernelTime.dwLowDateTime;
            Kernel.HighPart = KernelTime.dwHighDateTime;
            Result.User100ns = User.QuadPart;
            Result.Kernel100ns = Kernel.QuadPart;
        }
        PROCESS_MEMORY_COUNTERS_EX Counters{};
        Counters.cb = sizeof(Counters);
        const auto MemoryAvailable = K32GetProcessMemoryInfo(
            GetCurrentProcess(), reinterpret_cast<PROCESS_MEMORY_COUNTERS *>(&Counters),
            sizeof(Counters)) != FALSE;
        if (MemoryAvailable)
        {
            Result.WorkingSet = Counters.WorkingSetSize;
            Result.PrivateUsage = Counters.PrivateUsage;
        }
        Result.Available = TimesAvailable && MemoryAvailable;
        return Result;
    }
#endif

    namespace
    {
        auto WakeSamplerOnIo(const std::shared_ptr<DnsProcessSamplerState> &State) -> void
        {
            if (State->Begin)
            {
                (void)State->Begin->try_send(boost::system::error_code{});
            }
            if (State->Timer)
            {
                (void)State->Timer->cancel();
            }
        }

        auto RunDnsProcessSampler(
            const std::shared_ptr<DnsProcessSamplerState> &State) -> Net::awaitable<void>
        {
            try
            {
                const auto Executor = co_await Net::this_coro::executor;
                State->Timer = std::make_shared<Net::steady_timer>(Executor);
                State->Ready->Publish(true);
                boost::system::error_code BeginError;
                co_await State->Begin->async_receive(
                    Net::redirect_error(Net::use_awaitable, BeginError));
                if (BeginError)
                {
                    State->Valid = false;
                    State->Done->Publish(false);
                    co_return;
                }
#ifdef _WIN32
                while (!State->End.load(std::memory_order_acquire))
                {
                    const auto SampleStart = NowNs();
                    const auto Limit = State->EndNs.load(std::memory_order_acquire);
                    if (Limit != 0U && SampleStart >= Limit)
                    {
                        break;
                    }
                    const auto Sample = SampleDnsProcess();
                    const auto SampleEnd = NowNs();
                    if (Limit != 0U && SampleEnd > Limit)
                    {
                        break;
                    }
                    ++State->Samples;
                    if (!Sample.Available)
                    {
                        State->Valid = false;
                    }
                    else
                    {
                        State->PeakWorkingSet =
                            (std::max)(State->PeakWorkingSet, Sample.WorkingSet);
                        State->PeakPrivateUsage =
                            (std::max)(State->PeakPrivateUsage, Sample.PrivateUsage);
                    }
                    State->Timer->expires_after(std::chrono::milliseconds(1));
                    boost::system::error_code TimerError;
                    co_await State->Timer->async_wait(
                        Net::redirect_error(Net::use_awaitable, TimerError));
                    if (TimerError && !State->End.load(std::memory_order_acquire))
                    {
                        State->Valid = false;
                        break;
                    }
                }
#else
                while (!State->End.load(std::memory_order_acquire))
                {
                    State->Timer->expires_after(std::chrono::milliseconds(1));
                    boost::system::error_code TimerError;
                    co_await State->Timer->async_wait(
                        Net::redirect_error(Net::use_awaitable, TimerError));
                    if (TimerError && !State->End.load(std::memory_order_acquire))
                    {
                        State->Valid = false;
                        break;
                    }
                }
#endif
            }
            catch (...)
            {
                State->Valid = false;
                State->Ready->Publish(false);
            }
            State->Done->Publish(State->Valid);
            co_return;
        }

        auto StopDnsProcessSampler(const DnsSamplerHandle &Sampler,
                                   const std::uint64_t EndNs) -> DnsSamplerMetrics
        {
            if (!Sampler || !Sampler->State)
            {
                return {};
            }
            const auto State = Sampler->State;
            State->EndNs.store(EndNs, std::memory_order_release);
            State->End.store(true, std::memory_order_release);
            Net::post(Sampler->IoContext, std::bind_front(WakeSamplerOnIo, State));
            if (Sampler->Done.valid())
            {
                (void)Sampler->Done.wait_for(std::chrono::seconds(5));
            }
            if (Sampler->Thread.joinable())
            {
                Sampler->Thread.join();
            }
            return DnsSamplerMetrics{
                State->Samples, State->PeakWorkingSet, State->PeakPrivateUsage, State->Valid};
        }
    } // namespace

    auto StartDnsProcessSampler() -> DnsSamplerHandle
    {
        const auto Sampler = std::make_shared<DnsSamplerRuntime>();
        Sampler->State = std::make_shared<DnsProcessSamplerState>();
        Sampler->State->Begin = std::make_shared<GateChannel>(Sampler->IoContext.get_executor(), 1);
        Sampler->State->Ready = std::make_shared<ReadySignal>();
        Sampler->State->Done = std::make_shared<ReadySignal>();
        auto ReadyFuture = Sampler->State->Ready->Promise.get_future();
        Sampler->Done = Sampler->State->Done->Promise.get_future();
        Net::co_spawn(
            Sampler->IoContext,
            RunDnsProcessSampler(Sampler->State),
            std::bind_front(CompleteSamplerStart, Sampler->State));
        Sampler->Thread = std::thread([Sampler] { Sampler->IoContext.run(); });
        if (ReadyFuture.wait_for(std::chrono::seconds(2)) != std::future_status::ready ||
            !ReadyFuture.get())
        {
            (void)StopDnsProcessSampler(Sampler, NowNs());
            return {};
        }
        return Sampler;
    }

    auto BeginDnsProcessSampler(const DnsSamplerHandle &Sampler) -> void
    {
        if (!Sampler || !Sampler->State)
        {
            return;
        }
        Net::post(Sampler->IoContext, [State = Sampler->State]
        { (void)State->Begin->try_send(boost::system::error_code{}); });
    }

    auto FinishDnsProcessSampler(
        const DnsSamplerHandle &Sampler, const std::uint64_t EndNs) -> DnsSamplerMetrics
    {
        return StopDnsProcessSampler(Sampler, EndNs);
    }

} // namespace DnsPerf
