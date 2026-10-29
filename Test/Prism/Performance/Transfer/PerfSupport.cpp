/**
 * @file PerfSupport.cpp
 * @brief TransferPerf 模块所有者。
 */

#include "TransferPerf.hpp"

namespace TransferPerf
{
    auto SignalLaneReady(const LaneReadyRequest &Request) -> void
    {
        bool Expected = false;
        if (!Request.Signaled->compare_exchange_strong(
                Expected, true, std::memory_order_acq_rel))
        {
            return;
        }
        const auto Error = Request.Success
                               ? boost::system::error_code{}
                               : boost::system::errc::make_error_code(
                                     boost::system::errc::io_error);
        (void)Request.Ready->try_send(Error, Request.LaneIndex);
    }

    [[nodiscard]] auto RunProcessSampler(
        ProcessSamplerRequest Request) -> Net::awaitable<void>
    {
        (void)Request.Started->try_send(boost::system::error_code{});
        try
        {
            boost::system::error_code StartError;
            co_await Request.StartSampling->async_receive(
                Net::redirect_error(Net::use_awaitable, StartError));
            if (StartError)
            {
                Request.State->Valid = false;
            }
#ifdef _WIN32
            if (!StartError)
            {
                const auto Executor = co_await Net::this_coro::executor;
                Net::steady_timer Timer(Executor);
                while (!Request.State->Stop.load(std::memory_order_acquire))
                {
                    const auto Sample = SampleProcess();
                    ++Request.State->SampleCount;
                    if (!Sample.Available)
                    {
                        Request.State->Valid = false;
                    }
                    else
                    {
                        Request.State->PeakWorkingSet =
                            (std::max)(Request.State->PeakWorkingSet, Sample.WorkingSet);
                        Request.State->PeakPrivateUsage =
                            (std::max)(Request.State->PeakPrivateUsage, Sample.PrivateUsage);
                    }
                    Timer.expires_after(std::chrono::milliseconds(1));
                    boost::system::error_code TimerError;
                    co_await Timer.async_wait(
                        Net::redirect_error(Net::use_awaitable, TimerError));
                    if (TimerError && !Request.State->Stop.load(std::memory_order_acquire))
                    {
                        Request.State->Valid = false;
                        break;
                    }
                }
            }
#endif
        }
        catch (...)
        {
            Request.State->Valid = false;
        }
        (void)Request.Done->try_send(boost::system::error_code{});
        co_return;
    }

    auto HashBytes(std::uint64_t &Hash, std::span<const std::byte> Data) -> void
    {
        for (const auto Byte : Data)
        {
            Hash ^= std::to_integer<std::uint8_t>(Byte);
            Hash *= 1099511628211ULL;
        }
    }

    auto FillPayload(std::span<std::byte> Buffer, const std::size_t Offset) -> void
    {
        for (std::size_t Index = 0; Index < Buffer.size(); ++Index)
        {
            Buffer[Index] = std::byte{
                static_cast<unsigned char>((Offset + Index) & 0xFFU)};
        }
    }

    [[nodiscard]] auto PayloadHash(const std::size_t Total) -> std::uint64_t
    {
        std::uint64_t Hash = InitialHash;
        for (std::size_t Offset = 0; Offset < Total; ++Offset)
        {
            Hash ^= static_cast<std::uint8_t>(Offset & 0xFFU);
            Hash *= 1099511628211ULL;
        }
        return Hash;
    }

    [[nodiscard]] auto IsCleanEof(const std::error_code &ErrorCode) -> bool
    {
        return !ErrorCode ||
               Prism::Fault::ToCode(ErrorCode) == Prism::Fault::Code::Eof;
    }

    [[nodiscard]] auto RunAllocationObserverPreflight() -> bool
    {
        std::array<void *, 8> Pointers{};
        std::array<bool, 8> Forms{};
        TransferPerfAllocation::Start();
        try
        {
            auto Before = TransferPerfAllocation::ReadSnapshot();
            Pointers[0] = ::operator new(64);
            auto After = TransferPerfAllocation::ReadSnapshot();
            Forms[0] = Pointers[0] != nullptr &&
                       After.OrdinaryAllocations == Before.OrdinaryAllocations + 1U &&
                       After.OrdinaryBytes >= Before.OrdinaryBytes + 64U;

            Before = After;
            Pointers[1] = ::operator new[](64);
            After = TransferPerfAllocation::ReadSnapshot();
            Forms[1] = Pointers[1] != nullptr &&
                       After.OrdinaryAllocations == Before.OrdinaryAllocations + 1U &&
                       After.OrdinaryBytes >= Before.OrdinaryBytes + 64U;

            Before = After;
            Pointers[2] = ::operator new(64, std::nothrow);
            After = TransferPerfAllocation::ReadSnapshot();
            Forms[2] = Pointers[2] != nullptr &&
                       After.OrdinaryAllocations == Before.OrdinaryAllocations + 1U &&
                       After.OrdinaryBytes >= Before.OrdinaryBytes + 64U;

            Before = After;
            Pointers[3] = ::operator new[](64, std::nothrow);
            After = TransferPerfAllocation::ReadSnapshot();
            Forms[3] = Pointers[3] != nullptr &&
                       After.OrdinaryAllocations == Before.OrdinaryAllocations + 1U &&
                       After.OrdinaryBytes >= Before.OrdinaryBytes + 64U;

            Before = After;
            Pointers[4] = ::operator new(64, std::align_val_t{64});
            After = TransferPerfAllocation::ReadSnapshot();
            Forms[4] = Pointers[4] != nullptr &&
                       After.AlignedAllocations == Before.AlignedAllocations + 1U &&
                       After.AlignedBytes >= Before.AlignedBytes + 64U;

            Before = After;
            Pointers[5] = ::operator new[](64, std::align_val_t{64});
            After = TransferPerfAllocation::ReadSnapshot();
            Forms[5] = Pointers[5] != nullptr &&
                       After.AlignedAllocations == Before.AlignedAllocations + 1U &&
                       After.AlignedBytes >= Before.AlignedBytes + 64U;

            Before = After;
            Pointers[6] = ::operator new(64, std::align_val_t{64}, std::nothrow);
            After = TransferPerfAllocation::ReadSnapshot();
            Forms[6] = Pointers[6] != nullptr &&
                       After.AlignedAllocations == Before.AlignedAllocations + 1U &&
                       After.AlignedBytes >= Before.AlignedBytes + 64U;

            Before = After;
            Pointers[7] = ::operator new[](64, std::align_val_t{64}, std::nothrow);
            After = TransferPerfAllocation::ReadSnapshot();
            Forms[7] = Pointers[7] != nullptr &&
                       After.AlignedAllocations == Before.AlignedAllocations + 1U &&
                       After.AlignedBytes >= Before.AlignedBytes + 64U;
        }
        catch (...)
        {
            if (Pointers[0]) ::operator delete(Pointers[0]);
            if (Pointers[1]) ::operator delete[](Pointers[1]);
            if (Pointers[2]) ::operator delete(Pointers[2]);
            if (Pointers[3]) ::operator delete[](Pointers[3]);
            if (Pointers[4]) ::operator delete(Pointers[4], std::align_val_t{64});
            if (Pointers[5]) ::operator delete[](Pointers[5], std::align_val_t{64});
            if (Pointers[6]) ::operator delete(Pointers[6], std::align_val_t{64});
            if (Pointers[7]) ::operator delete[](Pointers[7], std::align_val_t{64});
            TransferPerfAllocation::Stop();
            const auto OrdinaryForms =
                static_cast<std::size_t>(Forms[0]) + static_cast<std::size_t>(Forms[1]) +
                static_cast<std::size_t>(Forms[2]) + static_cast<std::size_t>(Forms[3]);
            const auto AlignedForms =
                static_cast<std::size_t>(Forms[4]) + static_cast<std::size_t>(Forms[5]) +
                static_cast<std::size_t>(Forms[6]) + static_cast<std::size_t>(Forms[7]);
            std::printf(
                "io-allocation-preflight ordinary=%zu/4 aligned=%zu/4 result=fail\n",
                OrdinaryForms, AlignedForms);
            return false;
        }
        if (Pointers[0]) ::operator delete(Pointers[0]);
        if (Pointers[1]) ::operator delete[](Pointers[1]);
        if (Pointers[2]) ::operator delete(Pointers[2]);
        if (Pointers[3]) ::operator delete[](Pointers[3]);
        if (Pointers[4]) ::operator delete(Pointers[4], std::align_val_t{64});
        if (Pointers[5]) ::operator delete[](Pointers[5], std::align_val_t{64});
        if (Pointers[6]) ::operator delete(Pointers[6], std::align_val_t{64});
        if (Pointers[7]) ::operator delete[](Pointers[7], std::align_val_t{64});
        TransferPerfAllocation::Stop();
        const auto OrdinaryForms =
            static_cast<std::size_t>(Forms[0]) + static_cast<std::size_t>(Forms[1]) +
            static_cast<std::size_t>(Forms[2]) + static_cast<std::size_t>(Forms[3]);
        const auto AlignedForms =
            static_cast<std::size_t>(Forms[4]) + static_cast<std::size_t>(Forms[5]) +
            static_cast<std::size_t>(Forms[6]) + static_cast<std::size_t>(Forms[7]);
        const auto Passed = OrdinaryForms == 4U && AlignedForms == 4U;
        std::printf(
            "io-allocation-preflight ordinary=%zu/4 aligned=%zu/4 result=%s\n",
            OrdinaryForms, AlignedForms, Passed ? "pass" : "fail");
        return Passed;
    }


}

