/** @file ProcessMemory.cpp
 * @brief 操作系统进程驻留内存快照实现。
 */
#include <Prism/Foundation/Memory/ProcessMemory.hpp>

#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>

#if defined(_WIN32)
#include <windows.h>
#include <psapi.h>
#elif defined(__linux__)
#include <charconv>
#include <fcntl.h>
#include <sys/resource.h>
#include <system_error>
#include <unistd.h>
#endif

namespace Prism::Memory
{
#if defined(__linux__)
    namespace Detail
    {
        [[nodiscard]] static auto ParsePageCount(const char*& Cursor, const char* End,
            std::uint64_t& Value) noexcept -> bool
        {
            while (Cursor < End && (*Cursor == ' ' || *Cursor == '\t' || *Cursor == '\n'))
            {
                ++Cursor;
            }
            const auto Parsed = std::from_chars(Cursor, End, Value);
            if (Parsed.ec != std::errc{})
            {
                return false;
            }
            Cursor = Parsed.ptr;
            return true;
        }
    }
#endif

    auto ReadProcessMemoryUsage() noexcept -> std::optional<ProcessMemoryUsage>
    {
#if defined(_WIN32)
        using QueryProcessMemory = BOOL(WINAPI*)(HANDLE, PPROCESS_MEMORY_COUNTERS, DWORD);
        const auto Kernel = ::GetModuleHandleW(L"kernel32.dll");
        const auto Query = Kernel ? reinterpret_cast<QueryProcessMemory>(
            ::GetProcAddress(Kernel, "K32GetProcessMemoryInfo")) : nullptr;
        if (!Query)
        {
            return std::nullopt;
        }

        PROCESS_MEMORY_COUNTERS_EX Counters{};
        Counters.cb = sizeof(Counters);
        const auto Success = Query(::GetCurrentProcess(),
            reinterpret_cast<PPROCESS_MEMORY_COUNTERS>(&Counters), sizeof(Counters)) != FALSE;
        if (!Success)
        {
            return std::nullopt;
        }
        return ProcessMemoryUsage{static_cast<std::uint64_t>(Counters.WorkingSetSize),
            static_cast<std::uint64_t>(Counters.PeakWorkingSetSize)};
#elif defined(__linux__)
        const auto File = ::open("/proc/self/statm", O_RDONLY | O_CLOEXEC);
        if (File < 0)
        {
            return std::nullopt;
        }
        char Buffer[128]{};
        const auto ReadBytes = ::read(File, Buffer, sizeof(Buffer));
        (void)::close(File);
        if (ReadBytes <= 0)
        {
            return std::nullopt;
        }

        const char* Cursor = Buffer;
        const auto End = Buffer + static_cast<std::size_t>(ReadBytes);
        std::uint64_t VirtualPages{0};
        std::uint64_t ResidentPages{0};
        if (!Detail::ParsePageCount(Cursor, End, VirtualPages) ||
            !Detail::ParsePageCount(Cursor, End, ResidentPages))
        {
            return std::nullopt;
        }
        (void)VirtualPages;

        const auto PageSize = ::sysconf(_SC_PAGESIZE);
        constexpr auto Limit = std::numeric_limits<std::uint64_t>::max();
        if (PageSize <= 0 || ResidentPages > Limit / static_cast<std::uint64_t>(PageSize))
        {
            return std::nullopt;
        }

        rusage Usage{};
        if (::getrusage(RUSAGE_SELF, &Usage) != 0 || Usage.ru_maxrss < 0)
        {
            return std::nullopt;
        }
        const auto PeakKiB = static_cast<std::uint64_t>(Usage.ru_maxrss);
        if (PeakKiB > Limit / 1024U)
        {
            return std::nullopt;
        }
        return ProcessMemoryUsage{ResidentPages * static_cast<std::uint64_t>(PageSize), PeakKiB * 1024U};
#else
        return std::nullopt;
#endif
    }
}
