/**
 * @file DnsPerf.hpp
 * @brief DNS 性能基准入口与 allocation 边界。
 */

#pragma once

#include <Preview/Net/Dns/Answer.hpp>
#include <Preview/Net/Dns/Cache.hpp>
#include <Preview/Net/Dns/Format.hpp>
#include <Preview/Net/Dns/Resolver.hpp>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/experimental/channel.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <future>
#include <functional>
#include <memory>
#include <optional>
#include <random>
#include <string>
#include <string_view>
#include <vector>
#include <thread>

namespace DnsPerfAllocation
{
    struct Snapshot final
    {
        std::size_t OrdinaryAllocations{0}; std::size_t AlignedAllocations{0};
        std::size_t OrdinaryBytes{0}; std::size_t AlignedBytes{0};
    };
    inline std::atomic<bool> Active{false};
    inline std::atomic<std::size_t> OrdinaryAllocations{0};
    inline std::atomic<std::size_t> AlignedAllocations{0};
    inline std::atomic<std::size_t> OrdinaryBytes{0};
    inline std::atomic<std::size_t> AlignedBytes{0};
    inline auto Start() noexcept -> void
    {
        OrdinaryAllocations.store(0, std::memory_order_relaxed);
        AlignedAllocations.store(0, std::memory_order_relaxed);
        OrdinaryBytes.store(0, std::memory_order_relaxed);
        AlignedBytes.store(0, std::memory_order_relaxed);
        Active.store(true, std::memory_order_release);
    }
    inline auto Stop() noexcept -> void { Active.store(false, std::memory_order_release); }
    [[nodiscard]] inline auto Read() noexcept -> Snapshot
    {
        return {OrdinaryAllocations.load(std::memory_order_relaxed),
                AlignedAllocations.load(std::memory_order_relaxed),
                OrdinaryBytes.load(std::memory_order_relaxed),
                AlignedBytes.load(std::memory_order_relaxed)};
    }
}

namespace DnsPerf
{
}

