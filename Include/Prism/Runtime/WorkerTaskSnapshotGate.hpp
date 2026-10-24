/**
 * @file WorkerTaskSnapshotGate.hpp
 * @brief Worker TaskRegistry 值快照与退休之间的读者闸门。
 */
#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/error_code.hpp>

#include <atomic>
#include <cstdint>
#include <memory>
#include <utility>

#include <Prism/Lifecycle/TaskRegistry.hpp>

namespace Prism::Runtime::Detail
{

    /** @brief 关闭新快照并等待现有读取结束后，Worker 才可销毁 root TaskRegistry。 */
    class WorkerTaskSnapshotGate final
    {
    public:
        explicit WorkerTaskSnapshotGate(boost::asio::any_io_executor Executor);

        auto StoreRetiredStats(Prism::Lifecycle::TaskStats Stats) -> void;

        [[nodiscard]] auto Close() noexcept -> bool;

        [[nodiscard]] auto Snapshot(
            const std::unique_ptr<Prism::Lifecycle::TaskRegistry> &Tasks) const noexcept
            -> Prism::Lifecycle::TaskStats;

        [[nodiscard]] auto WaitForReaders() -> boost::asio::awaitable<bool>;

    private:
        inline static constexpr std::uint64_t ClosedBit = std::uint64_t{1} << 63;
        inline static constexpr std::uint64_t ReaderMask = ClosedBit - 1;

        auto ReleaseReader() const noexcept -> void;

        using Signal = boost::asio::experimental::concurrent_channel<void(boost::system::error_code)>;

        mutable Signal Released_;
        mutable std::atomic<std::uint64_t> Gate_{0};
        std::atomic<std::shared_ptr<const Prism::Lifecycle::TaskStats>> RetiredStats_{};
    };

} // namespace Prism::Runtime::Detail
