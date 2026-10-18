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
        explicit WorkerTaskSnapshotGate(boost::asio::any_io_executor Executor)
            : Released_(std::move(Executor), 1U)
        {
        }

        auto StoreRetiredStats(Prism::Lifecycle::TaskStats Stats) -> void
        {
            RetiredStats_.store(
                std::make_shared<const Prism::Lifecycle::TaskStats>(std::move(Stats)),
                std::memory_order_release);
        }

        [[nodiscard]] auto Close() noexcept -> bool
        {
            const auto State = Gate_.fetch_or(ClosedBit, std::memory_order_acq_rel);
            return (State & ReaderMask) != 0;
        }

        [[nodiscard]] auto Snapshot(
            const std::unique_ptr<Prism::Lifecycle::TaskRegistry> &Tasks) const noexcept
            -> Prism::Lifecycle::TaskStats
        {
            auto State = Gate_.load(std::memory_order_acquire);
            while ((State & ClosedBit) == 0)
            {
                if ((State & ReaderMask) == ReaderMask)
                {
                    Prism::Lifecycle::TaskStats Failed;
                    Failed.DrainBlocked = true;
                    return Failed;
                }
                if (Gate_.compare_exchange_weak(
                        State, State + 1, std::memory_order_acq_rel, std::memory_order_acquire))
                {
                    if (Tasks)
                    {
                        const auto Result = Tasks->Stats();
                        ReleaseReader();
                        return Result;
                    }
                    ReleaseReader();
                    break;
                }
            }
            const auto Retired = RetiredStats_.load(std::memory_order_acquire);
            if (Retired)
            {
                return *Retired;
            }
            Prism::Lifecycle::TaskStats Failed;
            Failed.DrainBlocked = true;
            return Failed;
        }

        [[nodiscard]] auto WaitForReaders() -> boost::asio::awaitable<bool>
        {
            co_await boost::asio::this_coro::reset_cancellation_state(
                boost::asio::disable_cancellation());
            boost::system::error_code Error;
            co_await Released_.async_receive(
                boost::asio::redirect_error(boost::asio::use_awaitable, Error));
            co_return !Error;
        }

    private:
        inline static constexpr std::uint64_t ClosedBit = std::uint64_t{1} << 63;
        inline static constexpr std::uint64_t ReaderMask = ClosedBit - 1;

        auto ReleaseReader() const noexcept -> void
        {
            const auto Previous = Gate_.fetch_sub(1, std::memory_order_acq_rel);
            if ((Previous & ClosedBit) != 0 && (Previous & ReaderMask) == 1)
            {
                (void)Released_.try_send(boost::system::error_code{});
            }
        }

        using Signal = boost::asio::experimental::concurrent_channel<void(boost::system::error_code)>;

        mutable Signal Released_;
        mutable std::atomic<std::uint64_t> Gate_{0};
        std::atomic<std::shared_ptr<const Prism::Lifecycle::TaskStats>> RetiredStats_{};
    };

} // namespace Prism::Runtime::Detail
