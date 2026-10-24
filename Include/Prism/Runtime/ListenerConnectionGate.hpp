/**
 * @file ListenerConnectionGate.hpp
 * @brief TCP listener 的连接容量、拒绝和真实排空 owner。
 * @details listener quota 与 worker admission receipt 由同一 Reservation 保持；传输关闭交付、
 *          Activity 排空和 worker receipt 归还分别表达，不能用同步 Close 冒充最终资源完成。
 */

#pragma once

#include <Prism/Foundation/Executor/ClosingStorage.hpp>
#include <Prism/Foundation/Fault/FailureState.hpp>
#include <Prism/Lifecycle/DrainBarrier.hpp>
#include <Prism/Runtime/Worker.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <atomic>
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <utility>

namespace Prism::Runtime::Detail
{

    namespace Net = boost::asio;

    class ListenerConnectionGate final
    {
    public:
        /** @brief 共享 listener quota；reservation 通过此 owner 延长 Active 的生命周期。 */
        class Quota final
        {
        public:
            Quota(const std::size_t LimitValue, Net::any_io_executor Executor);

            const std::size_t Limit;
            std::atomic<std::size_t> Active{0};
            /** @brief 覆盖全部已接收连接，包括无限额与尚未进入 SessionRegistry 的 owner。 */
            Prism::Lifecycle::DrainBarrier Drain;
        };

        using SharedQuota = std::shared_ptr<Quota>;

        [[nodiscard]] static auto TryAcquire(const SharedQuota &Value) noexcept -> bool;

        static auto ReturnQuota(const SharedQuota &Value) noexcept -> void;

        /** @brief 一次性 listener quota/worker receipt reservation；移交后只由真实 drain 显式归还。 */
        class Reservation final : public Prism::Executor::ClosingResource,
                                  public std::enable_shared_from_this<Reservation>
        {
        public:
            explicit Reservation(SharedQuota Value,
                                 std::shared_ptr<Prism::Executor::ClosingStorage> Storage,
                                 std::shared_ptr<Prism::Runtime::Worker::AdmissionReceipt> WorkerReceipt = {}) noexcept;

            ~Reservation() noexcept;

            Reservation(const Reservation &) = delete;
            auto operator=(const Reservation &) -> Reservation & = delete;

            Reservation(Reservation &&Other) noexcept;

            auto operator=(Reservation &&Other) noexcept -> Reservation & = delete;

            /** @brief 进入跨 Request/Task/Run 的正式 owner；只能显式 Release 归还。 */
            auto RetainOnDrop() noexcept -> void;

            /** @brief 真实 drain owner 完成后释放传输载体。 */
            auto ReleaseTransport() noexcept -> void;

            /** @brief 将尚未建立 Drain 的传输交给预先存在的 Reservation。 */
            auto AdoptTransport(Prism::SharedTransmission Value) noexcept -> void;

            /** @brief 竞争安全的一次归还门；重复完成、拒绝和取消不会重复递减。 */
            auto Release() noexcept -> void;

            /** @brief 关闭失败保留真实预约，并唤醒 listener 排空等待者返回失败。 */
            auto BlockDrain() noexcept -> void;

            /** @brief ClosingStorage 重试入口；失败保持传输和 quota，不在析构线程关闭。 */
            auto RequestRetirement() noexcept -> void override;

            [[nodiscard]] auto IsRetired() const noexcept -> bool override;

            [[nodiscard]] auto IsDispatchUnavailable() const noexcept -> bool override;

        private:
            struct DispatchCompletion final
            {
                std::shared_ptr<Reservation> Owner;
                std::uint64_t Generation{0};
                std::exception_ptr Error;
                bool Invoked{false};

                DispatchCompletion(std::shared_ptr<Reservation> Value,
                    const std::uint64_t ValueGeneration) noexcept;
                DispatchCompletion(DispatchCompletion &&Other) noexcept;
                ~DispatchCompletion() noexcept;
                auto operator()(std::exception_ptr Error) noexcept -> void;
            };

            static auto Run(std::shared_ptr<Reservation> Owner) -> Net::awaitable<void>;

            auto Block(Prism::Fault::Failure Error) noexcept -> void;

            auto OnDispatchDropped(const std::uint64_t Generation) noexcept -> void;

            auto OnDispatchCompleted(const std::uint64_t Generation,
                                     const std::exception_ptr &Error) noexcept -> void;

            SharedQuota Quota_;
            Prism::SharedTransmission Transport_;
            std::shared_ptr<Prism::Executor::ClosingStorage> Storage_;
            std::shared_ptr<Prism::Runtime::Worker::AdmissionReceipt> WorkerReceipt_;
            std::atomic<bool> Returned_{false};
            std::atomic<bool> RetainOnDrop_{false};
            std::atomic<bool> Started_{false};
            std::atomic<bool> Completed_{false};
            std::atomic<bool> Blocked_{false};
            std::atomic<bool> Retired_{false};
            std::atomic<std::uint64_t> DispatchGeneration_{0};
            Prism::Fault::FailureState Failure_;
        };

    };

} // namespace Prism::Runtime::Detail
