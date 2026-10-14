/**
 * @file ListenerConnectionGate.hpp
 * @brief TCP listener 的连接容量、拒绝和真实排空 owner。
 * @details listener quota 与 worker admission receipt 由同一 Reservation 保持；传输关闭交付、
 *          Activity 排空和 worker receipt 归还分别表达，不能用同步 Close 冒充最终资源完成。
 */

#pragma once

#include <Preview/Foundation/Executor/ClosingStorage.hpp>
#include <Preview/Foundation/Fault/FailureState.hpp>
#include <Preview/Lifecycle/DrainBarrier.hpp>
#include <Preview/Runtime/Worker.hpp>
#include <Preview/Transport/Transmission.hpp>

#include <atomic>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/this_coro.hpp>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <system_error>
#include <utility>

namespace Preview::Runtime::Detail
{

    namespace Net = boost::asio;

    class ListenerConnectionGate final
    {
    public:
        /** @brief 共享 listener quota；reservation 通过此 owner 延长 Active 的生命周期。 */
        class Quota final
        {
        public:
            Quota(const std::size_t LimitValue, Net::any_io_executor Executor)
                : Limit(LimitValue), Drain(std::make_shared<Preview::Executor::ExecutorReclaimer>(
                    std::move(Executor))) {}

            const std::size_t Limit;
            std::atomic<std::size_t> Active{0};
            /** @brief 覆盖全部已接收连接，包括无限额与尚未进入 SessionRegistry 的 owner。 */
            Preview::Lifecycle::DrainBarrier Drain;
        };

        using SharedQuota = std::shared_ptr<Quota>;

        [[nodiscard]] static auto TryAcquire(const SharedQuota &Value) noexcept -> bool
        {
            if (!Value) return false;
            if (Value->Limit == 0) return Value->Drain.Enter();
            auto Current = Value->Active.load(std::memory_order_relaxed);
            while (Current < Value->Limit &&
                   !Value->Active.compare_exchange_weak(Current, Current + 1U,
                                                        std::memory_order_acquire,
                                                        std::memory_order_relaxed))
            {
            }
            if (Current >= Value->Limit) return false;
            if (Value->Drain.Enter()) return true;
            Value->Active.fetch_sub(1U, std::memory_order_release);
            return false;
        }

        static auto ReturnQuota(const SharedQuota &Value) noexcept -> void
        {
            if (!Value) return;
            if (Value->Limit != 0)
            {
                auto Current = Value->Active.load(std::memory_order_acquire);
                while (Current != 0 &&
                       !Value->Active.compare_exchange_weak(Current, Current - 1U,
                                                            std::memory_order_acq_rel,
                                                            std::memory_order_acquire))
                {
                }
            }
            Value->Drain.Leave();
        }

        /** @brief 一次性 listener quota/worker receipt reservation；移交后只由真实 drain 显式归还。 */
        class Reservation final : public Preview::Executor::ClosingResource,
                                  public std::enable_shared_from_this<Reservation>
        {
        public:
            explicit Reservation(SharedQuota Value,
                                 std::shared_ptr<Preview::Executor::ClosingStorage> Storage,
                                 std::shared_ptr<Preview::Runtime::Worker::AdmissionReceipt> WorkerReceipt = {}) noexcept
                : Quota_(std::move(Value)), Storage_(std::move(Storage)),
                  WorkerReceipt_(std::move(WorkerReceipt))
            {
            }

            ~Reservation() noexcept
            {
                if (!RetainOnDrop_.load(std::memory_order_acquire))
                {
                    Release();
                }
            }

            Reservation(const Reservation &) = delete;
            auto operator=(const Reservation &) -> Reservation & = delete;

            Reservation(Reservation &&Other) noexcept
                : Quota_(std::move(Other.Quota_)),
                  Transport_(std::move(Other.Transport_)),
                  Storage_(std::move(Other.Storage_)),
                  WorkerReceipt_(std::move(Other.WorkerReceipt_)),
                  Returned_(Other.Returned_.load(std::memory_order_acquire)),
                  RetainOnDrop_(Other.RetainOnDrop_.load(std::memory_order_acquire))
            {
                Other.Returned_.store(true, std::memory_order_release);
                Other.RetainOnDrop_.store(true, std::memory_order_release);
            }

            auto operator=(Reservation &&Other) noexcept -> Reservation & = delete;

            /** @brief 进入跨 Request/Task/Run 的正式 owner；只能显式 Release 归还。 */
            auto RetainOnDrop() noexcept -> void
            {
                RetainOnDrop_.store(true, std::memory_order_release);
            }

            /** @brief 真实 drain owner 完成后释放传输载体。 */
            auto ReleaseTransport() noexcept -> void { Transport_.reset(); }

            /** @brief 将尚未建立 Drain 的传输交给预先存在的 Reservation。 */
            auto AdoptTransport(Preview::SharedTransmission Value) noexcept -> void
            {
                if (!Transport_) Transport_ = std::move(Value);
            }

            /** @brief 竞争安全的一次归还门；重复完成、拒绝和取消不会重复递减。 */
            auto Release() noexcept -> void
            {
                if (Returned_.exchange(true, std::memory_order_acq_rel))
                {
                    return;
                }
                ListenerConnectionGate::ReturnQuota(Quota_);
                if (WorkerReceipt_)
                {
                    WorkerReceipt_->Release();
                    WorkerReceipt_.reset();
                }
            }

            /** @brief 关闭失败保留真实预约，并唤醒 listener 排空等待者返回失败。 */
            auto BlockDrain() noexcept -> void
            {
                if (Quota_) Quota_->Drain.Block();
                if (WorkerReceipt_) WorkerReceipt_->Block();
            }

            /** @brief ClosingStorage 重试入口；失败保持传输和 quota，不在析构线程关闭。 */
            auto RequestRetirement() noexcept -> void override
            {
                if (Retired_.load(std::memory_order_acquire)) return;
                if (Blocked_.exchange(false, std::memory_order_acq_rel))
                    Started_.store(false, std::memory_order_release);
                if (Started_.exchange(true, std::memory_order_acq_rel)) return;
                try
                {
                    const auto Owner = shared_from_this();
                    Storage_->Retain(Owner);
                    if (!Transport_ || !Transport_->Activity())
                    {
                        Block({Preview::Fault::Code::InvalidArgument});
                        return;
                    }
                    const auto Generation = DispatchGeneration_.fetch_add(1, std::memory_order_acq_rel) + 1U;
                    Net::co_spawn(Transport_->Activity()->Executor(), Run(Owner),
                                  DispatchCompletion(Owner, Generation));
                }
                catch (const std::system_error &Error)
                { Block(Preview::Fault::FromNative(Error.code())); }
                catch (...)
                { Block({Preview::Fault::Code::Blocked}); }
            }

            [[nodiscard]] auto IsRetired() const noexcept -> bool override
            { return Retired_.load(std::memory_order_acquire); }

            [[nodiscard]] auto IsDispatchUnavailable() const noexcept -> bool override
            { return Blocked_.load(std::memory_order_acquire); }

        private:
            struct DispatchCompletion final
            {
                std::shared_ptr<Reservation> Owner;
                std::uint64_t Generation{0};
                std::exception_ptr Error;
                bool Invoked{false};

                DispatchCompletion(std::shared_ptr<Reservation> Value, const std::uint64_t ValueGeneration) noexcept
                    : Owner(std::move(Value)), Generation(ValueGeneration) {}
                DispatchCompletion(DispatchCompletion &&Other) noexcept
                    : Owner(std::move(Other.Owner)), Generation(Other.Generation), Error(std::move(Other.Error)),
                      Invoked(Other.Invoked)
                {
                }
                ~DispatchCompletion() noexcept
                {
                    if (!Owner) return;
                    if (!Invoked) Owner->OnDispatchDropped(Generation);
                    else Owner->OnDispatchCompleted(Generation, Error);
                }
                auto operator()(std::exception_ptr Error) noexcept -> void
                {
                    Invoked = true;
                    this->Error = std::move(Error);
                }
            };

            static auto Run(std::shared_ptr<Reservation> Owner) -> Net::awaitable<void>
            {
                try
                {
                    co_await Net::this_coro::throw_if_cancelled(false);
                    co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
                    const auto Canceled = Owner->Transport_->Cancel();
                    const auto Closed = Owner->Transport_->Close();
                    if (!Canceled) { Owner->Block(Canceled.error()); co_return; }
                    if (!Closed) { Owner->Block(Closed.error()); co_return; }
                    const auto Activity = Owner->Transport_->Activity();
                    if (!Activity)
                    {
                        Owner->Block({Preview::Fault::Code::InvalidArgument});
                        co_return;
                    }
                    const auto Drained = co_await Activity->Drain();
                    if (!Drained) { Owner->Block(Drained.error()); co_return; }
                    Owner->Completed_.store(true, std::memory_order_release);
                }
                catch (const std::system_error &Error)
                {
                    Owner->Block(Preview::Fault::FromNative(Error.code()));
                }
                catch (...)
                {
                    Owner->Block({Preview::Fault::Code::IoError});
                }
            }

            auto Block(Preview::Fault::Failure Error) noexcept -> void
            {
                BlockDrain();
                Failure_.TrySet(Error);
                Completed_.store(false, std::memory_order_release);
                Blocked_.store(true, std::memory_order_release);
                Started_.store(false, std::memory_order_release);
            }

            auto OnDispatchDropped(const std::uint64_t Generation) noexcept -> void
            {
                if (Generation == DispatchGeneration_.load(std::memory_order_acquire) &&
                    !Retired_.load(std::memory_order_acquire))
                    Block({Preview::Fault::Code::Blocked});
            }

            auto OnDispatchCompleted(const std::uint64_t Generation,
                                     const std::exception_ptr &Error) noexcept -> void
            {
                if (Generation != DispatchGeneration_.load(std::memory_order_acquire) ||
                    Retired_.load(std::memory_order_acquire))
                    return;
                if (Error)
                {
                    try { std::rethrow_exception(Error); }
                    catch (const std::system_error &Native)
                    { Block(Preview::Fault::FromNative(Native.code())); }
                    catch (...)
                    { Block({Preview::Fault::Code::IoError}); }
                    return;
                }
                if (!Completed_.load(std::memory_order_acquire)) return;
                Transport_.reset();
                Retired_.store(true, std::memory_order_release);
                Release();
                Storage_->Collect();
            }

            SharedQuota Quota_;
            Preview::SharedTransmission Transport_;
            std::shared_ptr<Preview::Executor::ClosingStorage> Storage_;
            std::shared_ptr<Preview::Runtime::Worker::AdmissionReceipt> WorkerReceipt_;
            std::atomic<bool> Returned_{false};
            std::atomic<bool> RetainOnDrop_{false};
            std::atomic<bool> Started_{false};
            std::atomic<bool> Completed_{false};
            std::atomic<bool> Blocked_{false};
            std::atomic<bool> Retired_{false};
            std::atomic<std::uint64_t> DispatchGeneration_{0};
            Preview::Fault::FailureState Failure_;
        };

    };

} // namespace Preview::Runtime::Detail
