/**
 * @file DatagramRetirementActions.hpp
 * @brief 数据报退休 owner 的 executor 投递与完成回执动作。
 */
#pragma once

#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Protocols/Common/DatagramFailure.hpp>

#include <cstdint>
#include <exception>
#include <expected>
#include <memory>
#include <utility>

namespace Prism::Protocols
{
    template <class Wire>
    class DatagramRetirement;

    namespace DatagramRetirementDetail
    {
        enum class DeliveryKind : std::uint8_t
        {
            Shutdown,
            Cancel,
            Seal,
            Retry
        };

        /** @brief 保持退休 owner 存活直至托管动作执行或被 quarantine。 */
        template <class Wire>
        struct Delivery final
        {
            using OwnerType = DatagramRetirement<Wire>;

            std::shared_ptr<OwnerType> Owner;
            DeliveryKind Kind;
            bool RetryControls;
            bool Invoked{false};
            bool FailureRecorded{false};

            Delivery(std::shared_ptr<OwnerType> Value, DeliveryKind Action, bool Retry)
                : Owner(std::move(Value)), Kind(Action), RetryControls(Retry)
            {
            }
            Delivery(Delivery &&Other) noexcept
                : Owner(std::move(Other.Owner)), Kind(Other.Kind),
                  RetryControls(Other.RetryControls), Invoked(Other.Invoked),
                  FailureRecorded(Other.FailureRecorded)
            {
            }
            Delivery(const Delivery &) = delete;
            ~Delivery()
            {
                if (!Owner || Invoked || FailureRecorded)
                {
                    return;
                }
                Owner->Record({Prism::Fault::Code::Blocked});
            }
            auto OnQuarantine() noexcept -> void
            {
                if (!Owner || Invoked || FailureRecorded)
                {
                    return;
                }
                Owner->Record({Prism::Fault::Code::Blocked});
                FailureRecorded = true;
            }
            auto operator()() -> void
            {
                Invoked = true;
                if (Kind == DeliveryKind::Shutdown)
                {
                    Owner->BeginShutdown(false);
                }
                else if (Kind == DeliveryKind::Cancel)
                {
                    Owner->BeginShutdown(true);
                }
                else if (Kind == DeliveryKind::Seal)
                {
                    Owner->SealOnStrand();
                }
                else
                {
                    const bool WasClosed = Owner->Closed_;
                    Owner->BeginShutdown(false);
                    Owner->RequestRetirementOnStrand(RetryControls && WasClosed);
                }
            }
        };

        /** @brief 保持退休完成 handler 的 owner，并统一处理完成、失败与重试。 */
        template <class Wire>
        struct Completion final
        {
            using OwnerType = DatagramRetirement<Wire>;
            using Result = std::expected<void, Prism::Fault::Failure>;

            std::shared_ptr<OwnerType> Owner;
            bool Invoked{false};

            explicit Completion(std::shared_ptr<OwnerType> Value)
                : Owner(std::move(Value))
            {
            }
            Completion(Completion &&Other) noexcept
                : Owner(std::move(Other.Owner)), Invoked(Other.Invoked)
            {
            }
            Completion(const Completion &) = delete;
            ~Completion()
            {
                if (!Owner || Invoked)
                {
                    return;
                }
                Owner->Record({Prism::Fault::Code::Blocked});
                Owner->Notify();
            }
            auto operator()(std::exception_ptr Exception, Result Value) -> void
            {
                Invoked = true;
                Owner->RetirementRunning_ = false;
                if (Exception)
                {
                    Owner->Record(DatagramFailure::FromException(Exception));
                }
                else if (!Value && !Owner->Retired_.load(std::memory_order_acquire))
                {
                    Owner->Record(Value.error());
                }
                else if (Value)
                {
                    Owner->FinalizeRetirement();
                }
                if (Owner->Retired_.load(std::memory_order_acquire))
                {
                    Owner->Storage_->Collect();
                }
                else
                {
                    Owner->StartRetirement();
                }
                Owner->Notify();
            }
        };
    }
}
