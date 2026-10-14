/**
 * @file WorkerAdmissionReceipt.hpp
 * @brief 持有 listener carrier 的 worker admission drain receipt。
 * @details Receipt 从准入预约保留到 carrier、activity 和 session 全部退役。
 */

#pragma once

#include <Preview/Foundation/Identifier/Id.hpp>
#include <Preview/Lifecycle/DrainBarrier.hpp>

#include <atomic>
#include <memory>
#include <utility>

namespace Preview::Runtime
{

    class Worker;

    /** @brief 绑定单一 WorkerId/Generation 的真实 listener admission receipt。 */
    class WorkerAdmissionReceipt final
    {
    public:
        WorkerAdmissionReceipt(const WorkerAdmissionReceipt &) = delete;
        auto operator=(const WorkerAdmissionReceipt &) -> WorkerAdmissionReceipt & = delete;

        ~WorkerAdmissionReceipt() noexcept
        {
            Release();
        }

        /** @brief 真实 owner 退栈后归还一次；被 Block 的 receipt 不会假装完成。 */
        auto Release() noexcept -> void
        {
            if (!Released_.exchange(true, std::memory_order_acq_rel))
            {
                Fence_->Leave();
            }
        }

        /** @brief 把 carrier 关闭失败传播到本 Worker 的 admission drain。 */
        auto Block() noexcept -> void
        {
            Fence_->Block();
        }

        [[nodiscard]] auto Id() const noexcept -> Preview::WorkerId
        {
            return Id_;
        }

        [[nodiscard]] auto Generation() const noexcept -> Preview::GenerationId
        {
            return Generation_;
        }

    private:
        friend class Worker;

        WorkerAdmissionReceipt(
            std::shared_ptr<Preview::Lifecycle::DrainBarrier> Fence,
            const Preview::WorkerId Id,
            const Preview::GenerationId Generation) noexcept
            : Fence_(std::move(Fence)), Id_(Id), Generation_(Generation)
        {
        }

        auto Disarm() noexcept -> void
        {
            Released_.store(true, std::memory_order_release);
        }

        std::shared_ptr<Preview::Lifecycle::DrainBarrier> Fence_;
        Preview::WorkerId Id_{};
        Preview::GenerationId Generation_{};
        std::atomic<bool> Released_{false};
    };

}
