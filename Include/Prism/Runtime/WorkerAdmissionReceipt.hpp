/**
 * @file WorkerAdmissionReceipt.hpp
 * @brief 持有 listener carrier 的 worker admission drain receipt。
 * @details Receipt 从准入预约保留到 carrier、activity 和 session 全部退役。
 */

#pragma once

#include <Prism/Foundation/Identifier/Id.hpp>
#include <Prism/Lifecycle/DrainBarrier.hpp>

#include <atomic>
#include <memory>

namespace Prism::Runtime
{

    class Worker;

    /** @brief 绑定单一 WorkerId/Generation 的真实 listener admission receipt。 */
    class WorkerAdmissionReceipt final
    {
    public:
        WorkerAdmissionReceipt(const WorkerAdmissionReceipt &) = delete;
        auto operator=(const WorkerAdmissionReceipt &) -> WorkerAdmissionReceipt & = delete;

        ~WorkerAdmissionReceipt() noexcept;

        /** @brief 真实 owner 退栈后归还一次；被 Block 的 receipt 不会假装完成。 */
        auto Release() noexcept -> void;

        /** @brief 把 carrier 关闭失败传播到本 Worker 的 admission drain。 */
        auto Block() noexcept -> void;

        [[nodiscard]] auto Id() const noexcept -> Prism::WorkerId
        {
            return Id_;
        }

        [[nodiscard]] auto Generation() const noexcept -> Prism::GenerationId
        {
            return Generation_;
        }

    private:
        friend class Worker;

        WorkerAdmissionReceipt(
            std::shared_ptr<Prism::Lifecycle::DrainBarrier> Fence,
            Prism::WorkerId Id,
            Prism::GenerationId Generation) noexcept;

        auto Disarm() noexcept -> void;

        std::shared_ptr<Prism::Lifecycle::DrainBarrier> Fence_;
        Prism::WorkerId Id_{};
        Prism::GenerationId Generation_{};
        std::atomic<bool> Released_{false};
    };

}
