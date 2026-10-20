/**
 * @file BackendLifecycle.hpp
 * @brief Diagnose backend 的生命周期控制接口。
 */
#pragma once

#include <Prism/Foundation/Utility/Diagnose/Detail/RenderEpoch.hpp>
#include <Prism/Foundation/Utility/Diagnose/Detail/SubmissionRequest.hpp>
#include <Prism/Foundation/Utility/Diagnose/SubmissionReceipt.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>

namespace Prism::Diagnose::Detail
{
    class BackendLifecycleOwner;

    /**
     * @brief process 日志资源的唯一控制 owner。
     * @details 输入值由对象或调用方拥有，所有 sink 与 worker 最终由 Shutdown 关闭；
     *          Submit 只同步捕获并返回回执，Drain 在调用控制线程等待，不隐式取消已接收记录。
     */
    class BackendLifecycle final
    {
        friend struct BackendLifecycleTestAccess;

    public:
        BackendLifecycle();
        BackendLifecycle(const BackendLifecycle&) = delete;
        auto operator=(const BackendLifecycle&) -> BackendLifecycle& = delete;
        ~BackendLifecycle() noexcept;

        [[nodiscard]] auto Install(BackendSettings Settings) -> std::expected<void, BackendError>;
        [[nodiscard]] auto PrepareEpoch(BackendSettings Settings)
            -> std::expected<Prism::Diagnose::RenderEpochPin, BackendError>;
        auto PublishEpoch(const Prism::Diagnose::RenderEpochPin& Epoch) noexcept -> bool;
        [[nodiscard]] auto CurrentEpoch() const noexcept -> Prism::Diagnose::RenderEpochPin;
        [[nodiscard]] auto Submit(const SubmissionRequest& Request) noexcept -> SubmissionReceipt;
        auto BeginShutdown() noexcept -> void;
        auto Flush() noexcept -> void;
        [[nodiscard]] auto DrainOnControlThread(std::chrono::milliseconds Timeout) const
            -> SubmissionReceipt;
        [[nodiscard]] auto Shutdown() noexcept -> SubmissionReceipt;
        [[nodiscard]] auto IsInstalled() const noexcept -> bool;
        [[nodiscard]] auto Dropped(LogLevel Level) const noexcept -> std::uint64_t;
        [[nodiscard]] auto QueueHighWatermark() const noexcept -> std::size_t;
        [[nodiscard]] auto TerminalFailures() const noexcept -> std::uint64_t;
        [[nodiscard]] auto CaptureFailures() const noexcept -> std::uint64_t;
        [[nodiscard]] auto RenderFailures() const noexcept -> std::uint64_t;
        [[nodiscard]] auto SinkFailures() const noexcept -> std::uint64_t;
        [[nodiscard]] auto Written() const noexcept -> std::uint64_t;
        auto ResetQueueHighWatermark() noexcept -> void;

    private:
        std::unique_ptr<BackendLifecycleOwner> Owner_;
    };
}
