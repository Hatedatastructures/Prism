/**
 * @file AsyncBackendState.hpp
 * @brief Preview Diagnose 唯一 spdlog async owner 的值状态和指标。
 */
#pragma once

#include <spdlog/async.h>
#include <spdlog/details/thread_pool.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>

#include <Preview/Foundation/Utility/Diagnose/Detail/SubmissionRecord.hpp>
#include <Preview/Foundation/Utility/Diagnose/RenderMode.hpp>
#include <Preview/Foundation/Utility/Diagnose/RuntimeOptions.hpp>
#include <Preview/Foundation/Utility/Diagnose/SubmissionReceipt.hpp>
#include <Preview/Statistics/Trace.hpp>

namespace Preview::Diagnose::Detail
{

    class SinkSet;

    /** @brief Diagnose backend 初始化或配置失败的分类。 */
    enum class BackendErrorCode : std::uint8_t
    {
        InvalidOptions,        ///< 参数不满足 backend 的边界约束。
        Directory,             ///< 无法创建或访问日志目录。
        FileOpen,              ///< 无法打开日志文件或创建 sink。
        LegacyArchive,         ///< 无法归档与当前格式不兼容的旧日志文件。
        ConfigurationConflict, ///< 已安装 backend 收到不同配置。
        OwnerConflict,         ///< 进程级 Diagnose backend owner 已被占用。
        WorkerStart,           ///< spdlog 异步线程池初始化失败。
    };

    /**
     * @brief 描述一次 backend 操作失败。
     */
    struct BackendError final
    {
        BackendErrorCode Code{BackendErrorCode::InvalidOptions}; ///< 稳定的失败分类。
        std::string Path{};    ///< 与失败有关的文件系统路径；非路径错误时可为空。
        std::string Message{}; ///< 面向维护者的具体错误说明。
    };

    /**
     * @brief BackendLifecycle 安装异步 backend 所需的完整配置。
     */
    struct BackendSettings final
    {
        RuntimeOptions Logging{};                             ///< 文件、队列和级别配置。
        RenderMode Mode{RenderMode::CompactHuman};            ///< 人类可读或结构化渲染方式。
        Preview::Statistics::TraceSelection TraceSelection{}; ///< HumanWithFields 模式下的身份字段选择。
        std::uint32_t FlushIntervalMs{250U}; ///< 应用运行时异步请求 sink flush 的周期，单位毫秒。
    };

    /**
     * @brief 保存唯一异步 backend 的不可变配置、指标和资源句柄。
     * @details BackendLifecycle 安装后创建该状态，并以 shared_ptr 保证正在执行的提交可以安全持有它。
     *          本类不创建线程或队列；异步线程池由 spdlog 管理。
     */
    class AsyncBackendState final
    {
    public:
        static constexpr std::size_t LevelCount =
            static_cast<std::size_t>(LogLevel::Off) + 1U; ///< LogLevel 的计数槽位数。

        /**
         * @brief 绑定 backend 配置、sink 和 logger 资源。
         * @param SettingsValue 安装后不可变的 backend 设置。
         * @param PoolValue 本模块独占的 spdlog async thread pool。
         * @param SinkValue sink 生命周期 owner。
         * @param LoggerValue spdlog 异步 logger。
         */
        AsyncBackendState(BackendSettings SettingsValue,
                          std::shared_ptr<spdlog::details::thread_pool> PoolValue,
                          std::shared_ptr<SinkSet> SinkValue,
                          std::shared_ptr<spdlog::async_logger> LoggerValue)
            : Settings_(std::move(SettingsValue)), Pool_(std::move(PoolValue)), Sinks_(std::move(SinkValue)),
              Logger_(std::move(LoggerValue))
        {
        }

        AsyncBackendState(const AsyncBackendState &) = delete;
        auto operator=(const AsyncBackendState &) -> AsyncBackendState & = delete;

        /**
         * @brief 读取本模块异步队列当前的记录数。
         * @return 当前排队记录数；线程池不存在时返回 0。
         */
        [[nodiscard]] auto QueueSize() const noexcept -> std::size_t
        {
            const auto Pool = Pool_.load(std::memory_order_acquire);
            if (Pool)
            {
                return Pool->queue_size();
            }
            return 0U;
        }

        /**
         * @brief 读取当前记录的队列最高水位。
         * @return 自安装或上次重置以来观察到的最大队列长度。
         */
        [[nodiscard]] auto QueueHighWatermark() const noexcept -> std::size_t
        {
            return QueueHighWatermark_.load(std::memory_order_relaxed);
        }

        /** @brief 在观测值高于当前记录时更新队列最高水位。
         * @param Value 本次观察到的队列长度。
         */
        auto ObserveQueueHighWatermark(const std::size_t Value) noexcept -> void
        {
            auto Previous = QueueHighWatermark_.load(std::memory_order_relaxed);
            while (Value > Previous &&
                   !QueueHighWatermark_.compare_exchange_weak(Previous, Value, std::memory_order_relaxed))
            {
            }
        }

        /** @brief 将队列最高水位重置为当前队列长度。
         * @details 调用期间队列仍可变化，因此结果是一次原子读取得到的近似基线。
         */
        auto ResetQueueHighWatermark() noexcept -> void
        {
            QueueHighWatermark_.store(QueueSize(), std::memory_order_relaxed);
        }

        /**
         * @brief 返回指定级别的非阻塞提交失败计数。
         * @param Level 要查询的日志级别。
         * @return 该级别因入队门闩竞争或异步队列满而未能提交的次数。
         */
        [[nodiscard]] auto Dropped(const LogLevel Level) const noexcept -> std::uint64_t
        {
            return Dropped_[static_cast<std::size_t>(Level)].load(std::memory_order_relaxed);
        }

        /**
         * @brief 读取因入队门闩竞争或队列满而未能提交的 Audit 记录数。
         * @return Audit 记录未入队的累计次数；不表示已入队记录已落盘。
         */
        [[nodiscard]] auto TerminalFailures() const noexcept -> std::uint64_t
        {
            return TerminalFailures_.load(std::memory_order_relaxed);
        }

    private:
        friend class BackendLifecycle;
        friend class BackendBridge;
        friend class AsyncSubmission;

        const BackendSettings Settings_;                                  ///< 安装后不可变的 backend 配置。
        std::atomic<std::shared_ptr<spdlog::details::thread_pool>> Pool_; ///< spdlog 异步线程池 owner。
        const std::shared_ptr<SinkSet> Sinks_;                            ///< spdlog sink 集合 owner。
        std::shared_ptr<spdlog::async_logger> Logger_;                    ///< spdlog 异步 logger owner。
        std::atomic<std::uint64_t> NextSequence_{1U};                     ///< 进程内单调提交序号。
        std::atomic<std::size_t> QueueHighWatermark_{0U}; ///< 观察到的 spdlog queue 最高水位。
        std::atomic_flag EnqueueGate_ = ATOMIC_FLAG_INIT; ///< 串行化非阻塞入队和 discard counter 归因。
        std::atomic<bool> Accepting_{true};               ///< 是否仍接受 facade 提交。
        std::array<std::atomic<std::uint64_t>, LevelCount> Dropped_{}; ///< 各级别未能进入异步队列的记录数。
        std::atomic<std::uint64_t> TerminalFailures_{0U};              ///< 未能进入异步队列的 Audit 记录数。
        std::atomic<std::uint64_t> CaptureFailures_{0U};               ///< Context 快照或消息捕获失败次数。
    };

} // namespace Preview::Diagnose::Detail
