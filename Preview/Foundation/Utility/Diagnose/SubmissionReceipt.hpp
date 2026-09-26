/**
 * @file SubmissionReceipt.hpp
 * @brief Diagnose 自有提交结果。
 */
#pragma once

#include <cstdint>

namespace Preview::Diagnose
{

    /**
     * @brief 表示日志提交或 backend 生命周期操作的结果。
     */
    enum class SubmissionStatus : std::uint8_t
    {
        Accepted,                ///< 记录已交给异步 backend；不代表普通 sink 已完成写入或 flush。
        Filtered,                ///< 普通记录因级别阈值未提交。
        Dropped,                 ///< 任一级别的记录因入队竞争或队列满而未能入队。
        FallbackWritten,         ///< 兼容旧调用方的状态；当前 facade 不执行同步应急写入。
        Stopped,                 ///< backend 未安装，或已停止接收新提交。
        Failed,                  ///< 格式化、上下文捕获或 backend 提交失败。
        TimedOut,                ///< 控制线程 drain barrier 未在截止时间前完成。
        ContextCapacityExceeded, ///< 新字段无法放入 per-call Context 的固定 inline 区。
    };

    /**
     * @brief 区分普通观测记录和终态审计记录。
     */
    enum class SubmissionKind : std::uint8_t
    {
        Ordinary, ///< 遵守级别阈值和普通队列丢弃策略的记录。
        Audit,    ///< 绕过普通级别阈值；队列满时仍可能丢弃，不保证持久化。
    };

    /**
     * @brief 不暴露 backend 类型的值语义提交回执。
     * @details Sequence 仅用于标识进程内提交顺序；它不代表记录已持久化。
     */
    struct SubmissionReceipt final
    {
        SubmissionStatus Status{SubmissionStatus::Accepted}; ///< 本次提交或生命周期操作的结果。
        std::uint64_t Sequence{0U}; ///< backend 分配的进程内单调序号；未获分配时为 0。

        /**
         * @brief 判断本次操作是否已被异步 backend 接收。
         * @return Status 为 Accepted 或 FallbackWritten 时返回 true。
         * @note Accepted 只确认进入异步 backend，不确认文件 sink 已写入或完成 flush；FallbackWritten 保留用于兼容旧回执。
         */
        [[nodiscard]] auto Accepted() const noexcept -> bool
        {
            return Status == SubmissionStatus::Accepted || Status == SubmissionStatus::FallbackWritten;
        }
    };

} // namespace Preview::Diagnose
