/**
 * @file SubmissionReceipt.hpp
 * @brief Diagnose 自有提交结果。
 */
#pragma once

#include <cstdint>
#include <Preview/Foundation/Fault/Failure.hpp>

namespace Preview::Diagnose
{

    /**
     * @brief 表示日志提交或 backend 生命周期操作的结果。
     */
    enum class SubmissionStatus : std::uint8_t
    {
        Accepted,                // 记录已交给异步 backend；不代表普通 sink 已完成写入或 flush。
        Filtered,                // 普通记录因级别阈值未提交。
        Dropped,                 // 任一级别的记录因入队竞争或队列满而未能入队。
        Stopped,                 // backend 未安装，或已停止接收新提交。
        Failed,                  // 提交、后台 sink write 或 flush 失败；Failure 保留原因。
        TimedOut,                // 控制线程 drain barrier 未在截止时间前完成。
        Flushed,                 // barrier 已越过此前记录，sink write 与 flush 均完成；不承诺 fsync。
        Closed,                  // 后台 owner 已排空、flush、join 并关闭 sink。
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
     * @brief 不暴露 backend 类型的提交或生命周期值回执。
     * @details 普通提交在同步调用返回前借用输入并快照；后台队列随后拥有记录。
     *          Accepted 只代表已入队，Flushed 代表此前记录已写入并完成 sink flush，
     *          Closed 代表后台线程与 sink owner 已关闭。二者均不承诺 fsync。
     *          普通提交无逐条取消句柄；关闭 owner 封止新提交并排空已接受记录。
     */
    struct SubmissionReceipt final
    {
        SubmissionStatus Status{SubmissionStatus::Accepted}; ///< 记录接受、屏障 flush 或最终关闭的阶段结果。
        std::uint64_t Sequence{0U}; ///< Accepted 为入队序号；首次成功 Flushed/Closed 为写入末序号，其它情况为 0。
        Preview::Fault::Failure Failure{}; ///< 观察失败的稳定原因，与业务结果分离。

        /**
         * @brief 判断本次操作是否已被异步 backend 接收。
         * @return 仅普通记录成功进入异步队列时返回 true。
         * @note Flushed/Closed 是生命周期回执，不会被解释为普通记录再次 Accepted。
         */
        [[nodiscard]] auto Accepted() const noexcept -> bool
        {
            return Status == SubmissionStatus::Accepted;
        }
    };

} // namespace Preview::Diagnose
