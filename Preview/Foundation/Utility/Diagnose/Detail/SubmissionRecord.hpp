/**
 * @file SubmissionRecord.hpp
 * @brief 入队前拥有全部文本和上下文值的日志记录。
 */
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <Preview/Foundation/Utility/Diagnose/FieldKey.hpp>
#include <Preview/Foundation/Utility/Diagnose/PrefixCache.hpp>
#include <Preview/Foundation/Utility/Diagnose/RenderMode.hpp>
#include <Preview/Foundation/Utility/Diagnose/RuntimeOptions.hpp>
#include <Preview/Foundation/Utility/Diagnose/SubmissionReceipt.hpp>

namespace Preview::Diagnose::Detail
{

    /**
     * @brief 可安全传入异步 backend 的拥有型字段值。
     * @details Text 不借用 ContextState 或调用方内存；CapturedField 可随记录一起进入异步队列。
     */
    struct CapturedField final
    {
        FieldId Id{};                                  ///< 字段目录中的稳定 ID。
        FieldValueKind Kind{FieldValueKind::Unsigned}; ///< 字段值编码种类。
        std::uint64_t Unsigned{0U};                    ///< 数值型字段值。
        bool Boolean{false};                           ///< 布尔型字段值。
        std::string Text{};                            ///< 已拥有的有界文本值。
        bool Truncated{false};                         ///< 文本是否发生截断。
    };

    /**
     * @brief 一条记录在入队前捕获的渲染上下文。
     * @details Prefix 和 Fields 均为值或拥有型字段，不依赖原始 ContextState 的生命周期。
     */
    struct CapturedContext final
    {
        RenderMode Mode{RenderMode::CompactHuman}; ///< 本条记录的渲染模式。
        PrefixCache Prefix{};                      ///< 已缓存的 W/S 前缀。
        std::vector<CapturedField> Fields{};       ///< 扩展模式下选中的拥有型字段。
    };

    /**
     * @brief 含有消息和完整上下文快照的 backend 记录。
     * @details 传给异步 logger 前，消息和文本字段均已拥有存储；Structured 模式还捕获提交时间和线程 ID。
     */
    struct SubmissionRecord final
    {
        LogLevel Level{LogLevel::Info};                ///< 记录级别。
        std::uint64_t Sequence{0U};                    ///< backend 分配的提交序号。
        std::uint64_t TimestampMilliseconds{0U};       ///< Structured 模式的 Unix 毫秒时间戳。
        std::uint32_t ThreadId{0U};                    ///< Structured 模式记录的提交线程 ID。
        SubmissionKind Kind{SubmissionKind::Ordinary}; ///< 普通记录或可靠审计记录。
        std::string Message{};                         ///< 已格式化并拥有的业务消息。
        CapturedContext Context{};                     ///< 提交前拥有的上下文快照。
    };

} // namespace Preview::Diagnose::Detail
