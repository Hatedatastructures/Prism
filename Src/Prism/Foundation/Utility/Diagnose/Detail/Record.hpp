/**
 * @file Record.hpp
 * @brief 异步日志队列拥有的记录值与后台渲染入口。
 */
#pragma once

#include <Prism/Foundation/Utility/Diagnose/FieldKey.hpp>
#include <Prism/Foundation/Utility/Diagnose/PrefixCache.hpp>
#include <Prism/Foundation/Utility/Diagnose/RenderMode.hpp>
#include <Prism/Foundation/Utility/Diagnose/RuntimeOptions.hpp>
#include <Prism/Foundation/Utility/Diagnose/SubmissionReceipt.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace Prism::Diagnose::Detail
{
    /** @brief 可安全传入异步 backend 的拥有型字段值。 */
    struct CapturedField final
    {
        FieldId Id{};
        FieldValueKind Kind{FieldValueKind::Unsigned};
        std::uint64_t Unsigned{0U};
        bool Boolean{false};
        std::string Text{};
        bool Truncated{false};
    };

    /** @brief 一条记录在入队前捕获的拥有型渲染上下文。 */
    struct CapturedContext final
    {
        RenderMode Mode{RenderMode::CompactHuman};
        PrefixCache Prefix{};
        std::vector<CapturedField> Fields{};
    };

    /** @brief 消息和上下文均已取得独立存储的后台记录。 */
    struct SubmissionRecord final
    {
        LogLevel Level{LogLevel::Info};
        std::uint64_t Sequence{0U};
        std::uint64_t TimestampMilliseconds{0U};
        SubmissionKind Kind{SubmissionKind::Ordinary};
        std::string Message{};
        bool MessageTruncated{false};
        CapturedContext Context{};
    };

    [[nodiscard]] auto FormatHumanTimestamp(std::uint64_t Milliseconds) -> std::string;
    [[nodiscard]] auto BuildPayload(const SubmissionRecord& Record) -> std::string;
}
