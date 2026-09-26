/**
 * @file SubmissionRequest.hpp
 * @brief Facade 传递给 backend owner 的内部值请求。
 */
#pragma once

#include <string>

#include <Preview/Foundation/Utility/Diagnose/ContextState.hpp>
#include <Preview/Foundation/Utility/Diagnose/RuntimeOptions.hpp>
#include <Preview/Foundation/Utility/Diagnose/SubmissionReceipt.hpp>

namespace Preview::Diagnose::Detail
{
    /**
     * @brief 从 facade 传给 backend 的一次提交请求。
     * @details Message 由请求拥有；Context 仅在同步提交回调期间借用，backend 必须在返回前捕获所需字段。
     */
    struct SubmissionRequest final
    {
        LogLevel Level{LogLevel::Info};                ///< 记录的级别。
        const ContextState *Context{nullptr};          ///< 调用方上下文的非拥有指针；不能为空才能提交。
        std::string Message{};                         ///< 已由 facade 格式化并拥有的消息正文。
        SubmissionKind Kind{SubmissionKind::Ordinary}; ///< 普通记录或终态 Audit 记录。
    };
} // namespace Preview::Diagnose::Detail
