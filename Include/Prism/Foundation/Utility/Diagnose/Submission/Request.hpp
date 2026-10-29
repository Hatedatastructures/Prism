/** @file Request.hpp
 * @brief facade 到 backend 的同步借用请求；快照在提交返回前完成。
 */
#pragma once
#include <Prism/Foundation/Utility/Diagnose/ContextState.hpp>
#include <Prism/Foundation/Utility/Diagnose/Submission/Message.hpp>
#include <Prism/Foundation/Utility/Diagnose/RuntimeOptions.hpp>
#include <Prism/Foundation/Utility/Diagnose/SubmissionReceipt.hpp>
#include <format>
#include <tuple>
#include <string_view>

namespace Prism::Diagnose::Detail
{
    /** @brief 编译期格式参数的同步借用入口，不越过 callback 返回点。 */
    template <typename... Args>
    struct MessageInput final
    {
        std::format_string<Args...> Format;
        std::tuple<Args&...> Values;
    };
    template <typename... Args>
    [[nodiscard]] auto CaptureMessage(DeferredMessage& Output, const void* Input,
        const FormattingLimits& Limits) noexcept -> Prism::Fault::Failure
    {
        const auto& Value = *static_cast<const MessageInput<Args...>*>(Input);
        return Output.template Capture<Args...>(Value.Format, Value.Values, Limits);
    }
    /** @brief 类型化元数据与消息捕获操作；全部输入只同步借用。 */
    struct SubmissionRequest final
    {
        LogLevel Level{LogLevel::Info};
        const ContextState* Context{nullptr};
        std::string_view Message{};
        SubmissionKind Kind{SubmissionKind::Ordinary};
        const void* Input{nullptr};
        Prism::Fault::Failure (*Capture)(DeferredMessage&, const void*, const FormattingLimits&) noexcept {nullptr};
        Prism::Diagnose::RenderEpochPin Epoch{};
    };
}
