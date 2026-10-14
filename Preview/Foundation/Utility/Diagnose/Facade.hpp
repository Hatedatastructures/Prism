/**
 * @file Facade.hpp
 * @brief Preview 业务唯一的诊断日志入口。
 */
#pragma once

#include <Preview/Foundation/Utility/Diagnose/ContextState.hpp>
#include <Preview/Foundation/Utility/Diagnose/Detail/SubmissionRequest.hpp>
#include <Preview/Foundation/Utility/Diagnose/Detail/SubmissionSlot.hpp>
#include <Preview/Foundation/Utility/Diagnose/RuntimeOptions.hpp>
#include <Preview/Foundation/Utility/Diagnose/SubmissionReceipt.hpp>

#include <atomic>
#include <cstdint>
#include <format>
#include <string>
#include <utility>

namespace Preview::Diagnose
{

    namespace Detail
    {

        /**
         * @brief 检查普通日志请求是否通过级别阈值。
         * @param Configured 当前配置的阈值。
         * @param Requested 本条记录的级别。
         * @return 级别策略允许该请求时返回 true。
         */
        [[nodiscard]] inline auto IsEnabled(const LogLevel Configured, const LogLevel Requested) noexcept
            -> bool
        {
            return IsLevelEnabled(Configured, Requested);
        }

        /**
         * @brief 查询普通日志级别是否会通过当前 facade 阈值。
         * @param Requested 本条记录的级别。
         * @return backend 已安装且普通级别可通过阈值时返回 true。
         * @note 可用于避免先计算昂贵的 Debug/Trace 参数；提交时仍会再次检查阈值。
         */
        [[nodiscard]] inline auto IsEnabled(const LogLevel Requested) noexcept -> bool
        {
            auto& Slot = GetSubmissionSlot();
            if ((Slot.Admission.load(std::memory_order_acquire) & SubmissionSlot::ClosedBit) != 0U)
            {
                return false;
            }
            if (Requested == LogLevel::Critical)
            {
                return true;
            }
            const auto Configured = static_cast<LogLevel>(Slot.Level.load(std::memory_order_acquire));
            return IsEnabled(Configured, Requested);
        }

        /** @brief 按该 generation context 固定阈值预检普通日志。 */
        [[nodiscard]] inline auto IsEnabled(const ContextState &Context,
            const LogLevel Requested) noexcept -> bool
        {
            if ((GetSubmissionSlot().Admission.load(std::memory_order_acquire) &
                    SubmissionSlot::ClosedBit) != 0U)
            {
                return false;
            }
            const auto Epoch = Context.RenderEpoch();
            if (!Epoch)
            {
                return IsEnabled(Requested);
            }
            return IsEnabled(Epoch->Value().Settings.Logging.Level, Requested);
        }

        /**
         * @brief 复制格式描述与参数快照并交给已安装的 backend。
         * @tparam Args 格式化实参的类型包；需与编译期检查的 Format 占位符匹配。
         * @param Request 本次提交的 typed level、kind、上下文借用和消息 owner；函数只在同步 callback 内借用 Context。
         * @param Format 编译期检查的 std::format 格式字符串。
         * @param Arguments 用于生成消息正文的格式化实参。
         * @return backend 返回的提交回执；未安装时为 Stopped，阈值过滤时为 Filtered，快照容量不足时为 Failed。
         * @details Audit 和 Critical 绕过普通级别阈值。提交线程只复制固定快照，格式化发生在 backend worker；回执 Accepted 只表示 backend 接受了异步请求。
         *          不等待队列、不执行同步 sink fallback；取消由 backend owner 的卸载/关闭流程处理。
         */
        template <typename... Args>
        [[nodiscard]] auto SubmitFormatted(SubmissionRequest Request,
            const std::format_string<Args...> Format, Args&&... Arguments) noexcept -> SubmissionReceipt
        {
            auto& Slot = GetSubmissionSlot();
            auto Call = SubmissionCall::Try(Slot);
            if (!Call.Acquired())
            {
                if (Call.Closed()) { return {SubmissionStatus::Stopped, 0U}; }
                Slot.AdmissionFailures.fetch_add(1U, std::memory_order_relaxed);
                return {SubmissionStatus::Dropped, 0U, {Preview::Fault::Code::ResourceUnavailable}};
            }
            const auto Submit = Slot.Submit.load(std::memory_order_relaxed);
            auto* Owner = Slot.Owner.load(std::memory_order_relaxed);
            auto Configured = static_cast<LogLevel>(Slot.Level.load(std::memory_order_acquire));
            if (Request.Context)
            {
                const auto Epoch = Request.Context->RenderEpoch();
                if (Epoch)
                {
                    Configured = Epoch->Value().Settings.Logging.Level;
                }
            }
            if (!IsEnabled(Configured, Request.Level) && Request.Kind != SubmissionKind::Audit &&
                Request.Level != LogLevel::Critical)
            {
                return {SubmissionStatus::Filtered, 0U};
            }

            const MessageInput<Args...> Input{Format, std::tie(Arguments...)};
            Request.Input = &Input;
            Request.Capture = &CaptureMessage<Args...>;
            const auto Receipt = Submit(Owner, Request);
            if (Receipt.Status == SubmissionStatus::Failed &&
                (Receipt.Failure.Code == Preview::Fault::Code::OversizedMsg ||
                    Receipt.Failure.Code == Preview::Fault::Code::InvalidArgument))
            {
                Slot.FormatFailures.fetch_add(1U, std::memory_order_relaxed);
            }
            return Receipt;
        }

    } // namespace Detail

    /** @brief 为独立载体/连接在创建时捕获已安装 Diagnose epoch。 */
    [[nodiscard]] inline auto CaptureCurrentContext() noexcept -> ContextState
    {
        return Detail::CaptureCurrentContext();
    }

    /**
     * @brief 查询指定级别是否会通过当前已安装 backend 的阈值。
     * @param Requested 普通日志请求级别。
     * @return backend 已安装且该普通级别可通过阈值时返回 true。
     * @note 用于避免预先计算昂贵日志实参；提交时仍会再次检查状态和阈值。
     */
    [[nodiscard]] inline auto IsEnabled(const LogLevel Requested) noexcept -> bool
    {
        return Detail::IsEnabled(Requested);
    }

    /**
     * @brief 按当前上下文固定的代次阈值检查普通日志请求。
     * @param Context 本次同步借用的上下文；内部读取其已固定的配置代次。
     * @param Requested 本条普通日志的级别。
     * @return 已关闭的backend返回false，否则采用该代阈值；没有代次时采用当前facade阈值。
     * @note 不分配、不等待、不取得关闭权；执行者是调用线程，实际提交仍重新检查入队状态。
     */
    [[nodiscard]] inline auto IsContextEnabled(
        const ContextState &Context, const LogLevel Requested) noexcept -> bool
    {
        return Detail::IsEnabled(Context, Requested);
    }

    /**
     * @brief 使用指定上下文提交 Trace 级别诊断记录。
     * @tparam Args 格式化实参类型包。
     * @param Context 要附带到记录中的字段上下文。
     * @param Format 编译期检查的 std::format 格式字符串。
     * @param Arguments 与格式占位符对应的格式化实参。
     * @return 本次提交的结果；Accepted 只表示 backend 接收了请求。
     */
    template <typename... Args>
    [[nodiscard]] auto Trace(const ContextState& Context, const std::format_string<Args...> Format,
        Args&&... Arguments) noexcept -> SubmissionReceipt
    {
        return Detail::SubmitFormatted(
            Detail::SubmissionRequest{LogLevel::Trace, &Context, {}, SubmissionKind::Ordinary},
            Format, std::forward<Args>(Arguments)...);
    }

    /**
     * @brief 使用空上下文提交 Trace 级别诊断记录。
     * @tparam Args 格式化实参类型包。
     * @param Format 编译期检查的 std::format 格式字符串。
     * @param Arguments 与格式占位符对应的格式化实参。
     * @return 本次提交的结果；Accepted 只表示 backend 接收了请求。
     */
    template <typename... Args>
    [[nodiscard]] auto Trace(const std::format_string<Args...> Format, Args&&... Arguments) noexcept
        -> SubmissionReceipt
    {
        const auto Context = ContextState::Empty();
        return Trace(Context, Format, std::forward<Args>(Arguments)...);
    }

    /**
     * @brief 使用指定上下文提交 Debug 级别普通日志。
     * @tparam Args 格式化实参类型包。
     * @param Context 要附带到记录中的字段上下文。
     * @param Format 编译期检查的 std::format 格式字符串。
     * @param Arguments 与格式占位符对应的格式化实参。
     * @return 本次提交的结果；Accepted 表示 backend 接收了请求，不代表 sink 已落盘。
     */
    template <typename... Args>
    [[nodiscard]] auto Debug(const ContextState& Context, const std::format_string<Args...> Format,
        Args&&... Arguments) noexcept -> SubmissionReceipt
    {
        return Detail::SubmitFormatted(
            Detail::SubmissionRequest{LogLevel::Debug, &Context, {}, SubmissionKind::Ordinary},
            Format, std::forward<Args>(Arguments)...);
    }

    /**
     * @brief 使用空上下文提交 Debug 级别普通日志。
     * @tparam Args 格式化实参类型包。
     * @param Format 编译期检查的 std::format 格式字符串。
     * @param Arguments 与格式占位符对应的格式化实参。
     * @return 本次提交的结果；Accepted 只表示 backend 接收了请求。
     */
    template <typename... Args>
    [[nodiscard]] auto Debug(const std::format_string<Args...> Format, Args&&... Arguments) noexcept
        -> SubmissionReceipt
    {
        const auto Context = ContextState::Empty();
        return Debug(Context, Format, std::forward<Args>(Arguments)...);
    }

    /**
     * @brief 使用指定上下文提交 Info 级别普通日志。
     * @tparam Args 格式化实参类型包。
     * @param Context 要附带到记录中的字段上下文。
     * @param Format 编译期检查的 std::format 格式字符串。
     * @param Arguments 与格式占位符对应的格式化实参。
     * @return 本次提交的结果；Accepted 表示 backend 接收了请求，不代表 sink 已落盘。
     */
    template <typename... Args>
    [[nodiscard]] auto Info(const ContextState& Context, const std::format_string<Args...> Format,
        Args&&... Arguments) noexcept -> SubmissionReceipt
    {
        return Detail::SubmitFormatted(
            Detail::SubmissionRequest{LogLevel::Info, &Context, {}, SubmissionKind::Ordinary},
            Format, std::forward<Args>(Arguments)...);
    }

    /**
     * @brief 使用空上下文提交 Info 级别普通日志。
     * @tparam Args 格式化实参类型包。
     * @param Format 编译期检查的 std::format 格式字符串。
     * @param Arguments 与格式占位符对应的格式化实参。
     * @return 本次提交的结果；Accepted 只表示 backend 接收了请求。
     */
    template <typename... Args>
    [[nodiscard]] auto Info(const std::format_string<Args...> Format, Args&&... Arguments) noexcept
        -> SubmissionReceipt
    {
        const auto Context = ContextState::Empty();
        return Info(Context, Format, std::forward<Args>(Arguments)...);
    }

    /**
     * @brief 使用指定上下文提交 Access 级别普通记录。
     * @tparam Args 格式化实参类型包。
     * @param Context 要附带到记录中的字段上下文。
     * @param Format 编译期检查的 std::format 格式字符串。
     * @param Arguments 与格式占位符对应的格式化实参。
     * @return 本次提交的结果；Access 是否通过筛选由 IsLevelEnabled 的专用规则决定。
     */
    template <typename... Args>
    [[nodiscard]] auto Access(const ContextState& Context, const std::format_string<Args...> Format,
        Args&&... Arguments) noexcept -> SubmissionReceipt
    {
        return Detail::SubmitFormatted(
            Detail::SubmissionRequest{LogLevel::Access, &Context, {}, SubmissionKind::Ordinary},
            Format, std::forward<Args>(Arguments)...);
    }

    /**
     * @brief 使用空上下文提交 Access 级别普通记录。
     * @tparam Args 格式化实参类型包。
     * @param Format 编译期检查的 std::format 格式字符串。
     * @param Arguments 与格式占位符对应的格式化实参。
     * @return 本次提交的结果；Accepted 只表示 backend 接收了请求。
     */
    template <typename... Args>
    [[nodiscard]] auto Access(const std::format_string<Args...> Format, Args&&... Arguments) noexcept
        -> SubmissionReceipt
    {
        const auto Context = ContextState::Empty();
        return Access(Context, Format, std::forward<Args>(Arguments)...);
    }

    /**
     * @brief 使用指定上下文提交 Warn 级别普通日志。
     * @tparam Args 格式化实参类型包。
     * @param Context 要附带到记录中的字段上下文。
     * @param Format 编译期检查的 std::format 格式字符串。
     * @param Arguments 与格式占位符对应的格式化实参。
     * @return 本次提交的结果；Accepted 表示 backend 接收了请求，不代表 sink 已落盘。
     */
    template <typename... Args>
    [[nodiscard]] auto Warn(const ContextState& Context, const std::format_string<Args...> Format,
        Args&&... Arguments) noexcept -> SubmissionReceipt
    {
        return Detail::SubmitFormatted(
            Detail::SubmissionRequest{LogLevel::Warn, &Context, {}, SubmissionKind::Ordinary},
            Format, std::forward<Args>(Arguments)...);
    }

    /**
     * @brief 使用空上下文提交 Warn 级别普通日志。
     * @tparam Args 格式化实参类型包。
     * @param Format 编译期检查的 std::format 格式字符串。
     * @param Arguments 与格式占位符对应的格式化实参。
     * @return 本次提交的结果；Accepted 只表示 backend 接收了请求。
     */
    template <typename... Args>
    [[nodiscard]] auto Warn(const std::format_string<Args...> Format, Args&&... Arguments) noexcept
        -> SubmissionReceipt
    {
        const auto Context = ContextState::Empty();
        return Warn(Context, Format, std::forward<Args>(Arguments)...);
    }

    /**
     * @brief 使用指定上下文提交 Error 级别普通日志。
     * @tparam Args 格式化实参类型包。
     * @param Context 要附带到记录中的字段上下文。
     * @param Format 编译期检查的 std::format 格式字符串。
     * @param Arguments 与格式占位符对应的格式化实参。
     * @return 本次提交的结果；Accepted 表示 backend 接收了请求，不代表 sink 已落盘。
     */
    template <typename... Args>
    [[nodiscard]] auto Error(const ContextState& Context, const std::format_string<Args...> Format,
        Args&&... Arguments) noexcept -> SubmissionReceipt
    {
        return Detail::SubmitFormatted(
            Detail::SubmissionRequest{LogLevel::Error, &Context, {}, SubmissionKind::Ordinary},
            Format, std::forward<Args>(Arguments)...);
    }

    /**
     * @brief 使用空上下文提交 Error 级别普通日志。
     * @tparam Args 格式化实参类型包。
     * @param Format 编译期检查的 std::format 格式字符串。
     * @param Arguments 与格式占位符对应的格式化实参。
     * @return 本次提交的结果；Accepted 只表示 backend 接收了请求。
     */
    template <typename... Args>
    [[nodiscard]] auto Error(const std::format_string<Args...> Format, Args&&... Arguments) noexcept
        -> SubmissionReceipt
    {
        const auto Context = ContextState::Empty();
        return Error(Context, Format, std::forward<Args>(Arguments)...);
    }

    /**
     * @brief 使用指定上下文提交 Critical 级别普通日志。
     * @details Critical 绕过普通级别阈值。
     * @tparam Args 格式化实参类型包。
     * @param Context 要附带到记录中的字段上下文。
     * @param Format 编译期检查的 std::format 格式字符串。
     * @param Arguments 与格式占位符对应的格式化实参。
     * @return 本次提交的结果；Accepted 表示 backend 接收了请求，不代表 sink 已落盘。
     */
    template <typename... Args>
    [[nodiscard]] auto Critical(const ContextState& Context, const std::format_string<Args...> Format,
        Args&&... Arguments) noexcept -> SubmissionReceipt
    {
        return Detail::SubmitFormatted(
            Detail::SubmissionRequest{LogLevel::Critical, &Context, {}, SubmissionKind::Ordinary},
            Format, std::forward<Args>(Arguments)...);
    }

    /**
     * @brief 使用空上下文提交 Critical 级别普通日志。
     * @details Critical 绕过普通级别阈值。
     * @tparam Args 格式化实参类型包。
     * @param Format 编译期检查的 std::format 格式字符串。
     * @param Arguments 与格式占位符对应的格式化实参。
     * @return 本次提交的结果；Accepted 只表示 backend 接收了请求。
     */
    template <typename... Args>
    [[nodiscard]] auto Critical(const std::format_string<Args...> Format, Args&&... Arguments) noexcept
        -> SubmissionReceipt
    {
        const auto Context = ContextState::Empty();
        return Critical(Context, Format, std::forward<Args>(Arguments)...);
    }

    /**
     * @brief 使用指定上下文提交终态 Audit 记录。
     * @details Audit 使用 Access 级别，并绕过普通级别阈值。
     * @tparam Args 格式化实参类型包。
     * @param Context 要附带到记录中的字段上下文。
     * @param Format 编译期检查的 std::format 格式字符串。
     * @param Arguments 与格式占位符对应的格式化实参。
     * @return 本次提交的结果；Accepted 表示 backend 接收了请求，不代表 sink 已落盘。
     */
    template <typename... Args>
    [[nodiscard]] auto Audit(const ContextState& Context, const std::format_string<Args...> Format,
        Args&&... Arguments) noexcept -> SubmissionReceipt
    {
        return Detail::SubmitFormatted(
            Detail::SubmissionRequest{LogLevel::Access, &Context, {}, SubmissionKind::Audit},
            Format, std::forward<Args>(Arguments)...);
    }

    /**
     * @brief 使用空上下文提交终态 Audit 记录。
     * @details Audit 使用 Access 级别，并绕过普通级别阈值。
     * @tparam Args 格式化实参类型包。
     * @param Format 编译期检查的 std::format 格式字符串。
     * @param Arguments 与格式占位符对应的格式化实参。
     * @return 本次提交的结果；Accepted 只表示 backend 接收了请求。
     */
    template <typename... Args>
    [[nodiscard]] auto Audit(const std::format_string<Args...> Format, Args&&... Arguments) noexcept
        -> SubmissionReceipt
    {
        const auto Context = ContextState::Empty();
        return Audit(Context, Format, std::forward<Args>(Arguments)...);
    }

} // namespace Preview::Diagnose
