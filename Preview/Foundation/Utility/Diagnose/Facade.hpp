/**
 * @file Facade.hpp
 * @brief Preview 业务唯一的诊断日志入口。
 */
#pragma once

#include <atomic>
#include <cstdint>
#include <format>
#include <string>
#include <utility>

#include <Preview/Foundation/Utility/Diagnose/ContextState.hpp>
#include <Preview/Foundation/Utility/Diagnose/Detail/SubmissionRequest.hpp>
#include <Preview/Foundation/Utility/Diagnose/RuntimeOptions.hpp>
#include <Preview/Foundation/Utility/Diagnose/SubmissionReceipt.hpp>

namespace Preview::Diagnose
{

    namespace Detail
    {

        /** @brief facade 调用的 backend 提交回调类型。 */
        using SubmissionFunction = SubmissionReceipt (*)(void *, const Detail::SubmissionRequest &) noexcept;

        /**
         * @brief 进程内共享的 facade 提交槽位。
         * @details 原子发布 backend owner、回调和级别阈值，并记录正在执行的调用数，供卸载时等待。
         */
        struct SubmissionSlot final
        {
            std::atomic<void *> Owner{nullptr}; ///< 当前 backend owner 的不透明指针。
            std::atomic<SubmissionFunction> Submit{nullptr}; ///< 指向 owner 的提交回调；空值表示不可提交。
            std::atomic<std::uint8_t> Level{static_cast<std::uint8_t>(LogLevel::Info)}; ///< 当前过滤阈值。
            std::atomic<std::uint32_t> ActiveCalls{0U}; ///< 已进入回调区且尚未退出的 facade 调用数。
            std::atomic<std::uint64_t> FormatFailures{0U}; ///< 格式化或请求构造失败的累计次数。
        };

        /**
         * @brief 获取进程内唯一的 facade 提交槽位。
         * @return 函数静态存储期的共享槽位引用。
         */
        inline auto GetSubmissionSlot() noexcept -> SubmissionSlot &
        {
            static SubmissionSlot Slot{};
            return Slot;
        }

        /** @brief 返回当前进程内 facade 捕获到的格式化异常次数。 */
        [[nodiscard]] inline auto FormatFailures() noexcept -> std::uint64_t
        {
            return GetSubmissionSlot().FormatFailures.load(std::memory_order_relaxed);
        }

        /**
         * @brief 安装或更新 facade 使用的 backend 提交入口。
         * @param Owner backend owner；不得为空，且须在所有活动调用结束前保持有效。
         * @param Submit owner 的提交回调；不得为空。
         * @param Level 普通日志的过滤阈值。
         * @return 槽位空闲或已属于同一 owner 且安装成功时返回 true；其他 owner 已安装时返回 false。
         */
        [[nodiscard]] inline auto InstallSubmissionBackend(void *Owner, const SubmissionFunction Submit,
                                                           const LogLevel Level) noexcept -> bool
        {
            if (Owner == nullptr || Submit == nullptr)
            {
                return false;
            }
            auto &Slot = GetSubmissionSlot();
            auto *Current = Slot.Owner.load(std::memory_order_acquire);
            if (Current == Owner)
            {
                Slot.Level.store(static_cast<std::uint8_t>(Level), std::memory_order_release);
                Slot.Submit.store(Submit, std::memory_order_release);
                return true;
            }
            if (Current != nullptr ||
                !Slot.Owner.compare_exchange_strong(Current, Owner, std::memory_order_acq_rel,
                                                    std::memory_order_acquire))
            {
                return false;
            }
            Slot.Level.store(static_cast<std::uint8_t>(Level), std::memory_order_release);
            Slot.Submit.store(Submit, std::memory_order_release);
            return true;
        }

        /**
         * @brief 释放一次正在进行的 facade 调用计数。
         * @param Slot 持有活动调用计数的共享提交槽位。
         * @details 计数降为零时通知只允许在运行循环外执行的 backend 最终回收操作。
         */
        inline auto ReleaseSubmissionCall(SubmissionSlot &Slot) noexcept -> void
        {
            if (Slot.ActiveCalls.fetch_sub(1U, std::memory_order_acq_rel) == 1U)
            {
                Slot.ActiveCalls.notify_all();
            }
        }

        /**
         * @brief 立即禁止指定 owner 的新 facade 提交。
         * @param Owner 要停止接收的 backend owner；与当前 owner 不匹配时返回 false。
         * @return 槽位仍由该 owner 持有且已关闭提交入口时返回 true。
         * @details 不等待已经进入的调用，可以在协程中调用；owner 指针保留到最终回收完成。
         */
        [[nodiscard]] inline auto DisableSubmissionBackend(void *Owner) noexcept -> bool
        {
            auto &Slot = GetSubmissionSlot();
            if (Slot.Owner.load(std::memory_order_acquire) != Owner)
            {
                return false;
            }
            Slot.Submit.store(nullptr, std::memory_order_release);
            return true;
        }

        /**
         * @brief 最终移除指定 owner 并等待已进入的 facade 调用退出。
         * @param Owner 要卸载的 backend owner；与当前 owner 不匹配时不执行操作。
         * @details 只能在 Asio 运行循环退出后调用；此处等待用于保证 owner 销毁前不再有回调使用它。
         */
        inline auto RemoveSubmissionBackend(void *Owner) noexcept -> void
        {
            auto &Slot = GetSubmissionSlot();
            if (!DisableSubmissionBackend(Owner))
            {
                return;
            }
            for (auto Active = Slot.ActiveCalls.load(std::memory_order_acquire); Active != 0U;
                 Active = Slot.ActiveCalls.load(std::memory_order_acquire))
            {
                Slot.ActiveCalls.wait(Active, std::memory_order_acquire);
            }
            Slot.Owner.store(nullptr, std::memory_order_release);
        }

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
         * @brief 同步格式化消息并将提交请求交给已安装的 backend。
         * @tparam Args 格式化实参的类型包；需与编译期检查的 Format 占位符匹配。
         * @param Level 本条记录的日志级别。
         * @param Kind 普通观测或终态审计提交类型。
         * @param Context 本条记录使用的上下文；只在本次提交期间借用。
         * @param Format 编译期检查的 std::format 格式字符串。
         * @param Arguments 用于生成消息正文的格式化实参。
         * @return backend 返回的提交回执；未安装时为 Stopped，阈值过滤时为 Filtered，格式化异常时为 Failed。
         * @details Audit 和 Critical 绕过普通级别阈值。格式化发生在调用线程；回执 Accepted 只表示 backend 接受了异步请求。
         */
        template <typename... Args>
        [[nodiscard]] auto SubmitFormatted(const LogLevel Level, const SubmissionKind Kind,
                                           const ContextState &Context,
                                           const std::format_string<Args...> Format,
                                           Args &&...Arguments) noexcept -> SubmissionReceipt
        {
            auto &Slot = GetSubmissionSlot();
            const auto Submit = Slot.Submit.load(std::memory_order_acquire);
            if (Submit == nullptr)
            {
                return {SubmissionStatus::Stopped, 0U};
            }
            const auto Configured = static_cast<LogLevel>(Slot.Level.load(std::memory_order_acquire));
            if (!IsEnabled(Configured, Level) && Kind != SubmissionKind::Audit && Level != LogLevel::Critical)
            {
                return {SubmissionStatus::Filtered, 0U};
            }

            Slot.ActiveCalls.fetch_add(1U, std::memory_order_acq_rel);
            auto *Owner = Slot.Owner.load(std::memory_order_acquire);
            if (Owner == nullptr || Slot.Submit.load(std::memory_order_acquire) != Submit)
            {
                ReleaseSubmissionCall(Slot);
                return {SubmissionStatus::Stopped, 0U};
            }

            try
            {
                auto Message = std::format(Format, std::forward<Args>(Arguments)...);
                Detail::SubmissionRequest Request{Level, &Context, std::move(Message), Kind};
                auto Receipt = Submit(Owner, Request);
                ReleaseSubmissionCall(Slot);
                return Receipt;
            }
            catch (...)
            {
                Slot.FormatFailures.fetch_add(1U, std::memory_order_relaxed);
                ReleaseSubmissionCall(Slot);
                return {SubmissionStatus::Failed, 0U};
            }
        }

    } // namespace Detail

    /**
     * @brief 使用指定上下文提交 Debug 级别普通日志。
     * @tparam Args 格式化实参类型包。
     * @param Context 要附带到记录中的字段上下文。
     * @param Format 编译期检查的 std::format 格式字符串。
     * @param Arguments 与格式占位符对应的格式化实参。
     * @return 本次提交的结果；Accepted 表示 backend 接收了请求，不代表 sink 已落盘。
     */
    template <typename... Args>
    [[nodiscard]] auto Debug(const ContextState &Context, const std::format_string<Args...> Format,
                             Args &&...Arguments) noexcept -> SubmissionReceipt
    {
        return Detail::SubmitFormatted(LogLevel::Debug, SubmissionKind::Ordinary, Context, Format,
                                       std::forward<Args>(Arguments)...);
    }

    /**
     * @brief 使用空上下文提交 Debug 级别普通日志。
     * @tparam Args 格式化实参类型包。
     * @param Format 编译期检查的 std::format 格式字符串。
     * @param Arguments 与格式占位符对应的格式化实参。
     * @return 本次提交的结果；Accepted 只表示 backend 接收了请求。
     */
    template <typename... Args>
    [[nodiscard]] auto Debug(const std::format_string<Args...> Format, Args &&...Arguments) noexcept
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
    [[nodiscard]] auto Info(const ContextState &Context, const std::format_string<Args...> Format,
                            Args &&...Arguments) noexcept -> SubmissionReceipt
    {
        return Detail::SubmitFormatted(LogLevel::Info, SubmissionKind::Ordinary, Context, Format,
                                       std::forward<Args>(Arguments)...);
    }

    /**
     * @brief 使用空上下文提交 Info 级别普通日志。
     * @tparam Args 格式化实参类型包。
     * @param Format 编译期检查的 std::format 格式字符串。
     * @param Arguments 与格式占位符对应的格式化实参。
     * @return 本次提交的结果；Accepted 只表示 backend 接收了请求。
     */
    template <typename... Args>
    [[nodiscard]] auto Info(const std::format_string<Args...> Format, Args &&...Arguments) noexcept
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
    [[nodiscard]] auto Access(const ContextState &Context, const std::format_string<Args...> Format,
                              Args &&...Arguments) noexcept -> SubmissionReceipt
    {
        return Detail::SubmitFormatted(LogLevel::Access, SubmissionKind::Ordinary, Context, Format,
                                       std::forward<Args>(Arguments)...);
    }

    /**
     * @brief 使用空上下文提交 Access 级别普通记录。
     * @tparam Args 格式化实参类型包。
     * @param Format 编译期检查的 std::format 格式字符串。
     * @param Arguments 与格式占位符对应的格式化实参。
     * @return 本次提交的结果；Accepted 只表示 backend 接收了请求。
     */
    template <typename... Args>
    [[nodiscard]] auto Access(const std::format_string<Args...> Format, Args &&...Arguments) noexcept
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
    [[nodiscard]] auto Warn(const ContextState &Context, const std::format_string<Args...> Format,
                            Args &&...Arguments) noexcept -> SubmissionReceipt
    {
        return Detail::SubmitFormatted(LogLevel::Warn, SubmissionKind::Ordinary, Context, Format,
                                       std::forward<Args>(Arguments)...);
    }

    /**
     * @brief 使用空上下文提交 Warn 级别普通日志。
     * @tparam Args 格式化实参类型包。
     * @param Format 编译期检查的 std::format 格式字符串。
     * @param Arguments 与格式占位符对应的格式化实参。
     * @return 本次提交的结果；Accepted 只表示 backend 接收了请求。
     */
    template <typename... Args>
    [[nodiscard]] auto Warn(const std::format_string<Args...> Format, Args &&...Arguments) noexcept
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
    [[nodiscard]] auto Error(const ContextState &Context, const std::format_string<Args...> Format,
                             Args &&...Arguments) noexcept -> SubmissionReceipt
    {
        return Detail::SubmitFormatted(LogLevel::Error, SubmissionKind::Ordinary, Context, Format,
                                       std::forward<Args>(Arguments)...);
    }

    /**
     * @brief 使用空上下文提交 Error 级别普通日志。
     * @tparam Args 格式化实参类型包。
     * @param Format 编译期检查的 std::format 格式字符串。
     * @param Arguments 与格式占位符对应的格式化实参。
     * @return 本次提交的结果；Accepted 只表示 backend 接收了请求。
     */
    template <typename... Args>
    [[nodiscard]] auto Error(const std::format_string<Args...> Format, Args &&...Arguments) noexcept
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
    [[nodiscard]] auto Critical(const ContextState &Context, const std::format_string<Args...> Format,
                                Args &&...Arguments) noexcept -> SubmissionReceipt
    {
        return Detail::SubmitFormatted(LogLevel::Critical, SubmissionKind::Ordinary, Context, Format,
                                       std::forward<Args>(Arguments)...);
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
    [[nodiscard]] auto Critical(const std::format_string<Args...> Format, Args &&...Arguments) noexcept
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
    [[nodiscard]] auto Audit(const ContextState &Context, const std::format_string<Args...> Format,
                             Args &&...Arguments) noexcept -> SubmissionReceipt
    {
        return Detail::SubmitFormatted(LogLevel::Access, SubmissionKind::Audit, Context, Format,
                                       std::forward<Args>(Arguments)...);
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
    [[nodiscard]] auto Audit(const std::format_string<Args...> Format, Args &&...Arguments) noexcept
        -> SubmissionReceipt
    {
        const auto Context = ContextState::Empty();
        return Audit(Context, Format, std::forward<Args>(Arguments)...);
    }

} // namespace Preview::Diagnose
