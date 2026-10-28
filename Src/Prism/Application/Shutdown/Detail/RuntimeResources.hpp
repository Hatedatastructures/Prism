/**
 * @file RuntimeResources.hpp
 * @brief 应用停机后段的周期 timer 取消与已完成资源释放 owner。
 */
#pragma once

#include <Prism/Application/Startup/Detail/RuntimeState.hpp>
#include <Prism/Application/Shutdown/Detail/BoundedOperation.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>

#include <boost/asio/steady_timer.hpp>

#include <expected>
#include <exception>
#include <memory>
#include <utility>

namespace Prism::Application::Shutdown::Detail
{

    namespace Net = boost::asio;
    using ReleaseOutcome = std::expected<void, Prism::Fault::Failure>;

    /**
     * @brief 取消应用周期 timer 并保留原生取消失败。
     * @param Runtime 拥有控制 ContextOwner 与关闭 cause 的运行时。
     * @param Timer 由该 control executor 创建的应用周期 timer。
     * @return 取消成功返回 success；失败返回 Native cause 并发布 Fatal。
     */
    [[nodiscard]] inline auto CancelApplicationTimer(
        const std::shared_ptr<Prism::Application::Application::RuntimeState> &Runtime,
        Net::steady_timer &Timer) noexcept -> ReleaseOutcome
    {
        try
        {
            Timer.cancel();
            return {};
        }
        catch (...)
        {
            const auto ExceptionValue = std::current_exception();
            const auto Cause = ShutdownOperation::FailureFromException(ExceptionValue);
            const auto StoredCause = Runtime->RecordShutdownFailure(Cause);
            Runtime->ControlContext->Fatal->Publish(ExceptionValue);
            return std::unexpected(StoredCause);
        }
    }

    /**
     * @brief 在全部 producer drain 后取消周期 timer 并释放已完成的应用入口。
     * @param Runtime 正在停机且所有异步 owner 已完成 drain 的运行时。
     * @return 所有 timer 取消成功后返回 success；首个原生失败保留完整运行时。
     */
    [[nodiscard]] inline auto ReleaseRuntimeResources(
        const std::shared_ptr<Prism::Application::Application::RuntimeState> &Runtime)
        noexcept -> ReleaseOutcome
    {
        const auto DiagnoseCanceled = CancelApplicationTimer(Runtime, Runtime->DiagnoseFlushTimer);
        if (!DiagnoseCanceled)
        {
            return std::unexpected(DiagnoseCanceled.error());
        }
        const auto StatisticsCanceled = CancelApplicationTimer(Runtime, Runtime->StatisticsFlushTimer);
        if (!StatisticsCanceled)
        {
            return std::unexpected(StatisticsCanceled.error());
        }
        if (Runtime->Traffic)
        {
            Runtime->Traffic->Finish();
        }
        Runtime->ProviderBindings.reset();
        Runtime->QuicConnectionRegistry.reset();
        Runtime->DatagramListener.reset();
        Runtime->BoundaryDispatcher.reset();
        Runtime->QuicPacketGateway.reset();
        Runtime->DatagramClassifier.reset();
        Runtime->Listener.reset();
        Runtime->Tasks.reset();
        return {};
    }

    /**
     * @brief 在 root I/O 已退栈的应用控制线程 join 独立 Operations controller。
     * @param Runtime 持有管理 controller 与完整失败运行时的应用状态。
     * @return thread join 成功返回 success；Native join failure 保留 controller 与首因。
     * @note 只等待线程，不提前释放 controller；调用者通过所有关闭前置检查后才可 reset。
     */
    [[nodiscard]] inline auto JoinManagementController(
        const std::shared_ptr<Prism::Application::Application::RuntimeState> &Runtime)
        noexcept -> ReleaseOutcome
    {
        if (!Runtime->ManagementController)
        {
            return {};
        }
        try
        {
            const auto Joined = Runtime->ManagementController->Join();
            if (!Joined)
            {
                return std::unexpected(Runtime->RecordShutdownFailure(Joined.error()));
            }
            return {};
        }
        catch (...)
        {
            const auto ExceptionValue = std::current_exception();
            const auto Cause = ShutdownOperation::FailureFromException(ExceptionValue);
            const auto StoredCause = Runtime->RecordShutdownFailure(Cause);
            Runtime->ControlContext->Fatal->Publish(ExceptionValue);
            return std::unexpected(StoredCause);
        }
    }

} // namespace Prism::Application::Shutdown::Detail
