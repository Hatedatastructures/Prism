/**
 * @file InteropHysteria2ClientDiagnostics.hpp
 * @brief Hysteria2 客户端互操作阶段刷新与有界 watchdog。
 */

#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/error_code.hpp>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <memory>

#include <Prism/Protocols/Http3/NativeClient.hpp>

namespace Prism::Testing::Integration::Hysteria2::Interop::ClientDiagnostics
{
    /// @brief 返回进程内唯一阶段单元；只用于刷新诊断，不参与协议状态。
    [[nodiscard]] inline auto StageCell() -> std::atomic<const char *> &
    {
        static std::atomic<const char *> Cell{"startup"};
        return Cell;
    }

    /// @brief 立即刷新客户端阶段，区分认证、流/数据报、等待响应与最终 Drain。
    inline auto ReportStage(const char *Stage) -> void
    {
        StageCell().store(Stage, std::memory_order_release);
        std::fprintf(stderr, "STAGE: Hysteria2 client %s\n", Stage);
        std::fflush(stderr);
    }

    /** @brief watchdog 到期后关闭 session，并忽略清理异常。 */
    inline auto CloseOnDeadline(
        const std::shared_ptr<Prism::Http3::NativeClientSession> &Session) noexcept -> void
    {
        ReportStage("watchdog deadline");
        try { (void)Session->Close(); }
        catch (...) {}
    }

    /** @brief 等待 timer 到期；取消视为正常退出，到期则关闭 session。 */
    inline auto WaitForDeadline(
        const std::shared_ptr<boost::asio::steady_timer> &Timer,
        std::shared_ptr<Prism::Http3::NativeClientSession> Session)
        -> boost::asio::awaitable<void>
    {
        boost::system::error_code WaitError;
        co_await Timer->async_wait(
            boost::asio::redirect_error(boost::asio::use_awaitable, WaitError));
        if (WaitError) co_return;
        CloseOnDeadline(Session);
    }

    /// @brief 启动阶段 watchdog；到期后关闭 session，让挂起的原生操作返回并留下最后阶段。
    [[nodiscard]] inline auto StartSessionWatchdog(
        boost::asio::any_io_executor Executor,
        std::shared_ptr<Prism::Http3::NativeClientSession> Session,
        const std::chrono::seconds Limit) -> std::shared_ptr<boost::asio::steady_timer>
    {
        auto Timer = std::make_shared<boost::asio::steady_timer>(Executor);
        Timer->expires_after(Limit);
        boost::asio::co_spawn(Executor,
            WaitForDeadline(Timer, std::move(Session)),
            boost::asio::detached);
        return Timer;
    }
}
