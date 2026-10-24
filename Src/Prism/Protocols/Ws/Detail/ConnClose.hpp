/**
 * @file ConnClose.hpp
 * @brief WebSocket 连接关闭、取消和底层所有权 owner。
 * @details ConnClose 统一执行最终底层关闭，区分取消挂起操作与关闭连接，
 *          并在 Release 时转移底层 Transmission 的共享所有权。
 * @note 实例非线程安全，应在同一协程或线程内使用。
 */
#pragma once

#include <utility>

#include <Prism/Transport/Transmission.hpp>

#include <Prism/Protocols/Ws/Detail/ConnSession.hpp>

namespace Prism::Ws::Detail
{

    /**
     * @class ConnClose
     * @brief WebSocket 连接关闭 owner。
     * @tparam Memory 会话内存策略。
     */
    template <Prism::Memory::Restrict Memory>
    class ConnClose final
    {
    public:
        explicit ConnClose(
            ConnSession<Memory> &Session,
            Prism::Transmission &Owner)
            : Session_(Session), Owner_(Owner)
        {
        }

        ConnClose(const ConnClose &) = delete;
        auto operator=(const ConnClose &) -> ConnClose & = delete;

        auto Reset() noexcept -> void
        {
            CloseSent_ = false;
        }

        [[nodiscard]] auto CloseSent() const noexcept -> bool
        {
            return CloseSent_;
        }

        auto MarkCloseSent() noexcept -> void
        {
            CloseSent_ = true;
        }

        /**
         * @brief 记录协议已收口但不触发底层关闭。
         * @details 用于底层 EOF 或已报告的读取错误，保留错误码来源。
         */
        auto MarkClosed() noexcept -> void
        {
            Session_.MarkClosed(false);
        }

        /**
         * @brief 终止连接、清除握手状态并请求关闭 owner。
         * @details 原样返回底层控制结果；成功只表示关闭命令已接管。
         */
        [[nodiscard]] auto Terminate()
            -> Prism::Transmission::ControlResult
        {
            Session_.CloseFrameWriter();
            Session_.MarkClosed(true);
            return Owner_.Close();
        }

        /** @brief 关闭连接并清除握手状态；返回下游命令结果，成功只表示命令已接管。 */
        [[nodiscard]] auto Close() -> Prism::Transmission::ControlResult
        {
            Session_.CloseFrameWriter();
            Session_.MarkClosed(true);
            if (auto Upstream = Session_.Underlying()) return Upstream->Close();
            return {};
        }

        /**
         * @brief 只取消底层挂起操作，保留连接状态。
         */
        [[nodiscard]] auto Cancel() -> Prism::Transmission::ControlResult
        {
            if (auto Upstream = Session_.Underlying())
            {
                return Upstream->Cancel();
            }
            return {};
        }

        /** @brief 真实写半关闭转交底层载体；读取方向保持可用。 */
        auto WriteShutdown(Prism::Transmission::Completion Handler) -> void
        {
            if (auto Upstream = Session_.Underlying())
            {
                Upstream->WriteShutdown(std::move(Handler));
                return;
            }
            Prism::Transmission::PostResult(Session_.Executor(), std::move(Handler), Prism::IoResult{0, {Prism::Fault::Code::IoError}});
        }

        [[nodiscard]] auto NextLayer() noexcept -> Prism::Transmission *
        {
            return Session_.NextLayer();
        }

        [[nodiscard]] auto NextLayer() const noexcept
            -> const Prism::Transmission *
        {
            return Session_.NextLayer();
        }

        [[nodiscard]] auto Release() -> SharedTransmission
        {
            return Session_.Release();
        }

        [[nodiscard]] auto IsValid() const noexcept -> bool
        {
            return Session_.HasUpstream() && Session_.IsHandshaken();
        }

    private:
        ConnSession<Memory> &Session_;
        Prism::Transmission &Owner_;
        bool CloseSent_{false};
    };

} // namespace Prism::Ws::Detail
