/**
 * @file server.hpp
 * @brief yamux 服务端封装（对象，包装传输）
 * @details 借鉴 Boost.Beast 服务端模式：accept() 绑定会话，
 *          accept_stream() 接收对端虚拟流。
 */

#pragma once

#include <common/core/protocol_base.hpp>
#include <common/core/transport/transport_base.hpp>
#include <common/mux/yamux/session.hpp>

#include <memory>

namespace psmtest::mux::yamux
{

    /// yamux 服务端
    class server
    {
    public:
        /// @brief 构造
        /// @param opt 会话选项
        explicit server(const session_options &opt = {})
            : opt_(opt)
        {
        }

        /// 不可拷贝
        server(const server &) = delete;
        auto operator=(const server &) -> server & = delete;

        /// @brief 接收会话（绑定底层传输）
        /// @param raw 底层传输（所有权移交）
        /// @return 会话；nullptr = 创建失败
        auto accept(std::shared_ptr<transport_base> raw) -> std::shared_ptr<session>
        {
            if (!raw || !raw->is_open())
                return nullptr;
            session_ = session::create(std::move(raw), opt_);
            return session_;
        }

        /// @brief 接受虚拟流（阻塞直到新流到达）
        /// @return 流句柄；nullptr = 会话关闭
        auto accept_stream() -> net::awaitable<std::shared_ptr<stream_handle>>
        {
            if (!session_)
                co_return nullptr;
            co_return co_await session_->accept_stream();
        }

        /// 当前会话
        [[nodiscard]] auto current() const -> std::shared_ptr<session>
        {
            return session_;
        }

        /// 关闭会话
        auto close() -> net::awaitable<void>
        {
            if (session_)
                co_await session_->close();
            co_return;
        }

    private:
        session_options opt_;
        std::shared_ptr<session> session_;
    };

} // namespace psmtest::mux::yamux
