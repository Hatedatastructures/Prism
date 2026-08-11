/**
 * @file client.hpp
 * @brief yamux 客户端封装（对象，包装传输）
 * @details 借鉴 Boost.Beast 客户端模式：持有底层传输 + 会话，
 *          connect() 建立会话，open_stream() 创建虚拟流。
 */

#pragma once

#include <common/core/protocol_base.hpp>
#include <common/core/transport/transport_base.hpp>
#include <common/mux/yamux/session.hpp>

#include <memory>

namespace psmtest::mux::yamux
{

    /// yamux 客户端
    class client
    {
    public:
        /// @brief 构造
        /// @param opt 会话选项
        explicit client(const session_options &opt = {})
            : opt_(opt)
        {
        }

        /// 不可拷贝
        client(const client &) = delete;
        auto operator=(const client &) -> client & = delete;

        /// @brief 建立会话（绑定底层传输）
        /// @param raw 底层传输（所有权移交）
        /// @return 会话；nullptr = 创建失败
        auto connect(std::shared_ptr<transport_base> raw) -> std::shared_ptr<session>
        {
            if (!raw || !raw->is_open())
                return nullptr;
            session_ = session::create(std::move(raw), opt_);
            return session_;
        }

        /// @brief 打开虚拟流
        /// @return 流句柄；nullptr = 会话未建立/已关闭
        auto open_stream() -> net::awaitable<std::shared_ptr<stream_handle>>
        {
            if (!session_)
                co_return nullptr;
            co_return co_await session_->open_stream();
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
