/**
 * @file server.hpp
 * @brief 多路复用服务端会话容器（共享模板）
 * @details 服务端视角的多路复用会话：绑定底层传输并启动帧循环，
 * accept_stream() 阻塞产出新流（包装为 stream_transmission 供上层
 * 协议挂载）。流 ID 按服务端偶数分配（对齐协议规范）。
 * 三族（smux/yamux/h2mux）通过 codec 类型实例化：
 *   using server = mux::server<codec>;
 * @note 与 client.hpp 配对使用（服务端/客户端分离设计）
 */

#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <cstddef>
#include <memory>
#include <utility>

#include <common/core/error.hpp>
#include <common/core/memory/container.hpp>
#include <common/core/memory/pointer.hpp>
#include <common/core/transmission.hpp>
#include <common/core/transport/legacy_bridge.hpp>
#include <common/mux/session.hpp>
#include <common/mux/stream.hpp>

namespace psmtest::mux
{

    /**
     * @class server
     * @brief 多路复用服务端会话容器
     * @tparam C 帧编解码策略（frame_codec concept）
     * @tparam Memory 会话内存策略（默认 8KB arena；下发给会话引擎）
     * @details 持有 session<C, Memory> 引擎，服务端角色（偶数流 ID）。
     */
    template <typename C, psmtest::memory::memory_policy Memory = psmtest::memory::session_memory<>>
    class server
    {
    public:
        /// 会话类型
        using session_type = session<C, Memory>;

        /// 内存策略类型（对外暴露，供嵌套层/测试使用）
        using memory_type = Memory;

        /**
         * @brief 绑定底层传输并启动会话
         * @param raw 底层传输（所有权移交）
         * @param opt 会话选项（role 强制服务端）
         * @return 是否成功
         */
        auto accept(shared_transmission raw, const session_options &opt = {}) -> bool
        {
            if (!raw)
            {
                return false;
            }
            auto o = opt;
            o.role = psmtest::role::server;
            session_ = session_type::create(make_legacy(std::move(raw)), o);
            return session_ != nullptr;
        }

        /**
         * @brief 接受新流（阻塞直到新流到达或会话关闭）
         * @return 包装后的流传输；nullptr = 会话关闭
         */
        auto accept_stream() -> net::awaitable<shared_transmission>
        {
            if (!session_)
            {
                co_return nullptr;
            }
            auto handle = co_await session_->accept_stream();
            if (!handle)
            {
                co_return nullptr;
            }
            co_return std::make_shared<stream_transmission>(std::move(handle));
        }

        /**
         * @brief 关闭会话
         */
        auto close() -> void
        {
            if (session_)
            {
                session_->close();
            }
        }

        /**
         * @brief 会话是否打开
         * @return true = 会话可用
         */
        [[nodiscard]] auto is_open() const -> bool
        {
            return session_ && session_->is_open();
        }

        /**
         * @brief 当前会话
         * @return 会话容器（未连接时为空）
         */
        [[nodiscard]] auto session() const noexcept -> std::shared_ptr<session_type>
        {
            return session_;
        }

    private:
        std::shared_ptr<session_type> session_;
    };

    /// 多路复用服务端共享指针
    template <typename C, psmtest::memory::memory_policy Memory = psmtest::memory::session_memory<>>
    using shared_server = std::shared_ptr<server<C, Memory>>;

    /**
     * @brief 创建服务端会话并绑定底层传输（工厂）
     * @tparam C 帧编解码（frame_codec concept）
     * @tparam Memory 会话内存策略（默认 8KB arena）
     * @param upstream 上游传输（所有权移交）
     * @param opt 会话选项
     * @return 服务端会话容器
     */
    template <typename C, psmtest::memory::memory_policy Memory = psmtest::memory::session_memory<>>
    [[nodiscard]] inline auto accept(shared_transmission upstream, const session_options &opt = {})
        -> server<C, Memory>
    {
        server<C, Memory> s;
        s.accept(std::move(upstream), opt);
        return s;
    }

} // namespace psmtest::mux
