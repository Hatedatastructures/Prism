/**
 * @file Server.hpp
 * @brief 多路复用服务端会话容器（共享模板）
 * @details 服务端视角的多路复用会话：绑定底层传输并启动帧循环，
 * AcceptStream() 阻塞产出新流（包装为 StreamTransmission 供上层
 * 协议挂载）。流 ID 按服务端偶数分配（对齐协议规范）。
 * 三族（smux/yamux/h2mux）通过 Codec 类型实例化：
 *   using Server = Mux::Server<Codec>;
 * @note 与 Client.hpp 配对使用（服务端/客户端分离设计）
 */

#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>

#include <cstddef>
#include <memory>
#include <utility>

#include <preview/Foundation/Error.hpp>
#include <preview/Foundation/Memory/Container.hpp>
#include <preview/Foundation/Memory/Pointer.hpp>
#include <preview/Transport/Transmission.hpp>

#include <preview/Protocols/Mux/Session.hpp>
#include <preview/Protocols/Mux/Stream.hpp>

namespace Preview::Mux
{

    /**
     * @class Server
     * @brief 多路复用服务端会话容器
     * @tparam C 帧编解码策略（FrameCodec concept）
     * @tparam Memory 会话内存策略（默认 8KB Arena；下发给会话引擎）
     * @details 持有 Session<C, Memory> 引擎，服务端角色（偶数流 ID）。
     */
    template <typename C, Preview::Memory::Restrict Memory = Preview::Memory::SessionResource<>>
    class Server
    {
    public:
        /// 会话类型
        using SessionType = Session<C, Memory>;

        /// 内存策略类型（对外暴露，供嵌套层/测试使用）
        using MemoryType = Memory;

        /**
         * @brief 绑定底层传输并启动会话
         * @param raw 底层传输（所有权移交）
         * @param opt 会话选项（Role 强制服务端）
         * @return 是否成功
         */
        auto Accept(SharedTransmission raw, const SessionOptions &opt = {}) -> bool
        {
            if (!raw)
            {
                return false;
            }
            auto O = opt;
            O.Role = Preview::Role::Server;
            Session_ = SessionType::Create(std::move(raw), O);
            return Session_ != nullptr;
        }

        /**
         * @brief 接受新流（阻塞直到新流到达或会话关闭）
         * @return 包装后的流传输；nullptr = 会话关闭
         */
        auto AcceptStream() -> net::awaitable<SharedTransmission>
        {
            if (!Session_)
            {
                co_return nullptr;
            }
            auto Handle = co_await Session_->AcceptStream();
            if (!Handle)
            {
                co_return nullptr;
            }
            co_return std::make_shared<StreamTransmission>(std::move(Handle));
        }

        /**
         * @brief 关闭会话
         * @details Session::Close() 是惰性协程，经 co_spawn 投递到
         * 会话执行器上执行；lambda 按值捕获会话保证存活。
         */
        auto Close() -> void
        {
            auto Session = Session_;
            if (!Session)
            {
                return;
            }
            net::co_spawn(
                Session->Executor(), [Session]() -> net::awaitable<void> { co_await Session->Close(); },
                net::detached);
        }

        /**
         * @brief 会话是否打开
         * @return true = 会话可用
         */
        [[nodiscard]] auto IsOpen() const -> bool
        {
            return Session_ && Session_->IsOpen();
        }

        /**
         * @brief 当前会话
         * @return 会话容器（未连接时为空）
         */
        [[nodiscard]] auto Session() const noexcept -> std::shared_ptr<SessionType>
        {
            return Session_;
        }

    private:
        std::shared_ptr<SessionType> Session_;
    };

    /// 多路复用服务端共享指针
    template <typename C, Preview::Memory::Restrict Memory = Preview::Memory::SessionResource<>>
    using SharedServer = std::shared_ptr<Server<C, Memory>>;

    /**
     * @brief 创建服务端会话并绑定底层传输（工厂）
     * @tparam C 帧编解码（FrameCodec concept）
     * @tparam Memory 会话内存策略（默认 8KB Arena）
     * @param upstream 上游传输（所有权移交）
     * @param opt 会话选项
     * @return 服务端会话容器
     */
    template <typename C, Preview::Memory::Restrict Memory = Preview::Memory::SessionResource<>>
    [[nodiscard]] inline auto Accept(SharedTransmission upstream, const SessionOptions &opt = {})
        -> Server<C, Memory>
    {
        Server<C, Memory> s;
        s.Accept(std::move(upstream), opt);
        return s;
    }

} // namespace Preview::Mux
