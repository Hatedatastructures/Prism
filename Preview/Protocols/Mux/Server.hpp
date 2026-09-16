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

#include <Preview/Foundation/Error.hpp>
#include <Preview/Foundation/Memory/Container.hpp>
#include <Preview/Foundation/Memory/Pointer.hpp>
#include <Preview/Transport/Transmission.hpp>

#include <Preview/Protocols/Mux/Session.hpp>
#include <Preview/Protocols/Mux/Stream.hpp>

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
         * @param Raw 底层传输（所有权移交）
         * @param Options 会话选项（Role 强制服务端）
         * @return 是否成功
         */
        auto Accept(SharedTransmission Raw, const SessionOptions &Options = {}) -> bool
        {
            if (!Raw)
            {
                return false;
            }
            if (Session_)
            {
                auto PreviousSession = std::move(Session_);
                Net::co_spawn(
                    PreviousSession->Executor(),
                    [PreviousSession]() -> Net::awaitable<void>
                    {
                        co_await PreviousSession->Close();
                    },
                    Net::detached);
            }
            auto OptionsValue = Options;
            OptionsValue.Role = Preview::Role::Server;
            Session_ = SessionType::Create(std::move(Raw), OptionsValue);
            return Session_ != nullptr;
        }

        /**
         * @brief 接受新流（阻塞直到新流到达或会话关闭）
         * @return 包装后的流传输；nullptr = 会话关闭
         */
        auto AcceptStream() -> Net::awaitable<SharedTransmission>
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
            Net::co_spawn(
                Session->Executor(),
                [Session]() -> Net::awaitable<void> { co_await Session->Close(); },
                Net::detached);
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
     * @param Upstream 上游传输（所有权移交）
     * @param Options 会话选项
     * @return 服务端会话容器
     */
    template <typename C,
              Preview::Memory::Restrict Memory = Preview::Memory::SessionResource<>>
    [[nodiscard]] inline auto Accept(
        SharedTransmission Upstream,
        const SessionOptions &Options = {}) -> Server<C, Memory>
    {
        Server<C, Memory> ServerValue;
        ServerValue.Accept(std::move(Upstream), Options);
        return ServerValue;
    }

} // namespace Preview::Mux
