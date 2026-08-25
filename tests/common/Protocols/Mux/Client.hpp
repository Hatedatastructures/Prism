/**
 * @file Client.hpp
 * @brief 多路复用客户端会话容器（共享模板）
 * @details 客户端视角的多路复用会话：绑定底层传输并启动帧循环，
 * OpenStream() 主动打开新流（包装为 StreamTransmission 供上层
 * 协议挂载）。流 ID 按客户端奇数分配（对齐协议规范）。
 * 三族（smux/yamux/h2mux）通过 Codec 类型实例化：
 *   using Client = Mux::Client<Codec>;
 * @note 与 Server.hpp 配对使用（服务端/客户端分离设计）
 */

#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <cstddef>
#include <memory>
#include <utility>

#include <common/Core/Error.hpp>
#include <common/Core/Memory/Container.hpp>
#include <common/Core/Memory/Pointer.hpp>
#include <common/Core/Transmission.hpp>

#include <common/Protocols/Mux/Session.hpp>
#include <common/Protocols/Mux/Stream.hpp>

namespace Preview::Mux
{

    /**
     * @class Client
     * @brief 多路复用客户端会话容器
     * @tparam C 帧编解码策略（FrameCodec concept）
     * @tparam Memory 会话内存策略（默认 8KB Arena；下发给会话引擎）
     * @details 持有 Session<C, Memory> 引擎，客户端角色（奇数流 ID）。
     */
    template <typename C, Preview::Memory::Restrict Memory = Preview::Memory::SessionResource<>>
    class Client
    {
    public:
        /// 会话类型
        using SessionType = Session<C, Memory>;

        /// 内存策略类型（对外暴露，供嵌套层/测试使用）
        using MemoryType = Memory;

        /**
         * @brief 绑定底层传输并启动会话
         * @param raw 底层传输（所有权移交）
         * @param opt 会话选项（Role 强制客户端）
         * @return 是否成功
         */
        auto Connect(SharedTransmission raw, const SessionOptions &opt = {}) -> bool
        {
            if (!raw)
            {
                return false;
            }
            auto o = opt;
            o.Role = Preview::Role::Client;
            session_ = SessionType::Create(std::move(raw), o);
            return session_ != nullptr;
        }

        /**
         * @brief 打开新流（客户端视角）
         * @return 包装后的流传输；nullptr = 会话关闭
         */
        auto OpenStream() -> net::awaitable<SharedTransmission>
        {
            if (!session_)
            {
                co_return nullptr;
            }
            auto Handle = co_await session_->OpenStream();
            if (!Handle)
            {
                co_return nullptr;
            }
            co_return std::make_shared<StreamTransmission>(std::move(Handle));
        }

        /**
         * @brief 关闭会话
         */
        auto Close() -> void
        {
            if (session_)
            {
                session_->Close();
            }
        }

        /**
         * @brief 会话是否打开
         * @return true = 会话可用
         */
        [[nodiscard]] auto IsOpen() const -> bool
        {
            return session_ && session_->IsOpen();
        }

        /**
         * @brief 当前会话
         * @return 会话容器（未连接时为空）
         */
        [[nodiscard]] auto Session() const noexcept -> std::shared_ptr<SessionType>
        {
            return session_;
        }

    private:
        std::shared_ptr<SessionType> session_;
    };

    /// 多路复用客户端共享指针
    template <typename C, Preview::Memory::Restrict Memory = Preview::Memory::SessionResource<>>
    using SharedClient = std::shared_ptr<Client<C, Memory>>;

    /**
     * @brief 创建客户端会话并绑定底层传输（工厂）
     * @tparam C 帧编解码（FrameCodec concept）
     * @tparam Memory 会话内存策略（默认 8KB Arena）
     * @param upstream 上游传输（所有权移交）
     * @param opt 会话选项
     * @return 客户端会话容器
     */
    template <typename C, Preview::Memory::Restrict Memory = Preview::Memory::SessionResource<>>
    [[nodiscard]] inline auto Connect(SharedTransmission upstream, const SessionOptions &opt = {})
        -> Client<C, Memory>
    {
        Client<C, Memory> c;
        c.Connect(std::move(upstream), opt);
        return c;
    }

} // namespace Preview::Mux
