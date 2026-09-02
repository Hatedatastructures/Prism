/**
 * @file StreamState.hpp
 * @brief 多路复用会话的流接口与流状态
 * @details SessionIface 是模板会话与 StreamHandle 之间的窄类型擦除契约；
 *          StreamHandle 负责单条虚拟流的接收队列、FIN/RST/取消状态和读超时。
 *          帧编解码与会话帧循环由 Session.hpp 负责。
 */

#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <memory>
#include <span>

#include <preview/Foundation/Error.hpp>
#include <preview/Foundation/Memory/Container.hpp>
#include <preview/Foundation/SessionBase.hpp>

namespace Preview::Mux
{

    /**
     * @class SessionIface
     * @brief 会话内部接口（供虚拟流回调，类型擦除）
     * @details 虚拟流句柄经本接口访问所属会话：推送数据、发送 FIN/RST、
     *          从流表移除自身。会话实现持有多态会话指针以解耦模板实例。
     */
    class SessionIface
    {
    public:
        virtual ~SessionIface() = default;

        /**
         * @brief 推送数据帧到流
         * @param StreamId 流标识符
         * @param Data 负载数据
         * @return 错误码
         */
        virtual auto PushData(std::uint32_t StreamId, std::span<const std::uint8_t> Data)
            -> net::awaitable<ProtocolEc> = 0;

        /**
         * @brief 发送 FIN（半关）
         * @param StreamId 流标识符
         */
        virtual auto SendFin(std::uint32_t StreamId) -> net::awaitable<void> = 0;

        /**
         * @brief 发送 RST（重置流）
         * @param StreamId 流标识符
         */
        virtual auto SendRst(std::uint32_t StreamId) -> net::awaitable<void> = 0;

        /**
         * @brief 流从表中移除
         * @param StreamId 流标识符
         */
        virtual auto RemoveStream(std::uint32_t StreamId) -> void = 0;

        /**
         * @brief 会话是否打开
         * @return true = 会话可用
         */
        [[nodiscard]] virtual auto IsOpen() const -> bool = 0;

        /**
         * @brief 获取执行器
         * @return 会话执行器
         */
        [[nodiscard]] virtual auto Executor() const -> net::any_io_executor = 0;
    };

    /**
     * @class StreamHandle
     * @brief 虚拟流句柄
     * @tparam Memory 会话内存策略
     * @details Shutdown 只发送 FIN，Close 只关闭本地句柄，Reset 发送 RST；
     *          对端 FIN/RST 和本地 Cancel 都通过通知通道唤醒挂起读。
     */
    template <Preview::Memory::Restrict Memory = Preview::Memory::SessionResource<>>
    class StreamHandle : public SessionBase
    {
    public:
        /// 内存策略类型（对外暴露，供嵌套层/测试使用）
        using MemoryType = Memory;

        /**
         * @brief 构造虚拟流
         * @param Id 流标识
         * @param Session 所属会话（共享所有权）
         * @param Executor 执行器
         */
        StreamHandle(std::uint32_t Id, std::shared_ptr<SessionIface> Session,
                     net::any_io_executor Executor)
            : Id_(Id), Session_(std::move(Session)), Ex_(std::move(Executor)),
              Notify_(Ex_, 1), Timer_(Ex_)
        {
        }

        /**
         * @brief 获取流标识
         * @return 流标识符
         */
        [[nodiscard]] auto Id() const noexcept -> std::uint32_t
        {
            return Id_;
        }

        /**
         * @brief 读取数据
         * @param Buffer 接收缓冲区
         * @return 实际读取字节数；0 = EOF/关闭/超时/取消
         */
        auto ReadSome(std::span<std::uint8_t> Buffer) -> net::awaitable<std::size_t> override
        {
            using namespace boost::asio::experimental::awaitable_operators;

            while (true)
            {
                if (Closed_ || Canceled_)
                {
                    Canceled_ = false;
                    co_return 0;
                }
                if (!Rx_.empty())
                {
                    const auto &Front = Rx_.front();
                    const auto N = std::min(Buffer.size(), Front.size());
                    std::memcpy(Buffer.data(), Front.data(), N);
                    if (N < Front.size())
                    {
                        Rx_.front().erase(Rx_.front().begin(),
                                          Rx_.front().begin() + static_cast<std::ptrdiff_t>(N));
                    }
                    else
                    {
                        Rx_.pop_front();
                    }
                    co_return N;
                }
                if (PeerEof_)
                {
                    co_return 0;
                }

                Notify_.reset();
                if (Timeout_.count() > 0)
                {
                    Timer_.expires_after(Timeout_);
                    auto Result = co_await (Notify_.async_receive(net::use_awaitable) ||
                                            Timer_.async_wait(net::use_awaitable));
                    if (Result.index() == 1)
                    {
                        co_return 0;
                    }
                }
                else
                {
                    co_await Notify_.async_receive(net::use_awaitable);
                }
            }
        }

        /**
         * @brief 写入数据并交给会话封装
         * @param Buffer 待写数据
         * @return 协议错误码
         */
        auto WriteAll(std::span<const std::uint8_t> Buffer) -> net::awaitable<ProtocolEc> override
        {
            if (Closed_ || !Session_ || !Session_->IsOpen())
            {
                co_return make_error_code(Error::BrokenPipe);
            }
            co_return co_await Session_->PushData(Id_, Buffer);
        }

        /**
         * @brief 半关并发送 FIN
         */
        auto Shutdown() -> net::awaitable<void> override
        {
            if (FinSent_)
            {
                co_return;
            }
            FinSent_ = true;
            if (Session_)
            {
                co_await Session_->SendFin(Id_);
            }
            co_return;
        }

        /**
         * @brief 本地关闭并从流表移除
         */
        auto Close() -> net::awaitable<void> override
        {
            Closed_ = true;
            Notify_.try_send(boost::system::error_code{});
            if (Session_)
            {
                Session_->RemoveStream(Id_);
            }
            co_return;
        }

        /**
         * @brief 发送 RST 并从流表移除
         */
        auto Reset() -> net::awaitable<void>
        {
            Closed_ = true;
            Notify_.try_send(boost::system::error_code{});
            if (Session_)
            {
                co_await Session_->SendRst(Id_);
                Session_->RemoveStream(Id_);
            }
            co_return;
        }

        /**
         * @brief 取消一次挂起读
         */
        auto Cancel() -> void override
        {
            Canceled_ = true;
            Notify_.try_send(boost::system::error_code{});
        }

        /**
         * @brief 设置读超时
         * @param Timeout 超时时间（0 = 禁用）
         */
        auto SetTimeout(std::chrono::milliseconds Timeout) -> void override
        {
            Timeout_ = Timeout;
        }

        /**
         * @brief 流是否打开
         * @return true = 未关闭且会话可用
         */
        [[nodiscard]] auto IsOpen() const -> bool override
        {
            return !Closed_ && Session_ && Session_->IsOpen();
        }

        /**
         * @brief 获取执行器
         * @return 流执行器
         */
        [[nodiscard]] auto Executor() const -> net::any_io_executor override
        {
            return Ex_;
        }

        /**
         * @brief 对端是否半关
         * @return true = 收到对端 FIN
         */
        [[nodiscard]] auto IsPeerEof() const -> bool
        {
            return PeerEof_;
        }

        /**
         * @brief 流是否已关闭
         * @return true = 本地关闭或对端 RST
         */
        [[nodiscard]] auto IsClosed() const -> bool
        {
            return Closed_;
        }

        /**
         * @brief 本端是否已发送 FIN
         * @return true = Shutdown 已调用
         */
        [[nodiscard]] auto IsFinSent() const -> bool
        {
            return FinSent_;
        }

        /**
         * @brief 推送数据到接收队列
         * @param Data 负载数据
         */
        auto PushRx(std::span<const std::uint8_t> Data) -> void
        {
            if (Closed_ || PeerEof_)
            {
                return;
            }
            Rx_.emplace_back(Data.begin(), Data.end(), Mem_.Arena());
            Notify_.try_send(boost::system::error_code{});
        }

        /**
         * @brief 标记对端 FIN 并唤醒挂起读
         */
        auto SetPeerEof() -> void
        {
            PeerEof_ = true;
            Notify_.try_send(boost::system::error_code{});
        }

        /**
         * @brief 标记对端 RST 并唤醒挂起读
         */
        auto OnRst() -> void
        {
            Closed_ = true;
            Notify_.try_send(boost::system::error_code{});
        }

    private:
        std::uint32_t Id_;                                                            ///< 流标识符
        std::shared_ptr<SessionIface> Session_;                                      ///< 所属会话
        net::any_io_executor Ex_;                                                    ///< 执行器
        Memory Mem_;                                                                  ///< 会话内存策略
        std::deque<typename Memory::template Buffer<std::uint8_t>> Rx_;              ///< 接收队列
        boost::asio::experimental::channel<void(boost::system::error_code)> Notify_; ///< 数据通知
        net::steady_timer Timer_;                                                    ///< 读超时定时器
        std::chrono::milliseconds Timeout_{0};                                       ///< 读超时
        bool PeerEof_{false};                                                        ///< 对端 FIN
        bool Closed_{false};                                                         ///< 本地关闭或对端 RST
        bool FinSent_{false};                                                        ///< 本端 FIN
        bool Canceled_{false};                                                       ///< 一次性取消
    };

} // namespace Preview::Mux
