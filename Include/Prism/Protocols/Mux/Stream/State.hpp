/**
 * @file State.hpp
 * @brief 多路复用会话的流接口与流状态
 * @details SessionIface 是模板会话与 StreamHandle 之间的窄类型擦除契约；
 *          StreamHandle 负责单条虚拟流的接收队列、FIN/RST/取消状态和读超时。
 *          帧编解码与会话帧循环由 Session.hpp 负责。
 */

#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/redirect_error.hpp>
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
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <system_error>
#include <utility>

#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Memory/Container.hpp>
#include <Prism/Foundation/Memory/Pointer.hpp>
#include <Prism/Lifecycle/Task/Registry.hpp>

namespace Prism::Mux
{
    namespace Net = boost::asio;

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
            -> Net::awaitable<ProtocolEc> = 0;

        /**
         * @brief 发送 FIN（半关）
         * @param StreamId 流标识符
         */
        virtual auto SendFin(std::uint32_t StreamId) -> Net::awaitable<void> = 0;

        /**
         * @brief 发送 RST（重置流）
         * @param StreamId 流标识符
         */
        virtual auto SendRst(std::uint32_t StreamId) -> Net::awaitable<void> = 0;

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
        [[nodiscard]] virtual auto Executor() const -> Net::any_io_executor = 0;
        [[nodiscard]] virtual auto Tasks() const noexcept
            -> std::shared_ptr<Prism::Lifecycle::TaskRegistry> = 0;

        /**
         * @brief 流消费接收队列字节后的预算归还
         * @param StreamId 流标识符
         * @param Bytes 已消费/释放的字节数
         * @details 会话据此维护会话级接收字节预算；实现必须幂等且不抛异常。
         */
        virtual void OnStreamRxConsumed(std::uint32_t StreamId, std::size_t Bytes) noexcept = 0;
    };

    /**
     * @class StreamHandle
     * @brief 虚拟流句柄
     * @tparam Memory 会话内存策略
     * @details Shutdown 只发送 FIN，Close 只关闭本地句柄，Reset 发送 RST；
     *          对端 FIN/RST 和本地 Cancel 都通过通知通道唤醒挂起读。
     */
    /** @brief 单条真实 wire stream 的标识、预算与任务父上下文。 */
    struct StreamOptions final
    {
        std::uint32_t Id;
        std::size_t MaxRxBytes{0};
        Prism::Lifecycle::TaskContext Context;
    };

    template <Prism::Memory::Restrict Memory = Prism::Memory::SessionResource<>>
    class StreamHandle final
        : public std::enable_shared_from_this<StreamHandle<Memory>>
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
        StreamHandle(StreamOptions Options, std::shared_ptr<SessionIface> Session)
            : Id_(Options.Id), RequestContext_(Options.Context), Session_(std::move(Session)),
              Ex_(Session_->Executor()),
              Notify_(Ex_, 1), Timer_(Ex_), MaxRxBytes_(Options.MaxRxBytes)
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
         * @return 实际读取字节数；0 表示终态、关闭、超时或取消，非 EOF 终态由 PeerFailure() 保留。
         */
        auto ReadSome(std::span<std::uint8_t> Buffer) -> Net::awaitable<std::size_t>
        {
            co_await Net::dispatch(Ex_, Net::use_awaitable);
            using Net::experimental::awaitable_operators::operator||;

            if (Buffer.empty())
            {
                if (CancelPending_)
                {
                    CancelPending_ = false;
                    ReadCanceled_ = true;
                }
                co_return 0;
            }

            ReadCanceled_ = false;
            while (true)
            {
                if (Closed_ || Canceled_)
                {
                    ReadCanceled_ = Canceled_ && !Closed_;
                    Canceled_ = false;
                    CancelPending_ = false;
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
                    CancelPending_ = false;
                    ReleaseRx(N);
                    co_return N;
                }
                if (PeerEof_ || PeerFailure_)
                {
                    co_return 0;
                }
                if (CancelPending_)
                {
                    CancelPending_ = false;
                    ReadCanceled_ = true;
                    co_return 0;
                }

                Notify_.reset();
                bool TimedOut = false;
                {
                    ReadPending_ = true;
                    PendingRead PendingReadGuard{ReadPending_, Canceled_};
                    if (Timeout_.count() > 0)
                    {
                        Timer_.expires_after(Timeout_);
                        const auto Result = co_await (Notify_.async_receive(Net::use_awaitable) ||
                                                      Timer_.async_wait(Net::use_awaitable));
                        TimedOut = Result.index() == 1U;
                    }
                    else
                    {
                        co_await Notify_.async_receive(Net::use_awaitable);
                    }
                PendingReadGuard.Completed = true;
                }
                if (TimedOut)
                {
                    if (Canceled_)
                    {
                        continue;
                    }
                    co_return 0;
                }
            }
        }

        /**
         * @brief 写入数据并交给会话封装
         * @param Buffer 待写数据
         * @return 协议错误码
         */
        auto WriteAll(std::span<const std::uint8_t> Buffer)
            -> Net::awaitable<ProtocolEc>
        {
            co_await Net::dispatch(Ex_, Net::use_awaitable);
            if (Closed_ || FinSent_ || !Session_ || !Session_->IsOpen())
            {
                co_return make_error_code(Error::BrokenPipe);
            }
            co_return co_await Session_->PushData(Id_, Buffer);
        }

        /**
         * @brief 半关并发送 FIN
         */
        auto Shutdown() -> Net::awaitable<void>
        {
            co_await Net::dispatch(Ex_, Net::use_awaitable);
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
        auto Close() -> Net::awaitable<void>
        {
            co_await Net::dispatch(Ex_, Net::use_awaitable);
            CloseOnExecutor();
            co_return;
        }

        /** @brief 已在所属 executor 的最终关闭；无 wire I/O，取消唤醒读取并解除会话引用。 */
        auto CloseOnExecutor() -> void
        {
            Closed_ = true;
            DropRx();
            Notify_.try_send(boost::system::error_code{});
            auto Session = std::move(Session_);
            if (Session)
            {
                Session->RemoveStream(Id_);
            }
            NotifyClosed();
        }

        [[nodiscard]] auto Tasks() const noexcept -> std::shared_ptr<Prism::Lifecycle::TaskRegistry>
        { return Session_ ? Session_->Tasks() : nullptr; }

        /** @brief 按值返回 FIN/RST 任务的完整 parent 和 stream 身份。 */
        [[nodiscard]] auto RetirementContext() const noexcept
            -> Prism::Lifecycle::TaskContext
        { return RequestContext_; }

        /**
         * @brief 发送 RST 并从流表移除
         */
        auto Reset() -> Net::awaitable<void>
        {
            co_await Net::dispatch(Ex_, Net::use_awaitable);
            Closed_ = true;
            DropRx();
            Notify_.try_send(boost::system::error_code{});
            NotifyClosed();
            auto Session = std::move(Session_);
            if (Session)
            {
                co_await Session->SendRst(Id_);
                Session->RemoveStream(Id_);
            }
            co_return;
        }

        /**
         * @brief 在 owner executor 上请求取消一次挂起读
         * @details 公开入口可从任意调用者 executor 发起，但取消代数和挂起读状态只在
         *          流 owner executor 上变更；本地读取消与 peer FIN/RST 仍由同一状态机结算。
         */
        auto Cancel() -> void
        {
            auto Self = this->shared_from_this();
            Net::dispatch(Ex_, [Self]
            {
                ++Self->CancelGeneration_;
                if (!Self->ReadPending_) Self->CancelPending_ = true;
                else { Self->Canceled_ = true; Self->Notify_.try_send(boost::system::error_code{}); }
            });
        }

        /**
         * @brief 设置读超时
         * @param Timeout 超时时间（0 = 禁用）
         */
        auto SetTimeout(std::chrono::milliseconds Timeout) -> void
        {
            Timeout_ = Timeout;
        }

        /**
         * @brief 流是否打开
         * @return true = 未关闭且会话可用
         */
        [[nodiscard]] auto IsOpen() const -> bool
        {
            return !Closed_ && Session_ && Session_->IsOpen();
        }

        /**
         * @brief 获取执行器
         * @return 流执行器
         */
        [[nodiscard]] auto Executor() const -> Net::any_io_executor
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

        /** @brief 返回 FIN 以外的对端读取终态；不消费状态。 */
        [[nodiscard]] auto PeerFailure() const noexcept
            -> std::optional<Prism::Fault::Failure>
        {
            return PeerFailure_;
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
         * @brief 等待 Closed_ 状态的真实转换
         * @param Owner 按值持有流句柄，直到等待回执完成
         * @details 本地 Close/Reset 或对端 RST 会完成等待；对端 FIN 只代表半关闭。
         *          等待切换到流 executor；完成、取消和底层通知错误均返回精确结果。
         * @return Closed_ 已置位时成功；取消或通知失败时返回 Failure。
         * @note 这是状态转换回执，不替代 RST 写入、TaskRegistry drain 或根任务完成回执。
         */
        [[nodiscard]] static auto WaitUntilClosed(std::shared_ptr<StreamHandle<Memory>> Owner)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            if (!Owner)
            {
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
            }
            co_await Net::this_coro::throw_if_cancelled(false);
            co_await Net::dispatch(Owner->Ex_, Net::use_awaitable);
            if (Owner->Closed_)
            {
                co_return std::expected<void, Prism::Fault::Failure>{};
            }
            const auto Cancellation = co_await Net::this_coro::cancellation_state;
            if (!!Cancellation.cancelled())
            {
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::Canceled});
            }
            if (!Owner->CloseNotify_)
            {
                Owner->CloseNotify_ = std::make_shared<Net::steady_timer>(Owner->Ex_);
                Owner->CloseNotify_->expires_at((Net::steady_timer::time_point::max)());
            }
            const auto Notification = Owner->CloseNotify_;
            boost::system::error_code Error;
            co_await Notification->async_wait(Net::redirect_error(Net::use_awaitable, Error));
            if (Owner->Closed_)
            {
                co_return std::expected<void, Prism::Fault::Failure>{};
            }
            const auto WaitCancellation = co_await Net::this_coro::cancellation_state;
            if (!!WaitCancellation.cancelled())
            {
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::Canceled});
            }
            if (Error)
            {
                co_return std::unexpected(
                    Prism::Fault::FromNative(static_cast<std::error_code>(Error)));
            }
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::IoError});
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
        [[nodiscard]] auto PushRx(std::span<const std::uint8_t> Data) -> bool
        {
            if (Closed_)
            {
                return true; // 本地已经移除流时由会话层决定如何处理未知帧
            }
            if (PeerEof_ || PeerFailure_)
            {
                return false; // 对端读取终态后的数据违反终止顺序
            }
            if (MaxRxBytes_ != 0 && Data.size() > MaxRxBytes_ - std::min(RxBytes_, MaxRxBytes_))
            {
                return false; // 超过每流接收预算
            }
            Rx_.emplace_back(Data.begin(), Data.end(), Mem_.Arena());
            RxBytes_ += Data.size();
            Notify_.try_send(boost::system::error_code{});
            return true;
        }

        /**
         * @brief 标记对端 FIN 并唤醒挂起读
         */
        auto SetPeerEof() -> void
        {
            if (PeerFailure_) return;
            PeerEof_ = true;
            Notify_.try_send(boost::system::error_code{});
        }

        /** @brief 广播非 EOF 的会话读取终态，保留领域码与原生 cause。 */
        auto SetPeerFailure(const Prism::Fault::Failure Failure) -> void
        {
            if (PeerEof_ || PeerFailure_ || Failure.Succeeded()) return;
            if (Failure.Code == Prism::Fault::Code::Eof)
            {
                SetPeerEof();
                return;
            }
            PeerFailure_ = Failure;
            Notify_.try_send(boost::system::error_code{});
        }

        /**
         * @brief 标记对端 RST 并唤醒挂起读
         */
        auto OnRst() -> void
        {
            Closed_ = true;
            DropRx();
            Notify_.try_send(boost::system::error_code{});
            Session_.reset();
            CancelPending_ = false;
            NotifyClosed();
        }

        /**
         * @brief 当前接收队列中尚未被消费的字节数
         */
        [[nodiscard]] auto QueuedRxBytes() const noexcept -> std::size_t
        {
            return RxBytes_;
        }

        /** @brief 会话退休时解除反向 owner；由会话流表在所属 executor 调用。 */
        auto DetachSession() noexcept -> void
        {
            Session_.reset();
        }

    private:
        friend struct StreamHandleReadPendingTestAccess;
        friend class StreamTransmission;

        struct PendingRead final
        {
            bool &Pending, &Canceled; bool Completed{false};
            ~PendingRead() { Pending = false; if (!Completed) Canceled = false; }
        };

        /** @brief 读取适配器消费本次零字节 read 是否由本地取消触发。 */
        auto ConsumeReadCancellation() noexcept -> bool
        {
            return std::exchange(ReadCanceled_, false);
        }

        /**
         * @brief 归还已消费字节给会话预算
         */
        auto ReleaseRx(std::size_t Bytes) -> void
        {
            const auto Released = std::min(RxBytes_, Bytes);
            if (Released == 0)
            {
                return;
            }
            RxBytes_ -= Released;
            if (Session_)
            {
                Session_->OnStreamRxConsumed(Id_, Released);
            }
        }

        /** @brief 广播关闭状态给正在等待的接收者。 */
        auto NotifyClosed() -> void
        {
            if (CloseNotify_)
            {
                (void)CloseNotify_->cancel();
            }
        }

        /** @brief 丢弃全部接收队列并归还预算（关流/RST 路径）。 */
        auto DropRx() -> void
        {
            Rx_.clear();
            ReleaseRx(RxBytes_);
        }

        std::uint32_t Id_;                                                            ///< 流标识符
        Prism::Lifecycle::TaskContext RequestContext_; ///< FIN/RST 任务的完整上下文
        std::shared_ptr<SessionIface> Session_;                                      ///< 所属会话
        Net::any_io_executor Ex_;                                                    ///< 执行器
        Memory Mem_;                                                                  ///< 会话内存策略
        std::deque<typename Memory::template Buffer<std::uint8_t>> Rx_;              ///< 接收队列
        Net::experimental::channel<void(boost::system::error_code)> Notify_; ///< 数据通知
        Net::steady_timer Timer_;                                                    ///< 读超时定时器
        std::shared_ptr<Net::steady_timer> CloseNotify_;                            ///< 懒创建的关闭状态广播
        std::chrono::milliseconds Timeout_{0};                                       ///< 读超时
        bool PeerEof_{false};                                                        ///< 对端 FIN
        std::optional<Prism::Fault::Failure> PeerFailure_; ///< 对端非 EOF 读取终态
        bool Closed_{false}; ///< 本地关闭或对端 RST
        bool FinSent_{false};                                                        ///< 本端 FIN
        bool Canceled_{false};                                                       ///< 一次性取消
        bool CancelPending_{false}; ///< 没有挂起读时保留下一次空读的取消
        bool ReadCanceled_{false}; ///< 最近一次读取因本地取消返回零字节
        bool ReadPending_{false}; ///< 当前唯一 reader 正在等待数据/终态/超时
        std::uint64_t CancelGeneration_{0}; ///< 在 handle executor 上已观察的取消命令代数
        std::size_t MaxRxBytes_{0}; ///< 每流接收预算（0 = 不限）
        std::size_t RxBytes_{0};                                                      ///< 接收队列当前字节数
    };

} // namespace Prism::Mux
