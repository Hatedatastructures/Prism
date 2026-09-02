/**
 * @file Session.hpp
 * @brief 多路复用共享会话框架（模板注入帧编解码策略）
 * @details 借鉴 Boost.Beast 模板策略模式：流表管理、帧循环、队列、
 *          背压只实现一次，smux/yamux/h2mux 通过 FrameCodec 策略
 *          注入帧构造（Open/Data/fin/rst）与帧事件判定
 *          （Open/Data/fin/rst），实现"一套会话逻辑，三个协议"。
 *          会话拥有多条虚拟流（StreamHandle），每条流满足统一
 *          SessionBase 接口，供上层协议（vmess/vless/...）承载。
 *          底层传输经 Transmission 类型擦除，支持内存流/套接字流。
 * @note 帧策略需额外提供（concept 之外，经 if constexpr 检测）：
 *          - FrameEvent(Frame) / FrameStreamId(Frame)
 *          - IsControl(Frame)（会话级控制帧判定）
 */

#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <deque>
#include <map>
#include <memory>
#include <span>
#include <vector>

#include <preview/Foundation/ByteSpan.hpp>
#include <preview/Foundation/Utility/Diagnose/Log.hpp>
#include <preview/Foundation/Error.hpp>
#include <preview/Foundation/Memory/Container.hpp>
#include <preview/Foundation/Memory/Pointer.hpp>
#include <preview/Foundation/Role.hpp>
#include <preview/Foundation/SessionBase.hpp>
#include <preview/Transport/Transmission.hpp>
#include <preview/Transport/Stream.hpp>
#include <preview/Protocols/Mux/Codec.hpp>
#include <preview/Protocols/Mux/SessionReadLoop.hpp>
#include <preview/Protocols/Mux/StreamState.hpp>
#include <preview/Protocols/Mux/SessionWriteLoop.hpp>

namespace Preview::Mux
{

    /**
     * @struct SessionOptions
     * @brief 多路复用会话选项
     * @details 构造后只读，经 Session::Create 传入。
     */
    struct SessionOptions
    {
        /// 连接角色（决定流 ID 奇偶：Client 奇数 / Server 偶数）
        Preview::Role Role{Preview::Role::Client};
        /// 最大并发流数
        std::size_t MaxStreams{256};
        /// 读超时（0 = 禁用）
        std::chrono::milliseconds timeout{0};
    };

    /**
     * @class Session
     * @brief 多路复用会话（共享框架，模板注入帧编解码策略）
     * @tparam C 帧编解码策略（FrameCodec concept）
     * @tparam Memory 会话内存策略（默认 8KB Arena；下发给流句柄）
     * @details 维护流表与入向队列，后台帧循环读取底层传输并分发
     *          帧事件（Open/Data/fin/rst）。AcceptStream / OpenStream
     *          分别对应服务端/客户端开流视角；Cancel() 可唤醒挂起
     *          的 AcceptStream 而不关闭会话。
     */
    template <typename C, Preview::Memory::Restrict Memory = Preview::Memory::SessionResource<>>
    class Session : public SessionIface, public std::enable_shared_from_this<Session<C, Memory>>
    {
    public:
        using FrameType = typename C::FrameType;

        /// 内存策略类型（对外暴露，供嵌套层/测试使用）
        using MemoryType = Memory;

        /**
         * @brief 创建会话（同时启动帧循环）
         * @param raw 底层传输（类型擦除）
         * @param opt 会话选项
         * @return 会话实例
         */
        static auto Create(SharedTransmission raw, const SessionOptions &opt)
            -> std::shared_ptr<Session<C, Memory>>
        {
            auto Self = std::shared_ptr<Session<C, Memory>>(new Session<C, Memory>(std::move(raw), opt));
            Self->Start();
            return Self;
        }

        /**
         * @brief 打开新流（客户端视角）
         * @return 流句柄；nullptr = 会话已关闭 / 流数达上限
         * @details 分配流 ID（奇偶随角色）并发送开流帧。
         */
        auto OpenStream() -> net::awaitable<std::shared_ptr<StreamHandle<Memory>>>
        {
            if (!Raw_ || !Raw_->IsOpen())
            {
                co_return nullptr;
            }
            const auto Id = AllocateId();
            if (Id == 0)
            {
                co_return nullptr;
            }
            auto Handle = std::make_shared<StreamHandle<Memory>>(Id, this->shared_from_this(), Ex_);
            Streams_[Id] = Handle;
            if (co_await RawWrite(C::BuildOpen(Id)))
            {
                Streams_.erase(Id);
                co_return nullptr;
            }
            co_return Handle;
        }

        /**
         * @brief 接受新流（服务端视角，阻塞直到新流到达或会话关闭）
         * @return 流句柄；nullptr = 会话关闭 / Cancel() 唤醒
         * @details 经 Cancel() 唤醒后返回 nullptr（一次性，可再次调用）。
         */
        auto AcceptStream() -> net::awaitable<std::shared_ptr<StreamHandle<Memory>>>
        {
            while (Raw_ && Raw_->IsOpen())
            {
                if (Canceled_)
                {
                    Canceled_ = false;
                    co_return nullptr;
                }
                if (!Incoming_.empty())
                {
                    auto Handle = Incoming_.front();
                    Incoming_.pop_front();
                    co_return Handle;
                }
                if (SessionClosed_)
                {
                    co_return nullptr;
                }
                AcceptNotify_.reset();
                co_await AcceptNotify_.async_receive(net::use_awaitable);
            }
            co_return nullptr;
        }

        /**
         * @brief 推送数据帧到流（StreamHandle 回调）
         * @param StreamId 流标识符
         * @param Data 负载数据
         * @return 错误码（会话/底层关闭 = broken_pipe）
         * @details 大负载分块发送（smux 帧长上限 64KB，yamux/h2mux
         * 无此限制，块大小 = MaxPayloadLen）。
         */
        auto PushData(std::uint32_t StreamId, std::span<const std::uint8_t> Data)
            -> net::awaitable<ProtocolEc> override
        {
            if (!Raw_ || !Raw_->IsOpen())
            {
                co_return make_error_code(Error::BrokenPipe);
            }
            std::size_t chunk;
            if (C::MaxPayloadLen > 0)
            {
                chunk = C::MaxPayloadLen;
            }
            else
            {
                chunk = Data.size();
            }
            std::size_t Done = 0;
            while (Done < Data.size())
            {
                const auto N = std::min(chunk, Data.size() - Done);
                const auto Ec = co_await RawWrite(C::BuildData(StreamId, Data.subspan(Done, N)));
                if (Ec)
                {
                    // 数据面写失败必须上抛：静默丢弃会让流进入假活状态（对端永远等不到数据）
                    co_return Ec;
                }
                Done += N;
            }
            co_return boost::system::error_code{};
        }

        /**
         * @brief 发送 FIN（StreamHandle 回调）
         * @param StreamId 流标识符
         */
        auto SendFin(std::uint32_t StreamId) -> net::awaitable<void> override
        {
            // 关闭路径 best-effort：写失败不阻塞半关（会话拆除由帧循环/底层关闭兜底）
            if (Raw_ && Raw_->IsOpen())
            {
                (void)co_await RawWrite(C::BuildFin(StreamId));
            }
            co_return;
        }

        /**
         * @brief 发送 RST（StreamHandle 回调）
         * @param StreamId 流标识符
         */
        auto SendRst(std::uint32_t StreamId) -> net::awaitable<void> override
        {
            // 重置路径 best-effort：写失败不阻塞流销毁（本端已丢弃该流）
            if (Raw_ && Raw_->IsOpen())
            {
                (void)co_await RawWrite(C::BuildRst(StreamId));
            }
            co_return;
        }

        /**
         * @brief 移除流（StreamHandle 回调）
         * @param StreamId 流标识符
         */
        auto RemoveStream(std::uint32_t StreamId) -> void override
        {
            Streams_.erase(StreamId);
        }

        /**
         * @brief 会话是否打开
         * @return true = 会话可用
         */
        [[nodiscard]] auto IsOpen() const -> bool override
        {
            return !SessionClosed_ && Raw_ && Raw_->IsOpen();
        }

        /**
         * @brief 获取执行器
         * @return 会话执行器
         */
        [[nodiscard]] auto Executor() const -> net::any_io_executor override
        {
            return Ex_;
        }

        /**
         * @brief 当前活跃流数
         * @return 流表中流数量
         */
        [[nodiscard]] auto StreamCount() const -> std::size_t
        {
            return Streams_.size();
        }

        /**
         * @brief 关闭会话（全部流 + 底层连接）
         * @details 置 SessionClosed_，唤醒挂起 AcceptStream 与
         * 全部流（对端半关语义），清空流表并关闭底层。
         */
        auto Close() -> net::awaitable<void>
        {
            Teardown();
            if (Raw_)
            {
                Raw_->Close();
            }
            co_return;
        }

        /**
         * @brief 取消挂起的 AcceptStream（不关闭会话）
         * @details 置 Canceled_ 标志并唤醒 AcceptNotify_，挂起的
         * AcceptStream 返回 nullptr（一次性，可再次接受）。
         */
        auto Cancel() -> void
        {
            Canceled_ = true;
            AcceptNotify_.try_send(boost::system::error_code{});
        }

    private:
        /**
         * @struct WriteRequest
         * @brief 单一 writer 队列中的帧请求
         * @details 请求节点由 Session 持有；完成与消费确认通过 channel
         *          传递，队列按会话执行器访问，不需要锁或额外共享指针。
         */
        struct WriteRequest
        {
            explicit WriteRequest(net::any_io_executor Ex, std::vector<std::uint8_t> frame)
                : Frame(std::move(frame)), Completion(Ex, 1), Consumed(Ex, 1)
            {
            }

            std::vector<std::uint8_t> Frame;
            net::experimental::channel<void(boost::system::error_code, ProtocolEc)> Completion;
            net::experimental::channel<void(boost::system::error_code)> Consumed;
            bool InFlight{false};
            bool Canceled{false};
        };

        /**
         * @brief 底层写入（Transmission 适配：u8 视图 + ec 转错误码）
         * @param Frame 待写数据
         * @return 错误码（成功 = 空）
         */
        auto RawWrite(std::vector<std::uint8_t> Frame) -> net::awaitable<ProtocolEc>
        {
            co_await net::dispatch(Ex_, net::use_awaitable);
            if (SessionClosed_ || !Raw_ || !Raw_->IsOpen())
            {
                co_return make_error_code(Error::BrokenPipe);
            }
            auto &Request = PendingWrites_.emplace_back(Ex_, std::move(Frame));
            StartWriter();
            try
            {
                const auto Ec = co_await Request.Completion.async_receive(net::use_awaitable);
                (void)Request.Consumed.try_send(boost::system::error_code{});
                co_return Ec;
            }
            catch (...)
            {
                Request.Canceled = true;
                (void)Request.Consumed.try_send(boost::system::error_code{});
                throw;
            }
        }

        /**
         * @brief 将固定数组帧转入动态帧队列
         * @param Frame 固定大小帧
         * @return 错误码
         */
        template <std::size_t Size>
        auto RawWrite(std::array<std::uint8_t, Size> Frame) -> net::awaitable<ProtocolEc>
        {
            co_return co_await RawWrite(std::vector<std::uint8_t>(Frame.begin(), Frame.end()));
        }

        /**
         * @brief 构造（私有，经 Create 创建）
         * @param raw 底层传输
         * @param opt 会话选项
         */
        Session(SharedTransmission raw, const SessionOptions &opt)
            : Raw_(std::move(raw)), Opt_(opt), Ex_(Raw_->Executor()), AcceptNotify_(Ex_, 1)
        {
            if (Raw_ && Opt_.timeout > std::chrono::milliseconds::zero())
            {
                Raw_->SetTimeout(Opt_.timeout);
            }
        }

        /**
         * @brief 启动帧循环（detached 协程）
         * @details 按值捕获 self 保活，帧循环退出后会话自行销毁。
         */
        auto Start() -> void
        {
            auto Self = this->shared_from_this();
            net::co_spawn(
                Ex_, [Self]() -> net::awaitable<void> { co_await Self->FrameLoop(); }, net::detached);
        }

        /**
         * @brief 启动唯一底层 writer
         * @details 仅在会话执行器上调用；每个帧只经过一个 writer，
         *          从而保证帧边界和 producer 顺序。
         */
        auto StartWriter() -> void
        {
            if (WriterRunning_ || SessionClosed_)
            {
                return;
            }
            WriterRunning_ = true;
            auto Self = this->shared_from_this();
            net::co_spawn(
                Ex_, [Self]() -> net::awaitable<void> { co_await Self->WriteLoop(); }, net::detached);
        }

        /**
         * @brief 写出队列中的所有帧
         * @details 底层 AsyncWrite 处理 partial write；写错时先关闭会话，
         *          再以同一错误唤醒当前和排队中的 producer。
         */
        auto WriteLoop() -> net::awaitable<void>
        {
            while (!PendingWrites_.empty())
            {
                auto &Request = PendingWrites_.front();
                if (Request.Canceled)
                {
                    PendingWrites_.pop_front();
                    continue;
                }
                Request.InFlight = true;
                ProtocolEc Ec = make_error_code(Error::BrokenPipe);
                if (!SessionClosed_ && Raw_ && Raw_->IsOpen())
                {
                    Ec = co_await Detail::WriteFrame(Raw_, Request.Frame);
                }
                Request.InFlight = false;
                if (Ec && !SessionClosed_)
                {
                    Teardown();
                    if (Raw_)
                    {
                        Raw_->Close();
                    }
                }
                if (!Request.Canceled)
                {
                    (void)Request.Completion.try_send(boost::system::error_code{}, Ec);
                    (void)co_await Request.Consumed.async_receive(net::use_awaitable);
                }
                PendingWrites_.pop_front();
                if (Ec)
                {
                    SessionClosed_ = true;
                }
            }
            WriterRunning_ = false;
            co_return;
        }

        /**
         * @brief 帧循环：读帧 → 分发
         * @details 分段读取帧头与负载（负载上限 = MaxPayloadLen），
         * 解析成功后经 Dispatch 分发；底层关闭时置
         * SessionClosed_ 并唤醒挂起 AcceptStream。
         */
        auto FrameLoop() -> net::awaitable<void>
        {
            std::vector<std::uint8_t> Header(C::HeaderLen);
            std::vector<std::uint8_t> payload;

            while (Raw_ && Raw_->IsOpen() && !SessionClosed_)
            {
                // 读帧头
                if (!co_await Detail::ReadExact(
                        Raw_, std::span<std::uint8_t>(Header.data(), C::HeaderLen)))
                {
                    Teardown();
                    co_return;
                }

                // 解析帧头
                FrameType Frame{};
                if (C::ParseHeader(Header, Frame) != Error::None)
                {
                    Diagnose::Warn("mux Frame Header Parse Failed; closing Session");
                    ProtocolErrorTeardown();
                    co_return;
                }

                // 读负载
                const auto Len = C::PayloadLen(Frame);
                if (Len == 0)
                {
                    if (C::ParsePayload(Frame, {}) != Error::None)
                    {
                        Diagnose::Warn("mux Empty payload Parse Failed; closing Session");
                        ProtocolErrorTeardown();
                        co_return;
                    }
                    Dispatch(Frame, {});
                    continue;
                }
                if (Len > C::MaxPayloadLen)
                {
                    Diagnose::Warn("mux Frame payload exceeds limit; closing Session");
                    ProtocolErrorTeardown();
                    co_return;
                }
                payload.resize(Len);
                if (!co_await Detail::ReadExact(Raw_, std::span<std::uint8_t>(payload.data(), Len)))
                {
                    Teardown();
                    co_return;
                }
                if (C::ParsePayload(Frame, payload) != Error::None)
                {
                    Diagnose::Warn("mux Frame payload Parse Failed; closing Session");
                    ProtocolErrorTeardown();
                    co_return;
                }
                Dispatch(Frame, payload);
            }
            Teardown();
            co_return;
        }

        /**
         * @brief 分发帧到流 / 控制逻辑
         * @param Frame 已解析帧头
         * @param payload 负载数据
         * @details Open：登记新流并排入入向队列；Data：投递到流，
         * 未知流隐式开流（h2mux 无 SYN 帧）；fin：置对端
         * 半关；rst：唤醒流并移除；控制帧忽略。
         */
        auto Dispatch(const FrameType &Frame, std::span<const std::uint8_t> payload) -> void
        {
            // 会话级控制帧（心跳/窗口/GO_AWAY）：忽略（测试库不实现流控）
            if (C::IsControl(Frame))
            {
                return;
            }
            const auto Event = C::FrameEvent(Frame);
            switch (Event)
            {
            case StreamEvent::Open: {
                const auto Id = C::FrameStreamId(Frame);
                if (Id == 0 || Streams_.contains(Id))
                {
                    break;
                }
                if (!IsPeerStreamId(Id) || Streams_.size() >= Opt_.MaxStreams)
                {
                    ProtocolErrorTeardown();
                    break;
                }
                auto Handle = std::make_shared<StreamHandle<Memory>>(Id, this->shared_from_this(), Ex_);
                Streams_[Id] = Handle;
                Incoming_.push_back(Handle);
                AcceptNotify_.try_send(boost::system::error_code{});
                if (!payload.empty())
                {
                    Handle->PushRx(payload);
                }
                break;
            }
            case StreamEvent::Data: {
                const auto Id = C::FrameStreamId(Frame);
                const auto It = Streams_.find(Id);
                if (It != Streams_.end() && It->second)
                {
                    It->second->PushRx(payload);
                    break;
                }
                // 隐式开流（h2mux 无 SYN 帧：首数据帧即开流）
                if (Id == 0)
                {
                    break;
                }
                if (!IsPeerStreamId(Id) || Streams_.size() >= Opt_.MaxStreams)
                {
                    ProtocolErrorTeardown();
                    break;
                }
                auto Handle = std::make_shared<StreamHandle<Memory>>(Id, this->shared_from_this(), Ex_);
                Streams_[Id] = Handle;
                Incoming_.push_back(Handle);
                AcceptNotify_.try_send(boost::system::error_code{});
                if (!payload.empty())
                {
                    Handle->PushRx(payload);
                }
                break;
            }
            case StreamEvent::Fin: {
                const auto Id = C::FrameStreamId(Frame);
                const auto It = Streams_.find(Id);
                if (It != Streams_.end() && It->second)
                {
                    It->second->SetPeerEof();
                }
                break;
            }
            case StreamEvent::Rst: {
                const auto Id = C::FrameStreamId(Frame);
                const auto It = Streams_.find(Id);
                if (It != Streams_.end() && It->second)
                {
                    It->second->OnRst(); // 唤醒挂起读（返回 0）
                }
                Streams_.erase(Id);
                break;
            }
            default: break; // 会话级/心跳帧：忽略
            }
        }

        /**
         * @brief 分配流 ID（按角色奇偶步进 2：Client 奇数 / Server 偶数）
         * @return 新流 ID；0 = 流数达上限 / ID 耗尽
         * @details 对齐协议规范：Client 奇数 / Server 偶数。
         */
        auto AllocateId() -> std::uint32_t
        {
            if (Streams_.size() >= Opt_.MaxStreams)
            {
                return 0;
            }
            const bool Odd = Opt_.Role == Preview::Role::Client;
            for (std::size_t I = 0; I < 65536; ++I)
            {
                if (NextId_ == 0)
                {
                    if (Odd)
                    {
                        NextId_ = 1u;
                    }
                    else
                    {
                        NextId_ = 2u;
                    }
                }
                else
                {
                    NextId_ = NextId_ + 2;
                }
                if (NextId_ == 0 || NextId_ > 65535)
                {
                    if (Odd)
                    {
                        NextId_ = 1u;
                    }
                    else
                    {
                        NextId_ = 2u;
                    }
                }
                if (!Streams_.contains(NextId_))
                {
                    return NextId_;
                }
            }
            return 0;
        }

        /**
         * @brief 校验入向流 ID 是否属于对端角色
         * @param Id 流标识符
         * @return 对端应使用该奇偶位时返回 true
         */
        [[nodiscard]] auto IsPeerStreamId(const std::uint32_t Id) const noexcept -> bool
        {
            const bool PeerOdd = Opt_.Role == Preview::Role::Server;
            return ((Id & 1U) != 0U) == PeerOdd;
        }

        /**
         * @brief 会话拆除：置关闭标志，唤醒挂起读并清空流表/入向队列
         * @details 打破 Session ↔ StreamHandle 的 shared_ptr 循环：
         * 帧循环退出或 Close() 时清空 Streams_ 与 Incoming_，释放
         * 句柄对会话的引用，避免底层断开后残余句柄与会话互相保活
         * 造成泄漏。
         */
        auto Teardown() -> void
        {
            SessionClosed_ = true;
            AcceptNotify_.try_send(boost::system::error_code{});
            for (auto &[Id, Handle] : Streams_)
            {
                if (Handle)
                {
                    Handle->SetPeerEof();
                }
            }
            Streams_.clear();
            Incoming_.clear();
        }

        /**
         * @brief 处理会话级协议错误并关闭底层传输
         * @details 帧头、长度或 payload 校验失败后无法安全定位下一帧，
         *          必须同时清理会话状态并关闭 raw，不能继续读取造成永久失步。
         */
        auto ProtocolErrorTeardown() -> void
        {
            Teardown();
            if (Raw_)
            {
                Raw_->Close();
            }
        }

        SharedTransmission Raw_;                                                     ///< 底层传输
        SessionOptions Opt_;                                                               ///< 会话选项
        net::any_io_executor Ex_;                                                           ///< 执行器
        boost::asio::experimental::channel<void(boost::system::error_code)> AcceptNotify_; ///< 新流通知
        std::map<std::uint32_t, std::shared_ptr<StreamHandle<Memory>>> Streams_; ///< 流表（ID → 句柄）
        std::deque<std::shared_ptr<StreamHandle<Memory>>> Incoming_;             ///< 入向流队列（待 Accept）
        std::deque<WriteRequest> PendingWrites_;                                 ///< 唯一 writer 队列
        std::uint32_t NextId_{0};                                        ///< 下一个流 ID 候选
        bool SessionClosed_{false};                                      ///< 会话已关闭
        bool Canceled_{false};                                            ///< Accept 被取消（一次性）
        bool WriterRunning_{false};                                      ///< writer 协程已运行
    };

} // namespace Preview::Mux
