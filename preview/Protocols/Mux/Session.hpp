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
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <limits>
#include <map>
#include <memory>
#include <span>
#include <utility>
#include <vector>

#include <preview/Foundation/Utility/Diagnose/Log.hpp>
#include <preview/Foundation/Error.hpp>
#include <preview/Foundation/Memory/Container.hpp>
#include <preview/Foundation/Memory/Pointer.hpp>
#include <preview/Foundation/Role.hpp>
#include <preview/Foundation/SessionBase.hpp>
#include <preview/Transport/Transmission.hpp>
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
        /// 每流接收队列字节预算（0 = 不限）；超限关闭会话
        std::size_t MaxStreamRxBytes{4 * 1024 * 1024};
        /// 会话接收队列总字节预算（0 = 不限）；超限关闭会话
        std::size_t MaxSessionRxBytes{16 * 1024 * 1024};
        /// 待发送帧总字节预算（0 = 不限）；超限只拒绝本次写入
        std::size_t MaxPendingWriteBytes{32 * 1024 * 1024};
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
    template <typename C,
              Preview::Memory::Restrict Memory = Preview::Memory::SessionResource<>>
    class Session : public SessionIface,
                    public std::enable_shared_from_this<Session<C, Memory>>
    {
    public:
        using FrameType = typename C::FrameType;

        /// 内存策略类型（对外暴露，供嵌套层/测试使用）
        using MemoryType = Memory;

        /**
         * @brief 创建会话（同时启动帧循环）
         * @param Raw 底层传输（类型擦除）
         * @param Options 会话选项
         * @return 会话实例
         */
        static auto Create(SharedTransmission Raw, const SessionOptions &Options)
            -> std::shared_ptr<Session<C, Memory>>
        {
            if (!Raw)
            {
                return {};
            }
            auto Self = std::shared_ptr<Session<C, Memory>>(
                new Session<C, Memory>(std::move(Raw), Options));
            Self->Start();
            return Self;
        }

        /**
         * @brief 打开新流（客户端视角）
         * @return 流句柄；nullptr = 会话已关闭 / 流数达上限
         * @details 分配流 ID（奇偶随角色）并发送开流帧。
         */
        auto OpenStream() -> Net::awaitable<std::shared_ptr<StreamHandle<Memory>>>
        {
            co_await Net::dispatch(Ex_, Net::use_awaitable);
            if (SessionClosed_ || !Raw_ || !Raw_->IsOpen())
            {
                co_return nullptr;
            }
            const auto Id = AllocateId();
            if (Id == 0)
            {
                if (StreamIdExhausted_)
                {
                    ProtocolErrorTeardown();
                }
                co_return nullptr;
            }
            auto Handle = std::make_shared<StreamHandle<Memory>>(Id, this->shared_from_this(), Ex_,
                                                                 Opt_.MaxStreamRxBytes);
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
        auto AcceptStream() -> Net::awaitable<std::shared_ptr<StreamHandle<Memory>>>
        {
            co_await Net::dispatch(Ex_, Net::use_awaitable);
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
                co_await AcceptNotify_.async_receive(Net::use_awaitable);
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
            -> Net::awaitable<ProtocolEc> override
        {
            co_await Net::dispatch(Ex_, Net::use_awaitable);
            if (SessionClosed_ || !Raw_ || !Raw_->IsOpen())
            {
                co_return make_error_code(Error::BrokenPipe);
            }
            std::size_t Chunk;
            if (C::MaxPayloadLen > 0)
            {
                Chunk = C::MaxPayloadLen;
            }
            else
            {
                Chunk = Data.size();
            }
            std::size_t Done = 0;
            while (Done < Data.size())
            {
                const auto N = std::min(Chunk, Data.size() - Done);
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
        auto SendFin(std::uint32_t StreamId) -> Net::awaitable<void> override
        {
            co_await Net::dispatch(Ex_, Net::use_awaitable);
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
        auto SendRst(std::uint32_t StreamId) -> Net::awaitable<void> override
        {
            co_await Net::dispatch(Ex_, Net::use_awaitable);
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
         * @brief 流消费接收队列字节后的预算归还
         * @param StreamId 流标识符（会话级预算不区分流）
         * @param Bytes 已消费/释放的字节数
         */
        void OnStreamRxConsumed(std::uint32_t StreamId, std::size_t Bytes) noexcept override
        {
            (void)StreamId;
            SessionRxBytes_ -= std::min(SessionRxBytes_, Bytes);
        }

        /**
         * @brief 获取执行器
         * @return 会话执行器
         */
        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
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
        auto Close() -> Net::awaitable<void>
        {
            co_await Net::dispatch(Ex_, Net::use_awaitable);
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
            auto Self = this->shared_from_this();
            Net::dispatch(Ex_, [Self]()
            {
                Self->Canceled_ = true;
                Self->AcceptNotify_.try_send(boost::system::error_code{});
            });
        }

    private:
        /**
         * @struct WriteRequest
         * @brief 单一 writer 队列中的帧请求
         * @details 请求节点由 producer 与 writer 共享所有权；完成通过 channel
         *          传递，writer 不依赖 producer 的二次确认即可推进队列。
         */
        struct WriteRequest
        {
            explicit WriteRequest(Net::any_io_executor Ex, std::vector<std::uint8_t> FrameValue)
                : Frame(std::move(FrameValue)), Completion(Ex, 1)
            {
            }

            std::vector<std::uint8_t> Frame;
            Net::experimental::channel<void(boost::system::error_code, ProtocolEc)> Completion;
            bool Canceled{false};
            bool BudgetReleased{false};
        };

        /**
         * @brief 底层写入（Transmission 适配：u8 视图和错误码转换）
         * @param Frame 待写数据
         * @return 错误码（成功 = 空）
         */
        auto RawWrite(std::vector<std::uint8_t> Frame) -> Net::awaitable<ProtocolEc>
        {
            co_await Net::dispatch(Ex_, Net::use_awaitable);
            if (SessionClosed_ || !Raw_ || !Raw_->IsOpen())
            {
                co_return make_error_code(Error::BrokenPipe);
            }
            if (Opt_.MaxPendingWriteBytes != 0)
            {
                const auto Used = (std::min)(PendingWriteBytes_, Opt_.MaxPendingWriteBytes);
                if (Frame.size() > Opt_.MaxPendingWriteBytes - Used)
                {
                    co_return make_error_code(Error::BadLength);
                }
            }
            auto Request = std::make_shared<WriteRequest>(Ex_, std::move(Frame));
            PendingWrites_.push_back(Request);
            if (Opt_.MaxPendingWriteBytes != 0)
            {
                PendingWriteBytes_ += Request->Frame.size();
            }
            StartWriter();
            try
            {
                co_return co_await Request->Completion.async_receive(Net::use_awaitable);
            }
            catch (...)
            {
                Request->Canceled = true;
                throw;
            }
        }

        /**
         * @brief 将固定数组帧转入动态帧队列
         * @param Frame 固定大小帧
         * @return 错误码
         */
        template <std::size_t Size>
        auto RawWrite(std::array<std::uint8_t, Size> Frame) -> Net::awaitable<ProtocolEc>
        {
            co_return co_await RawWrite(std::vector<std::uint8_t>(Frame.begin(), Frame.end()));
        }

        /**
         * @brief 构造（私有，经 Create 创建）
         * @param Raw 底层传输
         * @param Options 会话选项
         */
        Session(SharedTransmission Raw, const SessionOptions &Options)
            : Raw_(std::move(Raw)), Opt_(Options), Ex_(Raw_->Executor()), AcceptNotify_(Ex_, 1)
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
            Net::co_spawn(
                Ex_,
                [Self]() -> Net::awaitable<void> { co_await Self->FrameLoop(); },
                Net::detached);
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
            Net::co_spawn(
                Ex_,
                [Self]() -> Net::awaitable<void> { co_await Self->WriteLoop(); },
                Net::detached);
        }

        /**
         * @brief 写出队列中的所有帧
         * @details 底层 AsyncWrite 处理 partial write；写错时先关闭会话，
         *          再以同一错误唤醒当前和排队中的 producer。
         */
        auto WriteLoop() -> Net::awaitable<void>
        {
            while (!PendingWrites_.empty())
            {
                auto Request = PendingWrites_.front();
                PendingWrites_.pop_front();
                if (Request->Canceled)
                {
                    ReleasePendingWriteBudget(Request);
                    continue;
                }
                ProtocolEc Ec = make_error_code(Error::BrokenPipe);
                if (!SessionClosed_ && Raw_ && Raw_->IsOpen())
                {
                    Ec = co_await Detail::WriteFrame(Raw_, Request->Frame);
                }
                if (Ec && !SessionClosed_)
                {
                    Teardown();
                    if (Raw_)
                    {
                        Raw_->Close();
                    }
                }
                if (Ec)
                {
                    SessionClosed_ = true;
                }
                ReleasePendingWriteBudget(Request);
                (void)Request->Completion.try_send(boost::system::error_code{}, Ec);
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
        auto FrameLoop() -> Net::awaitable<void>
        {
            std::vector<std::uint8_t> Header(C::HeaderLen);
            std::vector<std::uint8_t> Payload;

            while (Raw_ && Raw_->IsOpen() && !SessionClosed_)
            {
                // 读帧头
                if (!co_await Detail::ReadExact(
                        Raw_, std::span<std::uint8_t>(Header.data(), C::HeaderLen)))
                {
                    Teardown();
                    if (Raw_)
                    {
                        Raw_->Close();
                    }
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
                Payload.resize(Len);
                if (!co_await Detail::ReadExact(Raw_, std::span<std::uint8_t>(Payload.data(), Len)))
                {
                    Teardown();
                    if (Raw_)
                    {
                        Raw_->Close();
                    }
                    co_return;
                }
                if (C::ParsePayload(Frame, Payload) != Error::None)
                {
                    Diagnose::Warn("mux Frame payload Parse Failed; closing Session");
                    ProtocolErrorTeardown();
                    co_return;
                }
                Dispatch(Frame, Payload);
            }
            Teardown();
            co_return;
        }

        /**
         * @brief 分发帧到流 / 控制逻辑
         * @param Frame 已解析帧头
         * @param Payload 负载数据
         * @details Open：登记新流并排入入向队列；Data：投递到流，
         * 未知流隐式开流（h2mux 无 SYN 帧）；fin：置对端
         * 半关；rst：唤醒流并移除；控制帧忽略。
         */
        auto Dispatch(const FrameType &Frame, std::span<const std::uint8_t> Payload) -> void
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
                auto Handle = std::make_shared<StreamHandle<Memory>>(
                    Id, this->shared_from_this(), Ex_, Opt_.MaxStreamRxBytes);
                Streams_[Id] = Handle;
                Incoming_.push_back(Handle);
                AcceptNotify_.try_send(boost::system::error_code{});
                if (!Payload.empty())
                {
                    if (!DeliverRx(Handle, Payload))
                    {
                        Diagnose::Warn("mux receive queue budget exceeded; closing Session");
                        ProtocolErrorTeardown();
                    }
                }
                break;
            }
            case StreamEvent::Data: {
                const auto Id = C::FrameStreamId(Frame);
                const auto It = Streams_.find(Id);
                if (It != Streams_.end() && It->second)
                {
                    if (!DeliverRx(It->second, Payload))
                    {
                        Diagnose::Warn("mux receive queue budget exceeded; closing Session");
                        ProtocolErrorTeardown();
                    }
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
                auto Handle = std::make_shared<StreamHandle<Memory>>(
                    Id, this->shared_from_this(), Ex_, Opt_.MaxStreamRxBytes);
                Streams_[Id] = Handle;
                Incoming_.push_back(Handle);
                AcceptNotify_.try_send(boost::system::error_code{});
                if (!Payload.empty())
                {
                    if (!DeliverRx(Handle, Payload))
                    {
                        Diagnose::Warn("mux receive queue budget exceeded; closing Session");
                        ProtocolErrorTeardown();
                    }
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
            constexpr auto MaxId = (std::numeric_limits<std::uint32_t>::max)();
            const auto FirstId = std::uint32_t{1} + static_cast<std::uint32_t>(!Odd);
            const auto ExpectedParity = static_cast<std::uint32_t>(Odd);
            if (NextId_ == 0)
            {
                NextId_ = FirstId;
            }
            else
            {
                // 32 位流 ID 单调递增，耗尽前禁止无符号回绕复用旧 ID。
                if (NextId_ > MaxId - 2U)
                {
                    StreamIdExhausted_ = true;
                    return 0;
                }
                NextId_ += 2U;
            }
            if (NextId_ == 0 || (NextId_ & 1U) != ExpectedParity || Streams_.contains(NextId_))
            {
                StreamIdExhausted_ = true;
                return 0;
            }
            return NextId_;
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
            SessionRxBytes_ = 0;
            AcceptNotify_.try_send(boost::system::error_code{});
            for (const auto &Request : PendingWrites_)
            {
                if (Request)
                {
                    Request->Canceled = true;
                    ReleasePendingWriteBudget(Request);
                    (void)Request->Completion.try_send(boost::system::error_code{},
                                                       make_error_code(Error::BrokenPipe));
                }
            }
            PendingWrites_.clear();
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
         * @brief 归还发送队列预算
         * @param Request 已完成、取消或从队列清理的写请求
         * @details 预算覆盖当前 writer 正在处理的请求；释放操作幂等，
         *          以便 Teardown 与 writer 错误路径不会重复扣减。
         */
        auto ReleasePendingWriteBudget(
            const std::shared_ptr<WriteRequest> &Request) noexcept -> void
        {
            if (!Request || Request->BudgetReleased || Opt_.MaxPendingWriteBytes == 0)
            {
                return;
            }
            PendingWriteBytes_ -= (std::min)(PendingWriteBytes_, Request->Frame.size());
            Request->BudgetReleased = true;
        }

        /**
         * @brief 投递接收数据并执行每流/会话字节预算
         * @param Handle 目标流句柄
         * @param Payload 待投递负载
         * @return true = 已入队；false = 超出预算（调用方关闭会话）
         * @details 先校验会话级预算，再交由流句柄校验每流预算；
         *          预算随 ReadSome 消费和关流/RST 释放而归还。
         */
        [[nodiscard]] auto DeliverRx(const std::shared_ptr<StreamHandle<Memory>> &Handle,
                                     std::span<const std::uint8_t> Payload) -> bool
        {
            if (Payload.empty())
            {
                return true;
            }
            if (!Handle || Handle->IsClosed() || Handle->IsPeerEof())
            {
                return true;
            }
            const auto Used = (std::min)(SessionRxBytes_, Opt_.MaxSessionRxBytes);
            if (Opt_.MaxSessionRxBytes != 0 &&
                Payload.size() > Opt_.MaxSessionRxBytes - Used)
            {
                return false;
            }
            if (!Handle->PushRx(Payload))
            {
                return false;
            }
            SessionRxBytes_ += Payload.size();
            return true;
        }

        /**
         * @brief 处理会话级协议错误并关闭底层传输
         * @details 帧头、长度或负载校验失败后无法安全定位下一帧，
         *          必须同时清理会话状态并关闭底层传输，不能继续读取造成永久失步。
         */
        auto ProtocolErrorTeardown() -> void
        {
            Teardown();
            if (Raw_)
            {
                Raw_->Close();
            }
        }

        SharedTransmission Raw_; ///< 底层传输
        SessionOptions Opt_; ///< 会话选项
        Net::any_io_executor Ex_; ///< 执行器
        Net::experimental::channel<void(boost::system::error_code)> AcceptNotify_; ///< 新流通知
        std::map<std::uint32_t, std::shared_ptr<StreamHandle<Memory>>> Streams_; ///< 流表（ID → 句柄）
        std::deque<std::shared_ptr<StreamHandle<Memory>>> Incoming_; ///< 入向流队列（待 Accept）
        std::deque<std::shared_ptr<WriteRequest>> PendingWrites_; ///< 唯一 writer 队列
        std::uint32_t NextId_{0}; ///< 下一个流 ID 候选
        bool StreamIdExhausted_{false}; ///< 32 位流 ID 已耗尽
        std::size_t SessionRxBytes_{0}; ///< 会话接收队列当前总字节数
        std::size_t PendingWriteBytes_{0}; ///< 当前未完成写请求总字节数
        bool SessionClosed_{false}; ///< 会话已关闭
        bool Canceled_{false}; ///< Accept 被取消（一次性）
        bool WriterRunning_{false}; ///< writer 协程已运行
    };

} // namespace Preview::Mux
