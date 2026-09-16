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

#include <Preview/Foundation/Utility/Diagnose/Log.hpp>
#include <Preview/Foundation/Error.hpp>
#include <Preview/Foundation/Memory/Container.hpp>
#include <Preview/Foundation/Memory/Pointer.hpp>
#include <Preview/Foundation/Role.hpp>
#include <Preview/Foundation/SessionBase.hpp>
#include <Preview/Runtime/SessionControl.hpp>
#include <Preview/Transport/Transmission.hpp>
#include <Preview/Protocols/Mux/Codec.hpp>
#include <Preview/Protocols/Mux/SessionReadLoop.hpp>
#include <Preview/Protocols/Mux/StreamState.hpp>
#include <Preview/Protocols/Mux/SessionWriteLoop.hpp>

namespace Preview::Mux
{

    /**
     * @struct SessionOptions
     * @brief 多路复用会话选项
     * @details 构造后只读，经 Session::Create 传入。
     */
    struct SessionOptions
    {
        /// 可选的 owner-held 会话控制器；存在时帧循环和 writer 进入该 registry。
        std::shared_ptr<Preview::Runtime::SessionControl> Control{};
        /// listener 提交的父任务身份；Mux 子任务只重新分配 TaskId。
        Preview::Lifecycle::TaskIdentity Identity{};
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
    private:
        using FlowNotify = Net::experimental::channel<void(boost::system::error_code)>;

        struct FlowState
        {
            std::uint64_t SendWindow{0};
            std::uint64_t ReceiveWindow{0};
            std::shared_ptr<FlowNotify> Notify{};
        };

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
            InitializeLocalFlow(Id);
            if (co_await RawWrite(C::BuildOpen(Id)))
            {
                Streams_.erase(Id);
                Flow_.erase(Id);
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
                std::size_t N = (std::min)(Chunk, Data.size() - Done);
                if constexpr (UsesFlowControl())
                {
                    while (N != 0 && (N = ReserveSendWindow(StreamId, N)) == 0)
                    {
                        if (!co_await WaitForSendWindow(StreamId))
                        {
                            co_return make_error_code(Error::BrokenPipe);
                        }
                        N = (std::min)(Chunk, Data.size() - Done);
                    }
                    if (N == 0)
                    {
                        co_return make_error_code(Error::BrokenPipe);
                    }
                }
                const auto Ec = co_await RawWrite(C::BuildData(StreamId, Data.subspan(Done, N)));
                if (Ec)
                {
                    if constexpr (UsesFlowControl())
                    {
                        ReturnSendWindow(StreamId, N);
                    }
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
            RemoveFlow(StreamId);
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
            SessionRxBytes_ -= std::min(SessionRxBytes_, Bytes);
            if constexpr (requires(std::uint32_t Id, std::uint32_t Delta)
                          {
                              C::BuildWindowUpdate(Id, Delta);
                          })
            {
                if (Bytes == 0 || SessionClosed_ || !Raw_ || !Raw_->IsOpen())
                {
                    return;
                }
                const auto Delta = (std::min)(
                    Bytes, static_cast<std::size_t>((std::numeric_limits<std::uint32_t>::max)()));
                if (Delta == 0)
                {
                    return;
                }
                if constexpr (UsesFlowControl())
                {
                    if (!Flow_.contains(StreamId))
                    {
                        return;
                    }
                    IncreaseReceiveWindow(StreamId, Delta);
                }
                try
                {
                    auto Self = this->shared_from_this();
                    Net::co_spawn(
                        Ex_,
                        [Self, StreamId, Delta = static_cast<std::uint32_t>(Delta)]() -> Net::awaitable<void>
                        {
                            (void)co_await Self->RawWrite(C::BuildWindowUpdate(StreamId, Delta));
                        },
                        Net::detached);
                }
                catch (...)
                {
                }
            }
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
            CancelRaw();
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

        /**
         * @brief 获取 owner-held 会话控制器
         * @return 外部控制器；未注入时为空
         */
        [[nodiscard]] auto Control() const noexcept
            -> std::shared_ptr<Preview::Runtime::SessionControl>
        {
            return Control_;
        }

    private:
        [[nodiscard]] static constexpr auto UsesFlowControl() noexcept -> bool
        {
            if constexpr (requires { C::UsesFlowControl; })
            {
                return C::UsesFlowControl;
            }
            return false;
        }

        [[nodiscard]] static constexpr auto InitialFlowWindow() noexcept -> std::uint64_t
        {
            if constexpr (requires { C::InitialWindow; })
            {
                return C::InitialWindow;
            }
            return 0;
        }

        auto InitializeLocalFlow(std::uint32_t StreamId) -> void
        {
            if constexpr (UsesFlowControl())
            {
                Flow_[StreamId] = FlowState{
                    .SendWindow = 0,
                    .ReceiveWindow = InitialFlowWindow(),
                    .Notify = std::make_shared<FlowNotify>(Ex_, 1)};
            }
        }

        auto InitializeIncomingFlow(const FrameType &Frame) -> void
        {
            if constexpr (UsesFlowControl())
            {
                auto SendWindow = InitialFlowWindow();
                if constexpr (requires(const FrameType &Value)
                              {
                                  C::OpenSendWindow(Value);
                              })
                {
                    SendWindow = C::OpenSendWindow(Frame);
                }
                Flow_[C::FrameStreamId(Frame)] = FlowState{
                    .SendWindow = SendWindow,
                    .ReceiveWindow = InitialFlowWindow(),
                    .Notify = std::make_shared<FlowNotify>(Ex_, 1)};
            }
        }

        auto RemoveFlow(std::uint32_t StreamId) -> void
        {
            if constexpr (UsesFlowControl())
            {
                if (const auto It = Flow_.find(StreamId); It != Flow_.end())
                {
                    if (It->second.Notify)
                    {
                        (void)It->second.Notify->try_send(boost::system::error_code{});
                    }
                    Flow_.erase(It);
                }
            }
        }

        auto WakeFlowWaiters() noexcept -> void
        {
            if constexpr (UsesFlowControl())
            {
                for (auto &[Id, State] : Flow_)
                {
                    (void)Id;
                    if (State.Notify)
                    {
                        (void)State.Notify->try_send(boost::system::error_code{});
                    }
                }
            }
        }

        auto AddSendWindow(std::uint32_t StreamId, std::uint32_t Delta) -> void
        {
            if constexpr (UsesFlowControl())
            {
                const auto It = Flow_.find(StreamId);
                if (It == Flow_.end())
                {
                    return;
                }
                const auto Limit = (std::numeric_limits<std::uint64_t>::max)();
                if (Delta > Limit - It->second.SendWindow)
                {
                    It->second.SendWindow = Limit;
                }
                else
                {
                    It->second.SendWindow += Delta;
                }
                if (It->second.Notify)
                {
                    (void)It->second.Notify->try_send(boost::system::error_code{});
                }
            }
        }

        auto ReturnSendWindow(std::uint32_t StreamId, std::size_t Delta) -> void
        {
            const auto Bounded = (std::min)(
                Delta, static_cast<std::size_t>((std::numeric_limits<std::uint32_t>::max)()));
            AddSendWindow(StreamId, static_cast<std::uint32_t>(Bounded));
        }

        [[nodiscard]] auto ReserveSendWindow(std::uint32_t StreamId, std::size_t Requested)
            -> std::size_t
        {
            if constexpr (UsesFlowControl())
            {
                const auto It = Flow_.find(StreamId);
                if (It == Flow_.end())
                {
                    return 0;
                }
                const auto Granted = (std::min)(
                    Requested, static_cast<std::size_t>(It->second.SendWindow));
                It->second.SendWindow -= Granted;
                return Granted;
            }
            return Requested;
        }

        [[nodiscard]] auto WaitForSendWindow(std::uint32_t StreamId)
            -> Net::awaitable<bool>
        {
            if constexpr (UsesFlowControl())
            {
                while (!SessionClosed_)
                {
                    const auto It = Flow_.find(StreamId);
                    if (It == Flow_.end() || !It->second.Notify)
                    {
                        co_return false;
                    }
                    if (It->second.SendWindow != 0)
                    {
                        co_return true;
                    }
                    auto Notify = It->second.Notify;
                    Notify->reset();
                    co_await Notify->async_receive(Net::use_awaitable);
                }
                co_return false;
            }
            co_return true;
        }

        auto IncreaseReceiveWindow(std::uint32_t StreamId, std::uint32_t Delta) -> void
        {
            if constexpr (UsesFlowControl())
            {
                const auto It = Flow_.find(StreamId);
                if (It == Flow_.end())
                {
                    return;
                }
                const auto Limit = (std::numeric_limits<std::uint64_t>::max)();
                if (Delta > Limit - It->second.ReceiveWindow)
                {
                    It->second.ReceiveWindow = Limit;
                }
                else
                {
                    It->second.ReceiveWindow += Delta;
                }
            }
        }

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
            bool CompletionSent{false};
        };

        /**
         * @brief 底层写入（Transmission 适配：u8 视图和错误码转换）
         * @param Frame 待写数据
         * @return 错误码（成功 = 空）
         */
        auto EnqueueWrite(std::vector<std::uint8_t> Frame, ProtocolEc &ErrorCode)
            -> std::shared_ptr<WriteRequest>
        {
            if (SessionClosed_ || !Raw_ || !Raw_->IsOpen())
            {
                ErrorCode = make_error_code(Error::BrokenPipe);
                return {};
            }
            if (Opt_.MaxPendingWriteBytes != 0)
            {
                const auto Used = (std::min)(PendingWriteBytes_, Opt_.MaxPendingWriteBytes);
                if (Frame.size() > Opt_.MaxPendingWriteBytes - Used)
                {
                    ErrorCode = make_error_code(Error::BadLength);
                    return {};
                }
            }
            auto Request = std::make_shared<WriteRequest>(Ex_, std::move(Frame));
            PendingWrites_.push_back(Request);
            if (Opt_.MaxPendingWriteBytes != 0)
            {
                PendingWriteBytes_ += Request->Frame.size();
            }
            StartWriter();
            ErrorCode.clear();
            return Request;
        }

        auto RawWrite(std::vector<std::uint8_t> Frame) -> Net::awaitable<ProtocolEc>
        {
            co_await Net::dispatch(Ex_, Net::use_awaitable);
            ProtocolEc ErrorCode;
            auto Request = EnqueueWrite(std::move(Frame), ErrorCode);
            if (!Request)
            {
                co_return ErrorCode;
            }
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
            : Raw_(std::move(Raw)), Opt_(Options), Ex_(Raw_->Executor()),
              Control_(Opt_.Control), Identity_(Opt_.Identity), AcceptNotify_(Ex_, 1)
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
            if (Control_)
            {
                Preview::Lifecycle::TaskRequest Request;
                Request.Identity = Identity_;
                const auto WeakSelf = std::weak_ptr<Session>(Self);
                Request.Cancel = [WeakSelf]
                {
                    if (const auto SessionValue = WeakSelf.lock())
                    {
                        SessionValue->CancelRaw();
                    }
                };
                if (!Control_->Start(std::move(Request), RunFrame(std::move(Self))))
                {
                    SessionClosed_ = true;
                    CancelRaw();
                    if (Raw_)
                    {
                        Raw_->Close();
                    }
                }
                return;
            }
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
            if (Control_)
            {
                Preview::Lifecycle::TaskRequest Request;
                Request.Identity = Identity_;
                const auto WeakSelf = std::weak_ptr<Session>(Self);
                Request.Cancel = [WeakSelf]
                {
                    if (const auto SessionValue = WeakSelf.lock())
                    {
                        SessionValue->CancelRaw();
                    }
                };
                if (!Control_->Start(std::move(Request), RunWriter(std::move(Self))))
                {
                    WriterRunning_ = false;
                    FailPendingWrites(make_error_code(Error::Canceled));
                }
                return;
            }
            Net::co_spawn(
                Ex_,
                [Self]() -> Net::awaitable<void> { co_await Self->WriteLoop(); },
                Net::detached);
        }

        /**
         * @brief 完成一个写请求且保证只发送一次
         * @param Request 写请求
         * @param ErrorCode 请求结果
         */
        auto CompleteWriteRequest(const std::shared_ptr<WriteRequest> &Request,
                                  const ProtocolEc &ErrorCode) -> void
        {
            if (!Request || Request->CompletionSent)
            {
                return;
            }
            Request->CompletionSent = true;
            ReleasePendingWriteBudget(Request);
            (void)Request->Completion.try_send(boost::system::error_code{}, ErrorCode);
        }

        /**
         * @brief 失败并清空尚未由 writer 取出的请求
         * @param ErrorCode 所有排队请求收到的终态错误
         */
        auto FailPendingWrites(const ProtocolEc &ErrorCode) -> void
        {
            while (!PendingWrites_.empty())
            {
                auto Request = std::move(PendingWrites_.front());
                PendingWrites_.pop_front();
                if (Request)
                {
                    Request->Canceled = true;
                    CompleteWriteRequest(Request, ErrorCode);
                }
            }
        }

        /**
         * @brief 写出队列中的所有帧
         * @details 底层 AsyncWrite 处理 partial write；写错时先关闭会话，
         *          再以同一错误唤醒当前和排队中的 producer。
         */
        auto WriteLoop() -> Net::awaitable<void>
        {
            std::shared_ptr<WriteRequest> Request;
            try
            {
                while (!PendingWrites_.empty())
                {
                    Request = std::move(PendingWrites_.front());
                    PendingWrites_.pop_front();
                    if (!Request)
                    {
                        continue;
                    }
                    if (Request->Canceled)
                    {
                        CompleteWriteRequest(Request, make_error_code(Error::Canceled));
                        Request.reset();
                        continue;
                    }

                    ProtocolEc ErrorCode = make_error_code(Error::BrokenPipe);
                    if (!SessionClosed_ && Raw_ && Raw_->IsOpen())
                    {
                        ErrorCode = co_await Detail::WriteFrame(Raw_, Request->Frame);
                    }
                    if (ErrorCode)
                    {
                        Teardown(ErrorCode);
                        if (Raw_)
                        {
                            Raw_->Close();
                        }
                        CompleteWriteRequest(Request, ErrorCode);
                        Request.reset();
                        break;
                    }
                    CompleteWriteRequest(Request, ErrorCode);
                    Request.reset();
                }
            }
            catch (...)
            {
                const auto ErrorCode = make_error_code(Error::IoError);
                Teardown(ErrorCode);
                if (Raw_)
                {
                    Raw_->Close();
                }
                CompleteWriteRequest(Request, ErrorCode);
                Request.reset();
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
            if constexpr (requires(const FrameType &Value)
                          {
                              C::IsWindowUpdate(Value);
                              C::IsWindowAck(Value);
                              C::IsOpenFrame(Value);
                              C::WindowDelta(Value);
                          })
            {
                if (C::IsWindowUpdate(Frame) && C::IsWindowAck(Frame))
                {
                    AddSendWindow(C::FrameStreamId(Frame), C::WindowDelta(Frame));
                    return;
                }
                if (C::IsWindowUpdate(Frame) && !C::IsOpenFrame(Frame))
                {
                    AddSendWindow(C::FrameStreamId(Frame), C::WindowDelta(Frame));
                    return;
                }
            }

            // 会话级控制帧（心跳/GO_AWAY）：不进入虚拟流状态机。
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
                    ProtocolErrorTeardown();
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
                InitializeIncomingFlow(Frame);
                if constexpr (requires(const FrameType &Value)
                              {
                                  C::IsOpenFrame(Value);
                                  C::BuildOpenAck(std::uint32_t{});
                              })
                {
                    if (C::IsOpenFrame(Frame))
                    {
                        ProtocolEc AckError;
                        (void)EnqueueWrite(C::BuildOpenAck(Id), AckError);
                    }
                }
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
                if constexpr (requires { C::AllowsImplicitOpen; })
                {
                    if (!C::AllowsImplicitOpen)
                    {
                        ProtocolErrorTeardown();
                        break;
                    }
                }
                else
                {
                    ProtocolErrorTeardown();
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
                    if (It->second->IsPeerEof())
                    {
                        ProtocolErrorTeardown();
                        break;
                    }
                    It->second->SetPeerEof();
                }
                break;
            }
            case StreamEvent::Rst: {
                const auto Id = C::FrameStreamId(Frame);
                RemoveFlow(Id);
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
        auto Teardown(
            const ProtocolEc &PendingError = make_error_code(Error::BrokenPipe)) -> void
        {
            SessionClosed_ = true;
            SessionRxBytes_ = 0;
            AcceptNotify_.try_send(boost::system::error_code{});
            WakeFlowWaiters();
            FailPendingWrites(PendingError);
            for (auto &[Id, Handle] : Streams_)
            {
                if (Handle)
                {
                    Handle->SetPeerEof();
                }
            }
            Streams_.clear();
            Incoming_.clear();
            Flow_.clear();
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
            if (!Handle || Handle->IsClosed())
            {
                return true;
            }
            const auto Used = (std::min)(SessionRxBytes_, Opt_.MaxSessionRxBytes);
            if (Opt_.MaxSessionRxBytes != 0 &&
                Payload.size() > Opt_.MaxSessionRxBytes - Used)
            {
                return false;
            }
            if constexpr (UsesFlowControl())
            {
                const auto It = Flow_.find(Handle->Id());
                if (It == Flow_.end() || Payload.size() > It->second.ReceiveWindow)
                {
                    return false;
                }
                It->second.ReceiveWindow -= Payload.size();
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

        static auto RunFrame(std::shared_ptr<Session> Self) -> Net::awaitable<void>
        {
            co_await Self->FrameLoop();
        }

        static auto RunWriter(std::shared_ptr<Session> Self) -> Net::awaitable<void>
        {
            co_await Self->WriteLoop();
        }

        auto CancelRaw() noexcept -> void
        {
            if (Raw_)
            {
                Raw_->Cancel();
            }
            WakeFlowWaiters();
            AcceptNotify_.try_send(boost::system::error_code{});
        }

        SharedTransmission Raw_; ///< 底层传输
        SessionOptions Opt_; ///< 会话选项
        Net::any_io_executor Ex_; ///< 执行器
        std::shared_ptr<Preview::Runtime::SessionControl> Control_; ///< owner-held 控制器
        Preview::Lifecycle::TaskIdentity Identity_{}; ///< 父任务身份
        Net::experimental::channel<void(boost::system::error_code)> AcceptNotify_; ///< 新流通知
        std::map<std::uint32_t, std::shared_ptr<StreamHandle<Memory>>> Streams_; ///< 流表（ID → 句柄）
        std::deque<std::shared_ptr<StreamHandle<Memory>>> Incoming_; ///< 入向流队列（待 Accept）
        std::deque<std::shared_ptr<WriteRequest>> PendingWrites_; ///< 唯一 writer 队列
        std::map<std::uint32_t, FlowState> Flow_; ///< yamux 每流发送/接收窗口
        std::uint32_t NextId_{0}; ///< 下一个流 ID 候选
        bool StreamIdExhausted_{false}; ///< 32 位流 ID 已耗尽
        std::size_t SessionRxBytes_{0}; ///< 会话接收队列当前总字节数
        std::size_t PendingWriteBytes_{0}; ///< 当前未完成写请求总字节数
        bool SessionClosed_{false}; ///< 会话已关闭
        bool Canceled_{false}; ///< Accept 被取消（一次性）
        bool WriterRunning_{false}; ///< writer 协程已运行
    };

} // namespace Preview::Mux
