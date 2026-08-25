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
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <deque>
#include <map>
#include <memory>
#include <span>
#include <vector>

#include <common/Core/ByteSpan.hpp>
#include <common/Core/Diagnose/Log.hpp>
#include <common/Core/Error.hpp>
#include <common/Core/Memory/Container.hpp>
#include <common/Core/Memory/Pointer.hpp>
#include <common/Core/Role.hpp>
#include <common/Core/SessionBase.hpp>
#include <common/Core/Transmission.hpp>
#include <common/Core/Transport/Stream.hpp>
#include <common/Protocols/Mux/Codec.hpp>

namespace Preview::Mux
{

    /**
     * @class SessionIface
     * @brief 会话内部接口（供虚拟流回调，类型擦除）
     * @details 虚拟流句柄经本接口访问所属会话：推送数据、发送
     *          FIN/RST、从流表移除自身。会话实现持有多态会话
     *          指针以解耦模板实例。
     */
    class SessionIface
    {
    public:
        virtual ~SessionIface() = default;

        /**
         * @brief 推送数据帧到流
         * @param StreamId 流标识符
         * @param Data 负载数据
         * @return 错误码（会话/底层关闭 = broken_pipe）
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
         * @brief 流从表中移除（清理）
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
     * @brief 虚拟流句柄（复用会话底层连接，满足 SessionBase）
     * @tparam Memory 会话内存策略（默认 8KB Arena；接收队列经
     *                mem_.Arena() 分配，随流析构一次性回收）
     * @details 每条虚拟流维护独立接收队列与通知通道，数据由会话
     *          帧循环经 PushRx 投递。关闭语义三态：
     *          - Shutdown()：半关（本端发 FIN，仍可读对端数据）
     *          - Reset()：重置（发 RST，本端丢弃流）
     *          - Close()：本地关闭（不发帧，仅从流表移除）
     *          对端事件经 SetPeerEof（FIN）/ OnRst（RST）唤醒
     *          挂起读并返回 0。
     */
    template <Preview::Memory::Restrict Memory = Preview::Memory::SessionResource<>>
    class StreamHandle : public SessionBase
    {
    public:
        /// 内存策略类型（对外暴露，供嵌套层/测试使用）
        using MemoryType = Memory;

        /**
         * @brief 构造
         * @param Id 流标识
         * @param Session 所属会话
         * @param ex 执行器
         */
        StreamHandle(std::uint32_t Id, std::shared_ptr<SessionIface> Session, net::any_io_executor ex)
            : id_(Id), session_(std::move(Session)), ex_(std::move(ex)), notify_(ex_, 1), timer_(ex_)
        {
        }

        /**
         * @brief 获取流标识
         * @return 流标识符
         */
        [[nodiscard]] auto Id() const noexcept -> std::uint32_t
        {
            return id_;
        }

        /**
         * @brief 读取数据
         * @param buf 接收缓冲区
         * @return 实际读取字节数；0 = 对端半关 / 关闭 / 超时 / 取消
         * @details 队列有数据立即消费；否则挂起等待通知，支持
         *          可配置读超时（timeout_，0 = 永久等待）。
         */
        auto ReadSome(std::span<std::uint8_t> buf) -> net::awaitable<std::size_t> override
        {
            using namespace boost::asio::experimental::awaitable_operators;

            while (true)
            {
                if (closed_ || canceled_)
                {
                    canceled_ = false;
                    co_return 0;
                }
                if (!rx_.empty())
                {
                    const auto &front = rx_.front();
                    const auto n = std::min(buf.size(), front.size());
                    std::memcpy(buf.data(), front.data(), n);
                    if (n < front.size())
                    {
                        rx_.front().erase(rx_.front().begin(),
                                          rx_.front().begin() + static_cast<std::ptrdiff_t>(n));
                    }
                    else
                    {
                        rx_.pop_front();
                    }
                    co_return n;
                }
                if (PeerEof_)
                {
                    co_return 0;
                }

                notify_.reset();
                if (timeout_.count() > 0)
                {
                    timer_.expires_after(timeout_);
                    auto Result = co_await (notify_.async_receive(net::use_awaitable) ||
                                            timer_.async_wait(net::use_awaitable));
                    if (Result.index() == 1)
                    {
                        co_return 0;
                    }
                }
                else
                {
                    co_await notify_.async_receive(net::use_awaitable);
                }
            }
        }

        /**
         * @brief 写入数据（经会话封装为数据帧）
         * @param buf 待写数据
         * @return 错误码（流已关 / 会话已关 = broken_pipe）
         */
        auto WriteAll(std::span<const std::uint8_t> buf) -> net::awaitable<ProtocolEc> override
        {
            if (closed_ || !session_ || !session_->IsOpen())
            {
                co_return make_error_code(Error::broken_pipe);
            }
            co_return co_await session_->PushData(id_, buf);
        }

        /**
         * @brief 半关（发 FIN，对端仍可回数据；本端仍可读对端后续数据）
         * @details 置 FinSent_ 标志，后续 IsFinSent() 返回 true。
         */
        auto Shutdown() -> net::awaitable<void> override
        {
            FinSent_ = true;
            if (session_)
            {
                co_await session_->SendFin(id_);
            }
            co_return;
        }

        /**
         * @brief 关闭（本地关闭，不发帧，从流表移除）
         * @details 置 closed_ 并唤醒挂起读（返回 0）。
         */
        auto Close() -> net::awaitable<void> override
        {
            closed_ = true;
            notify_.try_send(boost::system::error_code{});
            if (session_)
            {
                session_->RemoveStream(id_);
            }
            co_return;
        }

        /**
         * @brief 重置（发 RST，本端丢弃流）
         * @details 置 closed_ + 发送 BuildRst 帧 + 从流表移除，
         * 与 Close() 的区别是对端会收到重置通知。
         */
        auto Reset() -> net::awaitable<void>
        {
            closed_ = true;
            notify_.try_send(boost::system::error_code{});
            if (session_)
            {
                co_await session_->SendRst(id_);
                session_->RemoveStream(id_);
            }
            co_return;
        }

        /**
         * @brief 取消挂起读
         * @details 置 canceled_ 标志并唤醒挂起读（返回 0，一次性）。
         */
        auto Cancel() -> void override
        {
            canceled_ = true;
            notify_.try_send(boost::system::error_code{});
        }

        /**
         * @brief 设置读超时
         * @param ms 超时时间（0 = 禁用）
         */
        auto SetTimeout(std::chrono::milliseconds ms) -> void override
        {
            timeout_ = ms;
        }

        /**
         * @brief 流是否打开
         * @return true = 未关闭且会话可用
         */
        [[nodiscard]] auto IsOpen() const -> bool override
        {
            return !closed_ && session_ && session_->IsOpen();
        }

        /**
         * @brief 获取执行器
         * @return 流执行器
         */
        [[nodiscard]] auto Executor() const -> net::any_io_executor override
        {
            return ex_;
        }

        /**
         * @brief 对端是否半关（收到 FIN）
         * @return true = 对端已发送 FIN
         */
        [[nodiscard]] auto IsPeerEof() const -> bool
        {
            return PeerEof_;
        }

        /**
         * @brief 流是否已关闭
         * @return true = 本地关闭（Close/Reset）或收到对端 RST
         */
        [[nodiscard]] auto IsClosed() const -> bool
        {
            return closed_;
        }

        /**
         * @brief 本端是否已发送 FIN（半关）
         * @return true = Shutdown() 已调用
         */
        [[nodiscard]] auto IsFinSent() const -> bool
        {
            return FinSent_;
        }

        /**
         * @brief 内部：推送数据到接收队列（会话帧循环调用）
         * @param Data 负载数据
         * @details 队列元素经流内存策略的 Arena 分配（热路径零释放）。
         */
        auto PushRx(std::span<const std::uint8_t> Data) -> void
        {
            rx_.emplace_back(Data.begin(), Data.end(), mem_.Arena());
            notify_.try_send(boost::system::error_code{});
        }

        /**
         * @brief 内部：对端半关（FIN 处理，唤醒挂起读返回 0）
         */
        auto SetPeerEof() -> void
        {
            PeerEof_ = true;
            notify_.try_send(boost::system::error_code{});
        }

        /**
         * @brief 内部：对端重置（RST 处理，流被对端丢弃，读返回 0）
         */
        auto OnRst() -> void
        {
            closed_ = true;
            notify_.try_send(boost::system::error_code{});
        }

    private:
        std::uint32_t id_;                                                           ///< 流标识符
        std::shared_ptr<SessionIface> session_;                                     ///< 所属会话
        net::any_io_executor ex_;                                                    ///< 执行器
        Memory mem_;                                                                 ///< 会话内存策略（Arena，接收队列零释放分配）
        std::deque<typename std::template Buffer<std::uint8_t>> rx_;              ///< 接收队列
        boost::asio::experimental::channel<void(boost::system::error_code)> notify_; ///< 数据到达通知
        net::steady_timer timer_;                                                    ///< 读超时定时器
        std::chrono::milliseconds timeout_{0};                                       ///< 读超时（0 = 禁用）
        bool PeerEof_{false};                                                       ///< 对端半关（收到 FIN）
        bool closed_{false};                                                         ///< 本地关闭或对端 RST
        bool FinSent_{false};                                                       ///< 本端已发送 FIN
        bool canceled_{false};                                                       ///< 读被取消（一次性）
    };

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
            auto self = std::shared_ptr<Session<C, Memory>>(new Session<C, Memory>(std::move(raw), opt));
            self->Start();
            return self;
        }

        /**
         * @brief 打开新流（客户端视角）
         * @return 流句柄；nullptr = 会话已关闭 / 流数达上限
         * @details 分配流 ID（奇偶随角色）并发送开流帧。
         */
        auto OpenStream() -> net::awaitable<std::shared_ptr<StreamHandle<Memory>>>
        {
            if (!raw_ || !raw_->IsOpen())
            {
                co_return nullptr;
            }
            const auto Id = AllocateId();
            if (Id == 0)
            {
                co_return nullptr;
            }
            co_await RawWrite(C::BuildOpen(Id));
            auto Handle = std::make_shared<StreamHandle<Memory>>(Id, this->shared_from_this(), ex_);
            streams_[Id] = Handle;
            co_return Handle;
        }

        /**
         * @brief 接受新流（服务端视角，阻塞直到新流到达或会话关闭）
         * @return 流句柄；nullptr = 会话关闭 / Cancel() 唤醒
         * @details 经 Cancel() 唤醒后返回 nullptr（一次性，可再次调用）。
         */
        auto AcceptStream() -> net::awaitable<std::shared_ptr<StreamHandle<Memory>>>
        {
            while (raw_ && raw_->IsOpen())
            {
                if (canceled_)
                {
                    canceled_ = false;
                    co_return nullptr;
                }
                if (!incoming_.empty())
                {
                    auto Handle = incoming_.front();
                    incoming_.pop_front();
                    co_return Handle;
                }
                if (SessionClosed_)
                {
                    co_return nullptr;
                }
                accept_notify_.reset();
                co_await accept_notify_.async_receive(net::use_awaitable);
            }
            co_return nullptr;
        }

        /**
         * @brief 推送数据帧到流（StreamHandle 回调）
         * @param StreamId 流标识符
         * @param Data 负载数据
         * @return 错误码（会话/底层关闭 = broken_pipe）
         * @details 大负载分块发送（smux 帧长上限 64KB，yamux/h2mux
         * 无此限制，块大小 = max_payload_len）。
         */
        auto PushData(std::uint32_t StreamId, std::span<const std::uint8_t> Data)
            -> net::awaitable<ProtocolEc> override
        {
            if (!raw_ || !raw_->IsOpen())
            {
                co_return make_error_code(Error::broken_pipe);
            }
            std::size_t chunk;
            if (C::max_payload_len > 0)
            {
                chunk = C::max_payload_len;
            }
            else
            {
                chunk = Data.size();
            }
            std::size_t Done = 0;
            while (Done < Data.size())
            {
                const auto n = std::min(chunk, Data.size() - Done);
                const auto ec = co_await RawWrite(C::BuildData(StreamId, Data.subspan(Done, n)));
                if (ec)
                {
                    // 数据面写失败必须上抛：静默丢弃会让流进入假活状态（对端永远等不到数据）
                    co_return ec;
                }
                Done += n;
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
            if (raw_ && raw_->IsOpen())
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
            if (raw_ && raw_->IsOpen())
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
            streams_.erase(StreamId);
        }

        /**
         * @brief 会话是否打开
         * @return true = 会话可用
         */
        [[nodiscard]] auto IsOpen() const -> bool override
        {
            return !SessionClosed_ && raw_ && raw_->IsOpen();
        }

        /**
         * @brief 获取执行器
         * @return 会话执行器
         */
        [[nodiscard]] auto Executor() const -> net::any_io_executor override
        {
            return ex_;
        }

        /**
         * @brief 当前活跃流数
         * @return 流表中流数量
         */
        [[nodiscard]] auto StreamCount() const -> std::size_t
        {
            return streams_.size();
        }

        /**
         * @brief 关闭会话（全部流 + 底层连接）
         * @details 置 SessionClosed_，唤醒挂起 AcceptStream 与
         * 全部流（对端半关语义），清空流表并关闭底层。
         */
        auto Close() -> net::awaitable<void>
        {
            Teardown();
            if (raw_)
            {
                raw_->Close();
            }
            co_return;
        }

        /**
         * @brief 取消挂起的 AcceptStream（不关闭会话）
         * @details 置 canceled_ 标志并唤醒 accept_notify_，挂起的
         * AcceptStream 返回 nullptr（一次性，可再次接受）。
         */
        auto Cancel() -> void
        {
            canceled_ = true;
            accept_notify_.try_send(boost::system::error_code{});
        }

    private:
        /**
         * @brief 底层读取（Transmission 适配：u8 视图 + 无 ec）
         * @param buf 接收缓冲区（uint8_t 视图）
         * @return 实际读取字节数；0 = 对端关闭 / EOF
         */
        auto RawRead(std::span<std::uint8_t> buf) -> net::awaitable<std::size_t>
        {
            std::error_code ec;
            const auto n = co_await raw_->AsyncReadSome(AsBytes(buf), ec);
            if (ec)
            {
                co_return 0;
            }
            co_return n;
        }

        /**
         * @brief 底层写入（Transmission 适配：u8 视图 + ec 转错误码）
         * @param buf 待写数据（uint8_t 视图）
         * @return 错误码（成功 = 空）
         */
        auto RawWrite(std::span<const std::uint8_t> buf) -> net::awaitable<ProtocolEc>
        {
            std::error_code ec;
            co_await raw_->AsyncWriteSome(AsBytes(buf), ec);
            if (ec)
            {
                // 底层错误码属 fault 类别，直接搬 value 到 generic_category 会错乱；
                // 会话层只关心写失败事实，统一映射为协议库 io_error
                co_return make_error_code(Error::io_error);
            }
            co_return boost::system::error_code{};
        }

        /**
         * @brief 构造（私有，经 Create 创建）
         * @param raw 底层传输
         * @param opt 会话选项
         */
        Session(SharedTransmission raw, const SessionOptions &opt)
            : raw_(std::move(raw)), opt_(opt), ex_(raw_->Executor()), accept_notify_(ex_, 1)
        {
        }

        /**
         * @brief 启动帧循环（detached 协程）
         * @details 按值捕获 self 保活，帧循环退出后会话自行销毁。
         */
        auto Start() -> void
        {
            auto self = this->shared_from_this();
            net::co_spawn(
                ex_, [self]() -> net::awaitable<void> { co_await self->FrameLoop(); }, net::detached);
        }

        /**
         * @brief 帧循环：读帧 → 分发
         * @details 分段读取帧头与负载（负载上限 = max_payload_len），
         * 解析成功后经 Dispatch 分发；底层关闭时置
         * SessionClosed_ 并唤醒挂起 AcceptStream。
         */
        auto FrameLoop() -> net::awaitable<void>
        {
            std::vector<std::uint8_t> Header(C::header_len);
            std::vector<std::uint8_t> payload;

            while (raw_ && raw_->IsOpen() && !SessionClosed_)
            {
                // 读帧头
                std::size_t Done = 0;
                while (Done < C::header_len)
                {
                    const auto n = co_await RawRead(
                        std::span<std::uint8_t>(Header.data() + Done, C::header_len - Done));
                    if (n == 0)
                    {
                        Teardown();
                        co_return;
                    }
                    Done += n;
                }

                // 解析帧头
                FrameType Frame{};
                if (C::ParseHeader(Header, Frame) != Error::none)
                {
                    Diagnose::Warn("mux Frame Header Parse Failed; closing Session");
                    ProtocolErrorTeardown();
                    co_return;
                }

                // 读负载
                const auto len = C::PayloadLen(Frame);
                if (len == 0)
                {
                    if (C::ParsePayload(Frame, {}) != Error::none)
                    {
                        Diagnose::Warn("mux Empty payload Parse Failed; closing Session");
                        ProtocolErrorTeardown();
                        co_return;
                    }
                    Dispatch(Frame, {});
                    continue;
                }
                if (len > C::max_payload_len)
                {
                    Diagnose::Warn("mux Frame payload exceeds limit; closing Session");
                    ProtocolErrorTeardown();
                    co_return;
                }
                payload.resize(len);
                Done = 0;
                while (Done < len)
                {
                    const auto n =
                        co_await RawRead(std::span<std::uint8_t>(payload.data() + Done, len - Done));
                    if (n == 0)
                    {
                        Teardown();
                        co_return;
                    }
                    Done += n;
                }
                if (C::ParsePayload(Frame, payload) != Error::none)
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
            const auto event = C::FrameEvent(Frame);
            switch (event)
            {
            case StreamEvent::Open: {
                const auto Id = C::FrameStreamId(Frame);
                if (Id == 0 || streams_.contains(Id))
                {
                    break;
                }
                auto Handle = std::make_shared<StreamHandle<Memory>>(Id, this->shared_from_this(), ex_);
                streams_[Id] = Handle;
                incoming_.push_back(Handle);
                accept_notify_.try_send(boost::system::error_code{});
                if (!payload.empty())
                {
                    Handle->PushRx(payload);
                }
                break;
            }
            case StreamEvent::Data: {
                const auto Id = C::FrameStreamId(Frame);
                const auto it = streams_.find(Id);
                if (it != streams_.end() && it->second)
                {
                    it->second->PushRx(payload);
                    break;
                }
                // 隐式开流（h2mux 无 SYN 帧：首数据帧即开流）
                if (Id == 0)
                {
                    break;
                }
                auto Handle = std::make_shared<StreamHandle<Memory>>(Id, this->shared_from_this(), ex_);
                streams_[Id] = Handle;
                incoming_.push_back(Handle);
                accept_notify_.try_send(boost::system::error_code{});
                if (!payload.empty())
                {
                    Handle->PushRx(payload);
                }
                break;
            }
            case StreamEvent::fin: {
                const auto Id = C::FrameStreamId(Frame);
                const auto it = streams_.find(Id);
                if (it != streams_.end() && it->second)
                {
                    it->second->SetPeerEof();
                }
                break;
            }
            case StreamEvent::rst: {
                const auto Id = C::FrameStreamId(Frame);
                const auto it = streams_.find(Id);
                if (it != streams_.end() && it->second)
                {
                    it->second->OnRst(); // 唤醒挂起读（返回 0）
                }
                streams_.erase(Id);
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
            if (streams_.size() >= opt_.MaxStreams)
            {
                return 0;
            }
            const bool odd = opt_.Role == Preview::Role::Client;
            for (std::size_t i = 0; i < 65536; ++i)
            {
                if (NextId_ == 0)
                {
                    if (odd)
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
                    if (odd)
                    {
                        NextId_ = 1u;
                    }
                    else
                    {
                        NextId_ = 2u;
                    }
                }
                if (!streams_.contains(NextId_))
                {
                    return NextId_;
                }
            }
            return 0;
        }

        /**
         * @brief 会话拆除：置关闭标志，唤醒挂起读并清空流表/入向队列
         * @details 打破 Session ↔ StreamHandle 的 shared_ptr 循环：
         * 帧循环退出或 Close() 时清空 streams_ 与 incoming_，释放
         * 句柄对会话的引用，避免底层断开后残余句柄与会话互相保活
         * 造成泄漏。
         */
        auto Teardown() -> void
        {
            SessionClosed_ = true;
            accept_notify_.try_send(boost::system::error_code{});
            for (auto &[Id, Handle] : streams_)
            {
                if (Handle)
                {
                    Handle->SetPeerEof();
                }
            }
            streams_.clear();
            incoming_.clear();
        }

        /**
         * @brief 处理会话级协议错误并关闭底层传输
         * @details 帧头、长度或 payload 校验失败后无法安全定位下一帧，
         *          必须同时清理会话状态并关闭 raw，不能继续读取造成永久失步。
         */
        auto ProtocolErrorTeardown() -> void
        {
            Teardown();
            if (raw_)
            {
                raw_->Close();
            }
        }

        SharedTransmission raw_;                                                     ///< 底层传输
        SessionOptions opt_;                                                               ///< 会话选项
        net::any_io_executor ex_;                                                           ///< 执行器
        boost::asio::experimental::channel<void(boost::system::error_code)> accept_notify_; ///< 新流通知
        std::map<std::uint32_t, std::shared_ptr<StreamHandle<Memory>>> streams_; ///< 流表（ID → 句柄）
        std::deque<std::shared_ptr<StreamHandle<Memory>>> incoming_;             ///< 入向流队列（待 Accept）
        std::uint32_t NextId_{0};                                        ///< 下一个流 ID 候选
        bool SessionClosed_{false};                                      ///< 会话已关闭
        bool canceled_{false};                                            ///< Accept 被取消（一次性）
    };

} // namespace Preview::Mux
