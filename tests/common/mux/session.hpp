/**
 * @file session.hpp
 * @brief 多路复用共享会话框架（模板注入帧编解码策略）
 * @details 借鉴 Boost.Beast 模板策略模式：流表管理、帧循环、队列、
 *          背压只实现一次，smux/yamux/h2mux 通过 frame_codec 策略
 *          注入帧构造（open/data/fin/rst）与帧事件判定
 *          （open/data/fin/rst），实现"一套会话逻辑，三个协议"。
 *          会话拥有多条虚拟流（stream_handle），每条流满足统一
 *          session_base 接口，供上层协议（vmess/vless/...）承载。
 *          底层传输经 transport_base 类型擦除，支持内存流/套接字流。
 * @note 帧策略需额外提供（concept 之外，经 if constexpr 检测）：
 *          - frame_event(frame) / frame_stream_id(frame)
 *          - is_control(frame)（会话级控制帧判定）
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

#include <common/core/error.hpp>
#include <common/core/role.hpp>
#include <common/core/session_base.hpp>
#include <common/core/transport/stream.hpp>
#include <common/core/transport/transport_base.hpp>
#include <common/mux/codec.hpp>

namespace psmtest::mux
{

    /**
     * @class session_iface
     * @brief 会话内部接口（供虚拟流回调，类型擦除）
     * @details 虚拟流句柄经本接口访问所属会话：推送数据、发送
     *          FIN/RST、从流表移除自身。会话实现持有多态会话
     *          指针以解耦模板实例。
     */
    class session_iface
    {
    public:
        virtual ~session_iface() = default;

        /**
         * @brief 推送数据帧到流
         * @param stream_id 流标识符
         * @param data 负载数据
         * @return 错误码（会话/底层关闭 = broken_pipe）
         */
        virtual auto push_data(std::uint32_t stream_id, std::span<const std::uint8_t> data)
            -> net::awaitable<protocol_ec> = 0;

        /**
         * @brief 发送 FIN（半关）
         * @param stream_id 流标识符
         */
        virtual auto send_fin(std::uint32_t stream_id) -> net::awaitable<void> = 0;

        /**
         * @brief 发送 RST（重置流）
         * @param stream_id 流标识符
         */
        virtual auto send_rst(std::uint32_t stream_id) -> net::awaitable<void> = 0;

        /**
         * @brief 流从表中移除（清理）
         * @param stream_id 流标识符
         */
        virtual auto remove_stream(std::uint32_t stream_id) -> void = 0;

        /**
         * @brief 会话是否打开
         * @return true = 会话可用
         */
        [[nodiscard]] virtual auto is_open() const -> bool = 0;

        /**
         * @brief 获取执行器
         * @return 会话执行器
         */
        [[nodiscard]] virtual auto executor() const -> net::any_io_executor = 0;
    };

    /**
     * @class stream_handle
     * @brief 虚拟流句柄（复用会话底层连接，满足 session_base）
     * @details 每条虚拟流维护独立接收队列与通知通道，数据由会话
     *          帧循环经 push_rx 投递。关闭语义三态：
     *          - shutdown()：半关（本端发 FIN，仍可读对端数据）
     *          - reset()：重置（发 RST，本端丢弃流）
     *          - close()：本地关闭（不发帧，仅从流表移除）
     *          对端事件经 set_peer_eof（FIN）/ on_rst（RST）唤醒
     *          挂起读并返回 0。
     */
    class stream_handle : public session_base
    {
    public:
        /**
         * @brief 构造
         * @param id 流标识
         * @param session 所属会话
         * @param ex 执行器
         */
        stream_handle(std::uint32_t id, std::shared_ptr<session_iface> session, net::any_io_executor ex)
            : id_(id), session_(std::move(session)), ex_(std::move(ex)), notify_(ex_, 1), timer_(ex_)
        {
        }

        /**
         * @brief 获取流标识
         * @return 流标识符
         */
        [[nodiscard]] auto id() const noexcept -> std::uint32_t
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
        auto read_some(std::span<std::uint8_t> buf) -> net::awaitable<std::size_t> override
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
                if (peer_eof_)
                {
                    co_return 0;
                }

                notify_.reset();
                if (timeout_.count() > 0)
                {
                    timer_.expires_after(timeout_);
                    auto result = co_await (notify_.async_receive(net::use_awaitable) ||
                                            timer_.async_wait(net::use_awaitable));
                    if (result.index() == 1)
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
        auto write_all(std::span<const std::uint8_t> buf) -> net::awaitable<protocol_ec> override
        {
            if (closed_ || !session_ || !session_->is_open())
            {
                co_return make_error_code(error::broken_pipe);
            }
            co_return co_await session_->push_data(id_, buf);
        }

        /**
         * @brief 半关（发 FIN，对端仍可回数据；本端仍可读对端后续数据）
         * @details 置 fin_sent_ 标志，后续 is_fin_sent() 返回 true。
         */
        auto shutdown() -> net::awaitable<void> override
        {
            fin_sent_ = true;
            if (session_)
            {
                co_await session_->send_fin(id_);
            }
            co_return;
        }

        /**
         * @brief 关闭（本地关闭，不发帧，从流表移除）
         * @details 置 closed_ 并唤醒挂起读（返回 0）。
         */
        auto close() -> net::awaitable<void> override
        {
            closed_ = true;
            notify_.try_send(boost::system::error_code{});
            if (session_)
            {
                session_->remove_stream(id_);
            }
            co_return;
        }

        /**
         * @brief 重置（发 RST，本端丢弃流）
         * @details 置 closed_ + 发送 build_rst 帧 + 从流表移除，
         * 与 close() 的区别是对端会收到重置通知。
         */
        auto reset() -> net::awaitable<void>
        {
            closed_ = true;
            notify_.try_send(boost::system::error_code{});
            if (session_)
            {
                co_await session_->send_rst(id_);
                session_->remove_stream(id_);
            }
            co_return;
        }

        /**
         * @brief 取消挂起读
         * @details 置 canceled_ 标志并唤醒挂起读（返回 0，一次性）。
         */
        auto cancel() -> void override
        {
            canceled_ = true;
            notify_.try_send(boost::system::error_code{});
        }

        /**
         * @brief 设置读超时
         * @param ms 超时时间（0 = 禁用）
         */
        auto set_timeout(std::chrono::milliseconds ms) -> void override
        {
            timeout_ = ms;
        }

        /**
         * @brief 流是否打开
         * @return true = 未关闭且会话可用
         */
        [[nodiscard]] auto is_open() const -> bool override
        {
            return !closed_ && session_ && session_->is_open();
        }

        /**
         * @brief 获取执行器
         * @return 流执行器
         */
        [[nodiscard]] auto executor() const -> net::any_io_executor override
        {
            return ex_;
        }

        /**
         * @brief 对端是否半关（收到 FIN）
         * @return true = 对端已发送 FIN
         */
        [[nodiscard]] auto is_peer_eof() const -> bool
        {
            return peer_eof_;
        }

        /**
         * @brief 流是否已关闭
         * @return true = 本地关闭（close/reset）或收到对端 RST
         */
        [[nodiscard]] auto is_closed() const -> bool
        {
            return closed_;
        }

        /**
         * @brief 本端是否已发送 FIN（半关）
         * @return true = shutdown() 已调用
         */
        [[nodiscard]] auto is_fin_sent() const -> bool
        {
            return fin_sent_;
        }

        /**
         * @brief 内部：推送数据到接收队列（会话帧循环调用）
         * @param data 负载数据
         */
        auto push_rx(std::span<const std::uint8_t> data) -> void
        {
            rx_.emplace_back(data.begin(), data.end());
            notify_.try_send(boost::system::error_code{});
        }

        /**
         * @brief 内部：对端半关（FIN 处理，唤醒挂起读返回 0）
         */
        auto set_peer_eof() -> void
        {
            peer_eof_ = true;
            notify_.try_send(boost::system::error_code{});
        }

        /**
         * @brief 内部：对端重置（RST 处理，流被对端丢弃，读返回 0）
         */
        auto on_rst() -> void
        {
            closed_ = true;
            notify_.try_send(boost::system::error_code{});
        }

    private:
        std::uint32_t id_;                                                           ///< 流标识符
        std::shared_ptr<session_iface> session_;                                     ///< 所属会话
        net::any_io_executor ex_;                                                    ///< 执行器
        std::deque<std::vector<std::uint8_t>> rx_;                                   ///< 接收队列
        boost::asio::experimental::channel<void(boost::system::error_code)> notify_; ///< 数据到达通知
        net::steady_timer timer_;                                                    ///< 读超时定时器
        std::chrono::milliseconds timeout_{0};                                       ///< 读超时（0 = 禁用）
        bool peer_eof_{false};                                                       ///< 对端半关（收到 FIN）
        bool closed_{false};                                                         ///< 本地关闭或对端 RST
        bool fin_sent_{false};                                                       ///< 本端已发送 FIN
        bool canceled_{false};                                                       ///< 读被取消（一次性）
    };

    /**
     * @struct session_options
     * @brief 多路复用会话选项
     * @details 构造后只读，经 session::create 传入。
     */
    struct session_options
    {
        /// 连接角色（决定流 ID 奇偶：client 奇数 / server 偶数）
        psmtest::role role{psmtest::role::client};
        /// 最大并发流数
        std::size_t max_streams{256};
        /// 读超时（0 = 禁用）
        std::chrono::milliseconds timeout{0};
    };

    /**
     * @class session
     * @brief 多路复用会话（共享框架，模板注入帧编解码策略）
     * @tparam C 帧编解码策略（frame_codec concept）
     * @details 维护流表与入向队列，后台帧循环读取底层传输并分发
     *          帧事件（open/data/fin/rst）。accept_stream / open_stream
     *          分别对应服务端/客户端开流视角；cancel() 可唤醒挂起
     *          的 accept_stream 而不关闭会话。
     */
    template <typename C>
    class session : public session_iface, public std::enable_shared_from_this<session<C>>
    {
    public:
        using frame_type = typename C::frame_type;

        /**
         * @brief 创建会话（同时启动帧循环）
         * @param raw 底层传输（类型擦除）
         * @param opt 会话选项
         * @return 会话实例
         */
        static auto create(std::shared_ptr<transport_base> raw, const session_options &opt)
            -> std::shared_ptr<session<C>>
        {
            auto self = std::shared_ptr<session<C>>(new session<C>(std::move(raw), opt));
            self->start();
            return self;
        }

        /**
         * @brief 打开新流（客户端视角）
         * @return 流句柄；nullptr = 会话已关闭 / 流数达上限
         * @details 分配流 ID（奇偶随角色）并发送开流帧。
         */
        auto open_stream() -> net::awaitable<std::shared_ptr<stream_handle>>
        {
            if (!raw_ || !raw_->is_open())
            {
                co_return nullptr;
            }
            const auto id = allocate_id();
            if (id == 0)
            {
                co_return nullptr;
            }
            co_await raw_->write_all(C::build_open(id));
            auto handle = std::make_shared<stream_handle>(id, this->shared_from_this(), ex_);
            streams_[id] = handle;
            co_return handle;
        }

        /**
         * @brief 接受新流（服务端视角，阻塞直到新流到达或会话关闭）
         * @return 流句柄；nullptr = 会话关闭 / cancel() 唤醒
         * @details 经 cancel() 唤醒后返回 nullptr（一次性，可再次调用）。
         */
        auto accept_stream() -> net::awaitable<std::shared_ptr<stream_handle>>
        {
            while (raw_ && raw_->is_open())
            {
                if (canceled_)
                {
                    canceled_ = false;
                    co_return nullptr;
                }
                if (!incoming_.empty())
                {
                    auto handle = incoming_.front();
                    incoming_.pop_front();
                    co_return handle;
                }
                if (session_closed_)
                {
                    co_return nullptr;
                }
                accept_notify_.reset();
                co_await accept_notify_.async_receive(net::use_awaitable);
            }
            co_return nullptr;
        }

        /**
         * @brief 推送数据帧到流（stream_handle 回调）
         * @param stream_id 流标识符
         * @param data 负载数据
         * @return 错误码（会话/底层关闭 = broken_pipe）
         * @details 大负载分块发送（smux 帧长上限 64KB，yamux/h2mux
         * 无此限制，块大小 = max_payload_len）。
         */
        auto push_data(std::uint32_t stream_id, std::span<const std::uint8_t> data)
            -> net::awaitable<protocol_ec> override
        {
            if (!raw_ || !raw_->is_open())
            {
                co_return make_error_code(error::broken_pipe);
            }
            const auto chunk = C::max_payload_len > 0 ? C::max_payload_len : data.size();
            std::size_t done = 0;
            while (done < data.size())
            {
                const auto n = std::min(chunk, data.size() - done);
                co_await raw_->write_all(C::build_data(stream_id, data.subspan(done, n)));
                done += n;
            }
            co_return boost::system::error_code{};
        }

        /**
         * @brief 发送 FIN（stream_handle 回调）
         * @param stream_id 流标识符
         */
        auto send_fin(std::uint32_t stream_id) -> net::awaitable<void> override
        {
            if (raw_ && raw_->is_open())
            {
                co_await raw_->write_all(C::build_fin(stream_id));
            }
            co_return;
        }

        /**
         * @brief 发送 RST（stream_handle 回调）
         * @param stream_id 流标识符
         */
        auto send_rst(std::uint32_t stream_id) -> net::awaitable<void> override
        {
            if (raw_ && raw_->is_open())
            {
                co_await raw_->write_all(C::build_rst(stream_id));
            }
            co_return;
        }

        /**
         * @brief 移除流（stream_handle 回调）
         * @param stream_id 流标识符
         */
        auto remove_stream(std::uint32_t stream_id) -> void override
        {
            streams_.erase(stream_id);
        }

        /**
         * @brief 会话是否打开
         * @return true = 会话可用
         */
        [[nodiscard]] auto is_open() const -> bool override
        {
            return !session_closed_ && raw_ && raw_->is_open();
        }

        /**
         * @brief 获取执行器
         * @return 会话执行器
         */
        [[nodiscard]] auto executor() const -> net::any_io_executor override
        {
            return ex_;
        }

        /**
         * @brief 当前活跃流数
         * @return 流表中流数量
         */
        [[nodiscard]] auto stream_count() const -> std::size_t
        {
            return streams_.size();
        }

        /**
         * @brief 关闭会话（全部流 + 底层连接）
         * @details 置 session_closed_，唤醒挂起 accept_stream 与
         * 全部流（对端半关语义），清空流表并关闭底层。
         */
        auto close() -> net::awaitable<void>
        {
            session_closed_ = true;
            accept_notify_.try_send(boost::system::error_code{});
            for (auto &[id, handle] : streams_)
            {
                if (handle)
                {
                    handle->set_peer_eof();
                }
            }
            streams_.clear();
            if (raw_)
            {
                co_await raw_->close();
            }
            co_return;
        }

        /**
         * @brief 取消挂起的 accept_stream（不关闭会话）
         * @details 置 canceled_ 标志并唤醒 accept_notify_，挂起的
         * accept_stream 返回 nullptr（一次性，可再次接受）。
         */
        auto cancel() -> void
        {
            canceled_ = true;
            accept_notify_.try_send(boost::system::error_code{});
        }

    private:
        /**
         * @brief 构造（私有，经 create 创建）
         * @param raw 底层传输
         * @param opt 会话选项
         */
        session(std::shared_ptr<transport_base> raw, const session_options &opt)
            : raw_(std::move(raw)), opt_(opt), ex_(raw_->executor()), accept_notify_(ex_, 1)
        {
        }

        /**
         * @brief 启动帧循环（detached 协程）
         * @details 按值捕获 self 保活，帧循环退出后会话自行销毁。
         */
        auto start() -> void
        {
            auto self = this->shared_from_this();
            net::co_spawn(
                ex_, [self]() -> net::awaitable<void> { co_await self->frame_loop(); }, net::detached);
        }

        /**
         * @brief 帧循环：读帧 → 分发
         * @details 分段读取帧头与负载（负载上限 = max_payload_len），
         * 解析成功后经 dispatch 分发；底层关闭时置
         * session_closed_ 并唤醒挂起 accept_stream。
         */
        auto frame_loop() -> net::awaitable<void>
        {
            std::vector<std::uint8_t> header(C::header_len);
            std::vector<std::uint8_t> payload;

            while (raw_ && raw_->is_open() && !session_closed_)
            {
                // 读帧头
                std::size_t done = 0;
                while (done < C::header_len)
                {
                    const auto n = co_await raw_->read_some(
                        std::span<std::uint8_t>(header.data() + done, C::header_len - done));
                    if (n == 0)
                    {
                        session_closed_ = true;
                        accept_notify_.try_send(boost::system::error_code{});
                        co_return;
                    }
                    done += n;
                }

                // 解析帧头
                frame_type frame{};
                if (C::parse_header(header, frame) != error::none)
                {
                    continue;
                }

                // 读负载
                const auto len = C::payload_len(frame);
                if (len == 0)
                {
                    dispatch(frame, {});
                    continue;
                }
                if (len > C::max_payload_len)
                {
                    continue;
                }
                payload.resize(len);
                done = 0;
                while (done < len)
                {
                    const auto n =
                        co_await raw_->read_some(std::span<std::uint8_t>(payload.data() + done, len - done));
                    if (n == 0)
                    {
                        session_closed_ = true;
                        accept_notify_.try_send(boost::system::error_code{});
                        co_return;
                    }
                    done += n;
                }
                dispatch(frame, payload);
            }
            session_closed_ = true;
            accept_notify_.try_send(boost::system::error_code{});
            co_return;
        }

        /**
         * @brief 分发帧到流 / 控制逻辑
         * @param frame 已解析帧头
         * @param payload 负载数据
         * @details open：登记新流并排入入向队列；data：投递到流，
         * 未知流隐式开流（h2mux 无 SYN 帧）；fin：置对端
         * 半关；rst：唤醒流并移除；控制帧忽略。
         */
        auto dispatch(const frame_type &frame, std::span<const std::uint8_t> payload) -> void
        {
            // 会话级控制帧（心跳/窗口/GO_AWAY）：忽略（测试库不实现流控）
            if (C::is_control(frame))
            {
                return;
            }
            const auto event = C::frame_event(frame);
            switch (event)
            {
            case stream_event::open: {
                const auto id = C::frame_stream_id(frame);
                if (id == 0 || streams_.contains(id))
                {
                    break;
                }
                auto handle = std::make_shared<stream_handle>(id, this->shared_from_this(), ex_);
                streams_[id] = handle;
                incoming_.push_back(handle);
                accept_notify_.try_send(boost::system::error_code{});
                if (!payload.empty())
                {
                    handle->push_rx(payload);
                }
                break;
            }
            case stream_event::data: {
                const auto id = C::frame_stream_id(frame);
                const auto it = streams_.find(id);
                if (it != streams_.end() && it->second)
                {
                    it->second->push_rx(payload);
                    break;
                }
                // 隐式开流（h2mux 无 SYN 帧：首数据帧即开流）
                if (id == 0)
                {
                    break;
                }
                auto handle = std::make_shared<stream_handle>(id, this->shared_from_this(), ex_);
                streams_[id] = handle;
                incoming_.push_back(handle);
                accept_notify_.try_send(boost::system::error_code{});
                if (!payload.empty())
                {
                    handle->push_rx(payload);
                }
                break;
            }
            case stream_event::fin: {
                const auto id = C::frame_stream_id(frame);
                const auto it = streams_.find(id);
                if (it != streams_.end() && it->second)
                {
                    it->second->set_peer_eof();
                }
                break;
            }
            case stream_event::rst: {
                const auto id = C::frame_stream_id(frame);
                const auto it = streams_.find(id);
                if (it != streams_.end() && it->second)
                {
                    it->second->on_rst(); // 唤醒挂起读（返回 0）
                }
                streams_.erase(id);
                break;
            }
            default: break; // 会话级/心跳帧：忽略
            }
        }

        /**
         * @brief 分配流 ID（按角色奇偶步进 2：client 奇数 / server 偶数）
         * @return 新流 ID；0 = 流数达上限 / ID 耗尽
         * @details 对齐协议规范：client 奇数 / server 偶数。
         */
        auto allocate_id() -> std::uint32_t
        {
            if (streams_.size() >= opt_.max_streams)
            {
                return 0;
            }
            const bool odd = opt_.role == psmtest::role::client;
            for (std::size_t i = 0; i < 65536; ++i)
            {
                next_id_ = next_id_ == 0 ? (odd ? 1u : 2u) : next_id_ + 2;
                if (next_id_ == 0 || next_id_ > 65535)
                {
                    next_id_ = odd ? 1u : 2u;
                }
                if (!streams_.contains(next_id_))
                {
                    return next_id_;
                }
            }
            return 0;
        }

        std::shared_ptr<transport_base> raw_;                                               ///< 底层传输
        session_options opt_;                                                               ///< 会话选项
        net::any_io_executor ex_;                                                           ///< 执行器
        boost::asio::experimental::channel<void(boost::system::error_code)> accept_notify_; ///< 新流通知
        std::map<std::uint32_t, std::shared_ptr<stream_handle>> streams_; ///< 流表（ID → 句柄）
        std::deque<std::shared_ptr<stream_handle>> incoming_;             ///< 入向流队列（待 accept）
        std::uint32_t next_id_{0};                                        ///< 下一个流 ID 候选
        bool session_closed_{false};                                      ///< 会话已关闭
        bool canceled_{false};                                            ///< accept 被取消（一次性）
    };

} // namespace psmtest::mux
