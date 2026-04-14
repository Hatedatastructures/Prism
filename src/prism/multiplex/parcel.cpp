#include <prism/multiplex/parcel.hpp>
#include <prism/multiplex/core.hpp>
#include <prism/multiplex/smux/frame.hpp>
#include <prism/resolve/router.hpp>
#include <prism/trace.hpp>

#include <boost/asio/co_spawn.hpp>

constexpr std::string_view tag = "[Mux.Parcel]";

namespace psm::multiplex
{
    parcel::parcel(const std::uint32_t stream_id, std::shared_ptr<core> owner,
                   resolve::router &router, const std::uint32_t udp_idle_timeout, const std::uint32_t udp_max_dg,
                   const memory::resource_pointer mr, const bool packet_addr)
        : id_(stream_id), owner_(owner), router_(router),
          executor_(owner->executor()),
          udp_idle_timeout_ms_(udp_idle_timeout), udp_max_datagram_(udp_max_dg),
          mr_(mr), idle_timer_(executor_), recv_buffer_(mr), packet_addr_(packet_addr),
          mux_buffer_(mr)
    {
        recv_buffer_.resize(udp_max_datagram_);
    }

    parcel::~parcel()
    {
        close();
    }

    void parcel::start()
    {
        touch_idle_timer();

        auto self = shared_from_this();
        auto on_done = [self](const std::exception_ptr &ep)
        {
            if (ep)
            {
                try
                {
                    std::rethrow_exception(ep);
                }
                catch (const std::exception &e)
                {
                    trace::debug("{} stream {} UDP uplink error: {}", tag, self->id_, e.what());
                }
                catch (...)
                {
                    trace::error("{} stream {} UDP uplink unknown error", tag, self->id_);
                }
            }
            self->close();
        };
        net::co_spawn(executor_, uplink_loop(), std::move(on_done));
    }

    auto parcel::uplink_loop() -> net::awaitable<void>
    {
        while (!closed_)
        {
            boost::system::error_code ec;
            auto token = net::redirect_error(net::use_awaitable, ec);
            co_await idle_timer_.async_wait(token);

            if (ec == net::error::operation_aborted)
            {
                continue;
            }
            break;
        }
        trace::debug("{} stream {} UDP idle timeout", tag, id_);
        co_return;
    }

    void parcel::touch_idle_timer()
    {
        idle_timer_.expires_after(std::chrono::milliseconds(udp_idle_timeout_ms_));
    }

    auto parcel::ensure_socket(const net::ip::udp::endpoint::protocol_type protocol) -> net::awaitable<bool>
    {
        if (egress_socket_ && socket_protocol_ == protocol)
        {
            co_return true;
        }

        if (egress_socket_)
        {
            boost::system::error_code ec;
            egress_socket_->cancel(ec);
            egress_socket_->close(ec);
            egress_socket_.reset();
        }

        try
        {
            auto executor = co_await net::this_coro::executor;
            egress_socket_.emplace(executor, protocol);
            // 显式绑定到任意端口，确保 recv_from 在 Windows 上不会返回 WSAEINVAL
            egress_socket_->bind(net::ip::udp::endpoint(protocol, 0));
            socket_protocol_ = protocol;
            co_return true;
        }
        catch (const std::exception &e)
        {
            trace::warn("{} stream {} UDP socket create failed: {}", tag, id_, e.what());
            co_return false;
        }
    }

    auto parcel::on_mux_data(std::span<const std::byte> data) -> net::awaitable<void>
    {
        if (closed_)
        {
            co_return;
        }
        touch_idle_timer();

        // 累积到缓冲区
        mux_buffer_.insert(mux_buffer_.end(), data.begin(), data.end());

        // 如果没有处理循环在运行，启动一个
        if (!processing_.exchange(true))
        {
            auto self = shared_from_this();
            net::co_spawn(executor_, self->process_buffer(), net::detached);
        }
    }

    auto parcel::process_buffer() -> net::awaitable<void>
    {
        try
        {
            bool has_progress;
            do
            {
                // 交换缓冲区：local_buf 数据不再被 on_mux_data 修改，span 指针稳定
                memory::vector<std::byte> local_buf(mr_);
                std::swap(local_buf, mux_buffer_);

                std::size_t offset = 0;
                while (!closed_ && offset < local_buf.size())
                {
                    auto buf = std::span<const std::byte>(local_buf.data() + offset, local_buf.size() - offset);

                    if (packet_addr_)
                    {
                        auto dgram = smux::parse_udp_datagram(buf, mr_);
                        if (!dgram)
                        {
                            break;
                        }
                        co_await do_send(dgram->host, dgram->port, dgram->payload);
                        offset += dgram->consumed;
                    }
                    else
                    {
                        auto dgram = smux::parse_udp_length_prefixed(buf);
                        if (!dgram)
                        {
                            break;
                        }
                        co_await do_send(destination_host_, destination_port_, dgram->payload);
                        offset += dgram->consumed;
                    }
                }

                // 未消费数据移回 mux_buffer_ 前部
                if (offset < local_buf.size())
                {
                    const auto remaining = std::span<const std::byte>(
                        local_buf.data() + offset, local_buf.size() - offset);
                    mux_buffer_.insert(mux_buffer_.begin(), remaining.begin(), remaining.end());
                }

                has_progress = offset > 0;
                processing_.store(false, std::memory_order_release);

                // 仅在本轮消费了数据且仍有待处理数据时继续（避免不完整数据死循环）
                if (has_progress && !mux_buffer_.empty() && !closed_)
                {
                    processing_.store(true, std::memory_order_release);
                }
            } while (has_progress && !mux_buffer_.empty() && !closed_);
        }
        catch (const std::exception &e)
        {
            trace::debug("{} stream {} process_buffer error: {}", tag, id_, e.what());
        }
        catch (...)
        {
            trace::error("{} stream {} process_buffer unknown error", tag, id_);
        }
        processing_.store(false, std::memory_order_release);
    }

    auto parcel::do_send(const memory::string &target_host, const std::uint16_t target_port,
                         std::span<const std::byte> payload) -> net::awaitable<void>
    {
        // 通过路由器解析目标端点
        const auto [code, target_ep] = co_await router_.resolve_datagram_target(
            target_host, std::to_string(target_port));
        if (code != fault::code::success)
        {
            co_return;
        }

        // 跳过不可路由地址（如 sing-mux PacketAddr 占位地址 0.0.0.1）
        const auto &addr = target_ep.address();
        if (addr.is_v4() && addr.to_v4().to_bytes()[0] == 0)
        {
            co_return;
        }

        // 确保 UDP socket 可用
        if (!co_await ensure_socket(target_ep.protocol()))
        {
            co_return;
        }

        // 首次发送时启动接收循环
        if (!recv_running_.exchange(true))
        {
            auto self = shared_from_this();
            net::co_spawn(executor_, self->downlink_loop(), net::detached);
        }

        // 发送数据报（不等待响应）
        boost::system::error_code ec;
        auto token = net::redirect_error(net::use_awaitable, ec);
        co_await egress_socket_->async_send_to(net::buffer(payload.data(), payload.size()),
                                               target_ep, token);
        if (ec)
        {
            trace::debug("{} stream {} UDP send to {}:{} failed: {}",
                         tag, id_, target_host, target_port, ec.message());
        }
    }

    auto parcel::downlink_loop() -> net::awaitable<void>
    {
        try
        {
            // 持续从 UDP socket 读取目标服务器的响应，编码后通过 mux 回传给客户端
            while (!closed_ && egress_socket_ && egress_socket_->is_open())
            {
                // 读取一个完整的 UDP 响应数据报
                boost::system::error_code ec;
                auto token = net::redirect_error(net::use_awaitable, ec);

                net::ip::udp::endpoint sender_ep;
                auto recv_buf = net::buffer(recv_buffer_.data(), recv_buffer_.size());
                const auto n = co_await egress_socket_->async_receive_from(recv_buf, sender_ep, token);
                if (ec)
                {
                    if (ec != net::error::operation_aborted && ec != net::error::bad_descriptor)
                    {
                        trace::debug("{} stream {} UDP recv error: {}", tag, id_, ec.message());
                    }
                    break;
                }

                // 提取响应来源地址和负载
                memory::string reply_host(sender_ep.address().to_string().c_str(), mr_);
                const auto reply_port = sender_ep.port();
                const auto reply_payload = std::span<const std::byte>(recv_buffer_.data(), n);

                // 按协议格式编码：PacketAddr 模式带完整地址，否则仅 length+payload
                memory::vector<std::byte> encoded(mr_);
                if (packet_addr_)
                {
                    encoded = smux::build_udp_datagram(reply_host, reply_port, reply_payload, mr_);
                }
                else
                {
                    encoded = smux::build_udp_length_prefixed(reply_payload, mr_);
                }

                // 通过 mux PSH 帧回传给客户端
                if (auto owner = owner_.lock())
                {
                    co_await owner->send_data(id_, std::move(encoded));
                }
                else
                {
                    break;
                }
            }
        }
        catch (const std::exception &e)
        {
            trace::debug("{} stream {} downlink_loop error: {}", tag, id_, e.what());
        }
        catch (...)
        {
            trace::error("{} stream {} downlink_loop unknown error", tag, id_);
        }
        recv_running_.store(false, std::memory_order_release);
    }

    void parcel::close()
    {
        if (closed_)
        {
            return;
        }
        closed_ = true;

        if (egress_socket_)
        {
            // 先关闭 socket（取消所有 pending 异步操作），但不立即释放对象。
            // downlink_loop 可能正 co_await 在 async_receive_from 上，completion handler
            // 需要 egress_socket_ 在 close() 返回后、handler 执行时仍然存活。
            // egress_socket_ 将在 parcel 析构时自然释放，此时所有协程已完成。
            boost::system::error_code ec;
            egress_socket_->cancel(ec);
            egress_socket_->close(ec);
        }

        idle_timer_.cancel();
        if (auto owner = owner_.lock())
        {
            owner->remove_parcel(id_);
        }
        trace::debug("{} stream {} UDP parcel closed", tag, id_);
    }

} // namespace psm::multiplex
