#include <prism/diagnose/diagnose.hpp>
#include <prism/protocol/multiplex/datagram.hpp>

#include <boost/asio/co_spawn.hpp>

#include <charconv>

using namespace psm::diagnose;

namespace psm::multiplex
{

    datagram::datagram(datagram_options opts)
        : id_(opts.stream_id), egress_(std::move(opts.egress)), resolve_(std::move(opts.resolve)),
          emit_(std::move(opts.emit)), executor_(std::move(opts.executor)), idle_timeout_(opts.idle_timeout),
          max_dgram_(opts.max_dgram), mr_(opts.mr), prefix_(std::move(opts.prefix)),

          idle_timer_(executor_), recv_buffer_(opts.mr)
    {
        recv_buffer_.resize(max_dgram_);
    }

    datagram::~datagram() noexcept
    {
        close();
    }

    void datagram::start()
    {
        touch_timer();

        auto self = shared_from_this();
        net::co_spawn(executor_, idle_loop(),
                      [self](const std::exception_ptr &ep)
                      {
                          if (ep)
                          {
                              diagnose::debug(self->prefix_, "stream {} UDP idle loop error", self->id_);
                          }
                          self->close();
                      });
    }

    auto datagram::idle_loop() -> net::awaitable<void>
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
        diagnose::debug(prefix_, "stream {} UDP idle timeout", id_);
    }

    void datagram::touch_timer()
    {
        idle_timer_.expires_after(std::chrono::milliseconds(idle_timeout_));
    }

    auto datagram::ensure_socket(const net::ip::udp::endpoint::protocol_type protocol) -> net::awaitable<bool>
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
            diagnose::warn(prefix_, "stream {} UDP socket create failed: {}", id_, e.what());
            co_return false;
        }
    }

    auto datagram::send_to(const std::string_view host, const std::uint16_t port,
                           const std::span<const std::byte> payload) -> net::awaitable<void>
    {
        if (closed_)
        {
            co_return;
        }
        touch_timer();

        // 解析目标端点
        char port_buf[8];
        const auto [port_end, port_ec] = std::to_chars(port_buf, port_buf + sizeof(port_buf), port);
        const auto [code, target_ep] =
            co_await resolve_(host, std::string_view(port_buf, port_end - port_buf));
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
            net::co_spawn(executor_, self->recv_loop(), net::detached);
        }

        // 发送数据报（不等待响应）
        boost::system::error_code ec;
        auto token = net::redirect_error(net::use_awaitable, ec);
        co_await egress_socket_->async_send_to(net::buffer(payload.data(), payload.size()), target_ep, token);
        if (ec)
        {
            diagnose::debug(prefix_, "stream {} UDP send to {}:{} failed: {}", id_, host, port, ec.message());
        }
        else
        {
        }
    }

    auto datagram::recv_loop() -> net::awaitable<void>
    {
        try
        {
            // 持续从 UDP socket 读取目标服务器的响应，经 emit 回传会话层编码成帧
            while (!closed_ && egress_socket_ && egress_socket_->is_open())
            {
                boost::system::error_code ec;
                auto token = net::redirect_error(net::use_awaitable, ec);

                net::ip::udp::endpoint sender_ep;
                auto recv_buf = net::buffer(recv_buffer_.data(), recv_buffer_.size());
                const auto n = co_await egress_socket_->async_receive_from(recv_buf, sender_ep, token);
                if (ec)
                {
                    if (ec != net::error::operation_aborted && ec != net::error::bad_descriptor)
                    {
                        diagnose::debug(prefix_, "stream {} UDP recv error: {}", id_, ec.message());
                    }
                    break;
                }

                // 提取响应来源地址和负载，回传会话层
                memory::string reply_host(sender_ep.address().to_string().c_str(), mr_);
                const auto reply_port = sender_ep.port();
                const auto reply_payload = std::span<const std::byte>(recv_buffer_.data(), n);

                if (emit_)
                {
                    co_await emit_(reply_host, reply_port, reply_payload);
                }
            }
        }
        catch (const std::exception &e)
        {
            diagnose::debug(prefix_, "stream {} UDP recv loop error: {}", id_, e.what());
        }
        catch (...)
        {
            diagnose::error(prefix_, "stream {} UDP recv loop unknown error", id_);
        }
        recv_running_.store(false, std::memory_order_release);
    }

    void datagram::close()
    {
        if (closed_)
        {
            return;
        }
        closed_ = true;

        if (egress_socket_)
        {
            // 先关闭 socket（取消所有 pending 异步操作），但不立即释放对象。
            // recv_loop 可能正 co_await 在 async_receive_from 上，completion handler
            // 需要 egress_socket_ 在 close() 返回后、handler 执行时仍然存活。
            boost::system::error_code ec;
            egress_socket_->cancel(ec);
            egress_socket_->close(ec);
        }

        idle_timer_.cancel();
        if (auto ex = egress_.lock())
        {
            ex->drop(id_);
        }
        diagnose::debug(prefix_, "stream {} UDP datagram closed", id_);
    }

} // namespace psm::multiplex
