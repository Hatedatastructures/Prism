/**
 * @file parcel.cpp
 * @brief 多路复用 UDP 数据报管道实现
 * @details mux::parcel 的 UDP 中继实现。每个 PSH 帧承载
 * SOCKS5 UDP relay 格式数据报，解析目标地址后通过 UDP socket 中继.
 */

#include <prism/channel/mux/parcel.hpp>
#include <prism/channel/mux/core.hpp>
#include <prism/channel/smux/frame.hpp>
#include <prism/resolve/router.hpp>
#include <prism/trace.hpp>

#include <boost/asio/co_spawn.hpp>

constexpr std::string_view tag = "[Mux.Parcel]";

namespace psm::channel::mux
{
    parcel::parcel(const std::uint32_t stream_id, std::shared_ptr<core> owner,
                   const config &cfg, resolve::router &router, const memory::resource_pointer mr)
        : id_(stream_id), owner_(std::move(owner)), router_(router), config_(cfg), mr_(mr),
          idle_timer_(owner_->executor()), recv_buffer_(mr)
    {
        recv_buffer_.resize(config_.udp_max_datagram);
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
        net::co_spawn(owner_->executor(), uplink_loop(), std::move(on_done));
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
                continue; // timer 被 touch_idle_timer 重设
            }
            break; // 正常到期 = 空闲超时
        }
        trace::debug("{} stream {} UDP idle timeout", tag, id_);
        co_return;
    }

    void parcel::touch_idle_timer()
    {
        idle_timer_.expires_after(std::chrono::milliseconds(config_.udp_idle_timeout_ms));
    }

    auto parcel::ensure_socket(const net::ip::udp::endpoint::protocol_type protocol) -> net::awaitable<bool>
    {
        // 已有 socket 且协议匹配
        if (egress_socket_ && socket_protocol_ == protocol)
        {
            co_return true;
        }

        // 协议不匹配，关闭旧 socket
        if (egress_socket_)
        {
            boost::system::error_code ec;
            egress_socket_->close(ec);
            egress_socket_.reset();
        }

        // 创建新 socket
        try
        {
            auto executor = co_await net::this_coro::executor;
            egress_socket_.emplace(executor, protocol);
            socket_protocol_ = protocol;
            co_return egress_socket_->is_open();
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
        co_await relay_datagram(data);
    }

    auto parcel::relay_datagram(std::span<const std::byte> udp_packet) -> net::awaitable<void>
    {
        // 解析 SOCKS5 UDP relay 头部，比 socks5 udp 少了 RSV 字段和 frag 字段
        auto dgram = smux::parse_udp_datagram(udp_packet, mr_);
        if (!dgram)
        {
            trace::warn("{} stream {} UDP datagram parse failed", tag, id_);
            co_return;
        }

        trace::debug("{} stream {} UDP relay to {}:{}", tag, id_, dgram->host, dgram->port);

        // DNS 解析目标
        const auto [code, target_ep] = co_await router_.resolve_datagram_target(dgram->host, std::to_string(dgram->port));
        if (code != fault::code::success)
        {
            trace::debug("{} stream {} UDP resolve {}:{} failed", tag, id_, dgram->host, dgram->port);
            co_return;
        }

        if (!co_await ensure_socket(target_ep.protocol()))
        { // 确保 UDP socket 可用
            co_return;
        }

        // 发送数据报到目标
        boost::system::error_code ec;
        auto token = net::redirect_error(net::use_awaitable, ec);
        auto bytes_sent = net::buffer(dgram->payload.data(), dgram->payload.size());
        co_await egress_socket_->async_send_to(bytes_sent, target_ep, token);
        if (ec)
        {
            trace::debug("{} stream {} UDP send to {}:{} failed: {}",
                         tag, id_, dgram->host, dgram->port, ec.message());
            co_return;
        }

        // 接收回包
        net::ip::udp::endpoint sender_ep;
        auto recv_buffer = net::buffer(recv_buffer_.data(), recv_buffer_.size());
        const auto n = co_await egress_socket_->async_receive_from(recv_buffer, sender_ep, token);
        if (ec)
        {
            trace::debug("{} stream {} UDP recv failed: {}", tag, id_, ec.message());
            co_return;
        }

        // 编码回包为 SOCKS5 UDP 格式
        std::string reply_host;
        reply_host = sender_ep.address().to_string();
        auto reply_port = sender_ep.port();
        auto payload = std::span<const std::byte>(recv_buffer_.data(), n);
        auto encoded = smux::build_udp_datagram(reply_host, reply_port, payload, mr_);

        // 通过 mux 回传
        co_await owner_->send_data(id_, encoded);
        trace::debug("{} stream {} UDP relay completed", tag, id_);
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
            boost::system::error_code ec;
            egress_socket_->cancel(ec);
            egress_socket_->close(ec);
            egress_socket_.reset();
        }

        idle_timer_.cancel();
        owner_->remove_parcel(id_);
        trace::debug("{} stream {} UDP parcel closed", tag, id_);
    }

} // namespace psm::channel::mux
