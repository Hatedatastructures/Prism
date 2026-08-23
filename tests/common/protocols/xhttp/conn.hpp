/**
 * @file conn.hpp
 * @brief XHTTP 方案连接装饰器（stream-one：TLS + h2 + 单 POST 双向流）
 * @details 服务端流程：
 *          1. 底层传输执行 TLS 服务端握手（encrypted::ssl_handshake）
 *          2. 建立 h2 会话（session_impl），处理 SETTINGS/PING
 *          3. 匹配 POST {path} 请求 → 响应 200
 *          4. 返回双向流传输：读 = h2 DATA 帧载荷，写 = h2 DATA 帧
 * @note 依赖 core/http2 自包含实现（T2-6）
 */

#pragma once

#include <common/core/diagnose/log.hpp>
#include <common/core/error.hpp>
#include <common/protocols/http2/impl.hpp>
#include <common/protocols/http2/session.hpp>
#include <common/core/memory/container.hpp>
#include <common/core/transmission.hpp>
#include <common/core/transport/encrypted.hpp>
#include <common/protocols/xhttp/types.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/asio/ssl.hpp>

#include <array>
#include <cstddef>
#include <deque>
#include <exception>
#include <memory>
#include <span>
#include <string>

namespace preview::xhttp
{

    namespace net = boost::asio;
    namespace h2 = preview::http2;

    /// h2 会话共享指针
    using shared_h2_session = std::shared_ptr<h2::session_impl>;

    /**
     * @class xhttp_transport
     * @brief XHTTP 双向流传输（transmission 装饰器）
     * @details 读 = 会话 DATA 帧投递队列；写 = 经会话提交 DATA 帧。
     *          匹配的流 ID 在 POST 到达前为 -1（写缓冲至匹配后 flush）。
     */
    class xhttp_transport final : public transmission,
                                  public std::enable_shared_from_this<xhttp_transport>
    {
    public:
        /**
         * @brief 写回调（提交 DATA 帧到会话）
         * @param stream_id 目标流
         * @param data 载荷
         */
        using write_cb = std::function<net::awaitable<void>(std::int32_t stream_id,
                                                            std::span<const std::byte>)>;

        /**
         * @brief 构造
         * @param ex 执行器
         * @param write_fn 写回调（提交 DATA 帧）
         */
        explicit xhttp_transport(net::any_io_executor ex, write_cb write_fn)
            : ex_(std::move(ex)), write_fn_(std::move(write_fn)), notify_(ex_, 64)
        {
        }

        [[nodiscard]] auto executor() const -> executor_type override
        {
            return ex_;
        }

        [[nodiscard]] auto async_read_some(std::span<std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            while (rx_offset_ >= rx_current_.size())
            {
                if (closed_)
                {
                    ec = std::make_error_code(std::errc::not_connected);
                    co_return 0;
                }
                if (eof_)
                {
                    ec = make_error_code(error::unexpected_eof);
                    co_return 0;
                }
                if (eof_pending_ && !notify_.ready())
                {
                    eof_pending_ = false;
                    eof_ = true;
                    ec.clear();
                    co_return 0;
                }
                boost::system::error_code ch_ec;
                auto block = co_await notify_.async_receive(
                    net::redirect_error(net::use_awaitable, ch_ec));
                if (ch_ec)
                {
                    ec = std::make_error_code(std::errc::not_connected);
                    co_return 0;
                }
                if (block.empty())
                {
                    eof_ = true;
                    ec.clear();
                    co_return 0;
                }
                rx_current_ = std::move(block);
                rx_offset_ = 0;
            }
            const auto n = std::min(buffer.size(), rx_current_.size() - rx_offset_);
            std::memcpy(buffer.data(), rx_current_.data() + rx_offset_, n);
            rx_offset_ += n;
            ec.clear();
            co_return n;
        }

        [[nodiscard]] auto async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            if (closed_ || !write_fn_)
            {
                ec = std::make_error_code(std::errc::not_connected);
                co_return 0;
            }
            if (stream_id_ < 0)
            {
                // 流未匹配：缓冲写
                write_pending_.insert(write_pending_.end(), buffer.begin(), buffer.end());
            }
            else
            {
                co_await write_fn_(stream_id_, buffer);
            }
            ec.clear();
            co_return buffer.size();
        }

        void close() override
        {
            closed_ = true;
            notify_.cancel();
        }

        void cancel() override
        {
            closed_ = true;
            notify_.cancel();
        }

        [[nodiscard]] auto next_layer() noexcept -> transmission * override
        {
            return nullptr;
        }

        [[nodiscard]] auto next_layer() const noexcept -> const transmission * override
        {
            return nullptr;
        }

        /**
         * @brief 投递收到的 DATA 载荷
         * @param data 载荷字节
         */
        void push(std::span<const std::byte> data)
        {
            if (closed_ || data.empty())
            {
                return;
            }
            memory::vector<std::byte> copy(data.begin(), data.end(), memory::current_resource());
            if (!notify_.try_send(boost::system::error_code{}, std::move(copy)))
            {
                diagnose::error("xhttp receive channel full; closing stream");
                close();
            }
        }

        /**
         * @brief 对端 END_STREAM（流关闭）
         */
        void notify_eof()
        {
            if (!closed_ && !eof_ && !eof_pending_)
            {
                if (!notify_.try_send(boost::system::error_code{},
                                      memory::vector<std::byte>(memory::current_resource())))
                {
                    eof_pending_ = true;
                }
            }
        }

        /**
         * @brief 绑定匹配流 ID 并 flush 缓冲写
         * @param stream_id 匹配的 h2 流 ID
         */
        void bind_stream(std::int32_t stream_id)
        {
            stream_id_ = stream_id;
            if (!write_pending_.empty() && write_fn_)
            {
                auto pending = std::make_shared<memory::vector<std::byte>>(std::move(write_pending_));
                auto self = shared_from_this();
                auto write_fn = write_fn_;
                const auto bound_stream_id = stream_id_;
                auto async_flush = [self, write_fn = std::move(write_fn), pending, bound_stream_id]() mutable
                    -> net::awaitable<void>
                {
                    co_await write_fn(bound_stream_id, std::span<const std::byte>(*pending));
                };
                auto on_error = [self](const std::exception_ptr &ep)
                {
                    if (ep)
                    {
                        diagnose::error("xhttp pending write failed");
                        self->close();
                    }
                };
                net::co_spawn(ex_, std::move(async_flush), std::move(on_error));
            }
        }

        /// 当前匹配流 ID（-1 = 未匹配）
        std::int32_t stream_id_{-1};

    private:
        using channel_type =
            net::experimental::concurrent_channel<void(boost::system::error_code, memory::vector<std::byte>)>;

        net::any_io_executor ex_;
        write_cb write_fn_;
        channel_type notify_;
        memory::vector<std::byte> rx_current_;
        std::size_t rx_offset_{0};
        memory::vector<std::byte> write_pending_; ///< 匹配前的写缓冲
        bool closed_{false};
        bool eof_{false};
        bool eof_pending_{false};
    };

    /**
     * @class xhttp_accept
     * @brief XHTTP 服务端握手编排（TLS + h2 + stream-one 匹配）
     */
    class xhttp_accept : public std::enable_shared_from_this<xhttp_accept>
    {
    public:
        /**
         * @brief 构造
         * @param raw 底层传输（所有权转移）
         * @param ssl_ctx TLS 服务端上下文
         * @param cfg xhttp 配置
         */
        xhttp_accept(shared_transmission raw, net::ssl::context &ssl_ctx, const config &cfg)
            : raw_(std::move(raw)), ssl_ctx_(ssl_ctx), cfg_(cfg)
        {
        }

        /**
         * @brief 执行握手并等待流匹配
         * @return 匹配流的双向传输；失败返回 nullptr
         */
        [[nodiscard]] auto run() -> net::awaitable<shared_transmission>
        {
            if (!raw_)
            {
                co_return nullptr;
            }
            auto [code, stream, recovered] =
                co_await preview::transport::encrypted::ssl_handshake(std::move(raw_), ssl_ctx_);
            (void)code;
            (void)recovered;
            if (!stream)
            {
                co_return nullptr;
            }
            encrypted_ = std::make_shared<preview::transport::encrypted>(std::move(stream));

            session_ = std::make_shared<h2::session_impl>(encrypted_->executor(), true);
            // 写回调捕获 shared_ptr 成员（handler 析构后仍有效）
            auto session = session_;
            auto encrypted = encrypted_;
            transport_ = std::make_shared<xhttp_transport>(
                encrypted_->executor(),
                [session, encrypted](std::int32_t sid, std::span<const std::byte> data)
                    -> net::awaitable<void>
                {
                    session->submit_data(sid, data, false);
                    // flush：提交后立即写回
                    std::vector<std::byte> out;
                    if (session->collect(out) && !out.empty())
                    {
                        std::error_code w_ec;
                        co_await encrypted->async_write_some(out, w_ec);
                    }
                    co_return;
                });

            session_->on_headers = [transport = transport_, session = session_, path_cfg = cfg_.path]
                (std::int32_t sid, const h2::header_list &headers, bool)
            {
                if (transport->stream_id_ >= 0)
                {
                    return;
                }
                bool is_post = false;
                std::string_view path;
                for (const auto &h : headers)
                {
                    if (h.name == ":method" && h.value == "POST")
                    {
                        is_post = true;
                    }
                    else if (h.name == ":path")
                    {
                        path = h.value;
                    }
                }
                const std::string_view base(path_cfg.data(), path_cfg.size());
                bool path_ok;
                if (base == "/")
                {
                    path_ok = path.rfind('/', 0) == 0;
                }
                else
                {
                    path_ok = path.rfind(base, 0) == 0;
                }
                if (is_post && path_ok)
                {
                    transport->bind_stream(sid);
                    h2::header_list resp = {{":status", "200"}, {"content-type", "text/event-stream"}};
                    session->submit_headers(sid, resp, false);
                }
            };
            session_->on_data = [transport = transport_](std::int32_t sid, std::span<const std::byte> data)
            {
                if (sid == transport->stream_id_)
                {
                    transport->push(data);
                }
            };
            session_->on_stream_close = [transport = transport_](std::int32_t sid, std::uint32_t)
            {
                if (sid == transport->stream_id_)
                {
                    transport->notify_eof();
                }
            };

            // driver 捕获共享成员（self 保活）
            auto transport = transport_;
            net::co_spawn(encrypted_->executor(),
                          [session, encrypted, transport]() mutable -> net::awaitable<void>
                          {
                              std::array<std::byte, 16384> buf{};
                              while (true)
                              {
                                  std::error_code ec;
                                  const auto n = co_await encrypted->async_read_some(buf, ec);
                                  if (ec || n == 0)
                                  {
                                      break;
                                  }
                                  if (!session->feed(std::span<const std::byte>(buf.data(), n), ec))
                                  {
                                      break;
                                  }
                                  std::vector<std::byte> out;
                                  if (session->collect(out) && !out.empty())
                                  {
                                      std::error_code w_ec;
                                      co_await encrypted->async_write_some(out, w_ec);
                                      if (w_ec)
                                      {
                                          break;
                                      }
                                  }
                              }
                              transport->notify_eof();
                              co_return;
                          },
                          net::detached);
            co_return transport_;
        }

    private:
        shared_transmission raw_;
        net::ssl::context &ssl_ctx_;
        config cfg_;
        preview::shared_transmission encrypted_;
        shared_h2_session session_;
        std::shared_ptr<xhttp_transport> transport_;
        std::vector<std::byte> pending_out_;
    };

    /**
     * @brief 服务端 accept 便捷入口
     * @param raw 底层传输（所有权转移）
     * @param ssl_ctx TLS 服务端上下文
     * @param cfg xhttp 配置
     * @return 匹配流的双向传输；失败返回 nullptr
     */
    [[nodiscard]] inline auto accept(shared_transmission raw, net::ssl::context &ssl_ctx,
                                     const config &cfg) -> net::awaitable<shared_transmission>
    {
        auto handler = std::make_shared<xhttp_accept>(std::move(raw), ssl_ctx, cfg);
        co_return co_await handler->run();
    }

} // namespace preview::xhttp
