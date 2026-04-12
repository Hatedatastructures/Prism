#include <prism/agent/session/session.hpp>
#include <prism/agent/dispatch/handlers.hpp>
#include <prism/pipeline/primitives.hpp>
#include <prism/channel/transport/encrypted.hpp>
#include <prism/protocol/analysis.hpp>

namespace dispatch = psm::agent::dispatch;

namespace psm::agent::session
{
    session::session(session_params params)
        : id_(detail::generate_session_id()), ctx_{id_, params.server, params.worker, frame_arena_, nullptr, nullptr, params.server.cfg.buffer.size, std::move(params.inbound)}
    {
    }

    session::~session()
    {
        release_resources();
    }

    void session::start()
    {
        trace::debug("[Session] [{}] Session started.", id_);

        // 主处理协程：执行协议分流和数据转发
        auto process = [self = this->shared_from_this()]() -> net::awaitable<void>
        {
            try
            {
                co_await self->diversion();
            }
            catch (const std::exception &e)
            {
                trace::error("[Session] [{}] Unhandled exception in diversion: {}", self->id_, e.what());
            }
            catch (...)
            {
                trace::error("[Session] [{}] Unknown exception in diversion", self->id_);
            }

            // 处理完成后释放资源
            self->release_resources();
        };

        // 异常完成回调：捕获并记录协程异常
        auto completion = [self = this->shared_from_this()](const std::exception_ptr &ep) noexcept
        {
            if (!ep)
            {
                return;
            }

            try
            {
                std::rethrow_exception(ep);
            }
            catch (const ::psm::exception::deviant &e)
            {
                // 项目自定义异常，输出完整诊断信息
                trace::error("[Session] [{}] Abnormal exception: {}", self->id_, e.dump());
            }
            catch (const std::exception &e)
            {
                // 标准异常，输出 what() 消息
                trace::error("[Session] [{}] Standard exception: {}", self->id_, e.what());
            }
            catch (...)
            {
                // 未知异常类型
                trace::error("[Session] [{}] Unknown exception type", self->id_);
            }

            self->release_resources();
        };

        // 在 worker 的 io_context 上启动协程
        net::co_spawn(ctx_.worker.io_context, std::move(process), std::move(completion));
    }

    void session::close()
    {
        if (state_ != state::active)
        {
            return;
        }
        state_ = state::closing;
        trace::debug("[Session] [{}] Session closing.", id_);

        // 先取消活跃流（TLS 等），因为 ctx_.inbound 可能已被 move
        if (ctx_.active_stream_cancel)
        {
            ctx_.active_stream_cancel();
        }
        if (ctx_.inbound)
        {
            ctx_.inbound->cancel();
        }
        if (ctx_.outbound)
        {
            ctx_.outbound->cancel();
        }
    }

    void session::release_resources() noexcept
    {
        if (state_ == state::closed)
        {
            return;
        }

        state_ = state::closed;

        // 先关闭活跃流（TLS 等），因为 ctx_.inbound 可能已被 move
        if (ctx_.active_stream_close)
        {
            ctx_.active_stream_close();
            ctx_.active_stream_close = nullptr;
            ctx_.active_stream_cancel = nullptr;
        }

        if (ctx_.inbound)
        {
            ctx_.inbound->close();
            ctx_.inbound.reset();
        }
        if (ctx_.outbound)
        {
            ctx_.outbound->close();
            ctx_.outbound.reset();
        }

        if (on_closed_)
        {
            auto callback = std::move(on_closed_);
            on_closed_ = nullptr;
            callback();
        }

        trace::debug("[Session] [{}] Session closed.", id_);
    }

    auto session::diversion() -> net::awaitable<void>
    {
        // 检查入站传输层是否有效
        if (!ctx_.inbound)
        {
            trace::warn("[Session] [{}] diversion aborted: missing inbound transmission.", id_);
            co_return;
        }

        // 1：外层探测
        auto detect_result = co_await protocol::probe(*ctx_.inbound, 24);
        if (fault::failed(detect_result.ec))
        {
            trace::warn("[Session] [{}] Protocol detection failed: {}.", id_, fault::describe(detect_result.ec));
            co_return;
        }

        auto span = std::span<const std::byte>(detect_result.pre_read_data.data(), detect_result.pre_read_size);

        // 2：TLS 剥离（如果外层是 TLS
        if (detect_result.type == protocol::protocol_type::tls)
        {
            // TLS 握手（复用 ssl_handshake，它会 move ctx_.inbound）
            auto [ssl_ec, ssl_stream] = co_await pipeline::primitives::ssl_handshake(ctx_, span);
            if (fault::failed(ssl_ec) || !ssl_stream)
            {
                trace::warn("[Session] [{}] TLS handshake failed: {}", id_, fault::describe(ssl_ec));
                co_return;
            }

            // 创建加密传输层
            auto encrypted_trans = std::make_shared<channel::transport::encrypted>(ssl_stream);

            // 注册 TLS 流清理回调
            ctx_.active_stream_cancel = [ssl_stream]() noexcept
            {
                ssl_stream->lowest_layer().transmission().cancel();
            };
            ctx_.active_stream_close = [ssl_stream]() noexcept
            {
                ssl_stream->lowest_layer().transmission().close();
            };

            // 增量读取内层数据并逐次探测协议，避免短请求死锁
            // HTTP 方法前缀最短 4 字节（GET/PUT），Trojan 需 60 字节
            constexpr std::size_t trojan_min = 60;
            std::array<std::byte, 64> inner_buf{};
            std::size_t inner_n = 0;

            while (inner_n < trojan_min)
            {
                std::error_code ec;
                auto buf_span = std::span<std::byte>(inner_buf.data() + inner_n, inner_buf.size() - inner_n);
                const auto n = co_await encrypted_trans->async_read_some(std::move(buf_span), ec);
                if (ec)
                {
                    trace::warn("[Session] [{}] Inner probe read failed: {}", id_, ec.message());
                    co_return;
                }
                inner_n += n;

                // 每次读到数据后尝试探测，HTTP 方法最短前缀仅 4 字节即可识别
                const auto inner_view = std::string_view(reinterpret_cast<const char *>(inner_buf.data()), inner_n);
                detect_result.type = protocol::analysis::detect_tls(inner_view);

                // 调试：打印前 16 字节的 hex，辅助排查 SS2022 协议检测
                {
                    constexpr std::size_t hex_len = 16;
                    const auto dump_len = std::min(inner_n, hex_len);
                    std::string hex_dump;
                    hex_dump.reserve(dump_len * 3);
                    for (std::size_t i = 0; i < dump_len; ++i)
                    {
                        const auto b = static_cast<unsigned char>(inner_buf[i]);
                        char buf[4];
                        std::snprintf(buf, sizeof(buf), "%02x ", b);
                        hex_dump += buf;
                    }
                    trace::debug("[Session] [{}] TLS inner probe: {} bytes [{}] -> {}",
                                 id_, inner_n, hex_dump, protocol::to_string_view(detect_result.type));
                }

                if (detect_result.type != protocol::protocol_type::unknown)
                {
                    break;
                }
            }

            if (detect_result.type == protocol::protocol_type::unknown)
            {
                trace::warn("[Session] [{}] Cannot determine inner protocol", id_);
                co_return;
            }

            trace::debug("[Session] [{}] TLS inner protocol: {}", id_, protocol::to_string_view(detect_result.type));

            // 更新 ctx_.inbound 为加密传输层（不含 preview，留给 handler 做）
            ctx_.inbound = std::move(encrypted_trans);

            // 更新 span 为内层预读数据
            span = std::span<const std::byte>(inner_buf.data(), inner_n);
        }

        // 3：分发到 handler
        auto handler = dispatch::registry::global().create(detect_result.type);
        if (!handler)
        {
            // 尝试获取 unknown 协议的处理器
            handler = dispatch::registry::global().create(protocol::protocol_type::unknown);
            if (!handler)
            {
                trace::warn("[Session] [{}] No handler available for protocol.", id_);
                co_return;
            }
        }

        trace::debug("[Session] [{}] Dispatching to handler: {}", id_, handler->name());

        // 执行协议处理
        co_await handler->process(ctx_, span);
        trace::debug("[Session] [{}] Handler {} completed.", id_, handler->name());
    }

    std::shared_ptr<session> make_session(session_params &&params) noexcept
    {
        return std::make_shared<session>(std::move(params));
    }
} // namespace psm::agent::session
