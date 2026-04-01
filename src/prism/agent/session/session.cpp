#include <prism/agent/session/session.hpp>
#include <prism/agent/dispatch/handlers.hpp>

namespace dispatch = psm::agent::dispatch;

namespace psm::agent::session
{
    session::session(session_params params)
        : id_(detail::generate_session_id())
        , ctx_{id_, params.server, params.worker, frame_arena_, nullptr, nullptr, params.server.cfg.buffer.size, std::move(params.inbound)}
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

        // 预读前 24 字节进行协议检测
        auto detect_result = co_await protocol::probe(*ctx_.inbound, 24);
        if (fault::failed(detect_result.ec))
        {
            trace::warn("[Session] [{}] Protocol detection failed: {}.", id_, fault::describe(detect_result.ec));
            co_return;
        }

        // 从全局注册表获取协议处理器
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

        // 构造预读数据的 span，传递给处理器
        auto span = std::span<const std::byte>(detect_result.pre_read_data.data(), detect_result.pre_read_size);
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
