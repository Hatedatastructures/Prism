#include <forward-engine/agent/connection/session.hpp>
#include <forward-engine/agent/dispatch/handlers.hpp>

namespace dispatch = ngx::agent::dispatch;

namespace ngx::agent::connection
{
    session::session(session_params params)
        : ctx_{params.server, params.worker, frame_arena_, nullptr, nullptr, params.server.cfg.buffer.size, std::move(params.inbound)}
    {
    }

    session::~session()
    {
        release_resources();
    }

    void session::start()
    {
        trace::debug("[Session] Session started.");

        auto process = [self = this->shared_from_this()]() -> net::awaitable<void>
        {
            try
            {
                co_await self->diversion();
            }
            catch (const std::exception &e)
            {
                trace::error("[Session] Unhandled exception in diversion: {}", e.what());
            }
            catch (...)
            {
                trace::error("[Session] Unknown exception in diversion");
            }

            self->release_resources();
        };

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
            catch (const abnormal::exception &e)
            {
                trace::error("[Session] Abnormal exception: {}", e.dump());
            }
            catch (const std::exception &e)
            {
                trace::error("[Session] Standard exception: {}", e.what());
            }
            catch (...)
            {
                trace::error("[Session] Unknown exception type");
            }

            self->release_resources();
        };

        net::co_spawn(ctx_.worker.io_context, std::move(process), std::move(completion));
    }

    void session::close()
    {
        auto expected = state::active;
        if (!state_.compare_exchange_strong(expected, state::closing, std::memory_order_acq_rel))
        {
            return;
        }
        trace::debug("[Session] Session closing.");

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
        auto current = state_.load(std::memory_order_acquire);
        if (current == state::closed)
        {
            return;
        }

        if (!state_.compare_exchange_strong(current, state::closed, std::memory_order_acq_rel))
        {
            return;
        }

        trace::debug("[Session] Session releasing resources.");

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

        trace::debug("[Session] Session closed.");
    }

    auto session::diversion() -> net::awaitable<void>
    {
        if (!ctx_.inbound)
        {   //检测入站指针是否有效
            trace::warn("[Session] diversion aborted: missing inbound transmission.");
            co_return;
        }
        // 预读检测协议类型
        auto detect_result = co_await protocol::sniff::probe(*ctx_.inbound, 24);
        if (gist::failed(detect_result.ec))
        {
            trace::warn("[Session] Protocol detection failed: {}.", gist::describe(detect_result.ec));
            co_return;
        }

        auto handler = dispatch::registry::global().create(detect_result.type);
        if (!handler)
        {
            handler = dispatch::registry::global().create(protocol::protocol_type::unknown);
            if (!handler)
            {
                trace::warn("[Session] No handler available for protocol.");
                co_return;
            }
        }
        // 预读的24字节数据
        auto span = std::span<const std::byte>(detect_result.pre_read_data.data(), detect_result.pre_read_size);
        co_await handler->process(ctx_, span);
    }

    std::shared_ptr<session> make_session(session_params &&params) noexcept
    {
        return std::make_shared<session>(std::move(params));
    }
} // namespace ngx::agent::connection
