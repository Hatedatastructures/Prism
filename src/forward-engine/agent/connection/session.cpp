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
        close();
    }

    void session::start()
    {
        trace::debug("[Session] Session started.");

        auto process = [self = this->shared_from_this()]() -> net::awaitable<void>
        {
            co_await self->diversion();
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
                trace::error(e.dump());
            }
            catch (const std::exception &e)
            {
                trace::error(e.what());
            }

            self->close();
        };

        net::co_spawn(ctx_.worker.io_context, std::move(process), std::move(completion));
    }

    void session::close()
    {
        auto close_and_reset = [](auto &ptr) noexcept
        {   // 关闭并重置指针
            if (ptr)
            {
                ptr->close();
                ptr.reset();
            }
        };

        if (closed_)
        {
            return;
        }
        closed_ = true;
        trace::debug("[Session] Session closing.");
        
        close_and_reset(ctx_.inbound);
        close_and_reset(ctx_.outbound);
        if (on_closed_)
        {
            auto callback = std::move(on_closed_);
            on_closed_ = nullptr;
            callback();
        }
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
