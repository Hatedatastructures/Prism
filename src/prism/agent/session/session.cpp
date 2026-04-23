/**
 * @file session.cpp
 * @brief 连接会话编排模块实现
 * @details 会话通过 Stealth 方案管道执行 TLS 处理链路（Reality → ShadowTLS → Standard TLS），
 * 然后通过 handler_table 直接分发到协议处理函数。无虚函数、无工厂模式。
 */

#include <prism/agent/session/session.hpp>
#include <prism/agent/dispatch/table.hpp>
#include <prism/pipeline/primitives.hpp>
#include <prism/protocol/probe.hpp>
#include <prism/protocol/analysis.hpp>
#include <prism/stealth.hpp>
#include <prism/trace.hpp>
#include <prism/exception.hpp>

namespace psm::agent::session
{
    namespace net = boost::asio;

    session::session(session_params params)
        : id_(detail::generate_session_id()),
          ctx_{id_, params.server, params.worker, frame_arena_, nullptr, nullptr, params.server.config().buffer.size, std::move(params.inbound)}
    {
    }

    session::~session()
    {
        release_resources();
    }

    void session::start()
    {
        trace::debug("[Session] [{}] Session started.", id_);

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
            self->release_resources();
        };

        auto completion = [self = this->shared_from_this()](const std::exception_ptr &ep) noexcept
        {
            if (!ep)
                return;
            try
            {
                std::rethrow_exception(ep);
            }
            catch (const ::psm::exception::deviant &e)
            {
                trace::error("[Session] [{}] Abnormal exception: {}", self->id_, e.dump());
            }
            catch (const std::exception &e)
            {
                trace::error("[Session] [{}] Standard exception: {}", self->id_, e.what());
            }
            catch (...)
            {
                trace::error("[Session] [{}] Unknown exception type", self->id_);
            }
            self->release_resources();
        };

        net::co_spawn(ctx_.worker.io_context, std::move(process), std::move(completion));
    }

    void session::close()
    {
        if (state_ != state::active)
            return;
        state_ = state::closing;
        trace::debug("[Session] [{}] Session closing.", id_);

        if (ctx_.active_stream_cancel)
            ctx_.active_stream_cancel();
        if (ctx_.inbound)
            ctx_.inbound->cancel();
        if (ctx_.outbound)
            ctx_.outbound->cancel();
    }

    void session::release_resources() noexcept
    {
        if (state_ == state::closed)
            return;
        state_ = state::closed;

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
            ctx_.outbound->shutdown_write();
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
        if (!ctx_.inbound)
        {
            trace::warn("[Session] [{}] diversion aborted: missing inbound transmission.", id_);
            co_return;
        }

        // 1：外层协议探测
        auto detect_result = co_await protocol::probe(*ctx_.inbound, 24);
        if (fault::failed(detect_result.ec))
        {
            trace::warn("[Session] [{}] Protocol detection failed: {}.", id_, fault::describe(detect_result.ec));
            co_return;
        }

        auto span = std::span<const std::byte>(detect_result.pre_read_data.data(), detect_result.pre_read_size);

        // 2：TLS → Stealth 方案管道（Reality → ShadowTLS → Standard TLS）
        if (detect_result.type == protocol::protocol_type::tls)
        {
            // 用 preview 包装 inbound，使所有 scheme 都能读到预读数据
            ctx_.inbound = std::make_shared<pipeline::primitives::preview>(
                std::move(ctx_.inbound), span, ctx_.frame_arena.get());

            std::vector<std::shared_ptr<stealth::stealth_scheme>> schemes;
            schemes.push_back(std::make_shared<stealth::reality::scheme>());
            schemes.push_back(std::make_shared<stealth::shadowtls::scheme>());
            schemes.push_back(std::make_shared<stealth::schemes::native>());

            for (const auto &scheme : schemes)
            {
                if (!scheme->is_enabled(ctx_.server.config()))
                {
                    trace::debug("[Session] [{}] Scheme '{}' disabled, skipping", id_, scheme->name());
                    continue;
                }

                trace::debug("[Session] [{}] Executing scheme '{}'", id_, scheme->name());

                auto res = co_await scheme->execute(stealth::scheme_context{
                    .inbound = std::move(ctx_.inbound),
                    .cfg = &ctx_.server.config(),
                    .router = &ctx_.worker.router,
                    .session = &ctx_});

                if (res.transport)
                    ctx_.inbound = std::move(res.transport);
                if (res.detected != protocol::protocol_type::unknown)
                    detect_result.type = res.detected;
                if (!res.preread.empty())
                {
                    span = std::span<const std::byte>(res.preread.data(), res.preread.size());
                    // 为下一个 scheme 重新包装 preview
                    if (ctx_.inbound && detect_result.type == protocol::protocol_type::tls)
                    {
                        ctx_.inbound = std::make_shared<pipeline::primitives::preview>(
                            std::move(ctx_.inbound), span, ctx_.frame_arena.get());
                    }
                }

                if (fault::failed(res.error))
                {
                    trace::warn("[Session] [{}] Scheme '{}' failed: {}",
                                id_, scheme->name(), fault::describe(res.error));
                    co_return;
                }

                if (detect_result.type != protocol::protocol_type::tls &&
                    detect_result.type != protocol::protocol_type::unknown)
                {
                    trace::debug("[Session] [{}] Scheme '{}' succeeded, protocol: {}",
                                 id_, scheme->name(), protocol::to_string_view(detect_result.type));
                    break;
                }
            }
        }

        // 3：直接分发表分发 — 无虚函数、无工厂
        trace::debug("[Session] [{}] Dispatching to {}", id_, protocol::to_string_view(detect_result.type));
        co_await dispatch::dispatch(ctx_, detect_result.type, span);
    }

    std::shared_ptr<session> make_session(session_params &&params)
    {
        return std::make_shared<session>(std::move(params));
    }
} // namespace psm::agent::session
