/**
 * @file session.cpp
 * @brief 连接会话编排模块实现
 * @details 会话通过 Stage Chain 执行 TLS 处理链路（Reality → ShadowTLS → Standard TLS），
 * 然后通过 handler_table 直接分发到协议处理函数。无虚函数、无工厂模式。
 */

#include <prism/agent/session/session.hpp>
#include <prism/agent/dispatch/table.hpp>
#include <prism/pipeline/primitives.hpp>
#include <prism/protocol/probe.hpp>
#include <prism/protocol/analysis.hpp>
#include <prism/agent/pipeline/chain.hpp>
#include <prism/agent/pipeline/stages/reality.hpp>
#include <prism/agent/pipeline/stages/shadowtls.hpp>
#include <prism/agent/pipeline/stages/standard.hpp>
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

        // 2：TLS → Stage Chain（Reality → ShadowTLS → Standard TLS）
        if (detect_result.type == protocol::protocol_type::tls)
        {
            pipeline::stage_chain chain;
            chain.push_back(std::make_shared<pipeline::stages::reality_stage>());
            chain.push_back(std::make_shared<pipeline::stages::shadowtls_stage>());
            chain.push_back(std::make_shared<pipeline::stages::standard_tls_stage>());

            auto stage_result = co_await chain.execute(ctx_, detect_result, span);

            switch (stage_result.type)
            {
            case pipeline::stage_result_type::success:
                trace::debug("[Session] [{}] Stage chain succeeded, protocol: {}",
                             id_, protocol::to_string_view(detect_result.type));
                break;
            case pipeline::stage_result_type::fallback_complete:
                co_return;
            case pipeline::stage_result_type::failed:
                trace::warn("[Session] [{}] Stage chain failed", id_);
                co_return;
            case pipeline::stage_result_type::not_applicable:
                trace::warn("[Session] [{}] No applicable stage found", id_);
                co_return;
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
