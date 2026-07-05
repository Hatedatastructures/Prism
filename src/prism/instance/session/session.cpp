#include <prism/instance/session/session.hpp>

#include <prism/config/config.hpp>
#include <prism/net/connect/tunnel/tunnel.hpp>
#include <prism/net/connect/tunnel/tunnel_relay.hpp>
#include <prism/foundation/foundation.hpp>
#include <prism/foundation/fault/code.hpp>
#include <prism/proto/protocol/handler.hpp>
#include <prism/proto/protocol/types.hpp>
#include <prism/stealth/recognition/recognition.hpp>
#include <prism/stealth/scheme.hpp>
#include <prism/account/stats/traffic.hpp>
#include <prism/trace/trace.hpp>
#include <prism/net/transport/reliable.hpp>

#include <boost/asio/experimental/awaitable_operators.hpp>

#include <chrono>
#include <cstring>

using namespace psm::trace;

namespace psm::instance::session
{

    namespace net = boost::asio;

    session::session(session_params params)
        : id_(detail::next_conn_id()),
          prefix_(params.trace ? std::move(params.trace) : std::make_shared<trace::trace_context>()),
          ctx_{context::session_opts{id_, params.server, params.worker, frame_arena_,
              params.server.config().buffer.size, std::move(params.inbound),
              params.meta ? params.meta->src_ip_raw : std::array<std::byte, 16>{}},
              std::move(params.meta)}
    {
        // 同步 conn_id 到 trace_context（若 launch 未填）
        if (prefix_->conn_id == 0)
            prefix_->conn_id = id_;
        if (ctx_.meta)
            ctx_.meta->conn_id = id_;
    }

    session::~session() noexcept
    {
        release_resources();
    }

    void session::init_prefix(const trace::trace_context &pfx) noexcept
    {
        // trace_context 瘦身：仅同步 conn_id；端点信息已由 launch 填入 ctx_.meta
        prefix_->conn_id = pfx.conn_id != 0 ? pfx.conn_id : id_;
    }

    void session::start()
    {
        auto process = [self = this->shared_from_this()]() -> net::awaitable<void>
        {
            try
            {
                co_await self->diversion();
            }
            catch (const std::exception &e)
            {
                trace::error<flt::conn | flt::protocol>(*self->prefix_,
                    "unhandled exception in diversion: {}", e.what());
            }
            catch (...)
            {
                trace::error<flt::conn | flt::protocol>(*self->prefix_,
                    "unknown exception in diversion");
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
                trace::error<flt::conn | flt::protocol>(*self->prefix_,
                    "abnormal exception: {}", e.dump());
            }
            catch (const std::exception &e)
            {
                trace::error<flt::conn | flt::protocol>(*self->prefix_,
                    "standard exception: {}", e.what());
            }
            catch (...)
            {
                trace::error<flt::conn | flt::protocol>(*self->prefix_,
                    "unknown exception type");
            }
            self->release_resources();
        };

        net::co_spawn(ctx_.worker_ctx.io_context, std::move(process), std::move(completion));
    }

    void session::close()
    {
        if (state_ != state::active)
            return;
        state_ = state::closing;
        trace::debug<flt::conn | flt::protocol>(*prefix_, "session closing");

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

        if (auto wr = ctx_.worker_ctx.resources.lock())
        {
            wr->traffic().on_disconnect(ctx_.detected_protocol);
        }

        if (ctx_.inbound)
        {
            ctx_.inbound->close();
            ctx_.inbound.reset();
        }
        if (ctx_.outbound)
        {
            if (auto *rel = ctx_.outbound->lowest_layer<transport::reliable>())
            {
                rel->shutdown_write();
            }
            ctx_.outbound->close();
            ctx_.outbound.reset();
        }
        if (on_closed_)
        {
            auto callback = std::move(on_closed_);
            on_closed_ = nullptr;
            callback();
        }
        trace::info<flt::conn | flt::protocol>(*prefix_, "session closed");
    }

    auto session::diversion()
        -> net::awaitable<void>
    {
        if (!ctx_.inbound)
        {
            trace::warn<flt::conn | flt::protocol>(prefix_, 
                "diversion aborted: missing inbound transmission");
            co_return;
        }

        // 端点信息在 ctx_.meta（瘦身后 trace_context 不含 client/listen）
        const auto *meta_ptr = ctx_.meta.get();
        if (meta_ptr != nullptr)
        {
            trace::info<flt::conn | flt::protocol>(prefix_,
                "session established, {} -> {}",
                meta_ptr->src.address().to_string(),
                meta_ptr->dst.address().to_string());
        }
        else
        {
            trace::info<flt::conn | flt::protocol>(prefix_,
                "session established");
        }

        // 1. 完整识别流程
        handshake_deadline_ = std::make_unique<net::steady_timer>(
            ctx_.inbound->executor(), std::chrono::seconds(30));

        auto deadline_expired = [this]() -> net::awaitable<bool>
        {
            boost::system::error_code ec;
            co_await handshake_deadline_->async_wait(net::redirect_error(trace::use_prefix_awaitable, ec));
            co_return true;
        };

        auto do_recognize = [this, self = this->shared_from_this()]() -> net::awaitable<recognition::recognize_result>
        {
            auto wr = ctx_.worker_ctx.resources.lock();
            if (!wr)
            {
                trace::warn<flt::conn | flt::protocol>(prefix_, "worker resources expired before recognize");
                co_return recognition::recognize_result{};
            }
            ::psm::stealth::stealth_opts st_opts;
            st_opts.meta = ctx_.meta;
            st_opts.trace = prefix_;
            st_opts.cfg = &ctx_.server_ctx.config();
            st_opts.outbound = &wr->outbound();
            st_opts.transport = ctx_.inbound;
            st_opts.session = &ctx_;
            st_opts.session_keepalive = std::move(self);
            st_opts.frame_arena = &ctx_.frame_arena;
            st_opts.src_ip_raw = ctx_.meta ? ctx_.meta->src_ip_raw : std::array<std::byte, 16>{};
            co_return co_await recognition::recognize(st_opts);
        };

        using boost::asio::experimental::awaitable_operators::operator||;
        auto variant = co_await (do_recognize() || deadline_expired());
        recognition::recognize_result result;
        bool timed_out = false;

        if (std::holds_alternative<recognition::recognize_result>(variant))
        {
            result = std::get<recognition::recognize_result>(std::move(variant));
        }
        else
        {
            timed_out = true;
        }

        handshake_deadline_->cancel();
        handshake_deadline_.reset();

        if (timed_out)
        {
            ctx_.inbound->cancel();
            prefix_->phase.set("handshake");
            trace::warn<flt::conn | flt::protocol>(prefix_, 
                "handshake deadline exceeded, aborting");
            prefix_->phase.clear();
            co_return;
        }

        if (!result.success)
        {
            trace::warn<flt::conn | flt::protocol>(prefix_, 
                "recognition failed: {}", fault::describe(result.error));
            co_return;
        }

        // 记录识别出的协议类型并通知流量统计
        ctx_.detected_protocol = result.detected;
        auto proto_view = psm::protocol::to_string_view(result.detected);
        std::strncpy(prefix_->protocol, proto_view.data(), sizeof(prefix_->protocol) - 1);
        if (auto wr = ctx_.worker_ctx.resources.lock())
        {
            wr->traffic().on_protocol_detected(result.detected);
        }

        trace::info<flt::conn | flt::protocol>(prefix_, 
            "recognized as {}", proto_view);

        // 2. 更新传输层
        ctx_.inbound = std::move(result.transport);

        // Stack 方案内部已处理连接
        if (!ctx_.inbound)
        {
            trace::debug<flt::conn | flt::protocol>(prefix_, 
                "connection handled by stack scheme");
            co_return;
        }

        auto preread_span = std::span<const std::byte>(
            result.preread.data(), result.preread.size());

        // 3. 分发到协议处理器（工厂模式，消除 switch-case）
        auto wr = ctx_.worker_ctx.resources.lock();
        if (!wr)
        {
            trace::warn<flt::conn | flt::protocol>(prefix_, "worker resources expired before dispatch");
            co_return;
        }
        psm::protocol::handler_params h_params(ctx_, preread_span);
        h_params.meta = ctx_.meta;
        h_params.trace = prefix_;
        h_params.cfg = &ctx_.server_ctx.config();
        h_params.outbound = &wr->outbound();
        auto handler = psm::protocol::make_protocol_handler(result.detected, std::move(h_params));

        if (handler)
        {
            co_await handler->run();
        }
        else if (ctx_.inbound && ctx_.outbound)
        {
            connect::tunnel_options t_opts;
            t_opts.inbound = std::move(ctx_.inbound);
            t_opts.outbound = std::move(ctx_.outbound);
            t_opts.trace = prefix_;
            t_opts.buffer_size = ctx_.buffer_size;
            t_opts.traffic = &wr->traffic();
            t_opts.detected = ctx_.detected_protocol;
            t_opts.lease = &ctx_.account_lease;
            if (ctx_.server_ctx.config().stealth.pad.enabled())
                t_opts.pad_cfg = &ctx_.server_ctx.config().stealth.pad;
            connect::tunnel_relay relay{std::move(t_opts)};
            co_await relay.run();
        }
    }

    std::shared_ptr<session> make_session(session_params &&params)
    {
        return std::make_shared<session>(std::move(params));
    }
} // namespace psm::instance::session
