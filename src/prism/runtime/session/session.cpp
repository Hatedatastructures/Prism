#include <prism/runtime/session/session.hpp>

#include <prism/config/config.hpp>
#include <prism/foundation/foundation.hpp>
#include <prism/foundation/fault/code.hpp>
#include <prism/net/connect/tunnel/tunnel.hpp>
#include <prism/net/connect/tunnel/tunnel_relay.hpp>
#include <prism/protocol/handler.hpp>
#include <prism/net/connect/types.hpp>
#include <prism/stealth/recognition/recognition.hpp>
#include <prism/stealth/scheme.hpp>
#include <prism/account/stats/traffic.hpp>
#include <prism/trace/trace.hpp>
#include <prism/net/transport/reliable.hpp>

#include <boost/asio/experimental/awaitable_operators.hpp>

#include <chrono>
#include <cstring>
#include <utility>

using namespace psm::trace;

namespace psm::runtime::session
{

    namespace net = boost::asio;

    session::session(session_params params)
        : res_(std::move(params.res))
    {
        if (res_->conn == 0)
        {
            // launch 未填则自动生成（兼容路径）
            const auto cid = detail::next_conn_id();
            // session_resources 内部 conn_id_ 是 const，需要重新构造
            // 这里通过 set_meta 链路同步 meta.conn_id 即可
            if (auto meta = res_->meta)
                meta->conn_id = cid;
            if (auto trace = res_->trace)
                trace->conn_id = cid;
        }
        else if (auto meta = res_->meta)
        {
            meta->conn_id = res_->conn;
        }
    }

    session::~session() noexcept
    {
        release_resources();
    }

    auto session::start() -> void
    {
        auto process = [self = this->shared_from_this()]() -> net::awaitable<void>
        {
            try
            {
                co_await self->diversion();
            }
            catch (const std::exception &e)
            {
                if (auto trace = self->res_->trace)
                {
                    trace::error<flt::conn | flt::protocol>(*trace,
                        "unhandled exception in diversion: {}", e.what());
                }
            }
            catch (...)
            {
                if (auto trace = self->res_->trace)
                {
                    trace::error<flt::conn | flt::protocol>(*trace,
                        "unknown exception in diversion");
                }
            }
            self->release_resources();
        };

        auto completion = [self = this->shared_from_this()](const std::exception_ptr &ep) noexcept
        {
            if (!ep)
                return;
            auto trace = self->res_->trace;
            try
            {
                std::rethrow_exception(ep);
            }
            catch (const ::psm::exception::deviant &e)
            {
                if (trace)
                    trace::error<flt::conn | flt::protocol>(*trace,
                        "abnormal exception: {}", e.dump());
            }
            catch (const std::exception &e)
            {
                if (trace)
                    trace::error<flt::conn | flt::protocol>(*trace,
                        "standard exception: {}", e.what());
            }
            catch (...)
            {
                if (trace)
                    trace::error<flt::conn | flt::protocol>(*trace,
                        "unknown exception type");
            }
            self->release_resources();
        };

        net::co_spawn(res_->worker->ioc, std::move(process), std::move(completion));
    }

    auto session::close() -> void
    {
        if (state_ != state::active)
            return;
        state_ = state::closing;

        if (auto trace = res_->trace)
            trace::debug<flt::conn | flt::protocol>(*trace, "session closing");

        if (res_->inbound)
            res_->inbound->cancel();
        if (res_->outbound)
            res_->outbound->cancel();
    }

    auto session::release_resources() noexcept -> void
    {
        if (state_ == state::closed)
            return;
        state_ = state::closed;

        res_->worker->traffic.on_disconnect(res_->detected);

        if (res_->inbound)
        {
            res_->inbound->close();
            res_->inbound.reset();
        }
        if (res_->outbound)
        {
            if (auto *rel = res_->outbound->lowest_layer<transport::reliable>())
            {
                rel->shutdown_write();
            }
            res_->outbound->close();
            res_->outbound.reset();
        }
        if (on_closed_)
        {
            auto callback = std::move(on_closed_);
            on_closed_ = nullptr;
            callback();
        }
        if (auto trace = res_->trace)
            trace::info<flt::conn | flt::protocol>(*trace, "session closed");
    }

    auto session::diversion() -> net::awaitable<void>
    {
        auto trace = res_->trace;

        if (!res_->inbound)
        {
            if (trace)
                trace::warn<flt::conn | flt::protocol>(trace,
                    "diversion aborted: missing inbound transmission");
            co_return;
        }

        if (auto meta = res_->meta)
        {
            if (trace)
                trace::info<flt::conn | flt::protocol>(trace,
                    "session established, {} -> {}",
                    meta->src.address().to_string(),
                    meta->dst.address().to_string());
        }
        else if (trace)
        {
            trace::info<flt::conn | flt::protocol>(trace, "session established");
        }

        // 1. 完整识别流程
        handshake_deadline_ = std::make_unique<net::steady_timer>(
            res_->inbound->executor(), std::chrono::seconds(30));

        auto deadline_expired = [this]() -> net::awaitable<bool>
        {
            boost::system::error_code ec;
            co_await handshake_deadline_->async_wait(
                net::redirect_error(trace::use_prefix_awaitable, ec));
            co_return true;
        };

        auto do_recognize = [this, self = this->shared_from_this()]()
            -> net::awaitable<recognition::recognize_result>
        {
            ::psm::stealth::stealth_opts st_opts;
            st_opts.transport = res_->inbound;
            st_opts.session = res_.get();
            st_opts.session_keepalive = std::move(self);
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
            res_->inbound->cancel();
            if (trace)
            {
                trace->phase.set("handshake");
                trace::warn<flt::conn | flt::protocol>(trace,
                    "handshake deadline exceeded, aborting");
                trace->phase.clear();
            }
            co_return;
        }

        if (!result.success)
        {
            if (trace)
                trace::warn<flt::conn | flt::protocol>(trace,
                    "recognition failed: {}", fault::describe(result.error));
            co_return;
        }

        res_->detected = result.detected;
        auto proto_view = psm::connect::to_string_view(result.detected);
        if (trace)
            std::strncpy(trace->protocol, proto_view.data(), sizeof(trace->protocol) - 1);
        res_->worker->traffic.on_protocol_detected(result.detected);

        if (trace)
            trace::info<flt::conn | flt::protocol>(trace,
                "recognized as {}", proto_view);

        // 2. 更新传输层
        res_->inbound = std::move(result.transport);

        if (!res_->inbound)
        {
            if (trace)
                trace::debug<flt::conn | flt::protocol>(trace,
                    "connection handled by stack scheme");
            co_return;
        }

        auto preread_span = std::span<const std::byte>(
            result.preread.data(), result.preread.size());

        // 3. 分发到协议处理器
        psm::protocol::handler_params h_params(*res_, preread_span);
        auto handler = psm::protocol::make_protocol_handler(result.detected, std::move(h_params));

        if (handler)
        {
            // handler 通过 h_params 持有 res 引用
            co_await handler->run();
        }
        else if (res_->inbound && res_->outbound)
        {
            connect::tunnel_options t_opts;
            t_opts.inbound = std::move(res_->inbound);
            t_opts.outbound = std::move(res_->outbound);
            t_opts.trace = res_->trace;
            t_opts.buffer_size = res_->buffer;
            t_opts.traffic = &res_->worker->traffic;
            t_opts.detected = res_->detected;
            t_opts.lease = &res_->lease;
            if (res_->worker->process->cfg->stealth.pad.enabled())
                t_opts.pad_cfg = &res_->worker->process->cfg->stealth.pad;
            connect::tunnel_relay relay{std::move(t_opts)};
            co_await relay.run();
        }
    }

    auto make_session(session_params &&params) -> std::shared_ptr<session>
    {
        return std::make_shared<session>(std::move(params));
    }

} // namespace psm::runtime::session
