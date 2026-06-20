#include <prism/instance/session/session.hpp>

#include <prism/config/config.hpp>
#include <prism/net/connect/tunnel/tunnel.hpp>
#include <prism/core/core.hpp>
#include <prism/core/fault/code.hpp>
#include <prism/proto/protocol/http/process.hpp>
#include <prism/proto/protocol/shadowsocks/process.hpp>
#include <prism/proto/protocol/socks5/process.hpp>
#include <prism/proto/protocol/trojan/process.hpp>
#include <prism/proto/protocol/types.hpp>
#include <prism/proto/protocol/vless/process.hpp>
#include <prism/stealth/recognition/recognition.hpp>
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
          prefix_(std::make_shared<trace::session_prefix>()),
          ctx_{context::session_opts{id_, params.server, params.worker, frame_arena_, {},
              params.server.config().buffer.size, std::move(params.inbound), params.src_ip_raw}}
    {
    }

    session::~session() noexcept
    {
        release_resources();
    }

    void session::init_prefix(const trace::session_prefix &pfx) noexcept
    {
        prefix_->conn_id = id_;
        std::memcpy(prefix_->client, pfx.client, sizeof(prefix_->client));
        prefix_->client_port = pfx.client_port;
        std::memcpy(prefix_->listen, pfx.listen, sizeof(prefix_->listen));
        prefix_->listen_port = pfx.listen_port;
    }

    void session::start()
    {
        auto process = [self = this->shared_from_this()]() -> net::awaitable<void>
        {
            trace::scope_guard guard(self->prefix_);
            try
            {
                co_await self->diversion();
            }
            catch (const std::exception &e)
            {
                trace::error<flt::conn | flt::protocol>(
                    "unhandled exception in diversion: {}", e.what());
            }
            catch (...)
            {
                trace::error<flt::conn | flt::protocol>(
                    "unknown exception in diversion");
            }
            self->release_resources();
        };

        auto completion = [self = this->shared_from_this()](const std::exception_ptr &ep) noexcept
        {
            if (!ep)
                return;
            trace::scope_guard guard(self->prefix_);
            try
            {
                std::rethrow_exception(ep);
            }
            catch (const ::psm::exception::deviant &e)
            {
                trace::error<flt::conn | flt::protocol>(
                    "abnormal exception: {}", e.dump());
            }
            catch (const std::exception &e)
            {
                trace::error<flt::conn | flt::protocol>(
                    "standard exception: {}", e.what());
            }
            catch (...)
            {
                trace::error<flt::conn | flt::protocol>(
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
        trace::debug<flt::conn | flt::protocol>("session closing");

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

        if (ctx_.worker_ctx.traffic)
        {
            ctx_.worker_ctx.traffic->on_disconnect(ctx_.detected_protocol);
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
        trace::info<flt::conn | flt::protocol>("session closed");
    }

    auto session::diversion()
        -> net::awaitable<void>
    {
        if (!ctx_.inbound)
        {
            trace::warn<flt::conn | flt::protocol>(
                "diversion aborted: missing inbound transmission");
            co_return;
        }

        trace::info<flt::conn | flt::protocol>(
            "session established, {}:{} -> {}:{}",
            prefix_->client, prefix_->client_port,
            prefix_->listen, prefix_->listen_port);

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
            co_return co_await recognition::recognize(recognition::recognize_context{
                .transport = ctx_.inbound,
                .cfg = &ctx_.server_ctx.config(),
                .router = &ctx_.worker_ctx.router,
                .session = &ctx_,
                .session_keepalive = std::move(self),
                .frame_arena = &ctx_.frame_arena
            });
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
            trace::warn<flt::conn | flt::protocol>(
                "handshake deadline exceeded, aborting");
            prefix_->phase.clear();
            co_return;
        }

        if (!result.success)
        {
            trace::warn<flt::conn | flt::protocol>(
                "recognition failed: {}", fault::describe(result.error));
            co_return;
        }

        // 记录识别出的协议类型并通知流量统计
        ctx_.detected_protocol = result.detected;
        auto proto_view = psm::protocol::to_string_view(result.detected);
        std::strncpy(prefix_->protocol, proto_view.data(), sizeof(prefix_->protocol) - 1);
        if (ctx_.worker_ctx.traffic)
        {
            ctx_.worker_ctx.traffic->on_protocol_detected(result.detected);
        }

        trace::info<flt::conn | flt::protocol>(
            "recognized as {}", proto_view);

        // 2. 更新传输层
        ctx_.inbound = std::move(result.transport);

        // Stack 方案内部已处理连接
        if (!ctx_.inbound)
        {
            trace::debug<flt::conn | flt::protocol>(
                "connection handled by stack scheme");
            co_return;
        }

        auto preread_span = std::span<const std::byte>(
            result.preread.data(), result.preread.size());

        // 3. 分发到协议处理器
        switch (result.detected)
        {
        case psm::protocol::protocol_type::http:
            co_await psm::protocol::http::handle(ctx_, preread_span);
            break;
        case psm::protocol::protocol_type::socks5:
            co_await psm::protocol::socks5::handle(ctx_, preread_span);
            break;
        case psm::protocol::protocol_type::trojan:
            co_await psm::protocol::trojan::handle(ctx_, preread_span);
            break;
        case psm::protocol::protocol_type::vless:
            co_await psm::protocol::vless::handle(ctx_, preread_span);
            break;
        case psm::protocol::protocol_type::shadowsocks:
            co_await psm::protocol::shadowsocks::handle(ctx_, preread_span);
            break;
        default:
            if (ctx_.inbound && ctx_.outbound)
            {
                connect::tunnel_options t_opts{
                    std::move(ctx_.inbound), std::move(ctx_.outbound), ctx_};
                // 传递 pad 配置(RFC-009)
                if (ctx_.server_ctx.config().stealth.pad.enabled())
                    t_opts.pad_cfg = &ctx_.server_ctx.config().stealth.pad;
                co_await connect::tunnel(std::move(t_opts));
            }
            break;
        }
    }

    std::shared_ptr<session> make_session(session_params &&params)
    {
        return std::make_shared<session>(std::move(params));
    }
} // namespace psm::instance::session
