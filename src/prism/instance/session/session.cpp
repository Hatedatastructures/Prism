#include <prism/instance/session/session.hpp>

#include <prism/config.hpp>
#include <prism/connect/tunnel/tunnel.hpp>
#include <prism/exception.hpp>
#include <prism/fault/code.hpp>
#include <prism/protocol/http/process.hpp>
#include <prism/protocol/shadowsocks/process.hpp>
#include <prism/protocol/socks5/process.hpp>
#include <prism/protocol/trojan/process.hpp>
#include <prism/protocol/types.hpp>
#include <prism/protocol/vless/process.hpp>
#include <prism/recognition/recognition.hpp>
#include <prism/stats/traffic.hpp>
#include <prism/trace.hpp>
#include <prism/transport/reliable.hpp>

#include <boost/asio/experimental/awaitable_operators.hpp>

#include <chrono>

namespace psm::instance::session
{

    namespace net = boost::asio;

    session::session(session_params params)
        : id_(detail::next_sid()),
          ctx_{context::session_opts{id_, params.server, params.worker, frame_arena_, {},
              params.server.config().buffer.size, std::move(params.inbound)}}
    {
    }

    session::~session() noexcept
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

        net::co_spawn(ctx_.worker_ctx.io_context, std::move(process), std::move(completion));
    }

    void session::close()
    {
        if (state_ != state::active)
            return;
        state_ = state::closing;
        trace::debug("[Session] [{}] Session closing.", id_);

        if (ctx_.stream_cancel)
            ctx_.stream_cancel();
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

        // 通知流量统计连接断开
        if (ctx_.worker_ctx.traffic && ctx_.detected_protocol != psm::protocol::protocol_type::unknown)
        {
            ctx_.worker_ctx.traffic->on_disconnect(ctx_.detected_protocol);
        }

        if (ctx_.stream_close)
        {
            ctx_.stream_close();
            ctx_.stream_close = nullptr;
            ctx_.stream_cancel = nullptr;
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
        trace::debug("[Session] [{}] Session closed.", id_);
    }

    auto session::diversion()
        -> net::awaitable<void>
    {
        if (!ctx_.inbound)
        {
            trace::warn("[Session] [{}] diversion aborted: missing inbound transmission.", id_);
            co_return;
        }

        // 1. 完整识别流程（统一入口：外层探测 + TLS 伪装方案识别），带 30 秒握手超时
        handshake_deadline_ = std::make_unique<net::steady_timer>(
            ctx_.inbound->executor(), std::chrono::seconds(30));

        auto deadline_expired = [this]() -> net::awaitable<bool>
        {
            boost::system::error_code ec;
            co_await handshake_deadline_->async_wait(net::redirect_error(net::use_awaitable, ec));
            co_return true;
        };

        auto do_recognize = [this]() -> net::awaitable<recognition::recognize_result>
        {
            co_return co_await recognition::recognize(recognition::recognize_context{
                .transport = ctx_.inbound,
                .cfg = &ctx_.server_ctx.config(),
                .router = &ctx_.worker_ctx.router,
                .session = &ctx_,
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
            // 定时器先触发，识别超时
            timed_out = true;
        }

        // 无论谁先完成，取消定时器
        handshake_deadline_->cancel();
        handshake_deadline_.reset();

        if (timed_out)
        {
            // 取消传输层以中止识别流程
            ctx_.inbound->cancel();
            trace::warn("[Session] [{}] Handshake deadline exceeded, aborting.", id_);
            co_return;
        }

        if (!result.success)
        {
            trace::warn("[Session] [{}] Recognition failed: {}", id_, fault::describe(result.error));
            co_return;
        }

        // 记录识别出的协议类型并通知流量统计
        ctx_.detected_protocol = result.detected;
        if (ctx_.worker_ctx.traffic)
        {
            ctx_.worker_ctx.traffic->on_protocol_detected(result.detected);
        }

        // 2. 更新传输层
        ctx_.inbound = std::move(result.transport);

        auto preread_span = std::span<const std::byte>(
            result.preread.data(), result.preread.size());

        // 3. 分发到协议处理器
        trace::debug("[Session] [{}] Dispatching to {}", id_, psm::protocol::to_string_view(result.detected));
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
                co_await connect::tunnel({std::move(ctx_.inbound), std::move(ctx_.outbound), ctx_});
            }
            break;
        }
    }

    std::shared_ptr<session> make_session(session_params &&params)
    {
        return std::make_shared<session>(std::move(params));
    }
} // namespace psm::instance::session
