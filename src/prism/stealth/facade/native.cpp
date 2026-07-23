#include <prism/stealth/facade/native.hpp>

#include <prism/resource/session.hpp>
#include <prism/config/config.hpp>
#include <prism/net/net.hpp>
#include <prism/net/connect/util.hpp>
#include <prism/foundation/fault/handling.hpp>
#include <prism/net/connect/types.hpp>
#include <prism/protocol/tls/types.hpp>
#include <prism/stealth/recognition/probe/analyzer.hpp>
#include <prism/trace/trace.hpp>
#include <prism/net/transport/encrypted.hpp>
#include <prism/net/transport/preview.hpp>

using namespace psm::trace;

namespace psm::stealth::native
{

    namespace net = boost::asio;
    auto native::active(const psm::config &cfg) const noexcept
        -> bool
    {
        return cfg.stealth.native_tls.enabled;
    }


    auto native::name() const noexcept
        -> std::string_view
    {
        return "native";
    }


    auto native::guess(const psm::config & /*cfg*/) const
        -> verify_result
    {
        return {
            .score = 50,
            .solo_flag = 0,
            .note = "native TLS fallback"};
    }


    auto native::handshake(stealth::stealth_opts ctx)
        -> net::awaitable<stealth::handshake_result>
    {
        stealth::handshake_result result;

        if (!ctx.session)
        {
            trace::warn<flt::conn | flt::protocol>(prefix_, "No session context, aborting");
            result.error = fault::code::not_supported;
            co_return result;
        }

        if (!ctx.session->worker->process->ssl)
        {
            trace::warn<flt::conn | flt::protocol>(prefix_, "No SSL context configured, aborting");
            result.error = fault::code::not_supported;
            co_return result;
        }

        if (!ctx.transport)
        {
            trace::warn<flt::conn | flt::protocol>(prefix_, "No inbound transport, aborting");
            result.error = fault::code::not_supported;
            co_return result;
        }

        // native 不能在 snapshot 上做 SSL 握手：snapshot 的回放机制与
        // BoringSSL SSL_accept 的读写交替流程冲突
        auto raw = connect::peel(std::move(ctx.transport));

        if (!raw)
        {
            trace::warn<flt::conn | flt::protocol>(prefix_, "Unwrap exhausted all layers, no raw transport");
            result.error = fault::code::not_supported;
            co_return result;
        }

        trace::debug<flt::conn | flt::protocol>(prefix_, "Unwrap complete, preread={} bytes, raw={}",
                     ctx.preread.size(), fmt::ptr(raw.get()));

        // 用 preread（ClientHello 完整数据）创建干净的 preview 包装
        auto preread_span = std::span<const std::byte>(ctx.preread.data(), ctx.preread.size());
        auto clean_inbound = transport::wrap_with_preview(
            std::move(raw), preread_span);

        trace::debug<flt::conn | flt::protocol>(prefix_, "Starting SSL handshake");
        auto [ssl_ec, ssl_stream, recovered] = co_await transport::encrypted::ssl_handshake(
            std::move(clean_inbound), *ctx.session->worker->process->ssl);
        if (fault::failed(ssl_ec) || !ssl_stream)
        {
            ctx.transport = std::move(recovered);
            result.error = ssl_ec;
            trace::warn<flt::conn | flt::protocol>(prefix_, "TLS handshake failed: {}", fault::describe(ssl_ec));
            co_return result;
        }

        auto encrypted_trans = std::make_shared<transport::encrypted>(ssl_stream);

        // stream_close/stream_cancel 已移除：
        // encrypted::close() 和 encrypted::cancel() 内部已通过 ssl_stream 操作底层 socket，
        // session::close()/release_resources() 直接调用 transport 的 cancel()/close() 即可。
        // 原先的回调绕过 encrypted 层直接操作 lowest_layer，导致同一 socket 被 close/cancel 两次。

        // 一次性读取内部协议探测数据，避免多次 co_await 循环
        std::array<std::byte, 128> inner_buf{};
        std::error_code ec;
        const auto n = co_await encrypted_trans->async_read_some(inner_buf, ec);
        if (ec && n == 0)
        {
            result.error = fault::to_code(ec);
            trace::warn<flt::conn | flt::protocol>(prefix_, "Inner probe read failed: {}", ec.message());
            co_return result;
        }

        const auto inner_view = std::string_view(reinterpret_cast<const char *>(inner_buf.data()), n);
        result.detected = recognition::probe::detect_tls(inner_view);

        trace::debug<flt::conn | flt::protocol>(prefix_, "Inner protocol: {}",
                    psm::connect::to_string_view(result.detected));

        result.transport = std::move(encrypted_trans);
        result.preread.assign(inner_buf.begin(), inner_buf.begin() + static_cast<std::ptrdiff_t>(n));

        co_return result;
    }
} // namespace psm::stealth::native
