#include <prism/stealth/native.hpp>

#include <prism/config.hpp>
#include <prism/connect.hpp>
#include <prism/connect/util.hpp>
#include <prism/fault/handling.hpp>
#include <prism/protocol/types.hpp>
#include <prism/protocol/tls/types.hpp>
#include <prism/recognition/probe/analyzer.hpp>
#include <prism/trace.hpp>
#include <prism/transport/encrypted.hpp>
#include <prism/transport/preview.hpp>

namespace psm::stealth::native
{

    namespace net = boost::asio;
    namespace ssl = net::ssl;
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

    auto native::handshake(stealth::handshake_context ctx)
        -> net::awaitable<stealth::handshake_result>
    {
        stealth::handshake_result result;

        if (!ctx.session)
        {
            trace::warn("[Native] No session context, aborting");
            result.error = fault::code::not_supported;
            co_return result;
        }

        if (!ctx.session->server_ctx.ssl_ctx)
        {
            trace::warn("[Native] No SSL context configured, aborting");
            result.error = fault::code::not_supported;
            co_return result;
        }

        if (!ctx.inbound)
        {
            trace::warn("[Native] No inbound transport, aborting");
            result.error = fault::code::not_supported;
            co_return result;
        }

        // native 不能在 snapshot 上做 SSL 握手：snapshot 的回放机制与
        // BoringSSL SSL_accept 的读写交替流程冲突
        auto raw = connect::peel(std::move(ctx.inbound));

        if (!raw)
        {
            trace::warn("[Native] Unwrap exhausted all layers, no raw transport");
            result.error = fault::code::not_supported;
            co_return result;
        }

        trace::debug("[Native] Unwrap complete, preread={} bytes, raw={}",
                     ctx.preread.size(), fmt::ptr(raw.get()));

        // 用 preread（ClientHello 完整数据）创建干净的 preview 包装
        auto preread_span = std::span<const std::byte>(ctx.preread.data(), ctx.preread.size());
        auto clean_inbound = transport::wrap_with_preview(
            std::move(raw), preread_span, ctx.session->frame_arena.get());

        trace::debug("[Native] Starting SSL handshake");
        auto [ssl_ec, ssl_stream, recovered] = co_await transport::encrypted::ssl_handshake(
            std::move(clean_inbound), *ctx.session->server_ctx.ssl_ctx);
        if (fault::failed(ssl_ec) || !ssl_stream)
        {
            ctx.inbound = std::move(recovered);
            result.error = ssl_ec;
            trace::warn("[Native] TLS handshake failed: {}", fault::describe(ssl_ec));
            co_return result;
        }

        auto encrypted_trans = std::make_shared<transport::encrypted>(ssl_stream);

        ctx.session->stream_cancel = [ssl = ssl_stream]() noexcept
        {
            ssl->lowest_layer().transmission().cancel();
        };
        ctx.session->stream_close = [ssl = ssl_stream]() noexcept
        {
            ssl->lowest_layer().transmission().close();
        };

        constexpr std::size_t trojan_min = 60;
        std::array<std::byte, 128> inner_buf{};
        std::size_t inner_n = 0;

        while (inner_n < trojan_min)
        {
            std::error_code ec;
            auto buf_span = std::span(inner_buf.data() + inner_n, inner_buf.size() - inner_n);
            const auto n = co_await encrypted_trans->async_read_some(buf_span, ec);
            if (ec)
            {
                result.error = fault::to_code(ec);
                trace::warn("[Native] Inner probe read failed: {}", ec.message());
                co_return result;
            }
            inner_n += n;

            // safe: casting uint8_t buffer to string_view for protocol detection probe
            const auto inner_view = std::string_view(reinterpret_cast<const char *>(inner_buf.data()), inner_n);
            result.detected = recognition::probe::detect_tls(inner_view);
            if (result.detected != protocol::protocol_type::unknown)
            {
                break;
            }
        }

        // 60+ 字节仍无法识别，排除法 fallback 到 SS2022
        if (result.detected == protocol::protocol_type::unknown)
        {
            result.detected = protocol::protocol_type::shadowsocks;
            trace::debug("[Native] No known protocol matched, fallback to shadowsocks");
        }

        trace::debug("[Native] Inner protocol: {}",
                    protocol::to_string_view(result.detected));

        result.transport = std::move(encrypted_trans);
        result.preread.assign(inner_buf.begin(), inner_buf.begin() + static_cast<std::ptrdiff_t>(inner_n));

        co_return result;
    }
} // namespace psm::stealth::native