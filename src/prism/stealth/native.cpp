/**
 * @file native.cpp
 * @brief 原生 TLS 伪装方案实现（兜底）
 * @details Native 是 Tier 2 方案，作为兜底处理无法匹配其他方案的 TLS 连接。
 */

#include <prism/stealth/native.hpp>
#include <prism/pipeline/primitives.hpp>
#include <prism/channel/transport/encrypted.hpp>
#include <prism/trace.hpp>
#include <prism/fault/handling.hpp>
#include <prism/protocol/analysis.hpp>
#include <prism/protocol/tls/types.hpp>

namespace psm::stealth::schemes
{
    auto native::active([[maybe_unused]] const psm::config &cfg) const noexcept -> bool
    {
        return true;  // Native 始终启用，作为兜底
    }

    auto native::name() const noexcept -> std::string_view
    {
        return "native";
    }

    auto native::guess(const psm::config &cfg) const
        -> verify_result
    {
        // Native 是兜底方案，返回最低分
        return {
            .score = 50,  // 最低分，排在所有其他方案之后
            .solo_flag = 0,
            .note = "native TLS fallback"};
    }

    auto native::handshake(stealth::handshake_context ctx)
        -> net::awaitable<stealth::handshake_result>
    {
        stealth::handshake_result result;

        if (!ctx.session)
        {
            result.error = fault::code::not_supported;
            co_return result;
        }

        auto [ssl_ec, ssl_stream, recovered] = co_await pipeline::primitives::ssl_handshake(
            std::move(ctx.inbound), *ctx.session->server.ssl_ctx);
        if (fault::failed(ssl_ec) || !ssl_stream)
        {
            ctx.inbound = std::move(recovered);
            result.error = ssl_ec;
            trace::warn("[Native] TLS handshake failed: {}", fault::describe(ssl_ec));
            co_return result;
        }

        auto encrypted_trans = std::make_shared<channel::transport::encrypted>(ssl_stream);

        ctx.session->active_stream_cancel = [ssl = ssl_stream]() noexcept
        {
            ssl->lowest_layer().transmission().cancel();
        };
        ctx.session->active_stream_close = [ssl = ssl_stream]() noexcept
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
            const auto n = co_await encrypted_trans->async_read_some(std::move(buf_span), ec);
            if (ec)
            {
                result.error = fault::to_code(ec);
                trace::warn("[Native] Inner probe read failed: {}", ec.message());
                co_return result;
            }
            inner_n += n;

            const auto inner_view = std::string_view(reinterpret_cast<const char *>(inner_buf.data()), inner_n);
            result.detected = protocol::analysis::detect_tls(inner_view);
            if (result.detected != protocol::protocol_type::unknown)
            {
                break;
            }
        }

        if (result.detected == protocol::protocol_type::unknown)
        {
            result.error = fault::code::protocol_error;
            trace::warn("[Native] Cannot determine inner protocol");
            co_return result;
        }

        trace::debug("[Native] Inner protocol: {}",
                    protocol::to_string_view(result.detected));

        result.transport = std::move(encrypted_trans);
        result.preread.assign(inner_buf.begin(), inner_buf.begin() + static_cast<std::ptrdiff_t>(inner_n));

        co_return result;
    }
} // namespace psm::stealth::schemes