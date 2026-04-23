/**
 * @file native.cpp
 * @brief 原生 TLS 伪装方案实现（兜底）
 */

#include <prism/stealth/native.hpp>
#include <prism/pipeline/primitives.hpp>
#include <prism/channel/transport/encrypted.hpp>
#include <prism/trace.hpp>
#include <prism/fault/handling.hpp>
#include <prism/protocol/analysis.hpp>

namespace psm::stealth::schemes
{
    auto native::is_enabled([[maybe_unused]] const agent::config &cfg) const noexcept -> bool
    {
        return true;
    }

    auto native::name() const noexcept -> std::string_view
    {
        return "native";
    }

    auto native::execute(scheme_context ctx)
        -> net::awaitable<scheme_result>
    {
        scheme_result result;

        if (!ctx.session)
        {
            result.error = fault::code::not_supported;
            co_return result;
        }

        ctx.session->inbound = std::move(ctx.inbound);

        auto [ssl_ec, ssl_stream] = co_await pipeline::primitives::ssl_handshake(*ctx.session);
        if (fault::failed(ssl_ec) || !ssl_stream)
        {
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
            auto buf_span = std::span<std::byte>(inner_buf.data() + inner_n, inner_buf.size() - inner_n);
            const auto n = co_await encrypted_trans->async_read_some(std::move(buf_span), ec);
            if (ec)
            {
                result.error = fault::to_code(ec);
                trace::warn("[Native] Inner probe read failed: {}", ec.message());
                co_return result;
            }
            inner_n += n;

            auto inner_view = std::string_view(
                reinterpret_cast<const char *>(inner_buf.data()), inner_n);
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
