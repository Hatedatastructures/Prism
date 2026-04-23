/**
 * @file standard_tls_stage.cpp
 * @brief 标准 TLS 剥离 Stage 实现
 * @details 将 session.cpp 中 lines 289-353 的标准 TLS 逻辑迁移到此。
 */

#include <prism/agent/pipeline/stages/standard.hpp>
#include <prism/pipeline/primitives.hpp>
#include <prism/channel/transport/encrypted.hpp>
#include <prism/trace.hpp>
#include <prism/fault/handling.hpp>

namespace psm::agent::pipeline::stages
{
    auto standard_tls_stage::process(agent::session_context &ctx, protocol::detection_result &detect_result,
                                     std::span<const std::byte> &span)
        -> net::awaitable<stage_result>
    {
        stage_result result;

        // TLS 握手
        auto ssl_result = co_await psm::pipeline::primitives::ssl_handshake(ctx, span);
        auto ssl_ec = ssl_result.first;
        auto ssl_stream = std::move(ssl_result.second);
        if (psm::fault::failed(ssl_ec) || !ssl_stream)
        {
            result.type = stage_result_type::failed;
            trace::warn("[StandardTlsStage] TLS handshake failed: {}", psm::fault::describe(ssl_ec));
            co_return result;
        }

        // 创建加密传输层
        auto encrypted_trans = std::make_shared<channel::transport::encrypted>(ssl_stream);

        // 设置 TLS 流清理回调（通过 std::shared_ptr 捕获 ssl_stream）
        ctx.active_stream_cancel = [s = ssl_stream]() noexcept
        {
            s->lowest_layer().transmission().cancel();
        };
        ctx.active_stream_close = [s = ssl_stream]() noexcept
        {
            s->lowest_layer().transmission().close();
        };

        // 增量读取内层数据并逐次探测协议
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
                result.type = stage_result_type::failed;
                result.error = ec;
                trace::warn("[StandardTlsStage] Inner probe read failed: {}", ec.message());
                co_return result;
            }
            inner_n += n;

            const auto inner_view = std::string_view(
                reinterpret_cast<const char *>(inner_buf.data()), inner_n);
            detect_result.type = protocol::analysis::detect_tls(inner_view);
            if (detect_result.type != protocol::protocol_type::unknown)
            {
                break;
            }
        }

        if (detect_result.type == protocol::protocol_type::unknown)
        {
            result.type = stage_result_type::failed;
            trace::warn("[StandardTlsStage] Cannot determine inner protocol");
            co_return result;
        }

        trace::debug("[StandardTlsStage] Inner protocol: {}", protocol::to_string_view(detect_result.type));

        // 更新 ctx.inbound 和 span
        ctx.inbound = std::move(encrypted_trans);
        span = std::span<const std::byte>(inner_buf.data(), inner_n);

        result.type = stage_result_type::success;
        result.outbound_inbound = ctx.inbound;
        result.detected_protocol = detect_result.type;
        result.preread_data.assign(inner_buf.begin(), inner_buf.begin() + static_cast<std::ptrdiff_t>(inner_n));
        co_return result;
    }
} // namespace psm::agent::pipeline::stages
