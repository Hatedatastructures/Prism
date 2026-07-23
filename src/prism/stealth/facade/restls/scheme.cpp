#include <prism/stealth/facade/restls/scheme.hpp>

#include <prism/config/config.hpp>
#include <prism/resource/session.hpp>
#include <prism/foundation/fault/code.hpp>
#include <prism/net/connect/types.hpp>
#include <prism/stealth/recognition/probe/analyzer.hpp>
#include <prism/stealth/facade/restls/handshake.hpp>
#include <prism/stealth/facade/restls/transport.hpp>
#include <prism/trace/trace.hpp>
#include <prism/net/transport/reliable.hpp>

#include <boost/asio.hpp>

using namespace psm::trace;

namespace psm::stealth::restls
{

    namespace net = boost::asio;

    auto scheme::active(const psm::config &cfg) const noexcept
        -> bool
    {
        return cfg.stealth.restls.enabled();
    }

    auto scheme::name() const noexcept
        -> std::string_view
    {
        return "restls";
    }

    auto scheme::snis(const psm::config &cfg) const
        -> memory::vector<memory::string>
    {
        return make_sni_list(cfg.stealth.restls.server_names);
    }

    auto scheme::guess(const psm::config & /*cfg*/) const
        -> verify_result
    {
        return {
            .score = 100,
            .solo_flag = 0,
            .note = "Restls: rely on SNI match"};
    }

    auto scheme::handshake(stealth::stealth_opts ctx)
        -> net::awaitable<stealth::handshake_result>
    {
        stealth::handshake_result result;

        // 执行 Restls 握手（中间人代理模式：转发 ClientHello 到真实 TLS 后端）
        handshake_detail detail;
        auto hs_result = co_await restls::handshake(
            restls::handshake_opts{
                .raw_trans = ctx.transport,
                .cfg = ctx.session->worker->process->cfg->stealth.restls,
                .client_hello = std::move(ctx.preread),
                .detail = detail,
            });

        if (!fault::succeeded(hs_result.error))
        {
            result.detected = psm::connect::protocol_type::tls;
            result.error = hs_result.error;
            result.polluted = hs_result.polluted;
            result.transport = ctx.transport;
            trace::debug<flt::conn | flt::protocol>(prefix_, "handshake failed, pass to next scheme");
            co_return result;
        }

        trace::debug<flt::conn | flt::protocol>(
            "handshake succeeded, tls13={}", detail.version == tls_version::v13);

        // 从 restls_transport 预读内层数据（SS2022 加密流），无需做 TLS 识别
        // 早期实现调 detect_tls 试图区分内层协议，但 SS2022 salt 是随机的 16B，
        // 偶然匹配 TLS record header 字节模式（0x17 0x03 0x03 ...）会被误判为 tls，
        // 触发 Scheme 'restls' returned TLS → identify failed: not_supported
        // 实测命中率约 57%，导致成功率从 100% 跌到 ~40%
        // restls 内层只可能是 shadowsocks（协议设计如此），强制 fallback
        std::array<std::byte, 128> inner_buf{};
        std::size_t inner_n = 0;
        constexpr std::size_t min_probe = 32;

        while (inner_n < min_probe)
        {
            std::error_code probe_ec;
            auto buf_span = std::span<std::byte>(inner_buf.data() + inner_n, inner_buf.size() - inner_n);
            const auto n = co_await hs_result.transport->async_read_some(buf_span, probe_ec);
            if (probe_ec)
            {
                trace::warn<flt::conn | flt::protocol>(                    "inner probe read failed: {}", probe_ec.message());
                break;
            }
            inner_n += n;
        }

        if (inner_n >= 32)
        {
            result.detected = psm::connect::protocol_type::shadowsocks;
            trace::debug<flt::conn | flt::protocol>(                "restls inner fallback to shadowsocks, inner_n={}", inner_n);
        }

        result.preread.assign(inner_buf.begin(), inner_buf.begin() + static_cast<std::ptrdiff_t>(inner_n));
        result.transport = hs_result.transport;
        result.scheme = "restls";

        trace::debug<flt::conn | flt::protocol>(            "restls_transport created, inner protocol: {}",
            psm::connect::to_string_view(result.detected));

        co_return result;
    }
} // namespace psm::stealth::restls
