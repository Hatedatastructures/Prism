#include <prism/stealth/facade/restls/scheme.hpp>

#include <prism/config/config.hpp>
#include <prism/context/context.hpp>
#include <prism/core/fault/code.hpp>
#include <prism/proto/protocol/types.hpp>
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

    auto scheme::handshake(stealth::handshake_context ctx)
        -> net::awaitable<stealth::handshake_result>
    {
        stealth::handshake_result result;

        // 释放 raw TCP socket（去掉 inbound 上层包装）
        auto *rel = ctx.inbound->lowest_layer<transport::reliable>();
        if (!rel)
        {
            trace::debug<flt::conn | flt::protocol>("restls: cannot access reliable transport");
            result.detected = protocol::protocol_type::tls;
            result.transport = std::move(ctx.inbound);
            co_return result;
        }

        auto raw_socket_opt = rel->release_socket();
        if (!raw_socket_opt)
        {
            trace::warn<flt::conn | flt::protocol>("restls: cannot release socket");
            result.detected = protocol::protocol_type::tls;
            result.transport = std::move(ctx.inbound);
            co_return result;
        }

        auto raw_trans = std::make_shared<transport::reliable>(std::move(*raw_socket_opt));

        // 执行 Restls 握手（中间人代理模式：转发 ClientHello 到真实 TLS 后端）
        handshake_detail detail;
        auto hs_result = co_await restls::handshake(
            restls::handshake_opts{
                .raw_trans = raw_trans,
                .cfg = ctx.cfg->stealth.restls,
                .client_hello = std::move(ctx.preread),
                .detail = detail,
            });

        if (!fault::succeeded(hs_result.error))
        {
            result.detected = protocol::protocol_type::tls;
            result.error = hs_result.error;
            result.polluted = hs_result.polluted;
            trace::debug<flt::conn | flt::protocol>("handshake failed, pass to next scheme");
            co_return result;
        }

        trace::debug<flt::conn | flt::protocol>(
            "handshake succeeded, tls13={}", detail.version == tls_version::v13);

        // 从 restls_transport 预读内层数据，识别内层协议
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
                trace::warn<flt::conn | flt::protocol>(
                    "inner probe read failed: {}", probe_ec.message());
                break;
            }
            inner_n += n;

            auto inner_view = std::string_view(
                reinterpret_cast<const char *>(inner_buf.data()), inner_n);
            auto detected = recognition::probe::detect_tls(inner_view);
            if (detected != protocol::protocol_type::unknown)
            {
                result.detected = detected;
                break;
            }
        }

        if (result.detected == protocol::protocol_type::unknown && inner_n >= 32)
        {
            result.detected = protocol::protocol_type::shadowsocks;
            trace::debug<flt::conn | flt::protocol>(
                "restls inner fallback to shadowsocks, inner_n={}", inner_n);
        }

        result.preread.assign(inner_buf.begin(), inner_buf.begin() + static_cast<std::ptrdiff_t>(inner_n));
        result.transport = hs_result.transport;
        result.scheme = "restls";

        trace::debug<flt::conn | flt::protocol>(
            "restls_transport created, inner protocol: {}",
            protocol::to_string_view(result.detected));

        co_return result;
    }
} // namespace psm::stealth::restls
