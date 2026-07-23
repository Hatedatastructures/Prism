#include <prism/protocol/multiplex/bootstrap.hpp>
#include <prism/protocol/multiplex/h2mux/craft.hpp>
#include <prism/protocol/multiplex/smux/craft.hpp>
#include <prism/protocol/multiplex/yamux/craft.hpp>
#include <prism/trace/trace.hpp>
#include <prism/trace/context.hpp>
#include <prism/net/transport/transmission.hpp>

using transmission = psm::transport::transmission;

using namespace psm::trace;

namespace psm::multiplex
{

    namespace
    {
        auto negotiate(transmission &transport)
            -> net::awaitable<std::pair<std::error_code, protocol_type>>
        {
            std::error_code ec;

            std::array<std::byte, 2> header{};
            const auto n = co_await transport::async_read(transport, header, ec);
            if (ec)
            {
                co_return std::make_pair(ec, protocol_type::smux);
            }
            if (n < 2)
            {
                co_return std::make_pair(std::make_error_code(std::errc::connection_reset), protocol_type::smux);
            }

            const auto protocol = static_cast<protocol_type>(header[1]);

            if (const auto version = static_cast<std::uint8_t>(header[0]); version > 0)
            {
                std::array<std::byte, 1> padding_enabled_buf{};
                const auto pen = co_await transport::async_read(transport, padding_enabled_buf, ec);
                if (ec)
                {
                    co_return std::make_pair(ec, protocol_type::smux);
                }
                if (pen < 1)
                {
                    co_return std::make_pair(std::make_error_code(std::errc::connection_reset), protocol_type::smux);
                }

                if (padding_enabled_buf[0] != std::byte{0})
                {
                    std::array<std::byte, 2> padding_len_buf{};
                    const auto pn = co_await transport::async_read(transport, padding_len_buf, ec);
                    if (ec)
                    {
                        co_return std::make_pair(ec, protocol_type::smux);
                    }
                    if (pn < 2)
                    {
                        co_return std::make_pair(std::make_error_code(std::errc::connection_reset), protocol_type::smux);
                    }

                    const auto hi = static_cast<std::uint16_t>(padding_len_buf[0]) << 8;
                    const auto lo = static_cast<std::uint16_t>(padding_len_buf[1]);
                    const auto padding_len = static_cast<std::uint16_t>(hi | lo);
                    if (padding_len > 0)
                    {
                        memory::vector<std::byte> padding(padding_len);
                        const auto padding_n = co_await transport::async_read(transport, padding, ec);
                        if (ec || padding_n < padding_len)
                        {
                            std::error_code result_ec = std::make_error_code(std::errc::connection_reset);
                            if (ec)
                                result_ec = ec;
                            co_return std::make_pair(result_ec, protocol_type::smux);
                        }
                    }
                }
            }

            const auto *proto_name = "smux";
            if (protocol == protocol_type::yamux)
            {
                proto_name = "yamux";
            }
            trace::debug<flt::conn | flt::protocol>("sing-mux handshake completed, protocol={}", proto_name);
            co_return std::make_pair(std::error_code{}, protocol);
        }
    } // namespace

    auto bootstrap(bootstrap_context ctx)
        -> net::awaitable<std::shared_ptr<core>>
    {
        auto &res = *ctx.res;
        const auto prefix_ = res.trace;
        auto &mux_cfg = res.worker->process->cfg->mux;
        auto *outbound_ptr = &*res.worker->outbound;
        auto *traffic_ptr = &res.worker->traffic;
        const auto proto = res.detected;

        auto [ec, protocol] = co_await negotiate(*ctx.transport);
        if (ec)
        {
            if (prefix_)
                trace::warn<flt::conn | flt::protocol>(prefix_,
                    "sing-mux negotiate failed: {}", ec.message());
            co_return nullptr;
        }

        try
        {
            switch (protocol)
            {
            case protocol_type::yamux:
                if (prefix_)
                    trace::info<flt::conn | flt::protocol>(prefix_, "constructing yamux session");
                {
                    std::shared_ptr<core> session = std::make_shared<yamux::craft>(
                        core_options{std::move(ctx.transport), outbound_ptr, mux_cfg, {}});
                    session->set_traffic(traffic_ptr, proto);
                    session->set_prefix(prefix_);
                    if (prefix_)
                        trace::info<flt::conn | flt::protocol>(prefix_, "yamux session constructed");
                    co_return session;
                }

            case protocol_type::h2mux:
                if (prefix_)
                    trace::info<flt::conn | flt::protocol>(prefix_, "constructing h2mux session");
                {
                    auto singmux_resolver = [](std::int32_t, const h2mux::h2_headers &) -> h2mux::stream_info
                    {
                        return {};
                    };
                    std::shared_ptr<core> session = std::make_shared<h2mux::craft>(
                        core_options{std::move(ctx.transport), outbound_ptr, mux_cfg, {}},
                        h2mux::craft_init{outbound_ptr, mux_cfg, singmux_resolver});
                    session->set_traffic(traffic_ptr, proto);
                    session->set_prefix(prefix_);
                    if (prefix_)
                        trace::info<flt::conn | flt::protocol>(prefix_, "h2mux session constructed");
                    co_return session;
                }

            case protocol_type::smux:
            default:
                if (prefix_)
                    trace::info<flt::conn | flt::protocol>(prefix_, "constructing smux session");
                {
                    std::shared_ptr<core> session = std::make_shared<smux::craft>(
                        core_options{std::move(ctx.transport), outbound_ptr, mux_cfg, {}});
                    session->set_traffic(traffic_ptr, proto);
                    session->set_prefix(prefix_);
                    if (prefix_)
                        trace::info<flt::conn | flt::protocol>(prefix_, "smux session constructed");
                    co_return session;
                }
            }
        }
        catch (const std::exception &e)
        {
            if (prefix_)
                trace::error<flt::conn | flt::protocol>(prefix_,
                    "create_session exception: {}", e.what());
            co_return nullptr;
        }
        catch (...)
        {
            if (prefix_)
                trace::error<flt::conn | flt::protocol>(prefix_,
                    "create_session unknown exception");
            co_return nullptr;
        }
    }

} // namespace psm::multiplex
