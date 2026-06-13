#include <prism/proto/multiplex/bootstrap.hpp>
#include <prism/proto/multiplex/h2mux/craft.hpp>
#include <prism/proto/multiplex/smux/craft.hpp>
#include <prism/proto/multiplex/yamux/craft.hpp>
#include <prism/trace/trace.hpp>
#include <prism/trace/context.hpp>
#include <prism/net/transport/transmission.hpp>

using transmission = psm::transport::transmission;

using namespace psm::trace;

namespace psm::multiplex
{

    namespace
    {
        // 执行 sing-mux 协议协商
        // 从 transport 读取 sing-mux 协议头并消费。Protocol 字段指示
        // 客户端选择的多路复用协议类型（0=smux, 1=yamux）。
        auto negotiate(transmission &transport, const memory::resource_pointer mr)
            -> net::awaitable<std::pair<std::error_code, protocol_type>>
        {
            std::error_code ec;

            // 读取协议头：[Version 1B][Protocol 1B]
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

            // 解析客户端选择的协议类型
            const auto protocol = static_cast<protocol_type>(header[1]);

            // Version > 0 表示有 padding
            if (const auto version = static_cast<std::uint8_t>(header[0]); version > 0)
            {
                // 读取 2 字节 padding 长度（大端序）
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
                    memory::vector<std::byte> padding(mr);
                    padding.resize(padding_len);
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
        // 执行 sing-mux 协商，获取客户端选择的协议类型
        auto [ec, protocol] = co_await negotiate(*ctx.transport, ctx.mr);
        if (ec)
        {
            trace::warn<flt::conn | flt::protocol>("sing-mux negotiate failed: {}", ec.message());
            co_return nullptr;
        }

        // 根据协商结果创建对应协议实例
        try
        {
            switch (protocol)
            {
            case protocol_type::yamux:
                trace::info<flt::conn | flt::protocol>("constructing yamux session");
                {
                    std::shared_ptr<core> session = std::make_shared<yamux::craft>(
                        core_options{std::move(ctx.transport), ctx.router, ctx.cfg, ctx.mr});
                    session->set_traffic(ctx.traffic, ctx.proto);
                    if (trace::active_prefix && trace::active_prefix->is_alive()) session->set_prefix(*trace::active_prefix);
                    trace::info<flt::conn | flt::protocol>("yamux session constructed");
                    co_return session;
                }

            case protocol_type::h2mux:
                trace::info<flt::conn | flt::protocol>("constructing h2mux session");
                {
                    // h2mux bootstrap 路径：sing-mux resolver（等待 StreamRequest）
                    auto singmux_resolver = [](std::int32_t, const h2mux::h2_headers &) -> h2mux::stream_info
                    {
                        // sing-mux 模式：地址在 DATA 帧的 StreamRequest 中，HEADERS 无地址
                        return {};
                    };
                    std::shared_ptr<core> session = std::make_shared<h2mux::craft>(
                        core_options{std::move(ctx.transport), ctx.router, ctx.cfg, ctx.mr},
                        h2mux::craft_init{ctx.router, ctx.cfg, singmux_resolver});
                    session->set_traffic(ctx.traffic, ctx.proto);
                    if (trace::active_prefix && trace::active_prefix->is_alive()) session->set_prefix(*trace::active_prefix);
                    trace::info<flt::conn | flt::protocol>("h2mux session constructed");
                    co_return session;
                }

            case protocol_type::smux:
            default:
                trace::info<flt::conn | flt::protocol>("constructing smux session");
                {
                    std::shared_ptr<core> session = std::make_shared<smux::craft>(
                        core_options{std::move(ctx.transport), ctx.router, ctx.cfg, ctx.mr});
                    session->set_traffic(ctx.traffic, ctx.proto);
                    if (trace::active_prefix && trace::active_prefix->is_alive()) session->set_prefix(*trace::active_prefix);
                    trace::info<flt::conn | flt::protocol>("smux session constructed");
                    co_return session;
                }
            }
        }
        catch (const std::exception &e)
        {
            trace::error<flt::conn | flt::protocol>("create_session exception: {}", e.what());
            co_return nullptr;
        }
        catch (...)
        {
            trace::error<flt::conn | flt::protocol>("create_session unknown exception");
            co_return nullptr;
        }
    }
} // namespace psm::multiplex
