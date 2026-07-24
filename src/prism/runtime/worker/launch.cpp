#include <prism/runtime/worker/launch.hpp>

#include <prism/account/directory.hpp>
#include <prism/config/config.hpp>
#include <prism/foundation/rate/counter.hpp>
#include <prism/runtime/session/session.hpp>
#include <prism/resource/session.hpp>
#include <prism/trace/trace.hpp>
#include <prism/net/transport/reliable.hpp>

#include <cstring>

#ifndef _WIN32
#include <unistd.h>
#endif

using namespace psm::trace;

namespace psm::runtime::worker::launch
{

    auto prime(tcp::socket &socket, std::uint32_t buffer_size) noexcept -> void
    {
        boost::system::error_code ec;
        socket.set_option(tcp::no_delay(true), ec);
        socket.set_option(net::socket_base::receive_buffer_size(buffer_size), ec);
        socket.set_option(net::socket_base::send_buffer_size(buffer_size), ec);
    }

    [[nodiscard]] auto migrate_executor(tcp::socket &sock, net::io_context &target_ioc) noexcept
        -> std::optional<tcp::socket>
    {
        boost::system::error_code ec;
        auto local_ep = sock.local_endpoint(ec);
        auto protocol = tcp::v4();
        if (!ec && local_ep.address().is_v6())
            protocol = tcp::v6();

        auto native_handle = sock.release();

        tcp::socket migrated(target_ioc);
        migrated.assign(protocol, native_handle, ec);
        if (ec || !migrated.is_open())
        {
            trace::error("socket migration failed: {}", ec.message());
#ifdef _WIN32
            ::closesocket(native_handle);
#else
            ::close(native_handle);
#endif
            return std::nullopt;
        }

        return migrated;
    }

    auto start(launch_params params) -> void
    {
        auto &worker_res = params.worker;
        auto &metrics = params.metrics;

        // L1 入口层：构造 request_metadata + trace_context
        auto meta = std::make_shared<psm::resource::metadata>();
        auto trace_ctx = std::make_shared<trace::trace_context>();

        boost::system::error_code ep_ec;
        auto remote_ep = params.socket.remote_endpoint(ep_ec);
        if (!ep_ec)
        {
            meta->src = remote_ep;
            const auto &addr = remote_ep.address();
            if (addr.is_v4())
            {
                meta->src_ip = psm::rate::address_hash::from_v4(addr.to_v4().to_uint()).bytes;
            }
            else if (addr.is_v6())
            {
                auto v6_bytes = addr.to_v6().to_bytes();
                std::array<std::byte, 16> raw{};
                std::memcpy(raw.data(), v6_bytes.data(), 16);
                meta->src_ip = psm::rate::address_hash::from_v6(raw).bytes;
            }
        }
        auto local_ep = params.socket.local_endpoint(ep_ec);
        if (!ep_ec)
        {
            meta->dst = local_ep;
        }

        auto active_sessions = metrics.session_counter();
        auto on_closed = [active_sessions]() noexcept
        {
            active_sessions->fetch_sub(1U, std::memory_order_relaxed);
        };

        // 封装 socket 为可靠传输
        auto inbound = psm::transport::make_reliable(std::move(params.socket));

        // 构造 session::options
        psm::resource::session::options sess_res_opts;
        sess_res_opts.worker = worker_res;
        sess_res_opts.conn = session::detail::next_conn_id();
        sess_res_opts.buffer = worker_res->process->cfg->buffer.size;
        sess_res_opts.inbound = std::move(inbound);
        sess_res_opts.src = meta ? meta->src_ip : std::array<std::byte, 16>{};
        sess_res_opts.trace = trace_ctx;
        sess_res_opts.meta = meta;

        // 构造 session_resources
        auto sess_res = std::make_shared<psm::resource::session>(std::move(sess_res_opts));

        // 构造 session
        session::session_params sess_params{std::move(sess_res)};
        const auto shared_session = session::make_session(std::move(sess_params));

        metrics.session_open();
        worker_res->traffic.on_connect();

        try
        {
            shared_session->set_on_closed(std::move(on_closed));
            shared_session->start();
        }
        catch (...)
        {
            metrics.session_close();
            throw;
        }
    }

    auto dispatch(launch_params params) -> void
    {
        auto &worker_res = params.worker;
        auto &metrics = params.metrics;

        metrics.handoff_push();

        auto start_session = [worker_res, &metrics,
                              sock = std::move(params.socket),
                              ioc = &worker_res->ioc]() mutable
        {
            metrics.handoff_pop();

            auto migrated = migrate_executor(sock, *ioc);
            if (!migrated)
                return;

            prime(*migrated, worker_res->process->cfg->buffer.size);

            try
            {
                start(launch_params{worker_res, metrics, std::move(*migrated)});
            }
            catch (const std::exception &e)
            {
                trace::error("session launch failed: {}", e.what());
            }
        };
        net::post(worker_res->ioc, std::move(start_session));
    }

} // namespace psm::runtime::worker::launch
