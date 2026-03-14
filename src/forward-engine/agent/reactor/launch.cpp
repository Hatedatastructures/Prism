#include <forward-engine/agent/reactor/launch.hpp>

namespace ngx::agent::reactor::launch
{
    void prime(tcp::socket &socket, std::uint32_t buffer_size) noexcept
    {
        boost::system::error_code ec;
        socket.set_option(tcp::no_delay(true), ec);
        socket.set_option(net::socket_base::receive_buffer_size(buffer_size), ec);
        socket.set_option(net::socket_base::send_buffer_size(buffer_size), ec);
    }

    void start(server_context &server, worker_context &worker, stats::state &metrics, tcp::socket socket)
    {
        auto active_sessions = metrics.session_counter();
        auto on_closed = [active_sessions]() noexcept
        {
            active_sessions->fetch_sub(1U, std::memory_order_relaxed);
        };

        auto inbound = ngx::transport::make_reliable(std::move(socket));
        connection::session_params params{server, worker, std::move(inbound)};
        const auto shared_session = ngx::agent::connection::make_session(std::move(params));

        metrics.session_open();
        try
        {
            shared_session->set_on_closed(std::move(on_closed));

            const bool auth_enabled = !server.cfg.authentication.credentials.empty() || !server.cfg.authentication.users.empty();
            auto account_store = server.account_store;
            shared_session->set_account_directory(auth_enabled ? account_store.get() : nullptr);
            shared_session->set_credential_verifier(
                [auth_enabled, account_store](std::string_view credential) -> bool
                {
                    if (!auth_enabled)
                    {
                        return true;
                    }
                    if (!account_store)
                    {
                        return false;
                    }
                    return account::contains(*account_store, credential);
                });
            shared_session->start();
        }
        catch (...)
        {
            metrics.session_close();
            throw;
        }
    }

    void dispatch(net::io_context &ioc, server_context &server, worker_context &worker, stats::state &metrics, tcp::socket socket)
    {
        metrics.handoff_push();
        net::post(ioc, [&server, &worker, &metrics, sock = std::move(socket)]() mutable
                  {
            metrics.handoff_pop();
            if (!sock.is_open())
            {
                return;
            }

            prime(sock, server.cfg.buffer.size);
            try
            {
                start(server, worker, metrics, std::move(sock));
            }
            catch (const std::exception &e)
            {
                trace::error("session launch failed: {}", e.what());
            } });
    }
} // namespace ngx::agent::reactor::launch
