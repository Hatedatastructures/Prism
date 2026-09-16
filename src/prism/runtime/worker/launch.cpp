#include <prism/diagnose/diagnose.hpp>
#include <prism/foundation/rate/counter.hpp>
#include <prism/net/transport/reliable.hpp>
#include <prism/resource/session.hpp>
#include <prism/runtime/session/session.hpp>
#include <prism/runtime/worker/launch.hpp>
#include <prism/settings/settings.hpp>
#include <prism/user/directory.hpp>

#include <cstdint>
#include <cstring>

#ifndef _WIN32
#include <unistd.h>
#endif

using namespace psm::diagnose;

namespace psm::runtime::worker::launch
{

    namespace
    {
        auto close_socket(tcp::socket &socket) noexcept -> void
        {
            boost::system::error_code ec;
            socket.close(ec);
        }
    } // namespace

    enum class dispatch_phase : std::uint8_t
    {
        pending,
        running,
        cancelled,
        completed,
    };

    struct dispatch_entry
    {
        dispatch_entry(std::shared_ptr<psm::resource::worker> Worker,
                       std::shared_ptr<psm::stats::runtime::worker_load> Metrics,
                       ConnectionLauncher Launcher, tcp::socket Socket)
            : worker(std::move(Worker)), metrics(std::move(Metrics)), launcher(std::move(Launcher)),
              socket(std::move(Socket))
        {
        }

        [[nodiscard]] auto try_start() noexcept -> bool
        {
            auto expected = dispatch_phase::pending;
            return phase.compare_exchange_strong(expected, dispatch_phase::running,
                                                 std::memory_order_acq_rel,
                                                 std::memory_order_acquire);
        }

        auto cancel() noexcept -> void
        {
            auto expected = dispatch_phase::pending;
            if (!phase.compare_exchange_strong(expected, dispatch_phase::cancelled,
                                               std::memory_order_acq_rel,
                                               std::memory_order_acquire))
            {
                return;
            }
            metrics->handoff_pop();
            close_socket(socket);
        }

        auto execute() -> void
        {
            metrics->handoff_pop();

            if (!worker->alive())
            {
                close_socket(socket);
                complete();
                return;
            }

            auto migrated = migrate_executor(socket, worker->ioc);
            if (!migrated)
            {
                complete();
                return;
            }

            prime(*migrated);
            if (!worker->alive())
            {
                close_socket(*migrated);
                complete();
                return;
            }

            try
            {
                launch_params params{worker, metrics, std::move(*migrated)};
                if (launcher)
                {
                    launcher(std::move(params));
                }
                else
                {
                    start(std::move(params));
                }
            }
            catch (const std::exception &e)
            {
                diagnose::error("connection launch failed: {}", e.what());
            }
            catch (...)
            {
                diagnose::error("connection launch failed: unknown exception");
            }
            complete();
        }

        auto complete() noexcept -> void
        {
            phase.store(dispatch_phase::completed, std::memory_order_release);
        }

        std::shared_ptr<psm::resource::worker> worker;
        std::shared_ptr<psm::stats::runtime::worker_load> metrics;
        ConnectionLauncher launcher;
        tcp::socket socket;
        std::atomic<dispatch_phase> phase{dispatch_phase::pending};
    };

    dispatch_state::dispatch_state()
        : pending_(std::make_shared<const std::vector<std::shared_ptr<dispatch_entry>>>())
    {
    }

    dispatch_state::~dispatch_state()
    {
        cancel();
    }

    auto dispatch_state::add(std::shared_ptr<dispatch_entry> entry) -> bool
    {
        while (!stopped_.load(std::memory_order_acquire))
        {
            auto current = pending_.load(std::memory_order_acquire);
            if (stopped_.load(std::memory_order_acquire))
            {
                return false;
            }

            auto next = std::make_shared<std::vector<std::shared_ptr<dispatch_entry>>>(*current);
            next->push_back(entry);
            std::shared_ptr<const std::vector<std::shared_ptr<dispatch_entry>>> published(std::move(next));
            if (pending_.compare_exchange_weak(current, published,
                                                std::memory_order_acq_rel,
                                                std::memory_order_acquire))
            {
                if (stopped_.load(std::memory_order_acquire))
                {
                    remove(entry);
                    entry->cancel();
                    return false;
                }
                return true;
            }
        }
        return false;
    }

    auto dispatch_state::remove(const std::shared_ptr<dispatch_entry> &entry) -> void
    {
        for (;;)
        {
            auto current = pending_.load(std::memory_order_acquire);
            if (!current)
            {
                return;
            }
            auto next = std::make_shared<std::vector<std::shared_ptr<dispatch_entry>>>();
            next->reserve(current->size());
            bool found = false;
            for (const auto &candidate : *current)
            {
                if (candidate == entry)
                {
                    found = true;
                    continue;
                }
                next->push_back(candidate);
            }
            if (!found)
            {
                return;
            }

            std::shared_ptr<const std::vector<std::shared_ptr<dispatch_entry>>> published(std::move(next));
            if (pending_.compare_exchange_weak(current, published,
                                                std::memory_order_acq_rel,
                                                std::memory_order_acquire))
            {
                return;
            }
        }
    }

    auto dispatch_state::cancel() noexcept -> void
    {
        if (stopped_.exchange(true, std::memory_order_acq_rel))
        {
            return;
        }

        const auto current = pending_.exchange({}, std::memory_order_acq_rel);
        if (!current)
        {
            return;
        }
        for (const auto &entry : *current)
        {
            if (entry)
            {
                entry->cancel();
            }
        }
    }

    // 仅设 TCP_NODELAY；收发缓冲不设固定值，交由 Windows 自动调优
    // 自适应 RTT/丢包（固定 256KB 会在手机 Wi-Fi 等高 RTT 下截断带宽）
    auto prime(tcp::socket &socket) noexcept -> void
    {
        boost::system::error_code ec;
        socket.set_option(tcp::no_delay(true), ec);
    }

    [[nodiscard]] auto migrate_executor(tcp::socket &sock, net::io_context &target_ioc) noexcept
        -> std::optional<tcp::socket>
    {
        if (!sock.is_open())
        {
            return std::nullopt;
        }

        boost::system::error_code ec;
        auto local_ep = sock.local_endpoint(ec);
        auto protocol = tcp::v4();
        if (!ec && local_ep.address().is_v6())
        {
            protocol = tcp::v6();
        }

        auto native_handle = sock.release();

        tcp::socket migrated(target_ioc);
        migrated.assign(protocol, native_handle, ec);
        if (ec || !migrated.is_open())
        {
            diagnose::error("socket migration failed: {}", ec.message());
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
        auto &metrics = *params.metrics;

        // L1 入口层：构造 request_metadata + context
        auto meta = std::make_shared<psm::resource::metadata>();
        auto trace_ctx = std::make_shared<diagnose::context>();

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
        { active_sessions->fetch_sub(1U, std::memory_order_relaxed); };

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

    auto dispatch(launch_params params, ConnectionLauncher launcher,
                  std::shared_ptr<dispatch_state> state) -> void
    {
        if (!params.worker || !params.metrics || !params.worker->alive())
        {
            close_socket(params.socket);
            return;
        }

        if (!state)
        {
            state = std::make_shared<dispatch_state>();
        }

        auto entry = std::make_shared<dispatch_entry>(params.worker, params.metrics,
                                                       std::move(launcher), std::move(params.socket));
        entry->metrics->handoff_push();
        if (!state->add(entry))
        {
            entry->cancel();
            return;
        }

        try
        {
            net::post(entry->worker->ioc,
                      [state, entry]() mutable
                      {
                          if (!entry->try_start())
                          {
                              return;
                          }
                          state->remove(entry);
                          entry->execute();
                      });
        }
        catch (const std::exception &e)
        {
            state->remove(entry);
            entry->cancel();
            diagnose::error("connection dispatch failed: {}", e.what());
        }
        catch (...)
        {
            state->remove(entry);
            entry->cancel();
            diagnose::error("connection dispatch failed: unknown exception");
        }
    }

} // namespace psm::runtime::worker::launch
