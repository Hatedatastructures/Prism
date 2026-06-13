#include <prism/instance/worker/launch.hpp>

#include <prism/account/directory.hpp>
#include <prism/config/config.hpp>
#include <prism/context/context.hpp>
#include <prism/instance/session/session.hpp>
#include <prism/trace/trace.hpp>
#include <prism/net/transport/reliable.hpp>

using namespace psm::trace;

#ifndef _WIN32
#include <unistd.h>
#endif

#include <cstring>

namespace psm::instance::worker::launch
{

    void prime(tcp::socket &socket, std::uint32_t buffer_size) noexcept
    {
        boost::system::error_code ec;

        // 禁用 Nagle 算法，减少小包延迟
        socket.set_option(tcp::no_delay(true), ec);

        // 设置收发缓冲区大小，优化吞吐量
        socket.set_option(net::socket_base::receive_buffer_size(buffer_size), ec);
        socket.set_option(net::socket_base::send_buffer_size(buffer_size), ec);
    }


    [[nodiscard]] std::optional<tcp::socket> migrate_executor(tcp::socket &sock, net::io_context &target_ioc) noexcept
    {
        // release 前 query 本地地址，判断 IPv4/IPv6
        boost::system::error_code ec;
        auto local_ep = sock.local_endpoint(ec);
        auto protocol = tcp::v4();
        if (!ec && local_ep.address().is_v6())
            protocol = tcp::v6();

        // 剥离原生句柄，sock 变为空壳
        auto native_handle = sock.release();

        // 在目标 io_context 上重建 socket 并绑定句柄
        tcp::socket migrated(target_ioc);
        migrated.assign(protocol, native_handle, ec);
        if (ec || !migrated.is_open())
        {
            trace::error("socket migration failed: {}", ec.message());
            // assign 失败时关闭已 release 的 native handle，防止 fd 泄漏
#ifdef _WIN32
            ::closesocket(native_handle);
#else
            ::close(native_handle);
#endif
            return std::nullopt;
        }

        return migrated;
    }


    void start(launch_params params)
    {
        auto &server = params.server;
        auto &worker = params.worker;
        auto &metrics = params.metrics;

        // 在 socket 被移动前提取端点信息
        trace::session_prefix pfx;
        boost::system::error_code ep_ec;
        auto remote_ep = params.socket.remote_endpoint(ep_ec);
        if (!ep_ec)
        {
            auto addr_str = remote_ep.address().to_string();
            std::strncpy(pfx.client, addr_str.c_str(), sizeof(pfx.client) - 1);
            pfx.client_port = remote_ep.port();
        }
        auto local_ep = params.socket.local_endpoint(ep_ec);
        if (!ep_ec)
        {
            auto addr_str = local_ep.address().to_string();
            std::strncpy(pfx.listen, addr_str.c_str(), sizeof(pfx.listen) - 1);
            pfx.listen_port = local_ep.port();
        }

        // 获取活跃会话计数器，用于会话关闭时递减
        auto active_sessions = metrics.session_counter();
        auto on_closed = [active_sessions]() noexcept
        {
            active_sessions->fetch_sub(1U, std::memory_order_relaxed);
        };

        // 将原始 socket 封装为可靠传输，创建会话对象
        auto inbound = psm::transport::make_reliable(std::move(params.socket));
        session::session_params sess_params{server, worker, std::move(inbound)};
        const auto shared_session = psm::instance::session::make_session(std::move(sess_params));

        // 填充日志前缀的端点信息
        shared_session->init_prefix(pfx);

        // 记录会话开启
        metrics.session_open();
        if (worker.traffic)
        {
            worker.traffic->on_connect();
        }
        try
        {
            // 设置会话关闭回调
            shared_session->set_on_closed(std::move(on_closed));

            // 判断是否启用认证：检查统一用户列表是否非空
            const bool auth_enabled = !server.config().instance.auth.users.empty();
            auto account_store = server.account_store;

            // 设置账户目录，认证禁用时传入 nullptr
            account::directory *dir = nullptr;
            if (auth_enabled)
            {
                dir = account_store.get();
            }
            shared_session->set_account_directory(dir);

            auto credential_function = [auth_enabled, account_store, traffic = worker.traffic]
                (const std::string_view credential)
                    -> bool
            {
                if (!auth_enabled)
                {
                    return true;
                }
                if (!account_store)
                {
                    if (traffic)
                    {
                        traffic->on_auth_failure();
                    }
                    return false;
                }
                const auto result = psm::account::contains(*account_store, credential);
                if (traffic)
                {
                    if (result)
                    {
                        traffic->on_auth_success();
                    }
                    else
                    {
                        traffic->on_auth_failure();
                    }
                }
                return result;
            };
            // 设置凭证验证器，根据认证开关决定是否校验
            shared_session->set_credential_verifier(credential_function);

            // 设置出站代理（通过 worker 的 outbound::direct 实例）
            if (worker.outbound)
            {
                shared_session->set_outbound_proxy(worker.outbound);
            }

            // 启动会话处理流程
            shared_session->start();
        }
        catch (...)
        {
            // 异常时回滚会话计数
            metrics.session_close();
            throw;
        }
    }


    void dispatch(launch_params params)
    {
        auto &server = params.server;
        auto &worker = params.worker;
        auto &metrics = params.metrics;

        // 记录连接移交进入队列
        metrics.handoff_push();

        auto start_session = [&server, &worker, &metrics, sock = std::move(params.socket), ioc = &worker.io_context]() mutable
        {
            // 记录连接移交离开队列
            metrics.handoff_pop();

            // 将 socket 从 listener 的 io_context 迁移到 worker 的 io_context
            auto migrated = migrate_executor(sock, *ioc);
            if (!migrated)
            {
                return;
            }

            // 配置 socket 选项
            prime(*migrated, server.config().buffer.size);

            try
            {
                start(launch_params{server, worker, metrics, std::move(*migrated)});
            }
            catch (const std::exception &e)
            {
                trace::error("session launch failed: {}", e.what());
            }
        };
        net::post(worker.io_context, std::move(start_session));
    }

} // namespace psm::instance::worker::launch
