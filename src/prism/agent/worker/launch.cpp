#include <prism/agent/worker/launch.hpp>

namespace psm::agent::worker::launch
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
        const auto protocol = ec ? tcp::v4() : (local_ep.address().is_v6() ? tcp::v6() : tcp::v4());

        // 剥离原生句柄，sock 变为空壳
        auto native_handle = sock.release();

        // 在目标 io_context 上重建 socket 并绑定句柄
        tcp::socket migrated(target_ioc);
        migrated.assign(protocol, native_handle, ec);
        if (ec || !migrated.is_open())
        {
            trace::error("socket migration failed: {}", ec.message());
            // assign 失败时关闭已 release 的 native handle，防止 fd 泄漏
            ::closesocket(native_handle);
            return std::nullopt;
        }

        return migrated;
    }

    void start(server_context &server, worker_context &worker, stats::state &metrics, tcp::socket socket)
    {
        // 获取活跃会话计数器，用于会话关闭时递减
        auto active_sessions = metrics.session_counter();
        auto on_closed = [active_sessions]() noexcept
        {
            active_sessions->fetch_sub(1U, std::memory_order_relaxed);
        };

        // 将原始 socket 封装为可靠传输，创建会话对象
        auto inbound = psm::channel::transport::make_reliable(std::move(socket));
        session::session_params params{server, worker, std::move(inbound)};
        const auto shared_session = psm::agent::session::make_session(std::move(params));

        // 记录会话开启
        metrics.session_open();
        try
        {
            // 设置会话关闭回调
            shared_session->set_on_closed(std::move(on_closed));

            // 判断是否启用认证：检查统一用户列表是否非空
            const bool auth_enabled = !server.cfg.authentication.users.empty();
            auto account_store = server.account_store;

            // 设置账户目录，认证禁用时传入 nullptr
            shared_session->set_account_directory(auth_enabled ? account_store.get() : nullptr);

            auto credential_function = [auth_enabled, account_store](const std::string_view credential) -> bool
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
            };
            // 设置凭证验证器，根据认证开关决定是否校验
            shared_session->set_credential_verifier(credential_function);

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

    void dispatch(net::io_context &ioc, server_context &server, worker_context &worker, stats::state &metrics, tcp::socket socket)
    {
        // 记录连接移交进入队列
        metrics.handoff_push();

        auto start_session = [&server, &worker, &metrics, sock = std::move(socket), &ioc]() mutable
        {
            // 记录连接移交离开队列
            metrics.handoff_pop();

            // 将 socket 从 listener 的 io_context 迁移到 worker 的 io_context
            auto migrated = migrate_executor(sock, ioc);
            if (!migrated)
            {
                return;
            }

            // 配置 socket 选项
            prime(*migrated, server.cfg.buffer.size);

            try
            {
                start(server, worker, metrics, std::move(*migrated));
            }
            catch (const std::exception &e)
            {
                trace::error("session launch failed: {}", e.what());
            }
        };
        net::post(ioc, std::move(start_session));
    }
} // namespace psm::agent::worker::launch
