#include <prism/instance/worker/launch.hpp>

#include <prism/account/directory.hpp>
#include <prism/config/config.hpp>
#include <prism/context/context.hpp>
#include <prism/context/metadata.hpp>
#include <prism/worker/resources.hpp>
#include <prism/instance/session/session.hpp>
#include <prism/stealth/tracker.hpp>
#include <prism/trace/trace.hpp>
#include <prism/net/transport/reliable.hpp>

#include <cstring>

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

        // L1 入口层：构造 request_metadata（业务数据）+ trace_context（日志标签）
        auto meta = std::make_shared<psm::context::request_metadata>();
        auto trace_ctx = std::make_shared<trace::trace_context>();

        boost::system::error_code ep_ec;
        auto remote_ep = params.socket.remote_endpoint(ep_ec);
        if (!ep_ec)
        {
            meta->src = remote_ep;

            // 构造 address_hash 用于探测追踪(RFC-065)
            const auto &addr = remote_ep.address();
            if (addr.is_v4())
            {
                meta->src_ip_raw = psm::stealth::address_hash::from_v4(addr.to_v4().to_uint()).bytes;
            }
            else if (addr.is_v6())
            {
                auto v6_bytes = addr.to_v6().to_bytes();
                std::array<std::byte, 16> raw{};
                std::memcpy(raw.data(), v6_bytes.data(), 16);
                meta->src_ip_raw = psm::stealth::address_hash::from_v6(raw).bytes;
            }
        }
        auto local_ep = params.socket.local_endpoint(ep_ec);
        if (!ep_ec)
        {
            meta->dst = local_ep;
        }

        // 获取活跃会话计数器，用于会话关闭时递减
        auto active_sessions = metrics.session_counter();
        auto on_closed = [active_sessions]() noexcept
        {
            active_sessions->fetch_sub(1U, std::memory_order_relaxed);
        };

        // 将原始 socket 封装为可靠传输，创建会话对象
        auto inbound = psm::transport::make_reliable(std::move(params.socket));
        session::session_params sess_params{server, worker, std::move(inbound),
            std::move(meta), std::move(trace_ctx)};
        const auto shared_session = psm::instance::session::make_session(std::move(sess_params));

        // 记录会话开启
        metrics.session_open();
        auto wr = worker.resources.lock();
        if (wr)
        {
            wr->traffic().on_connect();
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

            // 持有 wr 保活，credential_function 异步调用时 worker::resources 仍有效
            auto credential_function = [auth_enabled, account_store, wr]
                (const std::string_view credential)
                    -> bool
            {
                if (!auth_enabled)
                {
                    return true;
                }
                if (!account_store)
                {
                    if (wr)
                    {
                        wr->traffic().on_auth_failure();
                    }
                    return false;
                }
                const auto result = psm::account::contains(*account_store, credential);
                if (wr)
                {
                    if (result)
                    {
                        wr->traffic().on_auth_success();
                    }
                    else
                    {
                        wr->traffic().on_auth_failure();
                    }
                }
                return result;
            };
            // 设置凭证验证器，根据认证开关决定是否校验

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
