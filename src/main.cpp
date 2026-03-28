/**
 * @file main.cpp
 * @brief ForwardEngine 服务端入口
 * @details 程序主入口，负责初始化全局资源、加载配置、构建工作线程池
 * 和监听线程。启动流程为：启用全局内存池 → 加载 JSON 配置 →
 * 初始化日志 → 注册协议处理器 → 构建账户目录 → 创建 worker 线程池
 * → 绑定负载均衡器 → 启动监听线程接受外部连接。
 */

#include <memory>
#include <thread>
#include <vector>
#include <iostream>
#include <fstream>

#include <forward-engine/agent.hpp>
#include <forward-engine/agent/account/directory.hpp>
#include <forward-engine/agent/dispatch/handlers.hpp>
#include <forward-engine/agent/front/balancer.hpp>
#include <forward-engine/agent/front/listener.hpp>
#include <forward-engine/memory.hpp>
#include <forward-engine/memory/pool.hpp>
#include <forward-engine/exception.hpp>
#include <forward-engine/config.hpp>
#include <forward-engine/loader/load.hpp>
#include <forward-engine/crypto/sha224.hpp>

namespace agent = ngx::agent;

// 配置文件路径（开发环境用绝对路径，生产环境应改为相对路径或启动参数传入）
constexpr std::string_view configuration_path = {R"(C:\Users\C1373\Desktop\code\forward-engine\src\configuration.json)"};

/**
 * @brief 程序主入口
 * @details 启动流程：启用全局内存池 → 加载配置并初始化日志 →
 * 注册协议处理器 → 构建账户目录（凭据哈希化）→ 按 CPU 核心数创建
 * worker 线程池 → 绑定到负载均衡器 → 启动监听线程。worker 数量为
 * CPU 核心数减一，至少一个；监听线程独立运行，负责接收新连接并
 * 通过均衡器分发到负载最低的 worker。
 */
int main()
{
    ngx::memory::system::enable_global_pooling();

    try
    {
        // 获取 CPU 核心数，用于确定 worker 线程数量
        const auto threads_count = std::thread::hardware_concurrency();
        if (threads_count == 0)
        {
            throw ngx::exception::security("system error : {}", "core acquisition failed");
        }

        // 加载配置并拆分为 agent 配置和日志配置
        auto [agent, trace] = ngx::loader::load(configuration_path);
        ngx::trace::init(trace);

        // 注册协议检测与处理函数（Trojan、SOCKS5、HTTP）
        ngx::agent::dispatch::register_handlers();

        // 构建共享账户目录，将配置中的凭据规范化后写入
        const auto account_store = std::make_shared<agent::account::directory>(ngx::memory::system::global_pool());
        const auto &[credentials, users] = agent.authentication;
        account_store->reserve(credentials.size() + users.size());
        for (const auto &cred : credentials)
        {
            const auto normalized = ngx::crypto::normalize_credential(std::string_view(cred.data(), cred.size()));
            account_store->upsert(normalized);
        }
        for (const auto &[credential, max_connections] : users)
        {
            const auto normalized = ngx::crypto::normalize_credential(std::string_view(credential.data(), credential.size()));
            account_store->upsert(normalized, max_connections);
        }

        // worker 线程数 = CPU 核心数 - 1（保留一个核心给监听线程），至少 1 个
        const std::uint32_t workers_count = threads_count > 1U ? threads_count - 1U : 1U;
        const agent::config &agent_config = agent;

        // 创建 worker 实例池，每个 worker 持有独立的 io_context 和协议处理管线
        ngx::memory::vector<std::unique_ptr<agent::worker::worker>> workers;
        workers.reserve(workers_count);
        for (std::uint32_t index = 0; index < workers_count; ++index)
        {
            workers.emplace_back(std::make_unique<agent::worker::worker>(agent_config, account_store));
        }

        // 将 worker 绑定到负载均衡器，提供连接分发和负载快照回调
        ngx::memory::vector<agent::front::balancer::worker_binding> bindings;
        bindings.reserve(workers_count);
        for (const auto &worker_ptr : workers)
        {
            agent::worker::worker *worker_ref = worker_ptr.get();
            auto delivery_function = [worker_ref](boost::asio::ip::tcp::socket socket)
            {
                worker_ref->dispatch_socket(std::move(socket));
            };
            auto snapshot_function = [worker_ref]() -> agent::front::worker_load_snapshot
            {
                return worker_ref->load_snapshot();
            };
            bindings.emplace_back(delivery_function, snapshot_function);
        }

        agent::front::balancer dispatcher(std::move(bindings));
        agent::front::listener service_listener(agent_config, dispatcher);

        // 启动所有线程：worker 线程运行 io_context 事件循环，监听线程接受新连接
        ngx::memory::vector<std::jthread> threads;
        threads.reserve(workers_count + 1U);

        for (const auto &worker_ptr : workers)
        {
            agent::worker::worker *worker_ref = worker_ptr.get();
            auto worker_handler = [worker_ref]()
            {
                try
                {
                    worker_ref->run();
                }
                catch (const std::exception &e)
                {
                    ngx::trace::error("dispatch exception: {}", e.what());
                }
                catch (...)
                {
                    ngx::trace::error("dispatch exception: unknown");
                }
            };
            threads.emplace_back(std::move(worker_handler));
        }

        auto listen_thread = [&service_listener]()
        {
            try
            {
                service_listener.listen();
            }
            catch (const std::exception &e)
            {
                ngx::trace::error("listen exception: {}", e.what());
            }
            catch (...)
            {
                ngx::trace::error("listen exception: unknown");
            }
        };
        threads.emplace_back(listen_thread);
    }
    catch (const ngx::exception::security &e)
    {
        std::cerr << e.what() << '\n';
    }
    catch (const std::exception &e)
    {
        std::cerr << e.what() << '\n';
    }
    catch (...)
    {
        std::cerr << "unknown exception" << '\n';
    }

    return 0;
}
