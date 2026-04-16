#include <exception>
#include <memory>
#include <thread>
#include <vector>
#include <iostream>
#include <fstream>
#include <filesystem>

#include <prism/agent.hpp>
#include <prism/agent/account/directory.hpp>
#include <prism/agent/dispatch/handlers.hpp>
#include <prism/agent/front/balancer.hpp>
#include <prism/agent/front/listener.hpp>
#include <prism/memory.hpp>
#include <prism/memory/pool.hpp>
#include <prism/exception.hpp>
#include <prism/config.hpp>
#include <prism/loader/load.hpp>

namespace agent = psm::agent;

// 启动流程：启用全局内存池 → 加载配置 → 注册处理器 → 构建 worker 线程池 → 绑定均衡器 → 启动监听
int main(int argc, char *argv[])
{
    psm::memory::system::enable_global_pooling();

    // 配置文件路径：命令行参数 > 可执行文件同目录下的 configuration.json
    std::filesystem::path configuration_path;
    if (argc > 1)
    {
        configuration_path = std::filesystem::absolute(std::filesystem::path(argv[1]));
    }
    else
    {
        configuration_path = std::filesystem::absolute(
            std::filesystem::path(argv[0]).parent_path() / "configuration.json");
    }

    if (!std::filesystem::exists(configuration_path))
    {
        std::cerr << "configuration file not found: " << configuration_path << '\n';
        return 1;
    }

    try
    {
        // 获取 CPU 核心数，用于确定 worker 线程数量
        const auto threads_count = std::thread::hardware_concurrency();
        if (threads_count == 0)
        {
            throw psm::exception::security("system error : {}", "core acquisition failed");
        }

        // 加载配置并拆分为 agent 配置和日志配置
        auto [agent, trace] = psm::loader::load(configuration_path.string());
        psm::trace::init(trace);

        // 注册协议检测与处理函数（Trojan、SOCKS5、HTTP、VLESS、Shadowsocks）
        psm::agent::dispatch::register_handlers();

        // 从认证配置构建共享账户目录
        const auto account_store = psm::loader::build_account_directory(agent.authentication);

        // worker 线程数 = CPU 核心数 - 1（保留一个核心给监听线程），至少 1 个
        const std::uint32_t workers_count = threads_count > 1U ? threads_count - 1U : 1U;
        const agent::config &agent_config = agent;

        // 创建 worker 实例池，每个 worker 持有独立的 io_context 和协议处理管线
        psm::memory::vector<std::unique_ptr<agent::worker::worker>> workers;
        workers.reserve(workers_count);
        for (std::uint32_t index = 0; index < workers_count; ++index)
        {
            workers.emplace_back(std::make_unique<agent::worker::worker>(agent_config, account_store));
        }

        // 将 worker 绑定到负载均衡器，提供连接分发和负载快照回调
        psm::memory::vector<agent::front::balancer::worker_binding> bindings;
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
        psm::memory::vector<std::jthread> threads;
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
                    psm::trace::error("dispatch exception: {}", e.what());
                }
                catch (...)
                {
                    psm::trace::error("dispatch exception: unknown");
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
                psm::trace::error("listen exception: {}", e.what());
            }
            catch (...)
            {
                psm::trace::error("listen exception: unknown");
            }
        };
        threads.emplace_back(listen_thread);
    }
    catch (const psm::exception::security &e)
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
