#include <memory>
#include <thread>
#include <iostream>
#include <fstream>

#include <forward-engine/agent.hpp>
#include <forward-engine/agent/distribute.hpp>
#include <forward-engine/agent/listener.hpp>
#include <forward-engine/agent/validator.hpp>
#include <forward-engine/memory.hpp>
#include <forward-engine/memory/pool.hpp>
#include <forward-engine/abnormal.hpp>
#include <forward-engine/core/configuration.hpp>
#include <forward-engine/adapter/load.hpp>

#include "agent/detection.hpp"

namespace agent = ngx::agent;
constexpr std::string_view configuration_path = {R"(C:\Users\C1373\Desktop\code\forward-engine\src\configuration.json)"};

/**
 * @brief 主函数
 * @return int 程序退出状态码
 * @details
 * 1. 启用全局内存池。
 * 2. 获取硬件并发线程数。
 * 3. 加载配置。
 * 4. 初始化日志系统。
 * 5. 创建并启动工作线程。
 */
// TODO: add more tests
int main()
{
    // 启用全局内存池
    ngx::memory::system::enable_global_pooling();
    try
    {
        const auto threads_count = std::thread::hardware_concurrency();
        if (threads_count == 0)
        {
            throw ngx::abnormal::security("system error : {}", "core acquisition failed");
        }
        ngx::core::configuration overall_situation_config = ngx::adapter::load(configuration_path);
        ngx::trace::init(overall_situation_config.trace);

        agent::register_handlers();

        const auto shared_validator = std::make_shared<agent::validator>(ngx::memory::system::global_pool());
        const auto &[credentials, users] = overall_situation_config.agent.authentication;
        shared_validator->reserve(credentials.size() + users.size());
        for (const auto &cred : credentials)
        {
            shared_validator->upsert_user(std::string_view(cred.data(), cred.size()));
        }
        for (const auto &[credential, max_connections] : users)
        {
            shared_validator->upsert_user(std::string_view(credential.data(), credential.size()), max_connections);
        }

        const std::uint32_t workers_count = threads_count > 1U ? threads_count - 1U : 1U;
        const agent::config &agent_config = overall_situation_config.agent;

        ngx::memory::vector<std::unique_ptr<agent::worker>> workers;
        workers.reserve(workers_count);
        for (std::uint32_t index = 0; index < workers_count; ++index)
        {
            workers.emplace_back(std::make_unique<agent::worker>(agent_config, shared_validator));
        }

        ngx::memory::vector<agent::distribute::worker_binding> bindings;
        bindings.reserve(workers_count);
        for (const auto &worker_ptr : workers)
        {   // 遍历 workers 把钩子注册到 bindings 后续方便投递 socket
            agent::worker *worker_ref = worker_ptr.get();
            auto delivery_function = [worker_ref](agent::tcp::socket socket) 
            {   // 投递到 worker 的函数钩子
                worker_ref->dispatch_socket(std::move(socket));
            };
            auto snapshot_function = [worker_ref]() -> agent::worker_load_snapshot 
            {   // 获取worker 负载快照函数钩子
                return worker_ref->load_snapshot();
            };
            bindings.emplace_back(delivery_function, snapshot_function);
        }

        agent::distribute dispatcher(std::move(bindings));
        agent::listener service_listener(agent_config, dispatcher);

        ngx::memory::vector<std::jthread> threads;
        threads.reserve(workers_count + 1U);

        for (const auto &worker_ptr : workers)
        {
            agent::worker *worker_ref = worker_ptr.get();
            auto worker_handler = [worker_ref]()
            {
                try
                {
                    worker_ref->run();
                }
                catch (const std::exception &e)
                {
                    ngx::trace::error("工作线程异常: {}", e.what());
                }
                catch (...)
                {
                    ngx::trace::error("工作线程未知异常");
                }
            };
            threads.emplace_back(std::move(worker_handler));
        }

        // 一个监听线程加n个工作线程 = n + 1

        auto listen_thread = [&service_listener]()
        {
            try
            {
                service_listener.listen();
            }
            catch (const std::exception &e)
            {
                ngx::trace::error("监听线程异常: {}", e.what());
            }
            catch (...)
            {
                ngx::trace::error("监听线程未知异常");
            }
        };
        // 添加监听线程处理 socket 的分发和哈希负载均衡
        threads.emplace_back(listen_thread);
    }
    catch (const ngx::abnormal::security &e)
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
