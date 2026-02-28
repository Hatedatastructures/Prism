#include <memory>
#include <thread>
#include <iostream>
#include <fstream>

#include <forward-engine/agent.hpp>
#include <forward-engine/agent/validator.hpp>
#include <forward-engine/memory.hpp>
#include <forward-engine/memory/pool.hpp>
#include <forward-engine/abnormal.hpp>
#include <forward-engine/core/configuration.hpp>
#include <forward-engine/adapter/load.hpp>

#include "agent/detection.hpp"

namespace agent = ngx::agent;
namespace http = ngx::protocol::http;
namespace net = agent::net;

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
            throw ngx::abnormal::security("system error : {}","core acquisition failed");
        }
        ngx::core::configuration overall_situation_config = ngx::adapter::load(configuration_path);
        ngx::trace::init(overall_situation_config.trace);

        const auto shared_validator = std::make_shared<agent::validator>(ngx::memory::system::global_pool());
        const auto&[credentials, users] = overall_situation_config.agent.authentication;
        shared_validator->reserve(credentials.size() + users.size());
        for (const auto &cred : credentials)
        {
            shared_validator->upsert_user(std::string_view(cred.data(), cred.size()));
        }
        for (const auto &[credential, max_connections] : users)
        {
            shared_validator->upsert_user(std::string_view(credential.data(), credential.size()), max_connections);
        }

        auto work = [=](const ngx::core::configuration& config)
        {
            try
            {
                const agent::config agent_config = config.agent;
                agent::worker worker(agent_config, shared_validator);
                worker.run();
            }
            catch (const std::exception& e)
            {
                ngx::trace::error("工作线程异常: {}", e.what());
            }
            catch (...)
            {
                ngx::trace::error("工作线程未知异常");
            }
        };

        ngx::memory::vector<std::jthread> threads;
        threads.reserve(threads_count);

        for (unsigned int i = 0; i < threads_count; ++i)
        {
            threads.emplace_back(work, overall_situation_config);
        }
        // ... 
    }
    catch(const ngx::abnormal::security& e)
    {
        std::cerr << e.what() << '\n';
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
    }
    catch(...)
    {
        std::cerr << "unknown exception" << '\n';
    }
    return 0;
}
