#include <forward-engine/agent.hpp>
#include <forward-engine/agent/validator.hpp>
#include <memory>
#include <thread>
#include <iostream>
#include <fstream>

#include <forward-engine/memory.hpp>
#include <forward-engine/memory/pool.hpp>
#include <forward-engine/abnormal.hpp>
#include <forward-engine/trace.hpp>
#include <forward-engine/transformer.hpp>
#include <forward-engine/core/configuration.hpp>

namespace agent = ngx::agent;
namespace http = ngx::protocol::http;
namespace net = agent::net;

auto load_file_data(const std::string_view path)
    -> ngx::memory::string
{
    std::ifstream file(path.data(), std::ios::binary);
    if (!file.is_open())
    {
        throw ngx::abnormal::security("system error : {}","file open failed");
    }
    file.seekg(0, std::ios::end);
    const auto size = file.tellg();
    file.seekg(0, std::ios::beg);
    ngx::memory::string content(size, '\0');
    file.read(content.data(), size);
    return content;
}

auto mapping_configuration()
    -> ngx::core::configuration
{
    ngx::core::configuration config;
    try
    {
        ngx::memory::string config_string{load_file_data(R"(C:\Users\C1373\Desktop\code\ForwardEngine\src\configuration.json)")};
        if (ngx::transformer::json::deserialize({config_string.data(), config_string.size()}, config))
        {
            return config;
        }
    }
    catch (...)
    {
    }

    return {};
}

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
        ngx::core::configuration overall_situation_config = mapping_configuration();
        ngx::trace::init(overall_situation_config.trace);

        auto shared_validator = std::make_shared<agent::validator>(ngx::memory::system::global_pool());
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

        auto work = [shared_validator](const ngx::core::configuration& config)
        {

            const agent::config agent_config = config.agent;
            agent::worker worker(agent_config, shared_validator);
            worker.run();
        };

        ngx::memory::vector<std::jthread> threads;
        threads.reserve(threads_count);

        for (auto i = 0U; i < threads_count; ++i)
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
