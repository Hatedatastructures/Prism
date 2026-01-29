#include <forward-engine/agent.hpp>
#include <memory>
#include <thread>
#include <iostream>
#include <fstream>

#include <forward-engine/memory.hpp>
#include <forward-engine/abnormal.hpp>
#include <forward-engine/trace.hpp>
#include <forward-engine/transformer.hpp>
#include <forward-engine/core/configuration.hpp>

namespace agent = ngx::agent;
namespace http = ngx::protocol::http;
namespace net = agent::net;

auto load_file_data(std::string_view path)
    -> ngx::memory::string
{
    std::ifstream file(path.data(), std::ios::binary);
    if (!file.is_open())
    {
        throw ngx::abnormal::security("system error : {}","file open failed");
    }
    file.seekg(0, std::ios::end);
    auto size = file.tellg();
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

        auto work = [](const ngx::core::configuration& config)
        {

            agent::config agent_config = config.agent;
            agent::worker worker(agent_config);
            worker.run();
        };

        std::vector<std::jthread> threads;
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
