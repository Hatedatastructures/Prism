#include <agent.hpp>
#include <memory>
#include <thread>
#include <iostream>
#include <fstream>

#include <memory.hpp>
#include <abnormal.hpp>
#include <http.hpp>
#include <agent.hpp>
#include <trace.hpp>
#include <rule.hpp>
#include <transformer.hpp>
#include <core/configuration.hpp>

namespace agent = ngx::agent;
namespace http = ngx::http;
namespace net = agent::net;

ngx::memory::string load_file_data(std::string_view path)
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

/**
 * @brief 从文件中映射配置
 * @return ngx::core::configuration 配置对象
 */
ngx::core::configuration mapping_configuration()
{
    ngx::core::configuration config;
    try
    {
        ngx::memory::string config_string{load_file_data("src/configuration.json")};
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

// const static std::string cert_path = R"(C:\Users\C1373\Desktop\ForwardEngine\cert.pem)";
// const static std::string key_path = R"(C:\Users\C1373\Desktop\ForwardEngine\key.pem)";


// TODO: add more tests
int main()
{
    // 启用全局内存池
    ngx::memory::system::enable_global_pooling(); 
    try
    {
        auto threads_count = std::thread::hardware_concurrency();
        if (threads_count == 0)
        {
            throw ngx::abnormal::security("system error : {}","core acquisition failed");
        }
        ngx::trace::config config;
        config.file_name = "forward.log";
        config.path_name = "logs";
        config.max_size = 64U * 1024U * 1024U;
        config.max_files = 8U;
        config.queue_size = 8192U;
        config.thread_count = 1U;
        ngx::trace::init(config);

        auto work = []()
        {
            ngx::core::configuration config = mapping_configuration();

            ngx::agent::config agent_config = config.agent;
            ngx::agent::worker worker(agent_config.addressable.port, agent_config.certificate.cert, agent_config.certificate.key);
            worker.run();
        };

        std::vector<std::thread> threads;
        threads.reserve(threads_count);

        for (auto i = 0U; i < threads_count; ++i)
        {
            threads.emplace_back(work);
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
