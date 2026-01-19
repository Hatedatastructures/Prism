#include <agent.hpp>
#include <memory>
#include <thread>
#include <iostream>
#include <fstream>

#include <memory.hpp>
#include <abnormal.hpp>
#include <trace.hpp>
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
        ngx::core::configuration config = mapping_configuration();
        ngx::trace::init(config.trace);


        ngx::trace::info("json string : {} ", ngx::transformer::json::serialize<ngx::core::configuration>(config));


        std::cout << ngx::transformer::json::serialize<ngx::core::configuration>(config) << std::endl;

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
