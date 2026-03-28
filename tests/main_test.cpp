#include <forward-engine/agent.hpp>
#include <thread>
#include <iostream>
#include <fstream>

#include <memory.hpp>
#include <exception.hpp>
#include <trace.hpp>
#include <transformer.hpp>
#include <forward-engine/config.hpp>

namespace agent = ngx::agent;
namespace http = ngx::protocol::http;
namespace net = agent::net;

ngx::memory::string load_file_data(std::string_view path)
{
    std::ifstream file(path.data(), std::ios::binary);
    if (!file.is_open())
    {
        throw ngx::exception::security("system error : {}","file open failed");
    }
    file.seekg(0, std::ios::end);
    const auto size = file.tellg();
    file.seekg(0, std::ios::beg);
    ngx::memory::string content(size, '\0');
    file.read(content.data(), size);
    return content;
}

/**
 * @brief 从文件中映射配置
 * @return ngx::config 配置对象
 */
ngx::config mapping_configuration()
{
    ngx::config cfg;
    try
    {
        ngx::memory::string config_string{load_file_data(R"(C:\Users\C1373\Desktop\code\ForwardEngine\src\configuration.json)")};
        if (ngx::transformer::json::deserialize({config_string.data(), config_string.size()}, cfg))
        {
            return cfg;
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
            throw ngx::exception::security("system error : {}","core acquisition failed");
        }
        ngx::config cfg = mapping_configuration();
        ngx::trace::init(cfg.trace);


        ngx::trace::info("json string : {} ", ngx::transformer::json::serialize<ngx::config>(cfg));


        std::cout << ngx::transformer::json::serialize<ngx::config>(cfg) << std::endl;

        // ...
    }
    catch(const ngx::exception::security& e)
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
