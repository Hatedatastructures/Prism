#include <prism/agent.hpp>
#include <thread>
#include <iostream>
#include <fstream>

#include <memory.hpp>
#include <exception.hpp>
#include <trace.hpp>
#include <transformer.hpp>
#include <prism/config.hpp>

namespace agent = psm::agent;
namespace http = psm::protocol::http;
namespace net = agent::net;

psm::memory::string load_file_data(std::string_view path)
{
    std::ifstream file(path.data(), std::ios::binary);
    if (!file.is_open())
    {
        throw psm::exception::security("system error : {}","file open failed");
    }
    file.seekg(0, std::ios::end);
    const auto size = file.tellg();
    file.seekg(0, std::ios::beg);
    psm::memory::string content(size, '\0');
    file.read(content.data(), size);
    return content;
}

/**
 * @brief 从文件中映射配置
 * @return psm::config 配置对象
 */
psm::config mapping_configuration()
{
    psm::config cfg;
    try
    {
        psm::memory::string config_string{load_file_data(R"(C:\Users\C1373\Desktop\code\ForwardEngine\src\configuration.json)")};
        if (psm::transformer::json::deserialize({config_string.data(), config_string.size()}, cfg))
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
    psm::memory::system::enable_global_pooling();
    try
    {
        const auto threads_count = std::thread::hardware_concurrency();
        if (threads_count == 0)
        {
            throw psm::exception::security("system error : {}","core acquisition failed");
        }
        psm::config cfg = mapping_configuration();
        psm::trace::init(cfg.trace);


        psm::trace::info("json string : {} ", psm::transformer::json::serialize<psm::config>(cfg));


        std::cout << psm::transformer::json::serialize<psm::config>(cfg) << std::endl;

        // ...
    }
    catch(const psm::exception::security& e)
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
