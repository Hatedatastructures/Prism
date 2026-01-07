#include <agent.hpp>
#include <memory>
#include <thread>
#include <iostream>

#include <abnormal.hpp>
#include <http.hpp>
#include <agent.hpp>
#include <trace.hpp>
#include <rule.hpp>
#include <transformer.hpp>

namespace agent = ngx::agent;
namespace http = ngx::http;
namespace net = agent::net;

const static std::string cert_path = R"(C:\Users\C1373\Desktop\ForwardEngine\cert.pem)";
const static std::string key_path = R"(C:\Users\C1373\Desktop\ForwardEngine\key.pem)";


// TODO: add more tests
int main()
{
    

    try
    {
        constexpr unsigned short port = 8080U;
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
            ngx::agent::worker worker(port, cert_path, key_path);
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
