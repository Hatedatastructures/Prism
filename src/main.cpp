#include <agent.hpp>
#include <memory>
#include <thread>
#include <http.hpp>
#include <agent.hpp>
#include <trace/monitor.hpp>
#include <iostream>

namespace agent = ngx::agent;
namespace http = ngx::http;
namespace net = agent::net;

constexpr  std::string_view cert_path = "C:\\Users\\C1373\\Desktop\\ForwardEngine\\cert.pem";
constexpr  std::string_view key_path = "C:\\Users\\C1373\\Desktop\\ForwardEngine\\key.pem";


// TODO: add more tests
int main()
{
    constexpr unsigned short port = 8080;
    auto threads_count = std::thread::hardware_concurrency();
    if (threads_count == 0)
    {
        threads_count = 1;
    }

    std::cout << "Starting ForwardEngine on port " << port
              << " with " << threads_count << " threads..." << std::endl;

    agent::worker w(port, {cert_path.data()}, {key_path.data()});
    w.load_reverse_map("src/configuration.json");
    w.run(threads_count);
}
