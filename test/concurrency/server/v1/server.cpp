#include "server.hpp"

#ifdef _WIN32
#include <windows.h>
#endif

auto main() -> int
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    ngx::trace::config trace_config;
    trace_config.enable_console = true;
    trace_config.enable_file = false;
    trace_config.log_level = "debug";
    ngx::trace::init(trace_config);
    try
    {
        const srv::core::config config;
        srv::core::server server(config);
        server.start();
    }
    catch (const std::exception &e)
    {
        ngx::trace::error("服务器异常: {}", e.what());
    }
    return 0;
}