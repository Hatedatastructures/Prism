#include "server/server.hpp"
#ifdef _WIN32
#include <windows.h>
#endif

int main(const int argc, char *argv[])
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    ngx::trace::config log;
    log.enable_console = true;
    log.enable_file = false;
    log.thread_count = 2;
    log.log_level = "debug";
    ngx::trace::init(log);
    std::cout << "日志初始化成功！" << std::endl;
    return srv::core::handler(argc, argv);
}
