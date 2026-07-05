#include <exception>
#include <memory>
#include <thread>
#include <vector>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <cstdio>
#include <ctime>

#include <boost/asio/signal_set.hpp>

#ifdef _WIN32
#include <windows.h>
#include <dbghelp.h>
#endif

#include <prism/context/context.hpp>
#include <prism/instance/instance.hpp>
#include <prism/account/directory.hpp>
#include <prism/account/stats/stats.hpp>
#include <prism/account/stats/runtime.hpp>
#include <prism/instance/front/balancer.hpp>
#include <prism/instance/front/listener.hpp>
#include <prism/foundation/foundation.hpp>
#include <prism/foundation/memory/pool.hpp>
#include <prism/foundation/foundation.hpp>
#include <prism/config/config.hpp>
#include <prism/config/loader/load.hpp>
#include <prism/stealth/registry.hpp>
#include <prism/trace/trace.hpp>

namespace instance = psm::instance;

#ifdef _WIN32
namespace
{
    // 未处理异常回调：崩溃时写 minidump 到可执行文件同目录
    // 事后用 cdb/WinDbg 打开 .dmp 文件即可看到精确崩溃栈
    LONG WINAPI crash_dump_handler(EXCEPTION_POINTERS *ep)
    {
        const auto crash_addr = reinterpret_cast<std::uintptr_t>(ep->ExceptionRecord->ExceptionAddress);
        const auto module_base = reinterpret_cast<std::uintptr_t>(GetModuleHandleA(NULL));
        const auto offset = crash_addr - module_base;

        std::fprintf(stderr,
            "\n=== CRASH ===\n"
            "exception code=0x%08X address=%p\n"
            "module_base=0x%llx offset=0x%llx\n",
            static_cast<unsigned>(ep->ExceptionRecord->ExceptionCode),
            ep->ExceptionRecord->ExceptionAddress,
            static_cast<unsigned long long>(module_base),
            static_cast<unsigned long long>(offset));

        // Backtrace
        void *stack[32];
        const USHORT frames = CaptureStackBackTrace(0, 32, stack, NULL);
        std::fprintf(stderr, "Backtrace (%u frames):\n", frames);
        for (USHORT i = 0; i < frames; i++)
        {
            const auto frame_offset = reinterpret_cast<std::uintptr_t>(stack[i]) - module_base;
            std::fprintf(stderr, "  [%u] offset=0x%llx\n", i,
                static_cast<unsigned long long>(frame_offset));
        }
        std::fflush(stderr);

        char dump_name[MAX_PATH];
        const auto pid = static_cast<unsigned long>(GetCurrentProcessId());
        const auto now = static_cast<long long>(std::time(nullptr));
        std::snprintf(dump_name, sizeof(dump_name),
            "prism_crash_%lu_%lld.dmp", pid, now);

        const HANDLE hFile = CreateFileA(
            dump_name, GENERIC_WRITE, 0, nullptr,
            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);

        if (hFile != INVALID_HANDLE_VALUE)
        {
            MINIDUMP_EXCEPTION_INFORMATION mei;
            mei.ThreadId = GetCurrentThreadId();
            mei.ExceptionPointers = ep;
            mei.ClientPointers = FALSE;

            const BOOL ok = MiniDumpWriteDump(
                GetCurrentProcess(),
                GetCurrentProcessId(),
                hFile,
                static_cast<MINIDUMP_TYPE>(
                    MiniDumpNormal |
                    MiniDumpWithIndirectlyReferencedMemory |
                    MiniDumpWithThreadInfo),
                &mei, nullptr, nullptr);
            CloseHandle(hFile);

            if (ok)
                std::fprintf(stderr, "minidump written: %s\n", dump_name);
            else
                std::fprintf(stderr, "MiniDumpWriteDump failed: error=%lu\n",
                    static_cast<unsigned long>(GetLastError()));
        }
        else
        {
            std::fprintf(stderr, "CreateFile failed: error=%lu\n",
                static_cast<unsigned long>(GetLastError()));
        }

        std::fflush(stderr);
        return EXCEPTION_EXECUTE_HANDLER;
    }
}
#endif

// 启动流程：启用全局内存池 → 加载配置 → 注册处理器 → 构建 worker 线程池 → 绑定均衡器 → 启动监听
int main(int argc, char *argv[])
{
    std::cerr << "DBG: main start\n";
#ifdef _WIN32
    SetUnhandledExceptionFilter(crash_dump_handler);
#endif

    psm::memory::system::enable_pooling();
    std::cerr << "DBG: pooling enabled\n";

    // 注册所有 TLS 伪装方案
    psm::stealth::register_schemes();

    // 配置文件路径：命令行参数 > 可执行文件同目录下的 configuration.json
    std::filesystem::path configuration_path;
    if (argc > 1)
    {
        configuration_path = std::filesystem::absolute(std::filesystem::path(argv[1]));
    }
    else
    {
        configuration_path = std::filesystem::absolute(
            std::filesystem::path(argv[0]).parent_path() / "configuration.json");
    }

    if (!std::filesystem::exists(configuration_path))
    {
        std::cerr << "configuration file not found: " << configuration_path << '\n';
        return 1;
    }

    try
    {
        // 获取 CPU 核心数，用于确定 worker 线程数量
        const auto threads_count = std::thread::hardware_concurrency();
        if (threads_count == 0)
        {
            throw psm::exception::security("system error : {}", "core acquisition failed");
        }

        // 加载配置
        const auto full_config = psm::loader::load(configuration_path.string());
        psm::trace::init(full_config.trace);

        // handler_table 为编译期常量数组，无需运行时注册

        // 从认证配置构建共享账户目录
        const auto account_store = psm::loader::build_dir(full_config.instance.auth);

        // worker 线程数 = CPU 核心数 - 1（保留一个核心给监听线程），至少 1 个
        std::uint32_t workers_count = 1U;
        if (threads_count > 1U)
            workers_count = threads_count - 1U;
        const psm::config &config_ref = full_config;

        // 创建 worker 实例池，每个 worker 持有独立的 io_context 和协议处理管线
        psm::memory::vector<std::unique_ptr<instance::worker::worker>> workers;
        workers.reserve(workers_count);
        for (std::uint32_t index = 0; index < workers_count; ++index)
        {
            workers.emplace_back(std::make_unique<instance::worker::worker>(config_ref, account_store));
        }

        // 标记系统启动，初始化运行时统计数据
        psm::stats::runtime::system_state::instance().mark_started(workers_count);

        // 将 worker 绑定到负载均衡器，提供连接分发、负载快照与健康检查回调
        psm::memory::vector<instance::front::balancer::worker_binding> bindings;
        bindings.reserve(workers_count);
        for (const auto &worker_ptr : workers)
        {
            instance::worker::worker *worker_ref = worker_ptr.get();
            auto delivery_function = [worker_ref](boost::asio::ip::tcp::socket socket)
            {
                worker_ref->dispatch_socket(std::move(socket));
            };
            auto snapshot_function = [worker_ref]() -> psm::stats::worker_snapshot
            {
                return worker_ref->load_snapshot();
            };
            auto alive_function = [worker_ref]() -> bool
            {
                return worker_ref->alive();
            };
            bindings.emplace_back(delivery_function, snapshot_function, alive_function);
        }

        instance::front::balancer dispatcher(std::move(bindings));
        instance::front::listener service_listener(config_ref, dispatcher);

        // 启动所有线程：worker 线程运行 io_context 事件循环，监听线程接受新连接
        psm::memory::vector<std::jthread> threads;
        threads.reserve(workers_count + 1U);

        for (const auto &worker_ptr : workers)
        {
            instance::worker::worker *worker_ref = worker_ptr.get();
            auto worker_handler = [worker_ref]()
            {
                try
                {
                    worker_ref->run();
                }
                catch (const std::exception &e)
                {
                    psm::trace::error("dispatch exception: {}", e.what());
                }
                catch (...)
                {
                    psm::trace::error("dispatch exception: unknown");
                }
            };
            threads.emplace_back(std::move(worker_handler));
        }

        auto listen_thread = [&service_listener]()
        {
            try
            {
                service_listener.listen();
            }
            catch (const std::exception &e)
            {
                psm::trace::error("listen exception: {}", e.what());
            }
            catch (...)
            {
                psm::trace::error("listen exception: unknown");
            }
        };
        threads.emplace_back(listen_thread);

        // 信号处理：监听 SIGINT/SIGTERM，触发优雅停机
        // 使用独立的 io_context 运行 signal_set，避免与 worker 或 listener 的事件循环耦合
        boost::asio::io_context signal_ioc;
        boost::asio::signal_set signals(signal_ioc, SIGINT, SIGTERM);

        signals.async_wait(
            [&workers, &service_listener, &threads, &signal_ioc](
                const boost::system::error_code & /*ec*/, int /*signo*/)
            {
                psm::trace::info("received shutdown signal, stopping gracefully...");

                // 停止接受新连接
                service_listener.stop();

                // 停止所有 worker 事件循环
                for (const auto &worker_ptr : workers)
                {
                    worker_ptr->stop();
                }

                // 等待所有线程退出（jthread 析构会自动 join）
                threads.clear();

                psm::trace::info("all threads stopped, shutting down logger");
                psm::trace::shutdown();
                std::cerr << "DBG: trace shutdown done\n";

                // 停止信号 io_context 自身
                signal_ioc.stop();
                std::cerr << "DBG: signal_ioc stopped\n";
            });

        // 在独立线程中运行信号 io_context，阻塞直到 signal_ioc.stop() 被调用
        std::jthread signal_thread([&signal_ioc]()
        {
            signal_ioc.run();
        });

        signal_thread.join();

        // 关键：跳过所有局部变量析构。
        // worker_resources 析构时 Boost.Asio concurrent_channel（yamux/smux）
        // 的 pending operations 存在 use-after-free（try_send 访问已销毁的
        // channel_receive → ACCESS_VIOLATION）。这是 Asio channel 的已知
        // 析构竞态，无法通过调整析构顺序解决（channel receiver 和 sender
        // 在不同成员中，析构顺序无法同时满足两者）。
        // 进程即将退出，析构是多余的——直接 ExitProcess 跳过。
        std::cerr << "DBG: exiting process\n";
        std::fflush(stderr);
        ExitProcess(0);
    }
    catch (const psm::exception::security &e)
    {
        std::cerr << e.what() << '\n';
    }
    catch (const std::exception &e)
    {
        std::cerr << e.what() << '\n';
    }
    catch (...)
    {
        std::cerr << "unknown exception" << '\n';
    }

    return 0;
}
