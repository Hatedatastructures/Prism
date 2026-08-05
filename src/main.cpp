/**
 * @file main.cpp
 * @brief Prism 代理服务器主入口
 */

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

#include <prism/resource/session.hpp>
#include <prism/resource/process.hpp>
#include <prism/runtime/runtime.hpp>
#include <prism/account/directory.hpp>
#include <prism/account/stats/stats.hpp>
#include <prism/account/stats/runtime.hpp>
#include <prism/runtime/front/balancer.hpp>
#include <prism/runtime/front/listener.hpp>
#include <prism/runtime/worker/tls.hpp>
#include <prism/foundation/foundation.hpp>
#include <prism/foundation/memory/pool.hpp>
#include <prism/config/config.hpp>
#include <prism/config/loader/load.hpp>
#include <prism/stealth/registry.hpp>
#include <prism/trace/trace.hpp>

namespace runtime = psm::runtime;

#ifdef _WIN32
namespace
{
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

        std::fflush(stderr);
        return EXCEPTION_EXECUTE_HANDLER;
    }
}
#endif

int main(int argc, char *argv[])
{
#ifdef _WIN32
    SetUnhandledExceptionFilter(crash_dump_handler);
#endif

    try
    {
        psm::memory::system::enable_pooling();
        psm::stealth::register_schemes();

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

        const auto threads_count = std::thread::hardware_concurrency();
        if (threads_count == 0)
        {
            throw psm::exception::security("system error : {}", "core acquisition failed");
        }

        auto full_config = psm::loader::load(configuration_path.string());
        psm::trace::init(full_config.trace);

        auto account_store = psm::loader::build_dir(full_config.instance.auth);

        // 构造进程级资源（global_resources）
        auto ssl_ctx = psm::runtime::worker::tls::make(full_config.instance);
        auto cfg_shared = std::make_shared<psm::config>(std::move(full_config));
        psm::resource::process::options gopts;
        gopts.cfg = cfg_shared;
        gopts.ssl = ssl_ctx;
        gopts.accounts = account_store;
        auto global_ctx = std::make_shared<psm::resource::process>(std::move(gopts));

        std::uint32_t workers_count = 1U;
        if (threads_count > 1U)
            workers_count = threads_count - 1U;
        const psm::config &config_ref = *cfg_shared;

        psm::memory::vector<std::unique_ptr<runtime::worker::worker>> workers;
        workers.reserve(workers_count);
        for (std::uint32_t index = 0; index < workers_count; ++index)
        {
            workers.emplace_back(std::make_unique<runtime::worker::worker>(global_ctx));
        }

        psm::stats::runtime::system_state::instance().mark_started(workers_count);

        psm::memory::vector<runtime::front::balancer::worker_binding> bindings;
        bindings.reserve(workers_count);
        for (const auto &worker_ptr : workers)
        {
            runtime::worker::worker *worker_ref = worker_ptr.get();
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

        runtime::front::balancer dispatcher(std::move(bindings));
        runtime::front::listener service_listener(config_ref, dispatcher);

        psm::memory::vector<std::jthread> threads;
        threads.reserve(workers_count + 1U);

        for (const auto &worker_ptr : workers)
        {
            runtime::worker::worker *worker_ref = worker_ptr.get();
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

        boost::asio::io_context signal_ioc;
        boost::asio::signal_set signals(signal_ioc, SIGINT, SIGTERM);

        signals.async_wait(
            [&workers, &service_listener, &threads, &signal_ioc](
                const boost::system::error_code & /*ec*/, int /*signo*/)
            {
                psm::trace::info("received shutdown signal, stopping gracefully...");

                service_listener.stop();

                for (const auto &worker_ptr : workers)
                {
                    worker_ptr->stop();
                }

                threads.clear();

                psm::trace::info("all threads stopped, shutting down logger");
                psm::trace::shutdown();

                signal_ioc.stop();
            });

        std::jthread signal_thread([&signal_ioc]()
        {
            signal_ioc.run();
        });

        signal_thread.join();

        // 跳过局部变量析构（worker_resources 析构时 Asio channel 竞态）
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
