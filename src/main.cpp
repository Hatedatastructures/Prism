#include <memory>
#include <thread>
#include <vector>
#include <iostream>
#include <fstream>

#include <forward-engine/agent.hpp>
#include <forward-engine/agent/account/directory.hpp>
#include <forward-engine/agent/dispatch/handlers.hpp>
#include <forward-engine/agent/front/balancer.hpp>
#include <forward-engine/agent/front/listener.hpp>
#include <forward-engine/memory.hpp>
#include <forward-engine/memory/pool.hpp>
#include <forward-engine/abnormal.hpp>
#include <forward-engine/core/configuration.hpp>
#include <forward-engine/adapter/load.hpp>
namespace agent = ngx::agent;
constexpr std::string_view configuration_path = {R"(C:\Users\C1373\Desktop\code\forward-engine\src\configuration.json)"};

int main()
{
    ngx::memory::system::enable_global_pooling();
    ngx::agent::dispatch::register_handlers();
    try
    {
        const auto threads_count = std::thread::hardware_concurrency();
        if (threads_count == 0)
        {
            throw ngx::abnormal::security("system error : {}", "core acquisition failed");
        }
        auto [agent, trace] = ngx::adapter::load(configuration_path);
        ngx::trace::init(trace);

        const auto account_store = std::make_shared<agent::account::directory>(ngx::memory::system::global_pool());
        const auto &[credentials, users] = agent.authentication;
        account_store->reserve(credentials.size() + users.size());
        for (const auto &cred : credentials)
        {
            account_store->upsert(std::string_view(cred.data(), cred.size()));
        }
        for (const auto &[credential, max_connections] : users)
        {
            account_store->upsert(std::string_view(credential.data(), credential.size()), max_connections);
        }

        const std::uint32_t workers_count = threads_count > 1U ? threads_count - 1U : 1U;
        const agent::config &agent_config = agent;

        ngx::memory::vector<std::unique_ptr<agent::reactor::worker>> workers;
        workers.reserve(workers_count);
        for (std::uint32_t index = 0; index < workers_count; ++index)
        {
            workers.emplace_back(std::make_unique<agent::reactor::worker>(agent_config, account_store));
        }

        ngx::memory::vector<agent::front::balancer::worker_binding> bindings;
        bindings.reserve(workers_count);
        for (const auto &worker_ptr : workers)
        {
            agent::reactor::worker *worker_ref = worker_ptr.get();
            auto delivery_function = [worker_ref](boost::asio::ip::tcp::socket socket)
            {
                worker_ref->dispatch_socket(std::move(socket));
            };
            auto snapshot_function = [worker_ref]() -> agent::front::worker_load_snapshot
            {
                return worker_ref->load_snapshot();
            };
            bindings.emplace_back(delivery_function, snapshot_function);
        }

        agent::front::balancer dispatcher(std::move(bindings));
        agent::front::listener service_listener(agent_config, dispatcher);

        ngx::memory::vector<std::jthread> threads;
        threads.reserve(workers_count + 1U);

        for (const auto &worker_ptr : workers)
        {
            agent::reactor::worker *worker_ref = worker_ptr.get();
            auto worker_handler = [worker_ref]()
            {
                try
                {
                    worker_ref->run();
                }
                catch (const std::exception &e)
                {
                    ngx::trace::error("dispatch exception: {}", e.what());
                }
                catch (...)
                {
                    ngx::trace::error("dispatch exception: unknown");
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
                ngx::trace::error("listen exception: {}", e.what());
            }
            catch (...)
            {
                ngx::trace::error("listen exception: unknown");
            }
        };
        threads.emplace_back(listen_thread);
    }
    catch (const ngx::abnormal::security &e)
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