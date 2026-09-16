/**
 * @file WorkerLauncher.cpp
 * @brief 生产 worker 连接启动器测试
 * @details 验证默认 PSM 会话路径与注入 launcher 的 executor、停止和资源生命周期语义。
 */

#include <prism/resource/process.hpp>
#include <prism/runtime/worker/worker.hpp>

#include <boost/asio.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <future>
#include <memory>
#include <thread>

#include <gtest/gtest.h>

namespace
{
    namespace net = boost::asio;
    using tcp = net::ip::tcp;

    struct socket_pair
    {
        socket_pair() : ioc(std::make_unique<net::io_context>()), client(*ioc), server(*ioc)
        {
            tcp::acceptor acceptor(*ioc, tcp::endpoint(net::ip::address_v4::loopback(), 0));
            client.connect(acceptor.local_endpoint());
            acceptor.accept(server);
        }

        std::unique_ptr<net::io_context> ioc;
        tcp::socket client;
        tcp::socket server;
    };

    auto make_process() -> std::shared_ptr<psm::resource::process>
    {
        auto cfg = std::make_shared<psm::settings>();
        return std::make_shared<psm::resource::process>(
            psm::resource::process::options{std::move(cfg), nullptr, nullptr});
    }

    auto close_socket(tcp::socket &socket) noexcept -> void
    {
        boost::system::error_code ec;
        socket.close(ec);
    }

    template <typename Predicate>
    auto wait_until(Predicate &&predicate) -> bool
    {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
        while (std::chrono::steady_clock::now() < deadline)
        {
            if (predicate())
            {
                return true;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        return predicate();
    }

    auto wait_for_peer_close(tcp::socket &socket) -> bool
    {
        boost::system::error_code ec;
        socket.non_blocking(true, ec);
        if (ec)
        {
            return false;
        }

        std::array<std::byte, 1> buffer{};
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
        while (std::chrono::steady_clock::now() < deadline)
        {
            ec.clear();
            socket.read_some(net::buffer(buffer), ec);
            if (ec == net::error::eof || ec == net::error::connection_reset)
            {
                return true;
            }
            if (ec && ec != net::error::would_block && ec != net::error::try_again)
            {
                return false;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        return false;
    }
} // namespace

TEST(WorkerLauncher, InjectedLauncherRunsOnWorkerThread)
{
    auto sockets = socket_pair{};
    auto callback_thread = std::make_shared<std::promise<std::thread::id>>();
    auto callback_count = std::make_shared<std::atomic_uint>(0U);

    const psm::runtime::worker::ConnectionLauncher launcher =
        [callback_thread, callback_count](psm::runtime::worker::launch_params params)
    {
        callback_count->fetch_add(1U, std::memory_order_relaxed);
        callback_thread->set_value(std::this_thread::get_id());
        close_socket(params.socket);
    };

    psm::runtime::worker::worker worker(make_process(), launcher);
    std::promise<std::thread::id> worker_thread_promise;
    auto worker_thread_future = worker_thread_promise.get_future();
    std::thread worker_thread([&worker, &worker_thread_promise]()
    {
        worker_thread_promise.set_value(std::this_thread::get_id());
        worker.run();
    });

    const auto worker_id = worker_thread_future.get();
    auto callback_future = callback_thread->get_future();
    worker.dispatch_socket(std::move(sockets.server));

    const bool callback_ready =
        callback_future.wait_for(std::chrono::seconds(2)) == std::future_status::ready;
    std::thread::id callback_id{};
    if (callback_ready)
    {
        callback_id = callback_future.get();
    }

    worker.stop();
    worker_thread.join();
    close_socket(sockets.client);

    EXPECT_TRUE(callback_ready);
    EXPECT_EQ(callback_count->load(std::memory_order_relaxed), 1U);
    if (callback_ready)
    {
        EXPECT_EQ(callback_id, worker_id);
    }
}

TEST(WorkerLauncher, DefaultLauncherStartsProductionSession)
{
    auto sockets = socket_pair{};
    psm::runtime::worker::worker worker(make_process());
    std::thread worker_thread([&worker]() { worker.run(); });

    worker.dispatch_socket(std::move(sockets.server));
    const bool session_started = wait_until(
        [&worker]() { return worker.load_snapshot().active_sessions == 1U; });

    close_socket(sockets.client);
    const bool session_closed = wait_until(
        [&worker]() { return worker.load_snapshot().active_sessions == 0U; });

    worker.stop();
    worker_thread.join();

    EXPECT_TRUE(session_started);
    EXPECT_TRUE(session_closed);
}

TEST(WorkerLauncher, StopRejectsNewDispatch)
{
    auto sockets = socket_pair{};
    auto callback_count = std::make_shared<std::atomic_uint>(0U);
    const psm::runtime::worker::ConnectionLauncher launcher =
        [callback_count](psm::runtime::worker::launch_params params)
    {
        callback_count->fetch_add(1U, std::memory_order_relaxed);
        close_socket(params.socket);
    };

    psm::runtime::worker::worker worker(make_process(), launcher);
    std::thread worker_thread([&worker]() { worker.run(); });
    worker.stop();
    worker_thread.join();

    worker.dispatch_socket(std::move(sockets.server));

    EXPECT_FALSE(worker.alive());
    EXPECT_EQ(callback_count->load(std::memory_order_relaxed), 0U);
    EXPECT_TRUE(wait_for_peer_close(sockets.client));
    close_socket(sockets.client);
}

TEST(WorkerLauncher, StopCancelsQueuedDispatch)
{
    auto sockets = socket_pair{};
    auto callback_count = std::make_shared<std::atomic_uint>(0U);
    const psm::runtime::worker::ConnectionLauncher launcher =
        [callback_count](psm::runtime::worker::launch_params params)
    {
        callback_count->fetch_add(1U, std::memory_order_relaxed);
        close_socket(params.socket);
    };

    psm::runtime::worker::worker worker(make_process(), launcher);
    worker.dispatch_socket(std::move(sockets.server));

    EXPECT_EQ(worker.load_snapshot().pending_handoffs, 1U);
    worker.stop();

    EXPECT_EQ(worker.load_snapshot().pending_handoffs, 0U);
    EXPECT_EQ(callback_count->load(std::memory_order_relaxed), 0U);
    EXPECT_TRUE(wait_for_peer_close(sockets.client));
    close_socket(sockets.client);
}

TEST(WorkerLauncher, LauncherHeldResourceOutlivesWorker)
{
    auto sockets = socket_pair{};
    auto callback_done = std::make_shared<std::promise<void>>();
    auto retained = std::make_shared<std::shared_ptr<psm::resource::worker>>();
    std::weak_ptr<psm::resource::worker> weak_resource;
    std::shared_ptr<psm::resource::worker> held_resource;

    const psm::runtime::worker::ConnectionLauncher launcher =
        [callback_done, retained](psm::runtime::worker::launch_params params)
    {
        *retained = std::move(params.worker);
        close_socket(params.socket);
        callback_done->set_value();
    };

    {
        psm::runtime::worker::worker worker(make_process(), launcher);
        weak_resource = worker.resources();
        std::thread worker_thread([&worker]() { worker.run(); });
        auto callback_future = callback_done->get_future();

        worker.dispatch_socket(std::move(sockets.server));
        const bool callback_ready =
            callback_future.wait_for(std::chrono::seconds(2)) == std::future_status::ready;

        worker.stop();
        worker_thread.join();
        EXPECT_TRUE(callback_ready);
        if (callback_ready)
        {
            held_resource = *retained;
        }
    }

    EXPECT_FALSE(weak_resource.expired());
    ASSERT_NE(held_resource, nullptr);
    EXPECT_FALSE(held_resource->alive());

    held_resource.reset();
    retained->reset();
    EXPECT_TRUE(weak_resource.expired());
    close_socket(sockets.client);
}
