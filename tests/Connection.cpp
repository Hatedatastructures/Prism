/**
 * @file Connection.cpp
 * @brief 连接池获取/释放/回收集成测试
 * @details 验证连接池的获取、释放、回收机制。
 * 测试使用回显服务器作为测试桩，通过协程驱动所有异步操作。
 */

#include <prism/channel/connection/pool.hpp>
#include <prism/memory/pool.hpp>
#include <prism/resolve/router.hpp>
#include <prism/resolve/config.hpp>
#include <prism/trace/spdlog.hpp>

#include "common/test_runner.hpp"

#include <boost/asio.hpp>

#include <array>
#include <format>
#include <string>
#include <string_view>

namespace net = boost::asio;
using tcp = boost::asio::ip::tcp;

namespace
{
    psm::testing::TestRunner runner("Connection");
} // namespace

/**
 * @brief 回显服务器（支持多连接）
 * @details 用于测试链路的最小上游服务：每接受一个连接就启动一个 echo 协程。
 * @param acceptor 接收器（按值接管所有权）
 * @return `net::awaitable<void>`
 */
net::awaitable<void> EchoServer(tcp::acceptor acceptor)
{
    // 每个连接启动独立的 echo 协程，原样回写收到的数据
    auto echo_one = [](tcp::socket socket) -> net::awaitable<void>
    {
        try
        {
            std::array<char, 4096> buf{};
            while (true)
            {
                // 使用 redirect_error 避免异常，通过 ec 判断连接关闭
                boost::system::error_code ec;
                auto token = net::redirect_error(net::use_awaitable, ec);
                const auto n = co_await socket.async_read_some(net::buffer(buf), token);
                if (ec || n == 0)
                {
                    co_return;
                }
                // 将收到的数据原样写回，形成回显
                co_await net::async_write(socket, net::buffer(buf.data(), n), token);
                if (ec)
                {
                    co_return;
                }
            }
        }
        catch (...)
        {
        }
    };

    try
    {
        // 循环接受新连接，为每个连接派生独立协程
        while (true)
        {
            tcp::socket socket = co_await acceptor.async_accept(net::use_awaitable);
            net::co_spawn(acceptor.get_executor(), echo_one(std::move(socket)), net::detached);
        }
    }
    catch (...)
    {
    }
}

/**
 * @brief 测试连接池获取与释放
 * @details 从连接池获取一个连接，验证返回码为成功且连接有效，
 * 然后释放连接，再次获取并验证两次拿到的是同一个底层 socket 指针。
 */
net::awaitable<void> TestPoolAcquireAndRelease(net::io_context &ioc, unsigned short echo_port)
{
    try
    {
        tcp::endpoint endpoint(net::ip::make_address("127.0.0.1"), echo_port);

        psm::channel::connection_pool pool(ioc);

        // 步骤 1：从连接池获取一个新连接
        runner.LogInfo("Step 1: Acquire connection");
        auto [code1, c1] = co_await pool.async_acquire(endpoint);
        if (!psm::fault::succeeded(code1))
        {
            runner.LogFail("TestPoolAcquireAndRelease - async_acquire returned error code");
            co_return;
        }
        if (!c1.valid())
        {
            runner.LogFail("TestPoolAcquireAndRelease - acquired connection is invalid");
            co_return;
        }
        // 保存底层 socket 指针，用于后续比较是否复用了同一连接
        auto c1_ptr = c1.get();

        // 步骤 2：将连接置空，触发析构并归还到连接池
        runner.LogInfo("Step 2: Recycle connection (by destruction)");
        c1 = psm::channel::pooled_connection{};

        // 步骤 3：再次获取，应命中池中回收的同一连接
        runner.LogInfo("Step 3: Acquire again (should reuse)");
        auto [code2, c2] = co_await pool.async_acquire(endpoint);
        if (!psm::fault::succeeded(code2))
        {
            runner.LogFail("TestPoolAcquireAndRelease - second async_acquire returned error code");
            co_return;
        }
        if (!c2.valid())
        {
            runner.LogFail("TestPoolAcquireAndRelease - second acquired connection is invalid");
            co_return;
        }
        // 验证两次拿到的是同一个底层 socket 指针
        if (c2.get() != c1_ptr)
        {
            runner.LogFail("TestPoolAcquireAndRelease - recycled connection is not the same socket");
            co_return;
        }

        // 测试通过后释放连接
        c2 = psm::channel::pooled_connection{};

        runner.LogPass("TestPoolAcquireAndRelease");
    }
    catch (const std::exception &e)
    {
        runner.LogFail(std::format("TestPoolAcquireAndRelease - exception: {}", e.what()));
    }
}

/**
 * @brief 测试连接池回收机制
 * @details 验证连接在被释放后能被连接池正确回收并再次分配。
 */
net::awaitable<void> TestPoolRecycling(net::io_context &ioc, unsigned short echo_port)
{
    try
    {
        tcp::endpoint endpoint(net::ip::make_address("127.0.0.1"), echo_port);

        psm::channel::connection_pool pool(ioc);

        // 获取第一个连接，记录其指针
        runner.LogInfo("Acquire first connection for recycling test");
        auto [code1, c1] = co_await pool.async_acquire(endpoint);
        if (!psm::fault::succeeded(code1))
        {
            runner.LogFail("TestPoolRecycling - first async_acquire returned error code");
            co_return;
        }
        if (!c1.valid())
        {
            runner.LogFail("TestPoolRecycling - first connection is invalid");
            co_return;
        }
        // 记录指针，后续验证是否复用同一 socket
        auto original_ptr = c1.get();

        // 释放连接，触发池回收
        runner.LogInfo("Release connection back to pool");
        c1 = psm::channel::pooled_connection{};

        // 再次获取，应命中回收的连接
        runner.LogInfo("Acquire recycled connection");
        auto [code2, c2] = co_await pool.async_acquire(endpoint);
        if (!psm::fault::succeeded(code2))
        {
            runner.LogFail("TestPoolRecycling - second async_acquire returned error code");
            co_return;
        }
        if (!c2.valid())
        {
            runner.LogFail("TestPoolRecycling - recycled connection is invalid");
            co_return;
        }
        // 验证指针相同，确认池的回收复用机制正常
        if (c2.get() != original_ptr)
        {
            runner.LogFail("TestPoolRecycling - did not receive the recycled connection");
            co_return;
        }

        // 释放连接
        c2 = psm::channel::pooled_connection{};

        runner.LogPass("TestPoolRecycling");
    }
    catch (const std::exception &e)
    {
        runner.LogFail(std::format("TestPoolRecycling - exception: {}", e.what()));
    }
}

/**
 * @brief 测试入口
 * @details 初始化全局内存池和日志系统，启动回显服务器，
 * 顺序运行连接池测试协程，最终输出测试结果。
 * @return 0 表示全部通过，1 表示存在失败
 */
int main()
{
    // 初始化 PMR 全局内存池和日志系统
    psm::memory::system::enable_global_pooling();
    psm::trace::init({});

    try
    {
        net::io_context ioc;

        // 绑定到随机可用端口，避免端口冲突
        tcp::acceptor echo_acceptor(ioc, tcp::endpoint(tcp::v4(), 0));
        const unsigned short echo_port = echo_acceptor.local_endpoint().port();
        runner.LogInfo(std::format("Echo server listening on port {}", echo_port));

        // 启动回显服务器协程，作为测试桩
        net::co_spawn(ioc, EchoServer(std::move(echo_acceptor)), net::detached);

        // 将测试协程顺序组合，确保测试间不互相干扰
        auto run_tests = [&]() -> net::awaitable<void>
        {
            co_await TestPoolAcquireAndRelease(ioc, echo_port);
            co_await TestPoolRecycling(ioc, echo_port);
        };

        // 启动测试协程，完成时捕获异常并停止事件循环
        std::exception_ptr test_error;
        net::co_spawn(ioc, run_tests(), [&](const std::exception_ptr &ep)
                      {
            test_error = ep;
            ioc.stop(); });

        // 阻塞运行事件循环，直到测试完成触发 stop
        ioc.run();

        // 若测试协程抛出异常则重新抛出
        if (test_error)
        {
            std::rethrow_exception(test_error);
        }
    }
    catch (const std::exception &e)
    {
        runner.LogFail(std::format("Main exception: {}", e.what()));
        return runner.Summary();
    }

    return runner.Summary();
}
