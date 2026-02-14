/**
 * @file transmission_test.cpp
 * @brief 传输层接口和实现单元测试
 * @details 测试 `transmission` 抽象接口以及 `reliable`、`unreliable` 具体实现。
 * 验证异步读写、关闭、取消等基本操作的正确性。
 */

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <forward-engine/transport/transmission.hpp>
#include <forward-engine/transport/reliable.hpp>
#include <forward-engine/transport/unreliable.hpp>
#include <memory>
#include <array>
#include <thread>
#include <iostream>
#include <cassert>

namespace net = boost::asio;

// 简单的测试断言宏
#define TEST_ASSERT(expr) \
    do { \
        if (!(expr)) { \
            std::cerr << "Test failed at " << __FILE__ << ":" << __LINE__ << ": " << #expr << std::endl; \
            return 1; \
        } \
    } while (0)

// 测试 reliable 构造函数和执行器获取
int test_reliable_constructor()
{
    net::io_context ioc;
    auto executor = ioc.get_executor();
    auto reliable = ngx::transport::make_reliable(executor);
    
    TEST_ASSERT(reliable->executor() == executor);
    std::cout << "✓ test_reliable_constructor passed" << std::endl;
    return 0;
}

// 测试 reliable 从现有 socket 构造
int test_reliable_from_socket()
{
    net::io_context ioc;
    auto executor = ioc.get_executor();
    net::ip::tcp::socket socket(executor);
    auto reliable = ngx::transport::make_reliable(std::move(socket));
    
    TEST_ASSERT(reliable->executor() == executor);
    std::cout << "✓ test_reliable_from_socket passed" << std::endl;
    return 0;
}

// 测试 reliable 异步读写（基础功能）
net::awaitable<int> test_reliable_basic_read_write_coro()
{
    net::io_context ioc;
    // 创建一对连接的 TCP socket
    auto executor = ioc.get_executor();
    net::ip::tcp::acceptor acceptor(executor, net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
    auto local_endpoint = acceptor.local_endpoint();
    
    // 服务器协程：接受连接并回显数据
    auto server_coro = [&]() -> net::awaitable<void>
    {
        net::ip::tcp::socket socket = co_await acceptor.async_accept(net::use_awaitable);
        auto transport = ngx::transport::make_reliable(std::move(socket));
        
        std::array<char, 1024> buffer{};
        auto mutable_buf = net::buffer(buffer);
        
        // 读取客户端数据
        std::size_t n = co_await ngx::transport::async_read_some(*transport, mutable_buf, net::use_awaitable);
        
        // 将数据回写给客户端
        auto const_buf = net::buffer(buffer.data(), n);
        std::size_t written = co_await ngx::transport::async_write_some(*transport, const_buf, net::use_awaitable);
        
        assert(n == written);
        assert(std::string_view(buffer.data(), n) == "Hello, Transmission!");
        
        co_return;
    };
    
    // 客户端协程：连接服务器并发送数据
    auto client_coro = [&]() -> net::awaitable<void>
    {
        net::ip::tcp::socket socket(executor);
        co_await socket.async_connect(local_endpoint, net::use_awaitable);
        auto transport = ngx::transport::make_reliable(std::move(socket));
        
        std::string test_message = "Hello, Transmission!";
        auto const_buf = net::buffer(test_message);
        
        // 发送数据
        std::size_t written = co_await ngx::transport::async_write_some(*transport, const_buf, net::use_awaitable);
        assert(written == test_message.size());
        
        // 接收回显
        std::array<char, 1024> buffer{};
        auto mutable_buf = net::buffer(buffer);
        std::size_t n = co_await ngx::transport::async_read_some(*transport, mutable_buf, net::use_awaitable);
        
        assert(n == test_message.size());
        assert(std::string_view(buffer.data(), n) == test_message);
        
        co_return;
    };
    
    // 启动协程
    net::co_spawn(executor, server_coro(), net::detached);
    net::co_spawn(executor, client_coro(), net::detached);
    
    // 运行 IO 上下文
    ioc.run_for(std::chrono::seconds(2));
    
    co_return 0;
}

int test_reliable_basic_read_write()
{
    net::io_context ioc;
    int result = 0;
    
    net::co_spawn(ioc, [&]() -> net::awaitable<void>
    {
        int coro_result = co_await test_reliable_basic_read_write_coro();
        result = coro_result;
        ioc.stop();
        co_return;
    }, net::detached);
    
    ioc.run();
    
    if (result == 0)
    {
        std::cout << "✓ test_reliable_basic_read_write passed" << std::endl;
    }
    
    return result;
}

// 测试 reliable 关闭操作
net::awaitable<int> test_reliable_close_coro()
{
    net::io_context ioc;
    auto executor = ioc.get_executor();
    net::ip::tcp::acceptor acceptor(executor, net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
    auto local_endpoint = acceptor.local_endpoint();
    
    auto server_coro = [&]() -> net::awaitable<void>
    {
        net::ip::tcp::socket socket = co_await acceptor.async_accept(net::use_awaitable);
        auto transport = ngx::transport::make_reliable(std::move(socket));
        
        // 立即关闭连接
        transport->close();
        
        // 尝试读取应该失败
        std::array<char, 1024> buffer{};
        auto mutable_buf = net::buffer(buffer);
        
        boost::system::error_code ec;
        co_await ngx::transport::async_read_some(*transport, mutable_buf, net::redirect_error(net::use_awaitable, ec));
        
        assert(ec);
        
        co_return;
    };
    
    auto client_coro = [&]() -> net::awaitable<void>
    {
        net::ip::tcp::socket socket(executor);
        co_await socket.async_connect(local_endpoint, net::use_awaitable);
        
        // 尝试读取应该失败（服务器关闭了连接）
        std::array<char, 1024> buffer{};
        boost::system::error_code ec;
        std::size_t n = co_await socket.async_read_some(net::buffer(buffer), net::redirect_error(net::use_awaitable, ec));
        
        assert(ec);
        
        co_return;
    };
    
    net::co_spawn(executor, server_coro(), net::detached);
    net::co_spawn(executor, client_coro(), net::detached);
    
    ioc.run_for(std::chrono::seconds(2));
    
    co_return 0;
}

int test_reliable_close()
{
    net::io_context ioc;
    int result = 0;
    
    net::co_spawn(ioc, [&]() -> net::awaitable<void>
    {
        int coro_result = co_await test_reliable_close_coro();
        result = coro_result;
        ioc.stop();
        co_return;
    }, net::detached);
    
    ioc.run();
    
    if (result == 0)
    {
        std::cout << "✓ test_reliable_close passed" << std::endl;
    }
    
    return result;
}

// 测试 unreliable 构造函数
int test_unreliable_constructor()
{
    net::io_context ioc;
    auto executor = ioc.get_executor();
    auto unreliable = std::make_shared<ngx::transport::unreliable>(executor);
    
    TEST_ASSERT(unreliable->executor() == executor);
    TEST_ASSERT(!unreliable->remote_endpoint().has_value());
    
    std::cout << "✓ test_unreliable_constructor passed" << std::endl;
    return 0;
}

// 测试 unreliable 设置远程端点
int test_unreliable_set_remote_endpoint()
{
    net::io_context ioc;
    auto executor = ioc.get_executor();
    auto unreliable = std::make_shared<ngx::transport::unreliable>(executor);
    
    net::ip::udp::endpoint endpoint(net::ip::make_address("127.0.0.1"), 8888);
    unreliable->set_remote_endpoint(endpoint);
    
    auto remote_opt = unreliable->remote_endpoint();
    TEST_ASSERT(remote_opt.has_value());
    TEST_ASSERT(remote_opt->address() == endpoint.address());
    TEST_ASSERT(remote_opt->port() == endpoint.port());
    
    std::cout << "✓ test_unreliable_set_remote_endpoint passed" << std::endl;
    return 0;
}

// 主测试函数
int main()
{
    std::cout << "Starting transmission layer tests..." << std::endl;
    
    int result = 0;
    
    result |= test_reliable_constructor();
    result |= test_reliable_from_socket();
    result |= test_reliable_basic_read_write();
    result |= test_reliable_close();
    result |= test_unreliable_constructor();
    result |= test_unreliable_set_remote_endpoint();
    
    if (result == 0)
    {
        std::cout << "\n✅ All transmission tests passed!" << std::endl;
    }
    else
    {
        std::cout << "\n❌ Some transmission tests failed!" << std::endl;
    }
    
    return result;
}