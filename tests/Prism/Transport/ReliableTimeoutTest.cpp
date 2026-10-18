/**
 * @file ReliableTimeoutTest.cpp
 * @brief Reliable TCP 读取 deadline 与连接拒绝结果测试。
 * @details 保留同步 loopback socket 输入、回调完成及普通错误值检查。
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/write.hpp>

#include <array>
#include <chrono>
#include <exception>
#include <memory>
#include <span>
#include <system_error>
#include <utility>

#include <Prism/Transport/Reliable.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    using ReadCompletion = Net::experimental::channel<void(boost::system::error_code)>;

    /** @brief 驱动超时协程并只传播实际抛出的异常。 */
    auto RunCoro(Net::io_context &Context, Net::awaitable<void> Operation) -> void
    {
        std::exception_ptr Failure;
        Context.restart();
        Net::co_spawn(Context, std::move(Operation), [&Failure](std::exception_ptr Error)
                      { Failure = std::move(Error); });
        Context.run();
        if (Failure)
        {
            std::rethrow_exception(Failure);
        }
    }

    /** @brief 建立原读取 deadline 场景使用的已连接本地 TCP socket 对。 */
    auto MakeTcpPair(Net::io_context &Context)
        -> std::pair<Net::ip::tcp::socket, Net::ip::tcp::socket>
    {
        Net::ip::tcp::acceptor Acceptor(
            Context, Net::ip::tcp::endpoint(Net::ip::address_v4::loopback(), 0));
        Net::ip::tcp::socket Client(Context);
        Client.connect(Acceptor.local_endpoint());
        Net::ip::tcp::socket Server(Context);
        Acceptor.accept(Server);
        return {std::move(Client), std::move(Server)};
    }

    /** @brief 保留 40 毫秒 deadline、零字节、Timeout 及 25 毫秒下界。 */
    auto RunReliableReadTimeout(
        const std::shared_ptr<Prism::Transport::Reliable> &Reliable,
        Net::ip::tcp::socket &Server) -> Net::awaitable<void>
    {
        Reliable->SetTimeout(std::chrono::milliseconds(40));
        std::array<std::byte, 8> Buffer{};
        const auto Started = std::chrono::steady_clock::now();
        const auto Result = co_await Reliable->ReadSome(Buffer);
        const auto Elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                                 std::chrono::steady_clock::now() - Started)
                                 .count();
        EXPECT_EQ(Result.Bytes, 0U);
        EXPECT_EQ(Result.Failure.Code, Prism::Fault::Code::Timeout);
        EXPECT_GE(Elapsed, 25);
        Server.close();
    }

    /** @brief 保留 500 毫秒窗口内的原四字节 payload 及首字节断言。 */
    auto RunReliableReadBeforeTimeout(
        const std::shared_ptr<Prism::Transport::Reliable> &Reliable,
        Net::ip::tcp::socket &Server,
        const std::array<std::byte, 4> &Payload) -> Net::awaitable<void>
    {
        Reliable->SetTimeout(std::chrono::milliseconds(500));
        std::array<std::byte, 8> Buffer{};
        const auto Result = co_await Reliable->ReadSome(Buffer);
        EXPECT_EQ(Result.Bytes, Payload.size());
        EXPECT_TRUE(Result.Failure.Succeeded());
        EXPECT_EQ(Buffer[0], Payload[0]);
        Server.close();
    }

    /** @brief 通过 callback 入口等待 40 毫秒读取超时的恰一次完成通知。 */
    auto RunReliableHandlerReadTimeout(
        const std::shared_ptr<Prism::Transport::Reliable> &Reliable,
        Net::ip::tcp::socket &Server) -> Net::awaitable<void>
    {
        Reliable->SetTimeout(std::chrono::milliseconds(40));
        std::array<std::byte, 8> Buffer{};
        const auto Result = std::make_shared<Prism::IoResult>();
        const auto Done = std::make_shared<ReadCompletion>(Reliable->Executor(), 1);
        Reliable->ReadSome(std::span<std::byte>(Buffer), [Result, Done](Prism::IoResult Value)
                           {
                               *Result = Value;
                               (void)Done->try_send(boost::system::error_code{});
                           });
        co_await Done->async_receive(Net::use_awaitable);
        EXPECT_EQ(Result->Bytes, 0U);
        EXPECT_EQ(Result->Failure.Code, Prism::Fault::Code::Timeout);
        Server.close();
    }
}

TEST(Transport, ReliableReadTimeout)
{
    Net::io_context Io;
    auto [Client, Server] = MakeTcpPair(Io);
    auto Reliable = std::make_shared<Prism::Transport::Reliable>(std::move(Client));
    RunCoro(Io, RunReliableReadTimeout(Reliable, Server));
}

TEST(Transport, ReliableReadBeforeTimeoutStillSucceeds)
{
    Net::io_context Io;
    auto [Client, Server] = MakeTcpPair(Io);
    auto Reliable = std::make_shared<Prism::Transport::Reliable>(std::move(Client));
    const std::array<std::byte, 4> Payload{
        std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44}};
    boost::system::error_code WriteError;
    Net::write(Server, Net::buffer(Payload), WriteError);
    ASSERT_FALSE(WriteError);
    RunCoro(Io, RunReliableReadBeforeTimeout(Reliable, Server, Payload));
}

TEST(Transport, ReliableConnectReturnsErrorCodeOnRefusal)
{
    Net::io_context Io;
    Net::ip::tcp::acceptor Acceptor(
        Io, Net::ip::tcp::endpoint(Net::ip::address_v4::loopback(), 0));
    const auto Endpoint = Acceptor.local_endpoint();
    boost::system::error_code CloseError;
    Acceptor.close(CloseError);
    ASSERT_FALSE(CloseError);

    auto Reliable = std::make_shared<Prism::Transport::Reliable>(Io.get_executor());
    Prism::Transmission::ControlResult Result;
    std::exception_ptr Thrown;
    Net::co_spawn(Io,
                  [&]() -> Net::awaitable<void>
                  {
                      Result = co_await Reliable->Connect(Endpoint, std::chrono::milliseconds(0));
                  },
                  [&Thrown](std::exception_ptr Error) { Thrown = std::move(Error); });
    Io.run();
    EXPECT_FALSE(Thrown);
    EXPECT_FALSE(Result.has_value());
}

TEST(Transport, ReliableHandlerReadTimeout)
{
    Net::io_context Io;
    auto [Client, Server] = MakeTcpPair(Io);
    auto Reliable = std::make_shared<Prism::Transport::Reliable>(std::move(Client));
    RunCoro(Io, RunReliableHandlerReadTimeout(Reliable, Server));
}
