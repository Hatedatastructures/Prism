/**
 * @file DialerTest.cpp
 * @brief TCP 拨号测试（T3-1）
 * @details 覆盖：
 *          - 成功连接（loopback）
 *          - 连接拒绝（未监听端口）
 *          - 超时（不可达地址）
 *          - 无效端口 / IPv6 禁用
 */

#include <Preview/Net/Dialer/Dialer.hpp>
#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Transport/Reliable.hpp>

#include <boost/asio/error.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <exception>
#include <expected>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <system_error>

#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    using Tcp = Net::ip::tcp;
    using Preview::SharedTransmission;

    using CompletionChannel = Net::experimental::channel<void(boost::system::error_code)>;

    struct CompletionState final
    {
        explicit CompletionState(Net::any_io_executor Executor) : Done(std::move(Executor), 1) {}

        CompletionChannel Done;
        std::exception_ptr Failure;
    };

    auto RecordCompletion(const std::shared_ptr<CompletionState> &State, std::exception_ptr Failure) -> void
    {
        State->Failure = Failure;
        (void)State->Done.try_send(boost::system::error_code{});
    }

    auto WaitForCompletion(const std::shared_ptr<CompletionState> &State) -> Net::awaitable<void>
    {
        co_await State->Done.async_receive(Net::use_awaitable);
        if (State->Failure)
        {
            std::rethrow_exception(State->Failure);
        }
    }

    auto RunCoro(Net::io_context &Ioc, Net::awaitable<void> Operation) -> void
    {
        std::exception_ptr Exception;
        Net::co_spawn(Ioc, std::move(Operation), [&](std::exception_ptr Error) { Exception = Error; });
        Ioc.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    /**
     * @brief 接受一个拨号连接并在完成后关闭服务端 socket。
     * @param Acceptor 监听 acceptor，由调用测试持有至 completion。
     * @return 接受和关闭完成后返回。
     */
    auto RunAcceptOnce(Tcp::acceptor &Acceptor) -> Net::awaitable<void>
    {
        auto Socket = co_await Acceptor.async_accept(Net::use_awaitable);
        Socket.close();
    }

    struct DialAttemptRequest final
    {
        Net::any_io_executor Executor;
        Preview::Network::Target Target;
        Preview::Network::Dialer::DialOptions Options{};
    };

    struct DialAttemptResult final
    {
        Preview::Fault::Failure Failure;
        SharedTransmission Connection;
    };

    /** @brief 执行一个明确目标和拨号选项并保留唯一 typed 结果。 */
    auto RunDialAttempt(DialAttemptRequest Request, DialAttemptResult &Result)
        -> Net::awaitable<void>
    {
        Preview::Network::Dialer::Dialer Dialer(Request.Executor, Request.Options);
        auto Dialed = co_await Dialer.Connect(Request.Target);
        if (Dialed)
        {
            Result.Connection = std::move(*Dialed);
        }
        else
        {
            Result.Failure = Dialed.error();
        }
    }

    struct SuccessfulDialRequest final
    {
        Tcp::acceptor &Acceptor;
        std::uint16_t Port;
    };

    /** @brief 拨号成功场景等待真实 accept owner 退栈。 */
    auto RunSuccessfulDial(SuccessfulDialRequest Request, DialAttemptResult &Result)
        -> Net::awaitable<void>
    {
        const auto Accepted = std::make_shared<CompletionState>(Request.Acceptor.get_executor());
        Net::co_spawn(Request.Acceptor.get_executor(), RunAcceptOnce(Request.Acceptor),
                      [Accepted](std::exception_ptr Failure)
                      { RecordCompletion(Accepted, Failure); });
        Preview::Network::Dialer::Dialer Dialer(Request.Acceptor.get_executor());
        auto Dialed = co_await Dialer.Connect(
            {*Preview::Network::ParseHost("127.0.0.1"), Request.Port});
        if (Dialed)
        {
            Result.Connection = std::move(*Dialed);
        }
        else
        {
            Result.Failure = Dialed.error();
        }
        co_await WaitForCompletion(Accepted);
    }

    /**
     * @brief 接受一次连接并完成一轮真实 echo 读写。
     * @param Acceptor 监听 acceptor，由调用测试持有至 completion。
     * @return echo 读写及 socket 关闭完成后返回。
     */
    auto RunEchoOnce(Tcp::acceptor &Acceptor) -> Net::awaitable<void>
    {
        auto Socket = co_await Acceptor.async_accept(Net::use_awaitable);
        std::array<std::byte, 64> Buffer{};
        boost::system::error_code ErrorCode;
        const auto Count = co_await Socket.async_read_some(
            Net::buffer(Buffer), Net::redirect_error(Net::use_awaitable, ErrorCode));
        if (!ErrorCode && Count > 0)
        {
            co_await Socket.async_write_some(
                Net::buffer(Buffer, Count), Net::redirect_error(Net::use_awaitable, ErrorCode));
        }
        Socket.close();
    }

    struct EchoScenarioRequest final
    {
        Tcp::acceptor &Acceptor;
        std::uint16_t Port;
        SharedTransmission &Connection;
        Preview::Fault::Failure &DialFailure;
    };

    /**
     * @brief 拨号后完成 echo 传输，并等待服务端任务真实退栈。
     * @param Acceptor 监听 acceptor。
     * @param Port 监听端口。
     * @param Connection 输出的拨号传输所有者。
     * @param DialFailure 输出的 typed 拨号失败。
     * @return 拨号、双向传输和服务端关闭完成后返回。
     */
    auto RunEchoScenario(EchoScenarioRequest Request) -> Net::awaitable<void>
    {
        const auto Completion = std::make_shared<CompletionState>(Request.Acceptor.get_executor());
        Net::co_spawn(Request.Acceptor.get_executor(), RunEchoOnce(Request.Acceptor),
                      [Completion](std::exception_ptr Failure)
                      { RecordCompletion(Completion, Failure); });

        Preview::Network::Dialer::Dialer Dialer(Request.Acceptor.get_executor());
        auto Dialed = co_await Dialer.Connect(
            {*Preview::Network::ParseHost("127.0.0.1"), Request.Port});
        if (Dialed)
        {
            Request.Connection = std::move(*Dialed);
        }
        else
        {
            Request.DialFailure = Dialed.error();
        }
        if (!Request.Connection)
        {
            boost::system::error_code CloseError;
            Request.Acceptor.close(CloseError);
            co_await WaitForCompletion(Completion);
            co_return;
        }

        const std::string Message = "Dialer-echo";
        std::error_code WriteError;
        const auto Write = co_await Request.Connection->WriteSome(
            std::span<const std::byte>(reinterpret_cast<const std::byte *>(Message.data()), Message.size()));
        WriteError = Preview::Fault::ToNative(Write.Failure);
        std::array<std::byte, 64> Buffer{};
        std::error_code ReadError;
        const auto Read = co_await Request.Connection->ReadSome(Buffer);
        ReadError = Preview::Fault::ToNative(Read.Failure);
        const auto Count = Read.Bytes;
        EXPECT_FALSE(WriteError);
        EXPECT_FALSE(ReadError);
        EXPECT_EQ(Count, Message.size());
        if (!ReadError && Count == Message.size())
        {
            EXPECT_EQ(std::string_view(reinterpret_cast<const char *>(Buffer.data()), Count), Message);
        }
        (void)Request.Connection->Close();
        co_await WaitForCompletion(Completion);
    }
} // namespace

TEST(Dialer, ConnectSuccess)
{
    Net::io_context ioc;
    Tcp::acceptor acceptor(ioc, Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
    const auto port = acceptor.local_endpoint().port();

    DialAttemptResult Result;
    RunCoro(ioc, RunSuccessfulDial(SuccessfulDialRequest{acceptor, port}, Result));
    EXPECT_TRUE(Result.Failure.Succeeded());
    EXPECT_EQ(Result.Failure.Code, Preview::Fault::Code::Success);
    ASSERT_NE(Result.Connection, nullptr);
    (void)Result.Connection->Close();
}

TEST(Dialer, ConnectRefused)
{
    Net::io_context ioc;
    // 找一个未监听端口
    Tcp::acceptor Probe(ioc, Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
    const auto port = Probe.local_endpoint().port();
    Probe.close();

    DialAttemptResult Result;
    RunCoro(ioc, RunDialAttempt(DialAttemptRequest{
        ioc.get_executor(), {*Preview::Network::ParseHost("127.0.0.1"), port}}, Result));
    EXPECT_EQ(Result.Failure.Code, Preview::Fault::Code::ConnectionRefused);
    EXPECT_TRUE(Result.Failure.Native);
    const auto ExpectedNative = static_cast<std::error_code>(
        Net::error::make_error_code(Net::error::connection_refused));
    EXPECT_EQ(Result.Failure.Native.category(), ExpectedNative.category());
    EXPECT_EQ(Result.Failure.Native.value(), ExpectedNative.value());
    EXPECT_EQ(Result.Connection, nullptr);
}

TEST(Dialer, ConnectTimeout)
{
    Net::io_context ioc;
    Preview::Network::Dialer::DialOptions Options;
    Options.Timeout = std::chrono::milliseconds(100);
    DialAttemptResult Result;
    RunCoro(ioc, RunDialAttempt(DialAttemptRequest{
        ioc.get_executor(), {*Preview::Network::ParseHost("192.0.2.1"), 8080}, Options}, Result));
    EXPECT_EQ(Result.Failure.Code, Preview::Fault::Code::Timeout);
    EXPECT_EQ(Result.Connection, nullptr);
}

TEST(Dialer, InvalidPortZero)
{
    Net::io_context ioc;
    DialAttemptResult Result;
    RunCoro(ioc, RunDialAttempt(DialAttemptRequest{
        ioc.get_executor(), {*Preview::Network::ParseHost("127.0.0.1"), 0}}, Result));
    // 端口 0 在拨号边界被明确拒绝。
    EXPECT_EQ(Result.Failure.Code, Preview::Fault::Code::InvalidArgument);
    EXPECT_EQ(Result.Connection, nullptr);
}

TEST(Dialer, Ipv6Disabled)
{
    Net::io_context ioc;
    Preview::Network::Dialer::DialOptions Options;
    Options.EnableIpv6 = false;
    DialAttemptResult Result;
    RunCoro(ioc, RunDialAttempt(DialAttemptRequest{
        ioc.get_executor(), {*Preview::Network::ParseHost("::1"), 8080}, Options}, Result));
    EXPECT_EQ(Result.Failure.Code, Preview::Fault::Code::NotSupported);
    EXPECT_EQ(Result.Connection, nullptr);
}

TEST(Dialer, ConnectEchoTransfer)
{
    Net::io_context ioc;
    Tcp::acceptor acceptor(ioc, Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
    const auto port = acceptor.local_endpoint().port();

    Preview::Fault::Failure DialFailure;
    SharedTransmission Conn;
    RunCoro(ioc, RunEchoScenario(EchoScenarioRequest{acceptor, port, Conn, DialFailure}));
    EXPECT_TRUE(DialFailure.Succeeded());
    ASSERT_NE(Conn, nullptr);
}
