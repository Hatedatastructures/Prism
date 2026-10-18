/**
 * @file DnsServerTestSupport.hpp
 * @brief DNS 回环测试服务器的任务所有者与关闭收束器。
 * @details 服务器显式关闭监听端点后，Drain 等待所有接受循环、数据循环和 TLS 连接任务退栈。
 */
#pragma once

#include <TestSupport/Tls/MockTlsServer.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>

#include <cstddef>
#include <cstdint>
#include <exception>
#include <limits>
#include <memory>
#include <utility>

namespace
{
    namespace Net = boost::asio;

    /**
     * @class DnsServerTaskGroup
     * @brief 保活并收束一个 DNS 测试服务器的异步任务。
     * @details 每个任务的 completion handler 持有真实服务器 owner；Drain 等待计数归零并重抛首个异常。
     *          调用方须先关闭监听端点和已接受连接，再等待 Drain。
     */
    class DnsServerTaskGroup final
    {
    public:
        explicit DnsServerTaskGroup(Net::any_io_executor Executor)
            : Executor_(std::move(Executor)),
              Completion_(Executor_, std::numeric_limits<std::size_t>::max())
        {
        }

        /** @brief 启动一个受 owner 保活的服务器任务。 */
        auto Spawn(std::shared_ptr<void> Owner, Net::awaitable<void> Operation) -> void
        {
            ++ActiveTasks_;
            Net::co_spawn(
                Executor_, std::move(Operation),
                [Owner = std::move(Owner), this](std::exception_ptr Failure)
                {
                    if (Failure && !FirstFailure_)
                    {
                        FirstFailure_ = std::move(Failure);
                    }
                    --ActiveTasks_;
                    (void)Completion_.try_send(boost::system::error_code{});
                });
        }

        /** @brief 等待所有已启动任务真实完成，再传播其首个异常。 */
        [[nodiscard]] auto Drain() -> Net::awaitable<void>
        {
            while (ActiveTasks_ != 0)
            {
                (void)co_await Completion_.async_receive(Net::use_awaitable);
            }
            if (FirstFailure_)
            {
                std::rethrow_exception(FirstFailure_);
            }
            co_return;
        }

    private:
        Net::any_io_executor Executor_;
        Net::experimental::channel<void(boost::system::error_code)> Completion_;
        std::size_t ActiveTasks_{0};
        std::exception_ptr FirstFailure_;
    };

    /**
     * @class DnsTlsTestServer
     * @brief 拥有回环 TLS acceptor 并跟踪 MockTlsServer 连接任务的 DNS 测试夹具。
     * @details Close 关闭 acceptor；客户端释放上游池连接后，嵌套 TlsServerConnection 读循环退栈，Drain 等待 Run 完成。
     */
    class DnsTlsTestServer final : public std::enable_shared_from_this<DnsTlsTestServer>
    {
    public:
        DnsTlsTestServer(Net::io_context &IoContext, const int MaxConnections,
                         Prism::Testing::Tls::TlsResponder Responder)
            : Acceptor_(IoContext,
                        Net::ip::tcp::endpoint(Net::ip::make_address("127.0.0.1"), 0)),
              Tasks_(IoContext.get_executor()), MaxConnections_(MaxConnections),
              Responder_(std::move(Responder))
        {
        }

        /** @brief 启动 TLS 服务协程，并由任务组保持夹具存活。 */
        auto Start() -> void
        {
            Tasks_.Spawn(shared_from_this(),
                         Prism::Testing::Tls::MockTlsServer::Run(
                             Acceptor_, MaxConnections_, Responder_));
        }

        /** @brief 返回回环 acceptor 当前端口。 */
        [[nodiscard]] auto Port() const -> std::uint16_t
        {
            return Acceptor_.local_endpoint().port();
        }

        /** @brief 关闭监听端点，使等待中的 accept 操作真实退栈。 */
        auto Close() -> void
        {
            boost::system::error_code ErrorCode;
            Acceptor_.close(ErrorCode);
        }

        /** @brief 等待 MockTlsServer 及其当前 TLS 连接 owner 完成。 */
        [[nodiscard]] auto Drain() -> Net::awaitable<void>
        {
            co_await Tasks_.Drain();
        }

    private:
        Net::ip::tcp::acceptor Acceptor_;
        DnsServerTaskGroup Tasks_;
        int MaxConnections_;
        Prism::Testing::Tls::TlsResponder Responder_;
    };

    /**
     * @brief 驱动根协程和所有由其显式关闭的测试服务器任务。
     * @details 不提前停止 io_context；run 返回时，已投递的关闭回调和被跟踪服务器任务均已处理。
     * @param IoContext 测试场景唯一的异步执行上下文。
     * @param Operation 场景根协程；必须关闭并 Drain 自己启动的服务器。
     */
    template <typename OperationType>
    auto RunCoro(Net::io_context &IoContext, OperationType Operation) -> void
    {
        std::exception_ptr Failure;
        Net::co_spawn(IoContext, std::move(Operation),
                      [&Failure](std::exception_ptr Error) { Failure = std::move(Error); });
        IoContext.run();
        if (Failure)
        {
            std::rethrow_exception(Failure);
        }
    }
} // namespace
