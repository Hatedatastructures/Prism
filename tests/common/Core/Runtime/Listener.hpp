/**
 * @file listener.hpp
 * @brief TCP 监听器骨架（T4-3）
 * @details listener Accept → 亲和性分发（FNV-1a 哈希）→ 会话工厂：
 *          - Accept 循环：async_accept + 分发 + co_spawn 会话
 *          - 亲和性：同一远端地址 → 同一 worker（哈希稳定）
 *          - Stop()：取消 acceptor，Accept 循环退出
 * @note 对应生产 runtime/front/listener + balancer；worker 池执行
 *       模型简化（单 ioc），分发逻辑完整可测
 */

#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string_view>

#include <common/Core/Fault/Code.hpp>
#include <common/Core/Runtime/Session.hpp>
#include <common/Core/Transport/Reliable.hpp>
#include <common/Core/Transmission.hpp>

namespace Preview::Runtime
{

    namespace net = boost::asio;

    /**
     * @class AffinityBalancer
     * @brief 亲和性分发器
     * @details FNV-1a 哈希远端标识 → worker 索引。
     *          相同标识稳定映射（亲和），分布近似均匀。
     */
    class AffinityBalancer
    {
    public:
        /**
         * @brief 构造
         * @param WorkerCount worker 数（≥1）
         */
        explicit AffinityBalancer(std::size_t WorkerCount) : WorkerCount_(WorkerCount)
        {
            if (WorkerCount_ < 1)
            {
                WorkerCount_ = 1;
            }
        }

        /**
         * @brief 选择 worker
         * @param key 亲和性键（如远端地址）
         * @return worker 索引 [0, WorkerCount)
         */
        [[nodiscard]] auto Select(std::string_view key) const noexcept -> std::size_t
        {
            std::uint64_t Hash = 14695981039346656037ULL;
            for (const char c : key)
            {
                Hash ^= static_cast<unsigned char>(c);
                Hash *= 1099511628211ULL;
            }
            return static_cast<std::size_t>(Hash % WorkerCount_);
        }

        /**
         * @brief worker 数
         */
        [[nodiscard]] auto WorkerCount() const noexcept -> std::size_t
        {
            return WorkerCount_;
        }

    private:
        std::size_t WorkerCount_; ///< worker 数
    };

    /**
     * @class TcpListener
     * @brief TCP 监听器
     * @details 绑定端点后进入 Accept 循环，每个连接按远端地址
     *          亲和性分发到 worker 并启动会话。
     */
    class TcpListener
    {
    public:
        /// 会话工厂签名：入站传输 + worker 索引 → 会话
        using SessionFactory =
            std::function<std::shared_ptr<Session>(Preview::SharedTransmission, std::size_t)>;

        /**
         * @brief 构造
         * @param ex 执行器
         * @param factory 会话工厂
         * @param WorkerCount worker 数（用于分发）
         */
        TcpListener(net::any_io_executor ex, SessionFactory factory, std::size_t WorkerCount = 1)
            : ex_(std::move(ex)), factory_(std::move(factory)), balancer_(WorkerCount),
              acceptor_(ex_)
        {
        }

        /**
         * @brief 绑定并启动监听
         * @param bind_ep 绑定端点（端口 0 = 随机）
         * @return 成功或 io_error
         */
        [[nodiscard]] auto Start(const net::ip::tcp::endpoint &bind_ep) -> net::awaitable<Preview::Fault::Code>
        {
            boost::system::error_code ec;
            acceptor_.open(bind_ep.protocol(), ec);
            if (!ec)
            {
                acceptor_.set_option(net::ip::tcp::acceptor::reuse_address(true), ec);
            }
            if (!ec)
            {
                acceptor_.bind(bind_ep, ec);
            }
            if (!ec)
            {
                acceptor_.listen(net::socket_base::max_listen_connections, ec);
            }
            if (ec)
            {
                co_return Preview::Fault::Code::io_error;
            }
            net::co_spawn(ex_, AcceptLoop(), net::detached);
            co_return Preview::Fault::Code::success;
        }

        /**
         * @brief 停止监听（关闭 acceptor，Accept 循环退出）
         */
        void Stop()
        {
            boost::system::error_code ec;
            acceptor_.close(ec);
        }

        /**
         * @brief 本地端点
         */
        [[nodiscard]] auto LocalEndpoint() const -> net::ip::tcp::endpoint
        {
            return acceptor_.local_endpoint();
        }

    private:
        /**
         * @brief Accept 循环：接受 → 亲和性分发 → 启动会话
         */
        [[nodiscard]] auto AcceptLoop() -> net::awaitable<void>
        {
            while (true)
            {
                boost::system::error_code ec;
                auto sock = co_await acceptor_.async_accept(
                    net::redirect_error(net::use_awaitable, ec));
                if (ec)
                {
                    co_return; // 停止或错误
                }
                const auto peer = sock.remote_endpoint().address().to_string();
                const auto worker = balancer_.Select(peer);
                auto transport = Preview::Transport::make_reliable(std::move(sock));
                if (factory_)
                {
                    auto sess = factory_(transport, worker);
                    if (sess)
                    {
                        // 按值捕获 shared_ptr 保持会话存活（协程生命周期独立于 Accept 循环）
                        net::co_spawn(ex_,
                                      [sess, transport]() -> net::awaitable<void>
                                      { co_await sess->Run(transport); },
                                      net::detached);
                    }
                }
            }
        }

        net::any_io_executor ex_;          ///< 执行器
        SessionFactory factory_;          ///< 会话工厂
        AffinityBalancer balancer_;       ///< 亲和性分发
        net::ip::tcp::acceptor acceptor_;  ///< TCP 接受器
    };

} // namespace Preview::Runtime
