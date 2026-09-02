/**
 * @file Listener.hpp
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
#include <utility>

#include <preview/Foundation/Fault/Code.hpp>
#include <preview/Runtime/Session.hpp>
#include <preview/Transport/Reliable.hpp>
#include <preview/Transport/Transmission.hpp>

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

    private:
        /**
         * @struct Lifetime
         * @brief detached accept loop 的共享状态
         * @details accept loop 不捕获 TcpListener 的 this；Stop 或析构后，
         *          状态对象仍由协程持有，直到取消完成。
         */
        struct Lifetime
        {
            Lifetime(net::any_io_executor ex, SessionFactory factory, const std::size_t WorkerCount)
                : Ex(std::move(ex)), Factory(std::move(factory)), Balancer(WorkerCount), Acceptor(Ex)
            {
            }

            net::any_io_executor Ex;
            SessionFactory Factory;
            AffinityBalancer Balancer;
            net::ip::tcp::acceptor Acceptor;
        };

    public:

        /**
         * @brief 构造
         * @param ex 执行器
         * @param factory 会话工厂
         * @param WorkerCount worker 数（用于分发）
         */
        TcpListener(net::any_io_executor ex, SessionFactory factory, std::size_t WorkerCount = 1)
            : State_(std::make_shared<Lifetime>(std::move(ex), std::move(factory), WorkerCount))
        {
        }

        /**
         * @brief 绑定并启动监听
         * @param BindEp 绑定端点（端口 0 = 随机）
         * @return 成功或 io_error
         */
        [[nodiscard]] auto Start(const net::ip::tcp::endpoint &BindEp) -> net::awaitable<Preview::Fault::Code>
        {
            const auto State = State_;
            boost::system::error_code ec;
            State->Acceptor.open(BindEp.protocol(), ec);
            if (!ec)
            {
                State->Acceptor.set_option(net::ip::tcp::acceptor::reuse_address(true), ec);
            }
            if (!ec)
            {
                State->Acceptor.bind(BindEp, ec);
            }
            if (!ec)
            {
                State->Acceptor.listen(net::socket_base::max_listen_connections, ec);
            }
            if (ec)
            {
                co_return Preview::Fault::Code::IoError;
            }
            net::co_spawn(
                State->Ex,
                [State]() -> net::awaitable<void> { co_await TcpListener::AcceptLoop(State); },
                net::detached);
            co_return Preview::Fault::Code::Success;
        }

        /**
         * @brief 停止监听（关闭 acceptor，Accept 循环退出）
         */
        void Stop()
        {
            boost::system::error_code ec;
            State_->Acceptor.close(ec);
        }

        /**
         * @brief 本地端点
         */
        [[nodiscard]] auto LocalEndpoint() const -> net::ip::tcp::endpoint
        {
            return State_->Acceptor.local_endpoint();
        }

    private:
        /**
         * @brief Accept 循环：接受 → 亲和性分发 → 启动会话
         */
        [[nodiscard]] static auto AcceptLoop(const std::shared_ptr<Lifetime> &State)
            -> net::awaitable<void>
        {
            while (true)
            {
                boost::system::error_code ec;
                auto Sock = co_await State->Acceptor.async_accept(
                    net::redirect_error(net::use_awaitable, ec));
                if (ec)
                {
                    co_return; // 停止或错误
                }
                boost::system::error_code pec;
                const auto Remote = Sock.remote_endpoint(pec);
                const auto Peer = pec ? std::string{"unknown"} : Remote.address().to_string();
                const auto Worker = State->Balancer.Select(Peer);
                auto Transport = Preview::Transport::MakeReliable(std::move(Sock));
                if (State->Factory)
                {
                    auto Sess = State->Factory(Transport, Worker);
                    if (Sess)
                    {
                        // 按值捕获 shared_ptr 保持会话存活（协程生命周期独立于 Accept 循环）
                        net::co_spawn(State->Ex,
                                      [Sess, Transport]() -> net::awaitable<void>
                                      { co_await Sess->Run(Transport); },
                                      net::detached);
                    }
                }
            }
        }

        std::shared_ptr<Lifetime> State_; ///< accept loop 生命周期状态
    };

} // namespace Preview::Runtime
