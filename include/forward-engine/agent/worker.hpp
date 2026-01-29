/**
 * @file worker.hpp
 * @brief 代理工作线程
 * @details 负责初始化核心组件（连接池、分发器、接收器等），并启动事件循环处理连接。
 */
#pragma once

#include <boost/asio.hpp>
#include <forward-engine/transport/source.hpp>  // 你已经写好的连接池
#include <forward-engine/agent/distributor.hpp> // 下一步要写的路由器
#include <forward-engine/agent/session.hpp>     // 最后一步要写的会话
#include <memory>
#include <thread>
#include <vector>

#include <forward-engine/agent/config.hpp>
#include <forward-engine/trace.hpp>

/**
 * @namespace ngx::agent
 * @brief 代理业务层 (Control Plane)
 * @details 包含代理服务的核心业务逻辑，如会话管理 (`session`)、流量分发 (`distributor`) 和协议处理 (`handler`)。
 * 它是整个系统的"大脑"，决定数据该往哪里走。
 */
namespace ngx::agent
{

    namespace net = boost::asio;
    using tcp = boost::asio::ip::tcp;
    using source = ngx::transport::source;
    using level = ngx::transport::detail::log_level;
    
    /**
     * @brief 日志转换函数
     * @details 将 `agent::level` 转换为 `ngx::trace::level` 并记录日志。
     * @param log_lvl `agent::level` 日志级别
     * @param msg `std::string_view` 日志消息
     * @note 该函数不会主动运行，需要由现有测试用例显式调用。或者根据用户自己写的log模块转换调用
     */
    inline auto log_transformation = [](level log_lvl, std::string_view msg)
    {
        switch (log_lvl)
        {
        case level::debug:
            ngx::trace::debug("{}", msg);
            break;
        case level::info:
            ngx::trace::info("{}", msg);
            break;
        case level::warn:
            ngx::trace::warn("{}", msg);
            break;
        case level::error:
            ngx::trace::error("{}", msg);
            break;
        case level::fatal:
            ngx::trace::fatal("{}", msg);
            break;
        default:
            break;
        }
    };

    /**
     * @class worker
     * @brief 代理工作线程 (Worker Thread)
     * @details 管理 IO 上下文、连接池、分发器和接收器，是代理服务的运行实体。
     * 每个 `worker` 实例维护一个独立的 `io_context`，可以单线程运行，也可以作为多线程 Reactor 组的一部分。
     * @see session
     */
    class worker
    {
    public:
        /**
         * @brief 构造工作线程
         * @details 初始化所有核心组件，加载证书，绑定端口。
         * @param cfg 代理配置对象
         */
        explicit worker(const agent::config& cfg)
            : ioc_(1),                   // 1. 初始化 IO 上下文 (hint=1 表示单线程)
              pool_(ioc_),               // 2. 初始化连接池 (依赖 ioc)
              distributor_(pool_, ioc_), // 3. 初始化路由器 (依赖 pool 和 ioc)
              ssl_ctx_(std::make_shared<net::ssl::context>(net::ssl::context::tls)),
              acceptor_(ioc_), // 4. 初始化接收器
              config_(cfg)
        {
            const auto port = cfg.addressable.port;
            const auto& cert = cfg.certificate.cert;
            const auto& key = cfg.certificate.key;
            // -------------------------------------------------------------
            // SSL 配置部分
            // -------------------------------------------------------------
            try
            {
                if (!cert.empty() && !key.empty())
                {
                    boost::system::error_code ec;
                    ssl_ctx_->use_certificate_chain_file({cert.data(), cert.size()},ec);
                    if (ec)
                    {
                        trace::error("ssl cert load failed: " + ec.message());
                        throw abnormal::protocol("ssl cert load failed:",ec.message());
                    }
                    ssl_ctx_->use_private_key_file({key.data(), key.size()}, net::ssl::context::pem);
                    if (ec)
                    {
                        trace::error("ssl key load failed: " + ec.message());
                        throw abnormal::protocol("ssl key load failed:",ec.message());
                    }
                    
                    // 只有在证书加载成功后，才有意义去设置这些底层参数
                    // 2. [新增] 开启 GREASE (油脂机制) - BoringSSL 特有
                    SSL_CTX_set_grease_enabled(ssl_ctx_->native_handle(), 1);

                    // 3. [新增] 开启 HTTP/2 ALPN (模拟浏览器指纹)
                    // 长度计算：1(len) + 2(h2) + 1(len) + 8(http/1.1) = 12
                    constexpr unsigned char ALPN[] = "\x02h2\x08http/1.1";
                    SSL_CTX_set_alpn_protos(ssl_ctx_->native_handle(), ALPN, sizeof(ALPN) - 1);
                }
                else
                {
                    // 如果没有证书，可能是想跑在 HTTP 模式下
                    // 根据你的业务逻辑决定是否 reset
                    ssl_ctx_.reset(); 
                    trace::warn("No certificate or key provided, running in plain HTTP mode");
                }
            }
            catch (const abnormal::protocol& e)
            {
                trace::error(" protocol exception: {}", e.dump());
                throw;
            }
            catch (const std::exception& e)
            {
                // 记录日志或直接抛出，不要带着损坏的 context 继续跑
                trace::error("SSL init failed: {}", e.what());
                throw; // 或者 ssl_ctx_.reset(); 但后面要判空
            }

            // -------------------------------------------------------------
            // 网络监听部分
            // -------------------------------------------------------------
            auto endpoint = tcp::endpoint(tcp::v4(), port);
            acceptor_.open(endpoint.protocol());
            acceptor_.set_option(net::socket_base::reuse_address(true));

            int one = 1;
    #ifdef SO_REUSEPORT
            setsockopt(acceptor_.native_handle(), SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
    #endif

            acceptor_.bind(endpoint);
            acceptor_.listen();

            // 加载反向代理路由
            for (const auto& [host, ep_config] : config_.reverse_map)
            {
                boost::system::error_code ec;
                const auto addr = net::ip::make_address(ep_config.host, ec);
                if (!ec && ep_config.port != 0)
                {
                    distributor_.add_reverse_route(host, tcp::endpoint(addr, ep_config.port));
                }
                else
                {
                    trace::warn("Invalid reverse route config for host: {}", host);
                }
            }
        }

        /**
         * @brief 运行工作线程 (单线程模式)
         * @details 启动 `io_context` 事件循环，阻塞当前线程直到所有任务完成或被停止。
         * @note 仅使用当前调用线程作为工作线程。
         */
        void run()
        {
            run(1);
        }

        /**
         * @brief 运行工作线程 (多线程模式)
         * @details 启动 `io_context` 事件循环，并创建指定数量的线程共同处理 IO 事件。
         * 在多线程模式下，所有线程共享同一个 `io_context`，ASIO 会自动在这些线程之间分发任务。
         * @param threads_count 线程池大小
         * @warning 该函数会阻塞调用线程。
         * @note 如果 `threads_count` 为 0，将自动修正为 1。
         */
        void run(std::size_t threads_count)
        {
            if (threads_count == 0)
            {
                threads_count = 1;
            }

            do_accept();

            std::vector<std::jthread> threads;
            threads.reserve(threads_count > 0 ? threads_count - 1 : 0);

            for (std::size_t i = 1; i < threads_count; ++i)
            {
                threads.emplace_back([this]
                {
                    ioc_.run();
                });
            }

            ioc_.run();
        }

    private:    
        /**
         * @brief 异步接收连接
         * @details 持续接收新的客户端连接，并为每个连接创建 `session`。
         * @note 这是一个递归的异步操作：每次处理完一个连接后，会立即发起下一个 `async_accept`。
         */
        void do_accept()
        {
            acceptor_.async_accept(
                [this](const boost::system::error_code &ec, tcp::socket socket)
                {
                    if (!ec)
                    {
                        // 创建会话，把“路由器”传给它
                        const auto session_ptr = std::make_shared<session<tcp::socket>>(
                            ioc_,
                            std::move(socket),
                            distributor_,
                            ssl_ctx_);
                        session_ptr->registered_log_function(log_transformation);
                        
                        // 设置密码验证器
                        session_ptr->set_password_verifier([this](std::string_view hash) -> bool {
                            if (config_.authentication.passwords.empty()) {
                                return true; // 如果未配置密码，默认允许（或根据策略拒绝）
                            }
                            for (const auto& pass : config_.authentication.passwords) {
                                if (pass == hash) return true;
                            }
                            return false;
                        });

                        session_ptr->start();
                    }
                    do_accept();
                });
        }

        net::io_context ioc_;
        source pool_;             // 资源仓库
        distributor distributor_; // 业务大脑
        std::shared_ptr<ssl::context> ssl_ctx_;
        tcp::acceptor acceptor_;
        agent::config config_;
    };

}
