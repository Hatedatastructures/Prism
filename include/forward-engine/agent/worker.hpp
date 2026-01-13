#pragma once

#include <boost/asio.hpp>
#include <agent/connection.hpp>  // 你已经写好的连接池
#include <agent/distributor.hpp> // 下一步要写的路由器
#include <agent/session.hpp>     // 最后一步要写的会话
#include <memory>
#include <thread>
#include <vector>

#include <trace.hpp>

namespace ngx::agent
{

    namespace net = boost::asio;
    using tcp = boost::asio::ip::tcp;
    
    /**
     * @brief 日志转换函数
     * @details 将 `agent::level` 转换为 `ngx::trace::level` 并记录日志。
     * @param level `agent::level` 日志级别
     * @param msg `std::string_view` 日志消息
     * @note 该函数不会主动运行，需要由现有测试用例显式调用。或者根据用户自己写的log模块转换调用
     */
    inline auto log_transformation = [](agent::level level, std::string_view msg)
    {
        switch (level)
        {
        case agent::level::debug:
            ngx::trace::debug("{}", msg);
            break;
        case agent::level::info:
            ngx::trace::info("{}", msg);
            break;
        case agent::level::warn:
            ngx::trace::warn("{}", msg);
            break;
        case agent::level::error:
            ngx::trace::error("{}", msg);
            break;
        case agent::level::fatal:
            ngx::trace::fatal("{}", msg);
            break;
        default:
            break;
        }
    };

    class worker
    {
    public:
        // 构造函数：初始化所有线程局部资源
        explicit worker(const unsigned short port, const ngx::memory::string &cert, const ngx::memory::string &key)
            : ioc_(1),                   // 1. 初始化 IO 上下文 (hint=1 表示单线程)
              pool_(ioc_),               // 2. 初始化连接池 (依赖 ioc)
              distributor_(pool_, ioc_), // 3. 初始化路由器 (依赖 pool 和 ioc)
              ssl_ctx_(std::make_shared<net::ssl::context>(net::ssl::context::tls)),
              acceptor_(ioc_) // 4. 初始化接收器
        {
            // -------------------------------------------------------------
            // SSL 配置部分
            // -------------------------------------------------------------
            try
            {
                if (!cert.empty() && !key.empty())
                {
                    ssl_ctx_->use_certificate_chain_file({cert.data(), cert.size()});
                    ssl_ctx_->use_private_key_file({key.data(), key.size()}, net::ssl::context::pem);
                    
                    // 只有在证书加载成功后，才有意义去设置这些底层参数
                    // 2. [新增] 开启 GREASE (油脂机制) - BoringSSL 特有
                    SSL_CTX_set_grease_enabled(ssl_ctx_->native_handle(), 1);

                    // 3. [新增] 开启 HTTP/2 ALPN (模拟浏览器指纹)
                    // 长度计算：1(len) + 2(h2) + 1(len) + 8(http/1.1) = 12
                    const unsigned char alpn[] = "\x02h2\x08http/1.1";
                    SSL_CTX_set_alpn_protos(ssl_ctx_->native_handle(), alpn, sizeof(alpn) - 1);
                }
                else
                {
                    // 如果没有证书，可能是想跑纯 HTTP 模式？
                    // 根据你的业务逻辑决定是否 reset
                    // ssl_ctx_.reset(); 
                }
            }
            catch (const std::exception& e)
            {
                // 记录日志或直接抛出，不要带着损坏的 context 继续跑
                // spdlog::error("SSL init failed: {}", e.what());
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
        }

        void load_reverse_map(const std::string &file_path)
        {
            distributor_.load_reverse_map(file_path);
        }

        void run()
        {
            run(1);
        }

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
        void do_accept()
        {
            acceptor_.async_accept(
                [this](const boost::system::error_code &ec, tcp::socket socket)
                {
                    if (!ec)
                    {
                        // 创建会话，把“路由器”传给它
                        auto session_ptr = std::make_shared<session<tcp::socket>>(
                            ioc_,
                            std::move(socket),
                            distributor_,
                            ssl_ctx_);
                        session_ptr->registered_log_function(log_transformation);
                        session_ptr->start();
                    }
                    do_accept();
                });
        }

        net::io_context ioc_;
        source pool_;             // 资源仓库
        distributor distributor_; // 业务大脑
        std::shared_ptr<net::ssl::context> ssl_ctx_;
        tcp::acceptor acceptor_;
    };

}
