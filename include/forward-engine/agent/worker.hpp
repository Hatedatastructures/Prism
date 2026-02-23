/**
 * @file worker.hpp
 * @brief 代理工作线程
 * @details 负责初始化核心组件（连接池、分发器、接收器等），并启动事件循环处理连接。
 * 该模块是代理服务的运行时容器，管理所有核心组件的生命周期和事件循环。
 *
 * 架构角色：
 * - 运行时容器：封装 `io_context` 和所有核心组件；
 * - 资源管理器：管理连接池、分发器、`SSL` 上下文等资源；
 * - 网络监听器：绑定端口，接受客户端连接；
 * - 事件循环执行器：运行 `io_context` 事件循环处理所有异步操作。
 *
 * 设计特性：
 * - 线程封闭：每个 `worker` 实例在独立线程中运行，无跨线程同步开销；
 * - 资源独占：拥有独立的连接池、分发器，避免资源竞争；
 * - 配置驱动：通过 `config` 对象统一管理所有运行时配置；
 * - 优雅启停：支持正常关闭所有连接和资源。
 *
 * 典型部署：
 * 1. 单核模式：创建一个 `worker` 实例，在单线程中运行；
 * 2. 多核扩展：创建多个 `worker` 实例（通常等于 CPU 核心数），通过 `SO_REUSEPORT` 实现负载均衡；
 * 3. 容器化部署：每个 `worker` 作为独立的服务单元，可独立扩展和重启。
 *
 * 初始化流程：
 * 1. 创建 `io_context` 和线程局部内存池；
 * 2. 初始化连接池 (`source`) 和分发器 (`distributor`)；
 * 3. 加载 `SSL` 证书和配置 `TLS` 参数（`GREASE`、`ALPN`）；
 * 4. 注册协议处理器到全局注册表；
 * 5. 绑定监听端口，配置 `socket` 选项；
 * 6. 加载反向代理和正向代理路由配置。
 *
 * @note 每个 `worker` 应运行在独立的操作系统线程中，以实现真正的并发。
 * @warning `SSL` 证书和私钥文件必须在构造函数中可访问，否则会抛出异常。
 */
#pragma once

#include <boost/asio.hpp>
#include <forward-engine/transport/source.hpp>
#include <forward-engine/agent/distributor.hpp>
#include <forward-engine/agent/session.hpp>
#include <forward-engine/agent/detection.hpp>
#include <forward-engine/agent/validator.hpp>
#include <forward-engine/transport/reliable.hpp>
#include <forward-engine/memory/pool.hpp>
#include <memory>

#include <forward-engine/agent/config.hpp>
#include <forward-engine/trace.hpp>

/**
 * @namespace ngx::agent
 * @brief 代理业务层 (Control Plane)
 * @details 包含代理服务的核心业务逻辑，如会话管理 (`session`)、流量分发 (`distributor`) 和协议处理 (`handler`)。
 * 它是整个系统的"大脑"，决定数据该往哪里走。
 *
 */
namespace ngx::agent
{

    namespace net = boost::asio;
    using tcp = boost::asio::ip::tcp;
    using source = ngx::transport::source;

    /**
     * @class worker
     * @brief 代理工作线程 (Worker Thread)
     * @note 通常每个 `CPU` 核心创建一个 `worker` 实例，通过 `SO_REUSEPORT` 实现负载均衡。
     * @warning 构造函数会加载 `SSL` 证书和私钥，文件读取失败会抛出异常。
     * @details 管理 `IO` 上下文、连接池、分发器和接收器，是代理服务的运行实体。
     * 每个 `worker` 实例维护一个独立的 `io_context`，可以单线程运行，也可以作为多线程 `Reactor` 组的一部分。
     *
     * 核心职责：
     * @details - 组件初始化：初始化连接池、分发器、`SSL` 上下文和接收器；
     * @details - 协议注册：注册所有协议处理器到全局注册表；
     * @details - 网络监听：绑定端口并监听客户端连接；
     * @details - 连接处理：接受新连接并创建会话进行处理；
     * @details - 事件循环：运行 `io_context` 事件循环处理所有异步操作。
     *
     * 线程安全性设计：
     * @details - 每个 `worker` 实例拥有独立的 `io_context` 和资源池，不与其他 `worker` 共享状态；
     * @details - 所有异步操作在关联的 `io_context` 线程中顺序执行，无需额外同步；
     * @details - 共享的 `validator` 必须是线程安全的，因为可能被多个 `worker` 并发访问。
     *
     * 性能优化：
     * @details - 线程局部内存：使用 `thread_local_pool` 避免全局堆竞争；
     * @details - 连接复用：通过 `source` 池减少 `TCP` 握手开销；
     * @details - 无锁设计：所有组件线程封闭，无锁操作最大化性能。
     *
     * ```
     * // 典型用法：创建多个 worker 实现多核并发
     * std::vector<std::unique_ptr<ngx::agent::worker>> workers;
     * auto validator = std::make_shared<ngx::agent::validator>();
     *
     * for (int i = 0; i < std::thread::hardware_concurrency(); ++i)
     * {
     *     workers.emplace_back(std::make_unique<ngx::agent::worker>(config, validator));
     * }
     *
     * // 在每个线程中运行 worker
     * std::vector<std::thread> threads;
     * for (auto &worker : workers)
     * {
     *     threads.emplace_back([&worker]() { worker->run(); });
     * }
     * ```
     */
    class worker
    {
    public:
        /**
         * @brief 构造工作线程
         * @details 初始化所有核心组件，加载证书，绑定端口。构造过程包括：
         * @details - IO 上下文初始化：创建 `io_context` 作为异步操作执行环境；
         * @details - 资源池创建：初始化连接池和分发器，使用线程独占内存池实现无锁分配；
         * @details - SSL 配置：加载证书和私钥文件，配置 `TLS` 参数（`GREASE`、`ALPN`）；
         * @details - 协议注册：注册所有协议处理器到全局注册表；
         * @details - 网络监听：绑定端口，设置 `socket` 选项，开始监听连接；
         * @details - 路由配置：加载反向代理和正向代理路由配置。
         *
         * 内存管理：
         * 内部会自动为 `pool` 和 `distributor` 分配 线程独占 的内存池 (`thread_local_pool`)，
         * 以实现无锁的高性能内存分配。
         *
         * @param cfg 代理配置对象，包含监听端口、证书路径、路由配置等
         * @param validator_ptr 全局共享的验证器指针，必须是线程安全的
         * @throws `std::bad_alloc` 如果内存分配失败
         * @throws `abnormal::protocol` 如果 `SSL` 证书加载失败
         * @throws `boost::system::system_error` 如果端口绑定失败
         * @note 构造函数执行大量初始化操作，失败时会抛出异常，确保不启动损坏的服务。
         * @warning `SSL` 证书和私钥文件必须在构造时可用，否则会抛出 `abnormal::protocol` 异常。
         */
        explicit worker(const agent::config &cfg, std::shared_ptr<validator> validator_ptr)
            : ioc_(1),                                                                                                      // 1. 初始化 IO 上下文 (hint=1 表示单线程)
              pool_(ioc_, memory::system::thread_local_pool(), cfg.pool.max_cache_per_endpoint, cfg.pool.max_idle_seconds), // 2. 初始化连接池 (使用线程独占内存池)
              distributor_(pool_, ioc_, memory::system::thread_local_pool()),                                               // 3. 初始化路由器 (使用线程独占内存池)
              ssl_ctx_(std::make_shared<ssl::context>(ssl::context::tls)),
              acceptor_(ioc_), // 4. 初始化接收器
              config_(cfg),
              account_validator_(std::move(validator_ptr)) // 5. 注入共享验证器
        {
            const auto port = cfg.addressable.port;
            const auto &cert = cfg.certificate.cert;
            const auto &key = cfg.certificate.key;
            // -------------------------------------------------------------
            // SSL 配置部分
            // -------------------------------------------------------------
            try
            {
                if (!cert.empty() && !key.empty())
                {
                    boost::system::error_code ec;
                    ssl_ctx_->use_certificate_chain_file({cert.data(), cert.size()}, ec);
                    if (ec)
                    {
                        trace::error("ssl cert load failed: " + ec.message());
                        throw abnormal::protocol("ssl cert load failed:", ec.message());
                    }
                    ssl_ctx_->use_private_key_file({key.data(), key.size()}, ssl::context::pem);
                    if (ec)
                    {
                        trace::error("ssl key load failed: " + ec.message());
                        throw abnormal::protocol("ssl key load failed:", ec.message());
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
            catch (const abnormal::protocol &e)
            {
                trace::error(" protocol exception: {}", e.dump());
                throw;
            }
            catch (const std::exception &e)
            {
                // 记录日志或直接抛出，不要带着损坏的 context 继续跑
                trace::error("SSL init failed: {}", e.what());
                throw; // 或者 ssl_ctx_.reset(); 但后面要判空
            }

            agent::register_handlers();

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
            for (const auto &[host, ep_config] : config_.reverse_map)
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

            /**
             * @details 设置上游正向代理（可选）：
             * - 用于 `distributor::route_forward` 在直连失败时的回退（HTTP `CONNECT`）
             * - 不影响直连成功场景，默认仍优先直连
             */
            if (!config_.positive.host.empty() && config_.positive.port != 0)
            {
                distributor_.set_positive_endpoint(std::string_view(config_.positive.host), config_.positive.port);
            }
        }

        /**
         * @brief 运行工作线程
         * @details 启动 `io_context` 事件循环，阻塞当前线程直到所有任务完成或被停止。
         * 执行流程：
         * @details - 1. 调用 `accept_connection()` 开始异步接受连接；
         * @details - 2. 调用 `ioc_.run()` 启动事件循环；
         * @details - 3. 事件循环会处理所有异步操作（连接接受、数据传输、协议处理等）；
         * @details - 4. 当所有异步操作完成或 `io_context` 被停止时返回。
         *
         * 阻塞特性：
         * @details - 该方法会阻塞当前线程直到 `io_context` 停止运行；
         * @details - 可通过调用 `ioc_.stop()` 从另一个线程停止工作线程；
         * @details - 正常停止时，所有待处理的异步操作会完成后再返回。
         *
         * @throws `std::bad_alloc` 如果内存分配失败
         * @throws `std::system_error` 如果 `io_context` 运行失败
         * @note 仅使用当前调用线程作为工作线程。如果需要多线程并发，应创建多个 `worker` 实例。
         * @warning 该方法会阻塞当前线程，应在专用工作线程中调用。
         * @warning 不要在同一 `worker` 实例的多个线程中同时调用此方法。
         */
        void run()
        {
            accept_connection();
            ioc_.run();
        }

    private:
        /**
         * @brief 异步接收连接
         * @details 持续接收新的客户端连接，并为每个连接创建 `session`。这是工作线程的核心循环：
         * @details - 1. 异步接受：调用 `async_accept` 等待新连接；
         * @details - 2. 连接处理：收到连接后创建可靠传输层 (`make_reliable`)；
         * @details - 3. 会话创建：创建 `session` 对象并配置验证器；
         * @details - 4. 会话启动：调用 `session::start()` 开始协议处理；
         * @details - 5. 递归调用：处理完成后立即发起下一个 `async_accept`。
         *
         * 错误处理：
         * @details - 如果 `async_accept` 失败，记录错误并继续循环；
         * @details - 如果创建会话失败，丢弃连接但继续循环；
         * @details - 如果内存分配失败，终止接受循环。
         *
         * 递归实现：
         * @details - 该函数通过 `async_accept` 的回调函数递归调用自身，形成无限循环。
         * @details - 每次连接处理完成后，立即发起下一个接受操作，实现高并发处理。
         *
         * @note 这是一个递归的异步操作：每次处理完一个连接后，会立即发起下一个 `async_accept`。
         * @throws `std::bad_alloc` 如果内存分配失败
         * @warning 如果创建会话或启动会话失败，连接会被丢弃但循环继续，确保服务不中断。
         * @warning 该方法不直接抛出异常，错误通过 `async_accept` 的回调处理。
         */
        void accept_connection()
        {
            auto func = [this](const boost::system::error_code &ec, tcp::socket socket)
            {
                if (!ec)
                {
                    // 创建会话，把"路由器"传给它
                    auto inbound = ngx::transport::make_reliable(std::move(socket));
                    const auto session_pointer = ngx::agent::make_session(ioc_, 
                        std::move(inbound), distributor_, ssl_ctx_,memory::system::thread_local_pool());

                    const bool auth_enabled = !config_.authentication.credentials.empty() || !config_.authentication.users.empty();
                    session_pointer->set_account_validator(auth_enabled ? account_validator_.get() : nullptr);

                    // 凭据验证器
                    auto verifier_func = [this](const std::string_view credential) -> bool
                    {
                        if (config_.authentication.credentials.empty() && config_.authentication.users.empty())
                        {
                            return true;
                        }
                        return account_validator_->verify(credential);
                    };
                    // 设置凭据验证器
                    session_pointer->set_credential_verifier(verifier_func);

                    session_pointer->start();
                }
                accept_connection();
            };
            acceptor_.async_accept(func);
        }

        net::io_context ioc_;                          ///< IO 上下文，所有异步操作的执行环境
        source pool_;                                  ///< 连接池（资源仓库），管理到后端服务的连接复用
        distributor distributor_;                      ///< 路由分发器（业务大脑），决定数据转发目标
        std::shared_ptr<ssl::context> ssl_ctx_;        ///< SSL 上下文，用于 TLS 协议处理（可为空）
        tcp::acceptor acceptor_;                       ///< TCP 接收器，监听客户端连接
        config config_;                                ///< 代理配置，包含监听端口、证书路径、路由规则等
        std::shared_ptr<validator> account_validator_; ///< 账户验证器，用于用户认证和连接数配额控制
    };

}
