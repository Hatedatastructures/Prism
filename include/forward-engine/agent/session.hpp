/**
 * @file session.hpp
 * @brief 会话管理
 * @details 定义了会话类，负责管理单个客户端连接的生命周期、协议识别和流量转发。
 * 该类采用分层流式架构，使用 `transport::transmission` 抽象接口，支持 `TCP`、`UDP` 和协议装饰器。
 * 核心工作流：
 * 1. 连接接受：`agent::worker` 接受连接，创建 `session` 对象；
 * 2. 协议检测：预读数据，调用 `detection::detect_from_transmission()` 识别协议；
 * 3. 处理器分发：从 `registry` 获取对应的协议处理器；
 * 4. 流量转发：通过协议处理器或原始转发 (`do_splice()`) 完成数据传输；
 * 5. 资源清理：会话结束，自动关闭所有传输层连接。
 *
 * 性能特性：
 * - 零拷贝转发：使用共享缓冲区避免数据拷贝；
 * - 协程并发：双向转发使用 `||` 操作符并发执行；
 * - 内存池化：缓冲区从线程局部内存池分配，提高缓存局部性；
 * - 异步异常处理：通过 `net::co_spawn` 的完成回调处理异常。
 *
 * 使用场景：
 * - HTTP/HTTPS 代理会话；
 * - SOCKS5 代理会话；
 * - TLS/Trojan/Obscura 加密代理会话；
 * - 通用 TCP 连接转发。
 *
 * @note 会话对象应在 `agent::worker` 中创建，并立即调用 `start()` 启动处理流程。
 * @warning 会话使用共享指针管理生命周期，确保异步操作期间对象保持存活。
 * @see ngx::agent::distributor 路由分发
 * @see ngx::agent::worker IO 工作器
 * @see ngx::transport 传输层
 *
 */

#pragma once

#include <cstddef>
#include <cctype>

#include <array>
#include <vector>
#include <memory>
#include <string>
#include <utility>
#include <functional>
#include <string_view>
#include <span>

#include <boost/asio.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

#include <forward-engine/abnormal.hpp>
#include <forward-engine/memory/pool.hpp>
#include <forward-engine/agent/distributor.hpp>
#include <forward-engine/protocol/analysis.hpp>
#include <forward-engine/agent/handler.hpp>
#include <forward-engine/trace/spdlog.hpp>
#include <forward-engine/transport/transmission.hpp>
#include <forward-engine/agent/dispatcher.hpp>

namespace ngx::agent
{
    namespace net = boost::asio;
    namespace ssl = boost::asio::ssl;

    using tcp = boost::asio::ip::tcp;
    using unique_sock = transport::unique_sock;

    /**
     * @class session
     * @brief 会话管理类
     * @note `session` 对象通过 `shared_from_this()` 管理生命周期，确保异步操作期间对象保持存活。
     * 应在 `worker::accept` 中创建并立即调用 `start()` 启动处理流程。
     * @warning `diversion` 方法会转移 `inbound_` 传输层的所有权，调用后 `inbound_` 变为空。
     * @details 代表一个活跃的客户端连接。它是一个自持有 (`shared_from_this`) 的对象，
     * 这意味着只要异步操作未完成，它就不会析构。
     *
     * 核心职责：
     * @details 1. 预读 (Peek): 读取少量数据以识别协议特征。
     * @details 2. 协议识别: 区分 HTTP, SOCKS5, TLS (Trojan/Obscura)。
     * @details 3. 任务分派: 将识别后的连接移交给对应的 `handler` 处理。
     * @details 4. 流量转发: 在入站和出站传输层之间进行全双工数据转发。
     *
     * 该类不再使用模板参数，而是通过 `transport::transmission` 抽象接口操作底层传输层。
     *
     * 线程安全性设计：
     * @details - 每个 `session` 实例关联单个连接，在其生命周期内只在一个 `io_context` 中运行；
     * @details - 内部状态通过 `std::enable_shared_from_this` 共享，异步操作通过协程挂起/恢复保证顺序性；
     * @details - 成员访问在单线程协程环境中进行，无需额外的同步原语。
     *
     * ```
     * // 典型用法：在 worker 中接受连接并创建会话
     * auto session = std::make_shared<ngx::agent::session>(io_context, std::move(transmission), distributor, ssl_ctx, resource);
     * session->set_credential_verifier(credential_verifier);
     * session->start();
     * ```
     */
    class session : public std::enable_shared_from_this<session>
    {
    public:
        /**
         * @brief 构造会话
         * @details 初始化会话的所有核心组件，包括传输层、内存池和验证器引用。
         * @param io_context `IO` 上下文，会话将在该上下文中运行所有异步操作
         * @param inbound 入站传输层（客户端连接），所有权将被转移到会话对象
         * @param dist 业务分发器，用于路由转发到后端服务
         * @param ssl_ctx `SSL` 上下文 (可选)，用于 `TLS` 协议处理
         * @param resource 内存资源 (通常为线程局部池)，用于会话内部缓冲区分配
         * @throws `std::bad_alloc` 如果内存分配失败
         * @note 构造后应立即调用 `start()` 启动会话处理流程，避免资源泄漏。
         * @warning `inbound` 参数的所有权将被转移，调用者不应再使用该传输层对象。
         * @warning 确保 `io_context` 在会话生命周期内保持运行。
         */
        explicit session(net::io_context &io_context, transport::transmission_pointer inbound,
                         distributor &dist, std::shared_ptr<ssl::context> ssl_ctx, memory::resource_pointer resource);

        /**
         * @brief 析构会话
         * @details 自动关闭所有关联的传输层并释放资源。
         * 会调用 `close()` 方法确保传输层正确关闭。
         * @note 析构函数是幂等的，多次调用 `close()` 无副作用。
         * @warning 析构函数不抛出异常（`noexcept` 隐含）。
         * @warning 不要在析构期间调用其他会话方法。
         */
        ~session();

        /**
         * @brief 启动会话
         * @details 开始异步处理流程。该方法会启动协程处理连接，包括协议检测和转发。
         * 处理流程：
         * @details 1. 构造 `handler_context` 包含所有必要的运行时上下文；
         * @details 2. 创建 `distributor` 的共享指针引用；
         * @details 3. 调用 `diversion()` 进行协议识别和分流；
         * @details 4. 设置异常处理回调，确保异常时正确关闭连接。
         *
         * 异常处理：
         * @details 如果协程抛出异常，会捕获并记录日志，然后自动关闭会话。
         * @throws `std::bad_alloc` 如果内存分配失败
         * @throws `std::system_error` 如果 `net::co_spawn` 失败
         * @note 该方法只能调用一次，重复调用会导致未定义行为。
         * @warning 该方法会立即启动异步操作，确保调用前已正确配置验证器等回调。
         * @warning 该方法不是线程安全的，应在会话创建后立即调用。
         */
        void start();

        /**
         * @brief 关闭会话
         * @details 强制关闭所有关联的传输层并释放资源。会依次关闭：
         * @details - 入站传输层 (`inbound_`)
         * @details - 出站传输层 (`outbound_`)
         *
         * 关闭操作会取消所有未完成的异步操作，并释放底层 `socket` 资源。
         * @note 该函数是幂等的，多次调用无副作用。
         * @warning 关闭后会话对象不再可用，不应再调用任何其他方法。
         * @warning 该方法不抛出异常。
         */
        void close();

        /**
         * @brief 设置用户凭据验证回调
         * @details 设置用于验证用户凭据的回调函数。该函数在需要验证用户身份时被调用。
         * @param verifier 验证函数，输入用户凭据 (`std::string_view`)，返回验证结果 (`bool`)
         * @note 应在调用 `start()` 之前设置此回调，否则验证将失败。
         * @warning 回调函数应快速返回，避免阻塞转发路径。复杂的验证逻辑应异步处理。
         * @warning 该方法不抛出异常。
         */
        void set_credential_verifier(std::function<bool(std::string_view)> verifier)
        {
            this->credential_verifier_ = std::move(verifier);
        }

        /**
         * @brief 设置账户验证器
         * @details 用于限制用户连接数，防止单用户滥用。如果未设置，默认不限制连接数。
         * 验证器在每个连接建立时被调用，用于检查连接数是否超过配额。
         * @param account_validator 账户验证器指针
         * @note 应在调用 `start()` 之前设置此验证器，否则配额控制不会生效。
         * @warning 验证器必须是线程安全的，因为可能被多个会话并发访问。
         * @warning 该方法不抛出异常（标记为 `noexcept`）。
         */
        void set_account_validator(validator *account_validator) noexcept
        {
            this->account_validator_ptr_ = account_validator;
        }

    private:
        using mutable_buf = std::span<std::byte>;
        using cancellation_slot = net::cancellation_slot;
        using cancellation_signal = net::cancellation_signal;

        /**
         * @brief 协议分流
         * @details 预读部分数据，根据协议特征进行分流处理。这是会话处理的核心流程：
         * @details - 协议检测：预读前 24 字节数据，调用 `detect_from_transmission` 识别协议类型；
         * @details - 处理器获取：从全局注册表获取对应的协议处理器；
         * @details - 回退处理：如果未找到处理器，尝试使用原始处理器或原始转发；
         * @details - 协议处理：将连接和数据移交给协议处理器进行后续处理。
         *
         * 回退策略：
         * @details - 如果协议检测为 `unknown`，尝试原始转发 (`do_splice()`)；
         * @details - 如果协议类型已注册但创建处理器失败，关闭连接；
         * @details - 如果处理器处理过程中抛出异常，记录日志并关闭连接。
         *
         * @param distributor 路由分发器，用于创建到目标服务的连接
         * @param ctx 协议处理器上下文，包含 `SSL`、内存池等运行时资源
         * @throws `std::bad_alloc` 如果内存分配失败
         * @throws `std::system_error` 如果底层系统调用失败
         * @note 该方法会转移 `inbound_` 传输层的所有权给协议处理器，调用后 `inbound_` 变为空。
         * @warning 如果协议检测失败或找不到处理器，连接可能会被关闭。
         * @warning 该方法是私有方法，仅供 `start()` 方法内部调用。
         */
        auto diversion(
            std::shared_ptr<distributor> distributor,
            const handler_context &ctx) -> net::awaitable<void>;

        /**
         * @brief 全双工数据转发
         * @details 在入站和出站传输层之间进行双向数据转发。这是协议的最终回退方案。
         * 并发执行：同时启动入站到出站和出站到入站的数据转发；
         * @details - 双向转发：两个方向独立进行，互不干扰；
         * @details - 任意完成：任意一个方向的转发完成（`EOF` 或错误），即终止整个转发；
         * @details - 资源清理：转发完成后关闭两个传输层。
         *
         * 并发实现：同时启动入站到出站和出站到入站的数据转发；
         * @details - 使用 `||` 操作符同时等待两个转发协程；
         * @details - `co_await (forward_inbound_to_outbound() || forward_outbound_to_inbound())`；
         * @details - 任意协程完成即取消另一个协程。
         *
         * 性能优化：
         * @details - 共享缓冲区：使用 `buffer_` 成员变量避免每次分配；
         * @details - 零拷贝：直接传递 `span<std::byte>` 给传输层；
         * @details - 批量操作：缓冲区大小为 8192 字节，减少系统调用次数。
         *
         * @throws `std::bad_alloc` 如果内存分配失败
         * @throws `std::system_error` 如果底层系统调用失败
         * @note 这是协议的最终回退方案，当协议识别失败或没有合适的处理器时使用。
         * @warning 该方法会阻塞直到转发完成或出错，避免在转发完成前析构传输层对象。
         * @warning 该方法是私有方法，仅供 `diversion()` 方法内部调用。
         */
        auto do_splice() -> net::awaitable<void>;

        net::io_context &io_context_;              ///< `IO` 上下文，所有异步操作的执行环境
        std::shared_ptr<ssl::context> ssl_ctx_;    ///< `SSL` 上下文，用于 `TLS` 协议处理（可选）
        distributor &distributor_;                 ///< 路由分发器，用于创建到目标服务的连接
        transport::transmission_pointer inbound_;  ///< 入站传输层（客户端连接），所有权在 `diversion()` 后转移
        transport::transmission_pointer outbound_; ///< 出站传输层（服务器连接），由 `distributor` 创建

        memory::vector<std::byte> buffer_;                          ///< 共享传输缓冲区，大小为 8192 字节
        memory::frame_arena frame_arena_;                           ///< 帧内存池，用于协议处理期间的临时内存分配
        std::function<bool(std::string_view)> credential_verifier_; ///< 用户凭据验证回调函数
        validator *account_validator_ptr_{nullptr};                 ///< 账户验证器指针，用于连接数配额控制（可选）
    }; // class session

    inline session::session(net::io_context &io_context, transport::transmission_pointer inbound,
                            distributor &dist, std::shared_ptr<ssl::context> ssl_ctx, memory::resource_pointer resource)
        : io_context_(io_context), ssl_ctx_(std::move(ssl_ctx)), distributor_(dist),
          inbound_(std::move(inbound)), buffer_(resource)
    {
        buffer_.reserve(8192);
    }

    inline session::~session()
    {
        close();
    }

    inline void session::start()
    {
        trace::debug("[Session] Session started.");

        // 定义处理协程，捕获 `shared_from_this()` 确保对象在协程期间保持存活
        auto process = [self = this->shared_from_this()]() -> net::awaitable<void>
        {
            // 构造 handler_context
            handler_context ctx{
                self->io_context_,
                self->ssl_ctx_,
                self->frame_arena_,
                self->credential_verifier_,
                self->account_validator_ptr_};

            // 创建不带删除器的 shared_ptr 指向 distributor 引用
            std::shared_ptr<distributor> dist_ptr(&self->distributor_, [](distributor *) {});

            co_await self->diversion(dist_ptr, ctx);
        };
        // 定义完成回调，处理协程中的异常
        auto completion = [self = this->shared_from_this()](const std::exception_ptr &ep) noexcept
        {
            if (!ep)
            {
                return;
            }

            try
            {
                std::rethrow_exception(ep);
            }
            catch (const abnormal::exception &e)
            {
                trace::error(e.dump());
            }
            catch (const std::exception &e)
            {
                trace::error(e.what());
            }

            self->close();
        };

        net::co_spawn(io_context_, std::move(process), std::move(completion));
    }

    inline void session::close()
    {
        trace::debug("[Session] Session closing.");
        if (inbound_)
        {
            inbound_->close();
            inbound_.reset();
        }
        if (outbound_)
        {
            outbound_->close();
            outbound_.reset();
        }
    }

    inline auto session::diversion(std::shared_ptr<distributor> distributor, const handler_context &ctx)
        -> net::awaitable<void>
    {
        if (!inbound_ || !distributor)
        {
            trace::warn("[Session] diversion aborted: missing inbound transmission or distributor.");
            co_return;
        }

        // 1. 协议检测
        auto detect_result = co_await ngx::agent::detection::detect_from_transmission(*inbound_, 24);

        if (gist::failed(detect_result.ec))
        {
            trace::warn("[Session] Protocol detection failed: {}.", gist::describe(detect_result.ec));
            co_return;
        }

        // 2. 获取协议处理器
        auto handler = registry::global().create(detect_result.type);
        if (!handler)
        {
            // 回退到原始处理器
            handler = registry::global().create(protocol::protocol_type::unknown);

            if (!handler)
            {
                // 最终回退：原始转发
                co_await do_splice();
                co_return;
            }
        }

        // 3. 执行协议处理
        co_await handler->process(std::move(inbound_), distributor, ctx,
                                  std::span<const std::byte>(detect_result.pre_read_data.data(), detect_result.pre_read_size));
    }

    inline auto session::do_splice() -> net::awaitable<void>
    {
        if (!inbound_ || !outbound_)
        {
            trace::warn("[Session] splice aborted: inbound or outbound transmission missing.");
            co_return;
        }

        // 分配缓冲区（8KB）
        buffer_.resize(8192);
        const auto buffer = net::buffer(buffer_.data(), buffer_.size());

        // 将缓冲区平分为两部分
        const std::size_t half = buffer_.size() / 2;
        const auto left = mutable_buf(buffer_.data(), half);
        const auto right = mutable_buf(buffer_.data() + half, buffer_.size() - half);

        // 定义单向转发 lambda
        auto forward = [](transport::transmission &from, transport::transmission &to, mutable_buf buf) 
            -> net::awaitable<void>
        {
            std::error_code ec;
            while (true)
            {
                ec.clear();
                const std::size_t n = co_await from.async_read_some(buf, ec);
                if (ec || n == 0)
                {
                    co_return;
                }
                ec.clear();
                co_await to.async_write_some(std::span<const std::byte>(buf.data(), n), ec);
                if (ec)
                {
                    co_return;
                }
            }
        };

        using namespace boost::asio::experimental::awaitable_operators;
        trace::debug("[Session] Starting full-duplex splice.");
        co_await (forward(*inbound_, *outbound_, left) || forward(*outbound_, *inbound_, right));
        trace::debug("[Session] Splice finished.");
    }

    /**
     * @brief 创建会话对象的工厂函数
     * @details 该函数封装了 `session` 对象的创建逻辑
     * @param io_context `IO` 上下文，会话将在该上下文中运行所有异步操作
     * @param inbound 入站传输层（客户端连接），所有权将被转移到会话对象
     * @param dist 业务分发器，用于路由转发到后端
     * @param ssl_ctx `SSL` 上下文 (可选)，用于 `TLS` 协议处理
     * @param resource 内存资源 (通常为线程局部池)，用于会话
     * @return `std::shared_ptr<session>` 创建的会话对象
     * @throws `std::bad_alloc` 如果内存分配失败
     * @note 该函数是 `noexcept` 的，不抛出任何异常。
     * @warning 调用者必须确保传入的 `io_context` 在会话生命周期内保持运行。
     */
    std::shared_ptr<session> make_session(net::io_context &io_context, transport::transmission_pointer inbound, 
        distributor &dist, std::shared_ptr<ssl::context> ssl_ctx,  memory::resource_pointer resource) noexcept
    {
        return std::make_shared<session>(io_context, std::move(inbound), 
                                         dist, std::move(ssl_ctx), resource);
    }

} // namespace ngx::agent
