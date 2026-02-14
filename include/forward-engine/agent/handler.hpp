/**
 * @file handler.hpp
 * @brief 协议处理器接口和工厂
 * @details 定义了基于 `transmission` 的协议处理器接口，支持运行时注册和动态分发，
 * 取代了传统的 `switch-case` 分发模式，提供了更灵活、可扩展的协议处理架构。
 *
 * 核心组件：
 * 1. `handler_context`：协议处理器运行时上下文，包含所有必要资源引用；
 * 2. `handler`：协议处理器抽象基类，定义统一的协议处理接口；
 * 3. `registry`：协议注册表（工厂模式），支持动态注册和处理器创建；
 * 4. `detection_result`：协议检测结果，包含协议类型和预读数据；
 * 5. `detection::detect_from_transmission()`：从传输层检测协议类型的核心函数。
 *
 * 工作流程：
 * 1. `agent::session` 接收客户端连接，包装为 `transmission` 对象；
 * 2. 调用 `detection::detect_from_transmission()` 检测协议类型；
 * 3. 通过 `registry::global().create()` 创建对应的协议处理器；
 * 4. 调用处理器的 `process()` 方法处理连接，传递 `handler_context`；
 * 5. 处理器内部调用具体的协议管线（`pipeline::http`、`pipeline::socks5` 等）。
 *
 * 设计优势：
 * - 可扩展性：新增协议只需实现 `handler` 接口并注册到 `registry`；
 * - 可维护性：统一的接口设计，避免分散的 `switch-case` 逻辑；
 * - 性能优化：预读数据重用，避免重复读取协议头部；
 * - 资源管理：通过 `handler_context` 统一管理运行时资源。
 *
 * @note 所有协议处理器应为无状态或线程安全的单例，通过 `registry` 工厂创建。
 * @warning 协议处理器不应在 `process()` 方法之外持有传输层或资源的长期引用。
 */

#pragma once

#include <forward-engine/transport/transmission.hpp>
#include <forward-engine/agent/distributor.hpp>
#include <forward-engine/protocol/analysis.hpp>
#include <forward-engine/memory/pool.hpp>
#include <forward-engine/trace/spdlog.hpp>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

#include <algorithm>
#include <array>
#include <functional>
#include <memory>
#include <unordered_map>
#include <forward-engine/gist/handling.hpp>

namespace ngx::agent
{
    namespace net = boost::asio;
    namespace ssl = net::ssl;
    class validator;

    /**
     * @struct handler_context
     * @brief 协议处理器上下文
     * @details 包含协议处理器运行所需的所有资源引用。该结构体在 `agent::session::diversion` 中构造，
     * 并传递给协议处理器进行后续处理，为协议处理提供统一的资源配置接口。
     *
     * 成员说明：
     * @details - `io_context`：全局 `IO` 上下文，所有异步操作的执行环境；
     * @details - `ssl_ctx`：`SSL` 上下文（可选），用于 `TLS` 协议处理；
     * @details - `frame_arena`：帧内存池，用于协议处理期间的临时内存分配；
     * @details - `credential_verifier`：凭据验证回调函数，用于用户身份验证；
     * @details - `account_validator_ptr`：账户验证器指针（可选），用于连接数配额控制。
     *
     * 使用流程：
     * @details - 1. `agent::session` 在 `diversion()` 方法中创建 `handler_context`；
     * @details - 2. 填充必要的运行时资源（`SSL` 上下文、内存池等）；
     * @details - 3. 传递给协议处理器的 `process()` 方法；
     * @details - 4. 处理器使用上下文中的资源进行协议处理。
     *
     * @note 该结构体在栈上分配，生命周期由调用者管理。
     * @warning 协议处理器不应存储对上下文中资源的长期引用，避免悬垂引用。
     *
     */
    struct handler_context
    {
        net::io_context &io_context;                                ///< 全局 IO 上下文，所有异步操作的执行环境
        std::shared_ptr<ssl::context> ssl_ctx;                      ///< SSL 上下文 (可选)，用于 TLS 协议处理
        memory::frame_arena &frame_arena;                           ///< 帧内存池，用于协议处理期间的临时内存分配
        std::function<bool(std::string_view)> &credential_verifier; ///< 凭据验证回调函数，用于用户身份验证
        validator *account_validator_ptr{nullptr};                  ///< 账户验证器指针，用于连接数配额控制（可选）

        /**
         * @brief 构造协议处理器上下文
         * @details 初始化所有上下文成员，通过引用绑定到外部资源。
         * @param io_ctx IO 上下文引用
         * @param ssl_ctx SSL 上下文共享指针（可空）
         * @param arena 帧内存池引用
         * @param cred_verifier 凭据验证回调函数引用
         * @param acc_validator 账户验证器指针（可空）
         * @note 所有参数都是引用或指针，构造后不应修改这些资源的所有权。
         * @warning 上下文对象的生命周期必须短于所有引用的资源，避免悬垂引用。
         */
        handler_context(net::io_context &io_ctx, std::shared_ptr<ssl::context> ssl_ctx, memory::frame_arena &arena,
                        std::function<bool(std::string_view)> &cred_verifier, validator *acc_validator = nullptr)
            : io_context(io_ctx), ssl_ctx(std::move(ssl_ctx)), frame_arena(arena), credential_verifier(cred_verifier),
              account_validator_ptr(acc_validator)
        {
        }
    };

    /**
     * @class handler
     * @brief 协议处理基类
     * @note 协议处理器应为轻量级对象，复杂的协议逻辑应委托给专门的 `pipeline` 函数。
     * @warning 处理器不应在 `process()` 方法之外持有传输层或资源的长期引用。
     * @details 所有协议处理器必须实现此接口。该接口定义了协议处理的统一抽象，
     * 支持运行时多态和动态分发，取代了传统的 `switch-case` 分发模式。
     *
     *
     * 继承要求：
     * @details 派生类必须实现以下纯虚函数：
     * @details - 1. `process()`：协议处理的核心逻辑；
     * @details - 2. `type()`：返回支持的协议类型；
     * @details - 3. `name()`：返回协议名称。
     *
     * ```
     * // 典型实现：HTTP 协议处理器
     * class http_handler : public handler
     * {
     * public:
     *     auto type() const -> protocol::protocol_type override { return protocol::protocol_type::http; }
     *     auto name() const -> std::string_view override { return "http"; }
     *
     *     auto process(transport::transmission_pointer inbound, std::shared_ptr<distributor> distributor,
     *                  const handler_context &ctx, std::span<const std::byte> data) -> net::awaitable<void> override
     *     {
     *         co_await pipeline::http(std::move(inbound), distributor, ctx, data);
     *     }
     * };
     * ```
     *
     */
    class handler
    {
    public:
        virtual ~handler() = default;

        /**
         * @brief 处理协议连接
         * @details 协议处理的核心方法，负责处理从客户端接收到的连接。该方法会：
         * @details - 1. 协议解析：解析协议头部和请求内容；
         * @details - 2. 路由决策：使用分发器确定目标服务地址；
         * @details - 3. 连接建立：创建到目标服务的出站连接；
         * @details - 4. 数据转发：在客户端和服务端之间转发数据；
         * @details - 5. 协议转换：执行必要的协议转换和适配。
         *
         * @param inbound 入站传输层（客户端连接），所有权将被转移到处理器
         * @param distributor 路由分发器，用于创建到目标服务的连接
         * @param ctx 协议处理器上下文，包含 `SSL`、内存池等运行时资源
         * @param data 预读的数据（可能为空），包含协议检测时读取的初始数据
         * @throws `std::bad_alloc` 如果内存分配失败
         * @throws `std::system_error` 如果底层系统调用失败
         * @note 该方法会转移 `inbound` 的所有权，调用后调用者不应再使用该传输层
         * @warning 如果协议处理失败，应确保正确关闭所有传输层资源，避免资源泄漏
         * @warning 该方法在协程中执行，错误通过协程传播而非异常抛出
         */
        virtual auto process(transport::transmission_pointer inbound, std::shared_ptr<distributor> distributor,
                             const handler_context &ctx, std::span<const std::byte> data)
            -> net::awaitable<void> = 0;

        /**
         * @brief 获取支持的协议类型
         * @details 返回处理器支持的协议类型枚举值。该值用于：
         * @details - 协议检测后的处理器查找；
         * @details - 日志记录和监控；
         * @details - 运行时协议统计。
         * @return protocol::protocol_type 协议类型枚举值
         * @note 每个处理器应只支持一种协议类型，确保职责单一。
         * @warning 派生类必须实现此方法，返回固定的协议类型值。
         */
        virtual auto type() const -> protocol::protocol_type = 0;

        /**
         * @brief 获取协议名称
         * @details 返回处理器支持的协议名称字符串。该名称用于：
         * @details - 日志输出和调试信息；
         * @details - 配置文件和运行时状态显示；
         * @details - 监控指标标签。
         * @return std::string_view 协议名称字符串视图
         * @note 名称应为简短、可读的字符串，如 `"http"`、`"socks5"`、`"tls"`。
         * @warning 派生类必须实现此方法，返回固定的协议名称。
         */
        virtual auto name() const -> std::string_view = 0;
    };

    using handler_pointer = std::shared_ptr<handler>;

    /**
     * @class registry
     * @brief 协议注册表（工厂模式）
     * @note 协议注册应在程序启动阶段完成，避免在运行中动态注册导致的数据竞争。
     * @warning `register_handler` 方法非线程安全，不应在多个线程中并发调用。
     * @details 支持动态注册和查找协议处理器。采用单例模式，全局共享一个注册实例。
     *
     * 工厂模式：将协议类型映射到处理器创建函数；
     * @details - 单例全局：全局唯一实例，通过 `registry::global()` 访问；
     * @details - 运行时注册：支持在运行时动态注册新的协议处理器；
     * @details - 懒汉单例：首次访问时创建，避免静态初始化顺序问题。
     *
     * 核心功能：
     * @details - 1. 协议注册：将协议类型与处理器工厂函数关联；
     * @details - 2. 处理器创建：根据协议类型创建对应的处理器实例；
     * @details - 3. 注册查询：检查协议类型是否已注册，获取已注册类型列表。
     *
     *
     * ```
     * // 典型用法：在程序启动时注册协议处理器
     * auto &factory = ngx::agent::registry::global();
     * factory.register_handler<http_handler>(protocol::protocol_type::http);
     * factory.register_handler<socks5_handler>(protocol::protocol_type::socks5);
     * factory.register_handler<tls_handler>(protocol::protocol_type::tls);
     *
     * // 在会话处理时创建处理器
     * auto handler = factory.create(detected_type);
     * if (handler)
     * {
     *     co_await handler->process(std::move(inbound), distributor, ctx, data);
     * }
     * ```
     */
    class registry
    {
        std::unordered_map<protocol::protocol_type, std::function<handler_pointer()>> registry_; ///< 协议类型到处理器工厂函数的映射表

        // 私有构造函数，确保单例
        registry() = default;

    public:
        /**
         * @brief 获取全局注册实例（单例实现）
         * @details 使用 `std::call_once` 实现线程安全的懒汉单例模式。
         * 首次调用时创建注册表实例，后续调用返回同一实例。
         * @return registry& 注册表引用
         * @throws `std::system_error` 如果 `std::call_once` 执行失败
         * @note 该方法线程安全，可被多个线程同时调用。
         */
        static auto instantiation() -> registry &;

        /**
         * @brief 获取全局注册实例（别名）
         * @details `instantiation()` 的便捷别名，提供更直观的访问方式。
         * @return registry& 注册表引用
         * @note 该方法线程安全，是访问注册表的标准方式。
         */
        static auto global() -> registry &
        {
            return instantiation();
        }

        // 禁止拷贝
        registry(const registry &) = delete;
        registry &operator=(const registry &) = delete;

        /**
         * @brief 注册协议处理器
         * @details 将协议类型与处理器工厂函数关联。注册后，可通过 `create()` 方法创建该协议的处理器实例。
         *  注册流程：
         * @details - 1. 检查协议类型是否已注册，避免重复注册；
         * @details - 2. 创建工厂函数，使用静态局部变量实现处理器单例；
         * @details - 3. 将工厂函数存储到注册表中。
         *
         * @tparam Handler 处理器类型，必须继承自 `handler` 类
         * @tparam Args 处理器构造函数参数类型
         * @param type 协议类型枚举值
         * @param args 处理器构造函数参数，会转发给处理器构造
         * @throws `std::bad_alloc` 如果内存分配失败
         * @throws `std::invalid_argument` 如果 `Handler` 不继承自 `handler`
         * @note 注册操作应在程序启动阶段完成，避免运行时动态注册导致的数据竞争。
         * @warning 该方法非线程安全，不应在多个线程中并发调用。
         */
        template <typename Handler, typename... Args>
        void register_handler(protocol::protocol_type type, Args &&...args)
        {
            if (registry_.contains(type))
            {
                return;
            }
            ngx::trace::debug("Registering handler for type {}", protocol::to_string_view(type));
            registry_[type] = [args...]() mutable
            {
                static handler_pointer instance = std::make_shared<Handler>(args...);
                return instance;
            };
        }

        /**
         * @brief 创建协议处理器
         * @details 根据协议类型创建对应的处理器实例。如果协议类型已注册，返回处理器单例；
         * 如果未注册，返回 `nullptr` 并记录警告日志。
         *  创建流程：
         * @details - 1. 在注册表中查找协议类型对应的工厂函数；
         * @details - 2. 如果找到，调用工厂函数返回处理器单例；
         * @details - 3. 如果未找到，记录警告并返回 `nullptr`。
         *
         * @param type 协议类型枚举值
         * @return handler_pointer 处理器共享指针，如果未注册返回 `nullptr`
         * @note 该方法返回处理器单例，多次调用返回同一实例。
         * @note 该方法是内联的（inline）和常量（const）的，不抛出异常。
         * @warning 如果协议未注册，返回 `nullptr`，调用者应检查返回值。
         */
        inline auto create(const protocol::protocol_type type) const -> handler_pointer
        {
            auto it = registry_.find(type);
            if (it != registry_.end())
            {
                return it->second();
            }
            ngx::trace::warn("Handler NOT found for type {}", protocol::to_string_view(type));
            return nullptr;
        }

        /**
         * @brief 判断协议是否已注册
         * @details 检查指定协议类型是否已在注册表中注册。
         * @param type 协议类型枚举值
         * @return `true` 如果已注册，否则 `false`
         * @note 该方法线程安全，可用于运行时检查协议支持情况。
         * @warning 该方法不抛出异常。
         */
        auto registered(protocol::protocol_type type) const -> bool
        {
            return registry_.contains(type);
        }

        /**
         * @brief 获取已注册的协议类型列表
         * @details 返回所有已注册协议类型的列表，用于运行时协议支持查询和监控。
         * @return std::vector<protocol::protocol_type> 协议类型列表，按注册顺序（实际为无序）
         * @throws `std::bad_alloc` 如果内存分配失败
         * @note 该方法线程安全，但返回的列表是注册表的快照，注册表后续变更不会影响已返回的列表。
         */
        auto registered_types() const -> std::vector<protocol::protocol_type>
        {
            std::vector<protocol::protocol_type> types;
            types.reserve(registry_.size());
            for (const auto &[type, _] : registry_)
            {
                types.push_back(type);
            }
            return types;
        }
    };

    /**
     * @struct detection_result
     * @brief 协议检测结果
     * @details 包含协议类型和预读数据。该结构体由 `detect_from_transmission` 函数返回，
     * 用于传递协议检测的结果和预读的初始数据。
     *
     * 设计目的：
     * @details - 1. 结果封装：统一封装协议检测的类型、数据和错误信息；
     * @details - 2. 数据复用：预读数据可被协议处理器复用，避免重复读取；
     * @details - 3. 错误处理：通过 `gist::code` 提供详细的错误信息。
     *
     * 数据流：
     * @details - 1. `detect_from_transmission` 预读数据并检测协议类型；
     * @details - 2. 将检测结果和预读数据填充到 `detection_result`；
     * @details - 3. 会话将结果传递给对应的协议处理器；
     * @details - 4. 处理器使用预读数据避免重复读取。
     *
     * 成员说明：
     * @details - 1. `type`：检测到的协议类型枚举值，失败时为 `unknown`；
     * @details - 2. `pre_read_data`：32 字节的预读数据缓冲区；
     * @details - 3. `pre_read_size`：实际预读的数据大小（0-32 字节）；
     * @details - 4. `ec`：检测过程中的错误代码，成功时为 `gist::code::success`。
     *
     * @note 预读数据的大小最多为 32 字节，足够识别大多数协议的头部特征。
     * @warning 如果检测失败，`type` 为 `unknown`，`ec` 包含错误代码。
     */
    struct detection_result
    {
        protocol::protocol_type type{protocol::protocol_type::unknown}; ///< 检测到的协议类型，如果检测失败为 `unknown`
        std::array<std::byte, 32> pre_read_data{};                      ///< 预读数据缓冲区，最大 32 字节
        std::size_t pre_read_size{0};                                   ///< 实际预读的数据大小（字节数）
        gist::code ec{gist::code::success};                             ///< 检测过程中的错误代码

        /**
         * @brief 检测是否成功
         * @details 检查协议检测是否成功。成功的条件：
         * @details - 1. 错误代码为 `gist::code::success`；
         * @details - 2. 协议类型不是 `unknown`。
         * @return `true` 如果检测成功，否则 `false`
         * @note 该方法是 `noexcept` 的，不抛出任何异常。
         * @warning 即使成功，预读数据可能为空（`pre_read_size` 为 0）。
         */
        auto success() const noexcept -> bool
        {
            return ec == gist::code::success && type != protocol::protocol_type::unknown;
        }

        /**
         * @brief 获取预读数据的字符串视图
         * @details 将预读的二进制数据转换为字符串视图，方便协议检测函数使用。
         * 转换是零拷贝的，直接引用原始缓冲区数据。
         * @return std::string_view 预读数据的字符串视图
         * @note 视图的生命周期与 `detection_result` 对象相同。
         * @note 该方法是 `noexcept` 的，不抛出任何异常。
         * @warning 不要修改返回的字符串视图指向的数据，它是原始缓冲区的只读视图。
         * @warning 返回的视图可能为空（如果 `pre_read_size` 为 0）。
         */
        auto preload_view() const noexcept -> std::string_view
        {
            return std::string_view(reinterpret_cast<const char *>(pre_read_data.data()), pre_read_size);
        }
    };

    namespace detection
    {
        /**
         * @brief 从 transmission 对象检测协议类型
         * @details 异步预读传输层数据并检测协议类型。这是协议识别的核心函数：
         * @details - 1. 异步预读：调用 `async_read_some` 读取最多 `max_peek_size` 字节数据；
         * @details - 2. 协议检测：将读取的数据转换为字符串视图，调用 `analysis::detect` 检测协议；
         * @details - 3. 结果填充：将检测结果和预读数据填充到 `detection_result`；
         * @details - 4. 错误处理：处理读取错误和 EOF 情况。
         *
         * 预读策略：
         * @details - 默认预读 24 字节，足够识别 `HTTP`、`SOCKS5` 和 `TLS` 协议头部；
         * @details - 实际读取量受传输层可用数据和缓冲区大小限制；
         * @details - 读取的数据保存在结果中，避免协议处理器重复读取。
         *
         * @param trans 传输层对象引用，必须处于已连接状态
         * @param max_peek_size 最大预读字节数（默认24），应足够识别协议特征
         * @return `detection_result` 异步检测结果
         * @throws `std::bad_alloc` 如果内存分配失败
         * @throws `std::system_error` 如果底层系统调用失败
         * @note 该函数会实际读取数据，读取的数据会传递给后续的协议处理器。
         * @warning 如果传输层已关闭或读取出错，返回的 `detection_result` 会包含错误代码。
         * @warning 该函数会修改传输层的读取位置，后续读取应从 `pre_read_data` 之后开始。
         *
         */
        inline auto detect_from_transmission(transport::transmission &trans, std::size_t max_peek_size = 24)
            -> net::awaitable<detection_result>
        {
            detection_result result;

            // 预读缓冲区
            const std::size_t peek_size = (std::min)(max_peek_size, result.pre_read_data.size());
            auto span = std::span<std::byte>(result.pre_read_data.data(), peek_size);

            // 尝试读取数据
            std::error_code sys_ec;
            std::size_t n = co_await trans.async_read_some(span, sys_ec);
            if (sys_ec)
            {
                result.ec = gist::to_code(sys_ec);
                co_return result;
            }
            if (n == 0)
            {
                result.ec = gist::code::eof;
                co_return result;
            }

            // 转换为 string_view 进行检测
            std::string_view peek_view(reinterpret_cast<const char *>(result.pre_read_data.data()), n);
            result.type = protocol::analysis::detect(peek_view);

            result.pre_read_size = n;
            result.ec = gist::code::success;

            co_return result;
        }
    } // namespace detection

} // namespace ngx::agent