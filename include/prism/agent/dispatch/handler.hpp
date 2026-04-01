/**
 * @file handler.hpp
 * @brief 协议处理器接口和工厂
 * @details 定义了基于 transmission 的协议处理器接口，支持运行时注册和动态分发，
 * 取代了传统的 switch-case 分发模式，提供了更灵活、可扩展的协议处理架构。
 * 核心组件包括 handler 协议处理器抽象基类，定义统一的协议处理接口。registry
 * 协议注册表工厂模式，支持动态注册和处理器创建。工作流程为 session 接收
 * 客户端连接，包装为 transmission 对象。调用 protocol::probe 检测
 * 协议类型。通过 registry::global().create 创建对应的协议处理器。调用处理器
 * 的 process 方法处理连接，传递 session_context。处理器内部调用具体的协议
 * 管道如 pipeline::http、pipeline::socks5 等。设计优势包括可扩展性，新增
 * 协议只需实现 handler 接口并注册到 registry。可维护性，统一的接口设计，
 * 避免分散的 switch-case 逻辑。性能优化，预读数据重用，避免重复读取协议
 * 头部。资源管理，通过 session_context 统一管理运行时资源。
 * @note 所有协议处理器应为无状态或线程安全的单例，通过 registry 工厂创建。
 * @warning 协议处理器不应在 process 方法之外持有传输层或资源的长期引用。
 */

#pragma once

#include <prism/agent/context.hpp>
#include <prism/protocol/analysis.hpp>
#include <prism/trace/spdlog.hpp>

#include <boost/asio.hpp>
#include <functional>
#include <memory>
#include <unordered_map>
#include <vector>

namespace psm::agent::dispatch
{
    namespace net = boost::asio;

    /**
     * @class handler
     * @brief 协议处理基类
     * @note 协议处理器应为轻量级对象，复杂的协议逻辑应委托给专门的 pipeline 函数。
     * @warning 处理器不应在 process 方法之外持有传输层或资源的长期引用。
     * @details 所有协议处理器必须实现此接口。该接口定义了协议处理的统一抽象，
     * 支持运行时多态和动态分发，取代了传统的 switch-case 分发模式。继承要求
     * 方面，派生类必须实现以下纯虚函数。process 协议处理的核心逻辑。type 返回
     * 支持的协议类型。name 返回协议名称。
     */
    class handler
    {
    public:
        virtual ~handler() = default;

        /**
         * @brief 处理协议连接
         * @details 协议处理的核心方法，负责处理从客户端接收到的连接。该方法会
         * 执行协议解析，解析协议头部和请求内容。路由决策，使用分发器确定目标
         * 服务地址。连接建立，创建到目标服务的出站连接。数据转发，在客户端和
         * 服务端之间转发数据。协议转换，执行必要的协议转换和适配。
         * @param ctx 会话上下文，包含所有必要的资源和状态如传输层、分发器等
         * @param data 预读的数据可能为空，包含协议检测时读取的初始数据
         * @throws std::bad_alloc 如果内存分配失败
         * @throws std::system_error 如果底层系统调用失败
         * @note 该方法会操作 ctx.inbound，调用后调用者不应再假设该传输层对象的所有权。
         * @warning 如果协议处理失败，应确保正确关闭所有传输层资源，避免资源泄漏
         * @warning 该方法在协程中执行，错误通过协程传播而非异常抛出
         */
        virtual auto process(session_context &ctx, std::span<const std::byte> data)
            -> net::awaitable<void> = 0;

        /**
         * @brief 获取支持的协议类型
         * @details 返回处理器支持的协议类型枚举值。该值用于协议检测后的处理器查找。
         * 日志记录和监控。运行时协议统计。
         * @return protocol::protocol_type 协议类型枚举值
         * @note 每个处理器应只支持一种协议类型，确保职责单一。
         * @warning 派生类必须实现此方法，返回固定的协议类型值。
         */
        [[nodiscard]] virtual auto type() const -> protocol::protocol_type = 0;

        /**
         * @brief 获取协议名称
         * @details 返回处理器支持的协议名称字符串。该名称用于日志输出和调试信息。
         * 配置文件和运行时状态显示。监控指标标签。
         * @return std::string_view 协议名称字符串视图
         * @note 名称应为简短、可读的字符串，如 http、socks5、tls。
         * @warning 派生类必须实现此方法，返回固定的协议名称。
         */
        [[nodiscard]] virtual auto name() const -> std::string_view = 0;
    };

    using shared_handler = std::shared_ptr<handler>;

    /**
     * @class registry
     * @brief 协议注册表工厂模式
     * @note 协议注册应在程序启动阶段完成，避免在运行中动态注册导致的数据竞争。
     * @warning register_handler 方法非线程安全，不应在多个线程中并发调用。
     * @details 支持动态注册和查找协议处理器。采用单例模式，全局共享一个注册实例。
     * 工厂模式将协议类型映射到处理器创建函数。单例全局，全局唯一实例，通过
     * registry::global 访问。运行时注册，支持在运行时动态注册新的协议处理器。
     * 懒汉单例，首次访问时创建，避免静态初始化顺序问题。核心功能包括协议注册，
     * 将协议类型与处理器工厂函数关联。处理器创建，根据协议类型创建对应的处理器
     * 实例。注册查询，检查协议类型是否已注册，获取已注册类型列表。
     */
    class registry
    {
        std::unordered_map<protocol::protocol_type, std::function<shared_handler()>> registry_;

        registry() = default;

    public:
        /**
         * @brief 获取全局注册实例单例实现
         * @details 使用 std::call_once 实现线程安全的懒汉单例模式。首次调用时创建
         * 注册表实例，后续调用返回同一实例。
         * @return registry& 注册表引用
         * @throws std::system_error 如果 std::call_once 执行失败
         * @note 该方法线程安全，可被多个线程同时调用。
         */
        static auto instantiation() -> registry &
        {
            static registry instance;
            return instance;
        }

        /**
         * @brief 获取全局注册实例别名
         * @details instantiation 的便捷别名，提供更直观的访问方式。
         * @return registry& 注册表引用
         * @note 该方法线程安全，是访问注册表的标准方式。
         */
        static auto global() -> registry &
        {
            return instantiation();
        }

        registry(const registry &) = delete;
        registry &operator=(const registry &) = delete;

        /**
         * @brief 注册协议处理器
         * @details 将协议类型与处理器工厂函数关联。注册后，可通过 create 方法创建
         * 该协议的处理器实例。注册流程为检查协议类型是否已注册，避免重复注册。
         * 创建工厂函数，使用静态局部变量实现处理器单例。将工厂函数存储到注册表中。
         * @tparam Handler 处理器类型，必须继承自 handler 类
         * @tparam Args 处理器构造函数参数类型
         * @param type 协议类型枚举值
         * @param args 处理器构造函数参数，会转发给处理器构造
         * @throws std::bad_alloc 如果内存分配失败
         * @throws std::invalid_argument 如果 Handler 不继承自 handler
         * @note 注册操作应在程序启动阶段完成，避免运行时动态注册导致的数据竞争。
         * @warning 该方法非线程安全，不应在多个线程中并发调用。
         */
        template <typename Handler, typename... Args>
        void register_handler(const protocol::protocol_type type, Args &&...args)
        {
            if (registry_.contains(type))
            {
                return;
            }
            trace::debug("Registering handler for type {}", protocol::to_string_view(type));
            registry_[type] = [args...]() mutable
            {   // 通过 lambda 表达式创建工厂函数，确保线程安全和单例行为
                static shared_handler instance = std::make_shared<Handler>(args...);
                return instance;
            };
        }

        /**
         * @brief 创建协议处理器
         * @details 根据协议类型创建对应的处理器实例。如果协议类型已注册，返回处理器
         * 单例。如果未注册，返回 nullptr 并记录警告日志。创建流程为在注册表中查找
         * 协议类型对应的工厂函数。如果找到，调用工厂函数返回处理器单例。如果未找到，
         * 记录警告并返回 nullptr。
         * @param type 协议类型枚举值
         * @return shared_handler 处理器共享指针，如果未注册返回 nullptr
         * @note 该方法返回处理器单例，多次调用返回同一实例。
         * @note 该方法是内联的和常量的，不抛出异常。
         * @warning 如果协议未注册，返回 nullptr，调用者应检查返回值。
         */
        auto create(const protocol::protocol_type type) const -> shared_handler
        {
            if (const auto it = registry_.find(type); it != registry_.end())
            {
                return it->second();
            }
            trace::warn("Handler NOT found for type {}", protocol::to_string_view(type));
            return nullptr;
        }

        /**
         * @brief 判断协议是否已注册
         * @details 检查指定协议类型是否已在注册表中注册。
         * @param type 协议类型枚举值
         * @return true 如果已注册，否则 false
         * @note 该方法线程安全，可用于运行时检查协议支持情况。
         * @warning 该方法不抛出异常。
         */
        auto registered(const protocol::protocol_type type) const -> bool
        {
            return registry_.contains(type);
        }

        /**
         * @brief 获取已注册的协议类型列表
         * @details 返回所有已注册协议类型的列表，用于运行时协议支持查询和监控。
         * @return std::vector<protocol::protocol_type> 协议类型列表，按注册顺序实际为无序
         * @throws std::bad_alloc 如果内存分配失败
         * @note 该方法线程安全，但返回的列表是注册表的快照，注册表后续变更不会影响已返回的列表。
         */
        auto registered_types() const -> std::vector<protocol::protocol_type>
        {
            std::vector<protocol::protocol_type> types;
            types.reserve(registry_.size());
            for (const auto &type : registry_ | std::views::keys)
            {
                types.push_back(type);
            }
            return types;
        }
    };

} // namespace psm::agent::dispatch
