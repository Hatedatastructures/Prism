/**
 * @file handler.hpp
 * @brief 协议处理器接口和工厂
 * @details 定义基于 transmission 的协议处理器接口，支持
 * 运行时注册和动态分发，取代传统的 switch-case 分发模式。
 * 核心组件包括 handler 协议处理器抽象基类和 registry
 * 协议注册表工厂。
 * @note 所有协议处理器应为无状态或线程安全的单例，通过
 * registry 工厂创建。
 * @warning 协议处理器不应在 process 方法之外持有传输层
 * 或资源的长期引用。
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
     * @details 所有协议处理器必须实现此接口。该接口定义
     * 了协议处理的统一抽象，支持运行时多态和动态分发。
     * @note 协议处理器应为轻量级对象，复杂的协议逻辑应
     * 委托给专门的 pipeline 函数。
     * @warning 处理器不应在 process 方法之外持有传输层
     * 或资源的长期引用。
     */
    class handler
    {
    public:
        virtual ~handler() = default;

        /**
         * @brief 处理协议连接
         * @param ctx 会话上下文，包含所有必要的资源和状态
         * @param data 预读的数据，包含协议检测时读取的初始数据
         * @return 协程等待对象
         * @throws std::bad_alloc 如果内存分配失败
         * @throws std::system_error 如果底层系统调用失败
         * @note 该方法会操作 ctx.inbound，调用后调用者不应
         * 再假设该传输层对象的所有权。
         * @warning 如果协议处理失败，应确保正确关闭所有传输层
         * 资源，避免资源泄漏。
         */
        virtual auto process(session_context &ctx, std::span<const std::byte> data)
            -> net::awaitable<void> = 0;

        /**
         * @brief 获取支持的协议类型
         * @details 返回该处理器所处理的协议类型枚举值。
         * @return 协议类型枚举值
         * @note 每个处理器应只支持一种协议类型，确保职责单一
         */
        [[nodiscard]] virtual auto type() const -> protocol::protocol_type = 0;

        /**
         * @brief 获取协议名称
         * @details 返回处理器的可读名称字符串，用于日志输出。
         * @return 协议名称字符串视图
         * @note 名称应为简短可读的字符串，如 http、socks5
         */
        [[nodiscard]] virtual auto name() const -> std::string_view = 0;
    }; // class handler

    using shared_handler = std::shared_ptr<handler>;

    /**
     * @class registry
     * @brief 协议注册表工厂模式
     * @details 支持动态注册和查找协议处理器。采用单例模式，
     * 全局共享一个注册实例。工厂模式将协议类型映射到处理器
     * 创建函数。
     * @note 协议注册应在程序启动阶段完成，避免在运行中动态
     * 注册导致的数据竞争。
     * @warning register_handler 方法非线程安全，不应在多个
     * 线程中并发调用。
     */
    class registry
    {
        std::unordered_map<protocol::protocol_type, std::function<shared_handler()>> registry_; // 协议类型到创建函数的映射表

        registry() = default;

    public:
        /**
         * @brief 获取全局注册实例
         * @return 注册表引用
         * @details 使用静态局部变量实现线程安全的懒汉单例模式
         * @note 该方法线程安全，可被多个线程同时调用
         */
        static auto instantiation() -> registry &
        {
            static registry instance;
            return instance;
        }

        /**
         * @brief 获取全局注册实例别名
         * @details 委托调用 instantiation()，提供更简洁的访问方式。
         * @return 注册表引用
         * @note 该方法线程安全，是访问注册表的标准方式
         */
        static auto global() -> registry &
        {
            return instantiation();
        }

        registry(const registry &) = delete;
        registry &operator=(const registry &) = delete;

        /**
         * @brief 注册协议处理器
         * @details 将协议类型映射到处理器创建函数，首次注册时
         * 创建单例实例并缓存。重复注册同一类型会被忽略。
         * @tparam Handler 处理器类型，必须继承自 handler 类
         * @tparam Args 处理器构造函数参数类型
         * @param type 协议类型枚举值
         * @param args 处理器构造函数参数
         * @note 注册操作应在程序启动阶段完成
         * @warning 该方法非线程安全，不应在多个线程中并发调用
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
            {
                static shared_handler instance = std::make_shared<Handler>(args...);
                return instance;
            };
        }

        /**
         * @brief 创建协议处理器
         * @details 根据协议类型查找注册表，返回对应的处理器
         * 单例实例。未注册的类型返回 nullptr。
         * @param type 协议类型枚举值
         * @return 处理器共享指针，如果未注册返回 nullptr
         * @note 该方法返回处理器单例，多次调用返回同一实例
         * @warning 如果协议未注册，返回 nullptr，调用者应检查
         * 返回值
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
         * @details 检查注册表中是否存在指定协议类型的映射。
         * @param type 协议类型枚举值
         * @return 已注册返回 true，否则返回 false
         */
        auto registered(const protocol::protocol_type type) const -> bool
        {
            return registry_.contains(type);
        }

        /**
         * @brief 获取已注册的协议类型列表
         * @details 遍历注册表收集所有已注册的协议类型枚举值。
         * @return 协议类型列表
         * @note 返回的列表是注册表的快照
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
    }; // class registry

} // namespace psm::agent::dispatch
