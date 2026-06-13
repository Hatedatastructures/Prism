/**
 * @file conn.hpp
 * @brief Trojan 协议中继器声明
 * @details 声明完整的 Trojan 协议中继器类，继承自 transport::transmission，
 * 提供协议握手、凭据验证和数据转发功能。Trojan 协议是一种基于 TLS 的
 * 加密代理协议，通过在应用层添加固定格式的头部来实现流量伪装和认证。
 * 该类采用装饰器设计模式，透明地增强底层传输层的功能，支持链式组合。
 * 协议流程包括凭据读取、协议头部解析、格式验证、命令检查和数据转发。
 * 所有操作基于 boost::asio::awaitable，支持异步无阻塞处理。
 * 方法实现位于 relay.cpp 中
 * @note 设计原则：严格遵循 Trojan 协议规范，确保与主流客户端兼容
 * @warning 安全考虑：必须启用凭据验证，否则协议无任何认证保护
 * @warning 加密依赖：协议本身不提供加密，依赖底层传输层提供机密性
 */
#pragma once

#include <prism/core/fault/code.hpp>
#include <prism/proto/protocol/trojan/config.hpp>
#include <prism/proto/protocol/trojan/packet.hpp>
#include <prism/proto/protocol/types.hpp>
#include <prism/net/transport/transmission.hpp>

#include <boost/asio.hpp>

#include <functional>
#include <memory>
#include <span>


namespace psm::stats::traffic { class traffic_state; }

namespace psm::protocol::trojan
{

    namespace net = boost::asio;
    using shared_transmission = psm::transport::shared_transmission;

    /**
     * @class conn
     * @brief Trojan 协议中继器
     * @details 实现完整的 Trojan 协议中继器，包装底层传输层并添加协议
     * 握手和数据处理功能。该类采用装饰器设计模式，透明地增强底层传输
     * 层的功能，支持链式组合和灵活配置。继承自 transport::transmission
     * 提供统一的传输层接口，继承自 std::enable_shared_from_this 支持安全
     * 的共享指针管理。持有 next_layer_ 的独占所有权，生命周期与对象绑定。
     * 支持命令包括 CONNECT（需 enable_tcp=true）和 UDP_ASSOCIATE（需
     * enable_udp=true），支持地址类型包括 IPv4、IPv6 和域名地址
     * @note 线程安全：单个实例非线程安全，应在同一协程或 strand 内使用
     * @warning 加密警告：本类不提供加密功能，必须与 TLS 等加密传输层组合
     * @warning 认证警告：未提供凭据验证器时，任何凭据都会通过，存在安全风险
     */
    class conn : public psm::transport::transmission, public std::enable_shared_from_this<conn>
    {
    public:
        /**
         * @brief 构造函数
         * @details 构造 Trojan 协议中继器，包装底层传输层并配置凭据验证器。
         * 构造后对象处于就绪状态，可立即开始协议握手或数据读写操作。
         * 构造函数通过 unique_ptr 获取底层传输层的所有权，调用者不应再使用原指针
         * @param next_layer 底层传输层智能指针，必须已建立连接
         * @param cfg 协议配置
         * @param credential_verifier 用户凭据验证回调函数，可选
         * @note 底层传输层必须已建立连接，否则后续操作将失败
         */
        explicit conn(shared_transmission next_layer, const config &cfg = {},
                       std::function<bool(std::string_view)> credential_verifier = nullptr);

        /**
         * @brief 获取关联的执行器
         * @return executor_type 执行器
         */
        [[nodiscard]] auto executor() const -> executor_type override;

        /**
         * @brief 异步读取数据
         * @details 透传到底层传输层的异步读取
         * @param buffer 接收缓冲区
         * @param ec 错误码输出参数
         * @return net::awaitable<std::size_t> 异步操作，完成后返回读取的字节数
         */
        [[nodiscard]] auto async_read_some(std::span<std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override;

        /**
         * @brief 异步写入数据
         * @details 透传到底层传输层的异步写入
         * @param buffer 发送缓冲区
         * @param ec 错误码输出参数
         * @return net::awaitable<std::size_t> 异步操作，完成后返回写入的字节数
         */
        [[nodiscard]] auto async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override;

        /**
         * @brief 关闭传输层
         */
        void close() override;

        /**
         * @brief 取消所有未完成的异步操作
         */
        void cancel() override;

        /**
         * @brief 执行 Trojan 协议握手
         * @details 完整的 Trojan 协议握手流程，包括凭据验证、协议头部解析
         * 和命令检查。状态机流程：首先读取 56 字节用户凭据并调用验证器检查
         * 有效性，然后读取 CRLF 分隔符，接着解析命令和地址类型，读取目标
         * 地址和端口，最后根据 config 检查命令是否允许。
         * 成功返回 request 对象，失败返回错误码
         * @return net::awaitable<std::pair<fault::code, request>> 握手结果和请求信息
         */
        [[nodiscard]] auto handshake() const
            -> net::awaitable<std::pair<fault::code, request>>;

        /**
         * @brief 获取内层传输指针（装饰器链导航）
         * @return transmission* 内层传输指针
         */
        [[nodiscard]] auto next_layer() noexcept -> psm::transport::transmission * override
        {
            return next_layer_.get();
        }

        [[nodiscard]] auto next_layer() const noexcept -> const psm::transport::transmission * override
        {
            return next_layer_.get();
        }

        /**
         * @brief 获取底层传输层引用
         * @return transport::transmission& 底层传输层引用
         */
        [[nodiscard]] auto underlying() noexcept -> psm::transport::transmission &;

        /**
         * @brief 获取底层传输层常量引用
         * @return const transport::transmission& 底层传输层常量引用
         */
        [[nodiscard]] auto underlying() const noexcept -> const psm::transport::transmission &;

        /**
         * @brief 释放底层传输层所有权
         * @details 释放后 relay 不再持有传输层，不应再调用其方法。
         * 适用于需要将底层传输层转移给其他组件的场景
         * @return transport::shared_transmission 底层传输层指针
         */
        [[nodiscard]] auto release() -> shared_transmission;

        /**
         * @brief 路由回调函数类型
         * @details 用于解析目标地址并返回 UDP 端点。
         * 参数为主机名和端口字符串，返回错误码和 UDP 端点
         */
        using route_callback = std::function<net::awaitable<std::pair<fault::code, net::ip::udp::endpoint>>(std::string_view, std::string_view)>;

        /**
         * @brief 处理 UDP_ASSOCIATE 命令
         * @details 进入 UDP over TLS 模式，从 TLS 流读取封装的 UDP 数据包，
         * 解析目标地址后通过 UDP socket 转发，并将响应封装回 TLS 流。
         * 支持空闲超时机制，在指定时间内无数据活动则自动关闭关联
         * @param route_cb 路由回调函数，用于解析目标地址
         * @return net::awaitable<fault::code> 异步操作结果
         * @note 此方法会阻塞直到连接关闭或空闲超时
         * @warning 调用前必须确保 handshake() 成功且命令为 udp_associate
         */
        [[nodiscard]] auto async_associate(route_callback route_cb) const
            -> net::awaitable<fault::code>;

        /**
         * @brief 设置流量统计状态
         * @param t 流量统计指针
         * @param p 协议类型
         */
        void set_traffic(stats::traffic::traffic_state *t, protocol::protocol_type p) noexcept
        {
            traffic_ = t;
            proto_ = p;
        }

    private:
        shared_transmission next_layer_;                 // 底层传输层，构造时转移所有权
        config config_;                                  // 协议配置
        std::function<bool(std::string_view)> verifier_; // 凭据验证回调函数
        stats::traffic::traffic_state *traffic_{nullptr};
        protocol::protocol_type proto_{protocol::protocol_type::unknown};
    };

    /**
     * @brief Trojan 中继器共享智能指针
     * @details 使用 shared_ptr 管理 conn 对象生命周期，支持协程
     * 上下文中的异步保活。通过 shared_from_this 实现安全回调
     */
    using shared_conn = std::shared_ptr<conn>;

    /**
     * @brief 创建 Trojan 中继器对象
     * @details 工厂函数，封装 std::make_shared 调用，简化对象创建
     * @param next_layer 底层传输层指针
     * @param cfg 协议配置
     * @param credential_verifier 凭据验证回调函数
     * @return shared_conn 中继器对象共享指针
     */
    [[nodiscard]] inline shared_conn make_conn(shared_transmission next_layer, const config &cfg = {},
                                   std::function<bool(std::string_view)> credential_verifier = nullptr)
    {
        return std::make_shared<conn>(std::move(next_layer), cfg, std::move(credential_verifier));
    }

}