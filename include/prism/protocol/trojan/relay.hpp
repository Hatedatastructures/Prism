/**
 * @file relay.hpp
 * @brief Trojan 协议中继器声明
 * @details 声明完整的 Trojan 协议中继器类，继承自 transport::transmission，
 * 提供协议握手、凭据验证和数据转发功能。Trojan 协议是一种基于 TLS 的
 * 加密代理协议，通过在应用层添加固定格式的头部来实现流量伪装和认证。
 * 该类采用装饰器设计模式，透明地增强底层传输层的功能，支持链式组合。
 * 协议流程包括凭据读取、协议头部解析、格式验证、命令检查和数据转发。
 * 所有操作基于 boost::asio::awaitable，支持异步无阻塞处理。
 * 方法实现位于 relay.cpp 中。
 *
 * @note 设计原则：严格遵循 Trojan 协议规范，确保与主流客户端兼容
 * @note 装饰器模式允许灵活组合，如 Trojan over TLS over TCP
 * @note 零拷贝设计：尽可能使用 std::span 引用原始数据，避免内存复制
 * @warning 安全考虑：必须启用凭据验证，否则协议无任何认证保护
 * @warning 加密依赖：协议本身不提供加密，依赖底层传输层提供机密性
 */

#pragma once

#include <boost/asio.hpp>
#include <prism/channel/transport/transmission.hpp>
#include <prism/protocol/common/form.hpp>
#include <prism/protocol/trojan/constants.hpp>
#include <prism/protocol/trojan/message.hpp>
#include <prism/protocol/trojan/format.hpp>
#include <prism/protocol/trojan/config.hpp>
#include <prism/fault.hpp>
#include <prism/fault/handling.hpp>
#include <memory>
#include <functional>
#include <span>

namespace psm::protocol::trojan
{
    namespace net = boost::asio;
    using shared_transmission = psm::channel::transport::shared_transmission;

    /**
     * @class relay
     * @brief Trojan 协议中继器
     * @details 实现完整的 Trojan 协议中继器，包装底层传输层并添加协议
     * 握手和数据处理功能。该类采用装饰器设计模式，透明地增强底层传输
     * 层的功能，支持链式组合和灵活配置。继承自 transport::transmission
     * 提供统一的传输层接口，继承自 std::enable_shared_from_this 支持安全
     * 的共享指针管理。持有 next_layer_ 的独占所有权，生命周期与对象绑定。
     * 支持命令包括 CONNECT（需 enable_tcp=true）和 UDP_ASSOCIATE（需
     * enable_udp=true），支持地址类型包括 IPv4、IPv6 和域名地址。
     *
     * @note 线程安全：单个实例非线程安全，应在同一协程或 strand 内使用
     * @note 生命周期：依赖底层传输层的生命周期，需确保底层传输层有效
     * @note 方法实现位于 stream.cpp 和 udp.cpp
     * @warning 加密警告：本类不提供加密功能，必须与 TLS 等加密传输层组合
     * @warning 认证警告：未提供凭据验证器时，任何凭据都会通过，存在安全风险
     */
    class relay : public psm::channel::transport::transmission, public std::enable_shared_from_this<relay>
    {
    public:
        /**
         * @brief 构造函数
         * @param next_layer 底层传输层智能指针，必须已建立连接
         * @param cfg 协议配置
         * @param credential_verifier 用户凭据验证回调函数，可选
         * @details 构造 Trojan 协议中继器，包装底层传输层并配置凭据验证器。
         * 构造后对象处于就绪状态，可立即开始协议握手或数据读写操作。
         * 构造函数通过 unique_ptr 获取底层传输层的所有权，调用者不应再使用原指针。
         * @note 方法定义在 relay.cpp 中
         * @note 底层传输层必须已建立连接，否则后续操作将失败
         */
        explicit relay(shared_transmission next_layer, const config &cfg = {},
                       std::function<bool(std::string_view)> credential_verifier = nullptr);

        /**
         * @brief 获取关联的执行器
         * @return executor_type 执行器
         * @note 方法定义在 relay.cpp 中
         */
        executor_type executor() const override;

        /**
         * @brief 异步读取数据
         * @param buffer 接收缓冲区
         * @param ec 错误码输出参数
         * @return net::awaitable<std::size_t> 异步操作，完成后返回读取的字节数
         * @note 方法定义在 relay.cpp 中
         */
        auto async_read_some(std::span<std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override;

        /**
         * @brief 异步写入数据
         * @param buffer 发送缓冲区
         * @param ec 错误码输出参数
         * @return net::awaitable<std::size_t> 异步操作，完成后返回写入的字节数
         * @note 方法定义在 relay.cpp 中
         */
        auto async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override;

        /**
         * @brief 关闭传输层
         * @note 方法定义在 relay.cpp 中
         */
        void close() override;

        /**
         * @brief 取消所有未完成的异步操作
         * @note 方法定义在 relay.cpp 中
         */
        void cancel() override;

        /**
         * @brief 执行 Trojan 协议握手
         * @return net::awaitable<std::pair<fault::code, request>> 握手结果和请求信息
         * @details 完整的 Trojan 协议握手流程，包括凭据验证、协议头部解析和命令检查。
         * 状态机流程：首先读取 56 字节用户凭据并调用验证器检查有效性，然后读取
         * CRLF 分隔符，接着解析命令和地址类型，读取目标地址和端口，最后根据
         * config 检查命令是否允许。成功返回 request 对象，失败返回错误码。
         * @note 方法定义在 relay.cpp 中
         */
        auto handshake() const -> net::awaitable<std::pair<fault::code, request>>;

        /**
         * @brief 获取底层传输层引用
         * @return transport::transmission& 底层传输层引用
         * @note 方法定义在 relay.cpp 中
         */
        psm::channel::transport::transmission &next_layer() noexcept;

        /**
         * @brief 获取底层传输层常量引用
         * @return const transport::transmission& 底层传输层常量引用
         * @note 方法定义在 relay.cpp 中
         */
        const psm::channel::transport::transmission &next_layer() const noexcept;

        /**
         * @brief 释放底层传输层所有权
         * @return transport::shared_transmission 底层传输层指针
         * @details 释放后 relay 不再持有传输层，不应再调用其方法。
         * 适用于需要将底层传输层转移给其他组件的场景。
         * @note 方法定义在 relay.cpp 中
         */
        shared_transmission release();

        /**
         * @brief 路由回调函数类型
         * @details 用于解析目标地址并返回 UDP 端点。
         * 参数为主机名和端口字符串，返回错误码和 UDP 端点。
         */
        using route_callback = std::function<net::awaitable<std::pair<fault::code, net::ip::udp::endpoint>>(std::string_view, std::string_view)>;

        /**
         * @brief 处理 UDP_ASSOCIATE 命令
         * @param route_cb 路由回调函数，用于解析目标地址
         * @return net::awaitable<fault::code> 异步操作结果
         * @details 进入 UDP over TLS 模式，从 TLS 流读取封装的 UDP 数据包，
         * 解析目标地址后通过 UDP socket 转发，并将响应封装回 TLS 流。
         * 支持空闲超时机制，在指定时间内无数据活动则自动关闭关联。
         *
         * @note 此方法会阻塞直到连接关闭或空闲超时
         * @note 方法定义在 relay.cpp 中
         * @warning 调用前必须确保 handshake() 成功且命令为 udp_associate
         */
        auto async_associate(route_callback route_cb) const -> net::awaitable<fault::code>;

    private:
        // 底层传输层，构造时通过 unique_ptr 转移所有权
        shared_transmission next_layer_;
        // 协议配置
        config config_;
        // 凭据验证回调函数
        std::function<bool(std::string_view)> verifier_;

        /**
         * @brief UDP 帧处理循环
         * @param route_cb 路由回调函数
         * @param idle_timer 空闲超时计时器
         * @return net::awaitable<void> 异步操作
         * @details 从 TLS 流读取 UDP 数据包，解析并转发到目标，
         * 然后将响应封装回 TLS 流。支持空闲超时和错误处理。
         * @note 方法定义在 relay.cpp 中
         */
        auto udp_frame_loop(route_callback &route_cb, net::steady_timer &idle_timer) const
            -> net::awaitable<void>;
    };

    /**
     * @brief Trojan 中继器共享智能指针
     * @details 使用 shared_ptr 管理 relay 对象生命周期，支持协程
     * 上下文中的异步保活。通过 shared_from_this 实现安全回调。
     */
    using shared_relay = std::shared_ptr<relay>;

    /**
     * @brief 创建 Trojan 中继器对象
     * @param next_layer 底层传输层指针
     * @param cfg 协议配置
     * @param credential_verifier 凭据验证回调函数
     * @return shared_relay 中继器对象共享指针
     * @details 工厂函数，封装 std::make_shared 调用，简化对象创建。
     */
    inline shared_relay make_relay(shared_transmission next_layer, const config &cfg = {},
                                   std::function<bool(std::string_view)> credential_verifier = nullptr)
    {
        return std::make_shared<relay>(std::move(next_layer), cfg, std::move(credential_verifier));
    }

}