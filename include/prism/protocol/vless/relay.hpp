/**
 * @file relay.hpp
 * @brief VLESS 协议中继器声明
 * @details 声明 VLESS 协议中继器类，提供协议握手和 UUID 验证功能。
 * VLESS 协议运行在 TLS 内层，通过 UUID 进行用户认证。认证逻辑
 * 通过 verifier 回调委托给 pipeline 层，与 account::directory 对接，
 * 实现与其他协议统一的连接数限制和租约管理。
 * 该类采用装饰器设计模式，透明地增强底层传输层的功能。
 * 所有操作基于 boost::asio::awaitable，支持异步无阻塞处理。
 * 方法实现位于 relay.cpp 中
 */
#pragma once

#include <boost/asio.hpp>
#include <prism/channel/transport/transmission.hpp>
#include <prism/protocol/vless/message.hpp>
#include <prism/protocol/vless/config.hpp>
#include <prism/fault/code.hpp>
#include <memory>
#include <span>
#include <functional>

namespace psm::protocol::vless
{
    namespace net = boost::asio;
    using shared_transmission = psm::channel::transport::shared_transmission;

    /**
     * @class relay
     * @brief VLESS 协议中继器
     * @details 实现 VLESS 协议的中继器，包装底层传输层并添加协议
     * 握手和 UUID 验证功能。采用装饰器设计模式，继承自
     * transport::transmission 提供统一的传输层接口。认证通过 verifier
     * 回调实现，pipeline 层传入的回调负责查询 account::directory
     * 并获取连接租约
     */
    class relay : public psm::channel::transport::transmission, public std::enable_shared_from_this<relay>
    {
    public:
        /**
         * @brief 构造函数
         * @details 构造 VLESS 协议中继器，包装底层传输层并配置 UUID 验证器
         * @param next_layer 底层传输层智能指针
         * @param cfg VLESS 协议配置
         * @param verifier UUID 验证回调，接收 UUID 字符串返回是否认证通过。
         * 为 nullptr 时跳过认证（允许所有连接）
         */
        explicit relay(shared_transmission next_layer, const config &cfg = {},
                       std::function<bool(std::string_view)> verifier = nullptr);

        /**
         * @brief 获取关联的执行器
         * @return executor_type 执行器
         */
        executor_type executor() const override;

        /**
         * @brief 异步读取数据
         * @details 透传到底层传输层的异步读取
         * @param buffer 接收缓冲区
         * @param ec 错误码输出参数
         * @return net::awaitable<std::size_t> 异步操作，完成后返回读取的字节数
         */
        auto async_read_some(std::span<std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override;

        /**
         * @brief 异步写入数据
         * @details 透传到底层传输层的异步写入
         * @param buffer 发送缓冲区
         * @param ec 错误码输出参数
         * @return net::awaitable<std::size_t> 异步操作，完成后返回写入的字节数
         */
        auto async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
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
         * @brief 执行 VLESS 协议握手
         * @details 从传输层读取并解析 VLESS 请求头，通过 verifier 回调验证
         * UUID，发送响应。数据通过 preview 回放，读取即消费，不会残留
         * @return 握手结果和请求信息
         */
        auto handshake()
            -> net::awaitable<std::pair<fault::code, request>>;

        /**
         * @brief 路由回调函数类型
         * @details 用于解析目标地址并返回 UDP 端点。
         * 参数为主机名和端口字符串，返回错误码和 UDP 端点
         */
        using route_callback = std::function<net::awaitable<std::pair<fault::code, net::ip::udp::endpoint>>(std::string_view, std::string_view)>;

        /**
         * @brief 处理 UDP 命令
         * @details 进入 UDP over TLS 模式，从 TLS 流读取封装的 UDP 数据包，
         * 解析目标地址后通过 UDP socket 转发，并将响应封装回 TLS 流。
         * 支持空闲超时机制，在指定时间内无数据活动则自动关闭关联
         * @param route_cb 路由回调函数，用于解析目标地址
         * @return net::awaitable<fault::code> 异步操作结果
         * @note 此方法会阻塞直到连接关闭或空闲超时
         * @warning 调用前必须确保 handshake() 成功且命令为 udp
         */
        auto async_associate(route_callback route_cb) const -> net::awaitable<fault::code>;

        /**
         * @brief 获取底层传输层引用
         * @return transport::transmission& 底层传输层引用
         */
        psm::channel::transport::transmission &next_layer() noexcept;

        /**
         * @brief 获取底层传输层常量引用
         * @return const transport::transmission& 底层传输层常量引用
         */
        const psm::channel::transport::transmission &next_layer() const noexcept;

        /**
         * @brief 释放底层传输层所有权
         * @details 释放后 relay 不再持有传输层，不应再调用其方法。
         * 适用于需要将底层传输层转移给其他组件的场景
         * @return transport::shared_transmission 底层传输层指针
         */
        shared_transmission release();

    private:
        shared_transmission next_layer_;                 // 底层传输层
        config config_;                                  // VLESS 协议配置
        std::function<bool(std::string_view)> verifier_; // UUID 验证回调

        /**
         * @brief UDP 帧处理循环
         * @details 从 TLS 流读取 UDP 数据包，解析并转发到目标，
         * 然后将响应封装回 TLS 流。支持空闲超时和错误处理
         * @param route_cb 路由回调函数
         * @param idle_timer 空闲超时计时器
         * @return net::awaitable<void> 异步操作
         */
        auto udp_frame_loop(route_callback &route_cb, net::steady_timer &idle_timer) const
            -> net::awaitable<void>;
    };

    using shared_relay = std::shared_ptr<relay>;

    /**
     * @brief 创建 VLESS 中继器
     * @details 工厂函数，封装 std::make_shared 调用，简化对象创建
     * @param next_layer 底层传输层智能指针
     * @param cfg VLESS 协议配置
     * @param verifier UUID 验证回调，为 nullptr 时跳过认证
     * @return shared_relay 中继器共享指针
     */
    inline shared_relay make_relay(shared_transmission next_layer, const config &cfg = {},
                                   std::function<bool(std::string_view)> verifier = nullptr)
    {
        return std::make_shared<relay>(std::move(next_layer), cfg, std::move(verifier));
    }
} // namespace psm::protocol::vless
