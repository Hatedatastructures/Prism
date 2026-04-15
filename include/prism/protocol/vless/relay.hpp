/**
 * @file relay.hpp
 * @brief VLESS 协议中继器声明
 * @details 声明 VLESS 协议中继器类，提供协议握手和 UUID 验证功能。
 * VLESS 协议运行在 TLS 内层，通过 UUID 进行用户认证。认证逻辑
 * 通过 verifier 回调委托给 pipeline 层，与 account::directory 对接，
 * 实现与其他协议统一的连接数限制和租约管理。
 * 该类采用装饰器设计模式，透明地增强底层传输层的功能。
 * 所有操作基于 boost::asio::awaitable，支持异步无阻塞处理。
 * 方法实现位于 relay.cpp 中。
 */

#pragma once

#include <boost/asio.hpp>
#include <prism/channel/transport/transmission.hpp>
#include <prism/protocol/vless/message.hpp>
#include <prism/protocol/vless/config.hpp>
#include <prism/fault.hpp>
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
     * 并获取连接租约。
     */
    class relay : public psm::channel::transport::transmission, public std::enable_shared_from_this<relay>
    {
    public:
        /**
         * @brief 构造函数
         * @param next_layer 底层传输层智能指针
         * @param cfg VLESS 协议配置
         * @param verifier UUID 验证回调，接收 UUID 字符串返回是否认证通过。
         * 为 nullptr 时跳过认证（允许所有连接）
         */
        explicit relay(shared_transmission next_layer, const config &cfg = {},
                       std::function<bool(std::string_view)> verifier = nullptr);

        executor_type executor() const override;

        auto async_read_some(std::span<std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override;

        auto async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override;

        void close() override;
        void cancel() override;

        /**
         * @brief 执行 VLESS 协议握手
         * @return 握手结果和请求信息
         * @details 从传输层读取并解析 VLESS 请求头，通过 verifier 回调验证
         * UUID，发送响应。数据通过 preview 回放，读取即消费，不会残留。
         */
        auto handshake()
            -> net::awaitable<std::pair<fault::code, request>>;

        /// 获取底层传输层引用
        psm::channel::transport::transmission &next_layer() noexcept;
        const psm::channel::transport::transmission &next_layer() const noexcept;

        /// 释放底层传输层所有权
        shared_transmission release();

    private:
        shared_transmission next_layer_;
        config config_;
        std::function<bool(std::string_view)> verifier_;
    };

    using shared_relay = std::shared_ptr<relay>;

    /**
     * @brief 创建 VLESS 中继器
     * @param next_layer 底层传输层智能指针
     * @param cfg VLESS 协议配置
     * @param verifier UUID 验证回调，为 nullptr 时跳过认证
     */
    inline shared_relay make_relay(shared_transmission next_layer, const config &cfg = {},
                                   std::function<bool(std::string_view)> verifier = nullptr)
    {
        return std::make_shared<relay>(std::move(next_layer), cfg, std::move(verifier));
    }
} // namespace psm::protocol::vless
