/**
 * @file conn.hpp
 * @brief VMess 协议中继器声明
 * @details 继承 transport::transmission 装饰器模式，实现 VMess 协议
 *          握手（AEAD 认证头逆推用户）、指令头解析、数据分块编解码。
 *          支持 TCP / UDP 命令；v2ray mux 命令由 handler 分发。
 */

#pragma once

#include <prism/foundation/fault/code.hpp>
#include <prism/net/connection/types.hpp>
#include <prism/net/transport/transmission.hpp>
#include <prism/protocol/common/address.hpp>
#include <prism/protocol/vmess/codec/chunk.hpp>
#include <prism/protocol/vmess/codec/header.hpp>
#include <prism/protocol/vmess/config.hpp>

#include <boost/asio.hpp>

#include <array>
#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <vector>

namespace psm::stats::traffic
{
    class traffic_state;
}

namespace psm::protocol::vmess
{

    namespace net = boost::asio;
    using shared_transmission = psm::transport::shared_transmission;

    /**
     * @struct user_key
     * @brief VMess 用户密钥项
     * @details 由账户目录枚举的 UUID 预派生 cmdKey。
     */
    struct user_key
    {
        std::array<std::uint8_t, 16> cmd_key{}; ///< 连接密钥
    };

    /**
     * @struct request
     * @brief VMess 握手结果
     */
    struct request
    {
        std::uint8_t command{0};                      ///< 命令码
        psm::protocol::common::address destination{}; ///< 目标地址
        std::uint16_t port{0};                        ///< 目标端口
    };

    /**
     * @class conn
     * @brief VMess 协议中继器
     * @details 包装底层传输层，完成 VMess 握手与数据加解密。
     *          数据流按请求 option 对称响应（chunk 层 + AEAD 层）。
     */
    class conn : public psm::transport::transmission, public std::enable_shared_from_this<conn>
    {
    public:
        /**
         * @brief 构造函数
         * @param next_layer 底层传输层（已连接）
         * @param cfg 协议配置
         * @param keys 用户密钥表（cmdKey 列表）
         */
        explicit conn(shared_transmission next_layer, const config &cfg, std::vector<user_key> keys);

        /**
         * @brief 获取关联的执行器
         * @return executor_type 执行器
         */
        [[nodiscard]] auto executor() const -> executor_type override;

        /**
         * @brief 异步读取数据
         * @details 从底层传输层读取 AEAD 加密数据并解密返回明文
         * @param buffer 接收缓冲区
         * @param ec 错误码输出参数
         * @return 异步操作，完成后返回读取的字节数
         */
        [[nodiscard]] auto async_read_some(std::span<std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override;

        /**
         * @brief 异步写入数据
         * @details 将明文数据按块加密后写入底层传输层
         * @param buffer 发送缓冲区
         * @param ec 错误码输出参数
         * @return 异步操作，完成后返回写入的字节数
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
         * @brief 执行 VMess 握手
         * @return 错误码 + 请求信息
         * @details 读首包 → 枚举用户解密认证头（CRC+时间窗校验）→
         *          解密指令头 → 校验版本/命令 → 写响应头。
         */
        [[nodiscard]] auto handshake() const -> net::awaitable<std::pair<fault::code, request>>;

        /**
         * @brief 获取内层传输指针（装饰器链导航）
         * @return transmission* 内层传输指针
         */
        [[nodiscard]] auto next_layer() noexcept -> psm::transport::transmission * override
        {
            return next_layer_.get();
        }

        /**
         * @brief 获取内层传输常量指针（装饰器链导航）
         * @return const transmission* 内层传输常量指针
         */
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
         * @return 底层传输层共享指针
         * @details 释放后不应再调用读写方法，用于将底层连接转移给其他组件管理
         */
        [[nodiscard]] auto release() -> shared_transmission;

        /// UDP 路由回调（解析目标地址 → UDP 端点）
        using route_callback = std::function<net::awaitable<std::pair<fault::code, net::ip::udp::endpoint>>(
            std::string_view, std::string_view)>;

        /**
         * @brief 处理 UDP 命令
         * @details 每个数据块即一个 UDP 数据报，固定目标地址。
         *          回包同样按块封装写回。
         * @param route_cb 路由回调
         * @return 错误码
         */
        [[nodiscard]] auto async_associate(route_callback route_cb) const -> net::awaitable<fault::code>;

        /**
         * @brief 设置流量统计状态
         * @param t 流量统计指针
         * @param p 协议类型
         */
        void set_traffic(stats::traffic::traffic_state *t, psm::connect::protocol_type p) noexcept
        {
            traffic_ = t;
            proto_ = p;
        }

    private:
        shared_transmission next_layer_;                      ///< 底层传输层
        config config_;                                       ///< 协议配置
        std::vector<user_key> keys_;                          ///< 用户密钥表
        mutable codec::request_header header_{};              ///< 解析后的指令头
        mutable std::unique_ptr<codec::read_stream> reader_;  ///< 请求数据流
        mutable std::unique_ptr<codec::write_stream> writer_; ///< 响应数据流
        stats::traffic::traffic_state *traffic_{nullptr};   ///< 流量统计指针
        psm::connect::protocol_type proto_{psm::connect::protocol_type::unknown}; ///< 协议类型
    };

    using shared_conn = std::shared_ptr<conn>;

    /**
     * @brief 创建 VMess 中继器
     * @param next_layer 底层传输层
     * @param cfg 协议配置
     * @param keys 用户密钥表
     * @return shared_conn
     */
    [[nodiscard]] inline shared_conn make_conn(shared_transmission next_layer, const config &cfg,
                                               std::vector<user_key> keys)
    {
        return std::make_shared<conn>(std::move(next_layer), cfg, std::move(keys));
    }

} // namespace psm::protocol::vmess
