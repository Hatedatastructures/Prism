/**
 * @file transport.hpp
 * @brief WebSocket 帧传输装饰器
 * @details 继承 transmission：读侧解析 WS 帧（处理掩码、控制帧），
 *          写侧封装 binary 帧（服务端不掩码）。供内层协议（VLESS/
 *          Trojan）作为传输层使用。
 */

#pragma once

#include <prism/foundation/fault/code.hpp>
#include <prism/foundation/memory/container.hpp>
#include <prism/handshake/ws/codec.hpp>
#include <prism/net/transport/transmission.hpp>

#include <boost/asio.hpp>

#include <memory>

namespace psm::handshake::ws
{

    namespace net = boost::asio;

    /**
     * @class transport
     * @brief WS 帧传输装饰器
     */
    class transport final : public psm::transport::transmission
    {
    public:
        /**
         * @brief 构造 WS 传输
         * @param next_layer 底层传输层（已完成 WS 升级）
         * @param mr 内存资源
         */
        explicit transport(psm::transport::shared_transmission next_layer,
                           memory::resource_pointer mr = memory::current_resource());

        /**
         * @brief 获取执行器
         * @return 底层传输的执行器，用于协程调度
         */
        [[nodiscard]] auto executor() const -> executor_type override;

        /**
         * @brief 异步读取数据
         * @details 解析 WS 帧（处理掩码、控制帧）后返回载荷。
         * @param buffer 接收缓冲区
         * @param ec 错误码输出参数
         * @return 异步操作，返回读取字节数
         */
        [[nodiscard]] auto async_read_some(std::span<std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override;

        /**
         * @brief 异步写入数据
         * @details 封装为 binary 帧（服务端不掩码）后写入。
         * @param buffer 发送缓冲区
         * @param ec 错误码输出参数
         * @return 异步操作，返回写入字节数
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
         * @brief 获取内层传输
         * @return 底层传输指针
         */
        [[nodiscard]] auto next_layer() noexcept -> psm::transport::transmission * override
        {
            return next_layer_.get();
        }

        /**
         * @brief 获取内层传输（const 版本）
         * @return 底层传输指针
         */
        [[nodiscard]] auto next_layer() const noexcept -> const psm::transport::transmission * override
        {
            return next_layer_.get();
        }

    private:
        psm::transport::shared_transmission next_layer_; // 底层传输层（已完成 WS 升级）
        memory::resource_pointer mr_;                    // 内存资源
        memory::vector<std::byte> frame_buf_; ///< 当前帧载荷
        std::size_t frame_offset_{0};         ///< 帧内消费游标
        bool closed_{false};                  // 是否已关闭
    };

    using shared_transport = std::shared_ptr<transport>;

    /**
     * @brief 创建 WS 传输
     */
    [[nodiscard]] inline auto make_transport(psm::transport::shared_transmission next_layer,
                                             memory::resource_pointer mr = memory::current_resource())
        -> shared_transport
    {
        return std::make_shared<transport>(std::move(next_layer), mr);
    }

} // namespace psm::handshake::ws
