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

        [[nodiscard]] auto executor() const -> executor_type override;

        [[nodiscard]] auto async_read_some(std::span<std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override;

        [[nodiscard]] auto async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override;

        void close() override;

        void cancel() override;

        [[nodiscard]] auto next_layer() noexcept -> psm::transport::transmission * override
        {
            return next_layer_.get();
        }

        [[nodiscard]] auto next_layer() const noexcept -> const psm::transport::transmission * override
        {
            return next_layer_.get();
        }

    private:
        psm::transport::shared_transmission next_layer_;
        memory::resource_pointer mr_;
        memory::vector<std::byte> frame_buf_; ///< 当前帧载荷
        std::size_t frame_offset_{0};         ///< 帧内消费游标
        bool closed_{false};
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
