/**
 * @file quic_gateway.hpp
 * @brief QUIC 入站网关（Hysteria2 / TUIC v5）
 * @details 绑定 UDP 端口监听 QUIC 流量：
 *          1. UDP 数据报按对端端点键控 quic::server 连接
 *          2. 新连接握手完成后，首条流执行协议认证
 *          3. 认证通过后创建协议 handler（hysteria2/tuic）
 * @note 与 TCP listener 共享端口（Windows 允许 TCP+UDP 同端口共存）
 */

#pragma once

#include <prism/settings/settings.hpp>
#include <prism/runtime/front/balancer.hpp>
#include <prism/runtime/config.hpp>
#include <prism/resource/worker.hpp>
#include <prism/net/transport/quic/server.hpp>
#include <prism/net/connection/types.hpp>
#include <prism/protocol/hysteria2/h3_server.hpp>
#include <prism/foundation/memory/container.hpp>

#include <boost/asio.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>

#include <memory>
#include <unordered_map>

namespace psm::runtime::front
{

    namespace net = boost::asio;
    using udp = net::ip::udp;

    /**
     * @class quic_gateway
     * @brief QUIC 入站网关
     * @details 独立 UDP 接收循环。首包到达时按对端端点创建
     *          quic::server，握手完成后的首条流做协议认证，
     *          认证通过后分发给 hysteria2/tuic 协议处理器。
     *          认证期间所有流数据经单泵协程串行喂入 nghttp3
     *          （Hysteria2 完整 HTTP/3），天然无并发竞态。
     */
    class quic_gateway : public std::enable_shared_from_this<quic_gateway>
    {
    public:
        /**
         * @brief 构造网关
         * @param cfg 全局配置（stealth.hysteria2 / stealth.tuic）
         * @param dispatcher 负载均衡器（选择 worker）
         * @param workers worker 资源列表
         */
        quic_gateway(const psm::settings &cfg, balancer &dispatcher,
                     psm::memory::vector<std::shared_ptr<psm::resource::worker>> workers);

        /**
         * @brief 启动 UDP 接收循环（独立线程）
         */
        void start();

        /**
         * @brief 停止网关
         */
        void stop();

        [[nodiscard]] auto io_context() noexcept -> net::io_context &
        {
            return ioc_;
        }

    private:
        /// h3 泵数据通道（cap 256，防背压饿死读协程）
        using h3_channel = net::experimental::concurrent_channel<
            void(boost::system::error_code, std::int64_t, psm::memory::vector<std::byte>, bool)>;

        struct connection_state
        {
            quic::shared_server conn;
            bool authenticated{false};
            bool auth_started{false};   ///< hysteria2 认证流已开始处理
            psm::connect::protocol_type type{psm::connect::protocol_type::unknown};
            /// 认证期间到达的流（含已读的首字节，bidi 首字节用于区分 h3/TUIC）
            psm::memory::vector<std::pair<quic::shared_stream, std::byte>> pending;
            std::shared_ptr<psm::protocol::hysteria2::h3::server> h3; ///< HTTP/3 认证会话
            std::unique_ptr<h3_channel> h3_queue;   ///< 流数据 → h3 泵
            bool h3_auth_checked{false};            ///< 认证头已完成判定
        };

        auto receive_loop() -> net::awaitable<void>;
        auto on_packet(const udp::endpoint &from, std::span<const std::byte> data)
            -> net::awaitable<void>;
        auto on_stream(connection_state &state, quic::shared_stream stream)
            -> net::awaitable<void>;
        void start_h3(connection_state &state);
        auto h3_pump(std::uint64_t key) -> net::awaitable<void>;
        auto h3_read_stream(connection_state &state, quic::shared_stream stream,
                            std::byte first, bool has_first) -> net::awaitable<void>;
        auto authenticate_tuic(connection_state &state, quic::shared_stream stream,
                               std::byte first) -> net::awaitable<void>;
        auto launch_handler(connection_state &state, quic::shared_stream stream,
                            const std::span<const std::byte> preread = {})
            -> net::awaitable<void>;
        auto launch_udp_channel(connection_state &state, quic::shared_stream stream)
            -> net::awaitable<void>;
        [[nodiscard]] static auto conn_key(const udp::endpoint &ep) noexcept -> std::uint64_t;
        [[nodiscard]] auto pick_worker(const udp::endpoint &peer)
            -> std::shared_ptr<psm::resource::worker>;

        const psm::settings &cfg_;
        balancer &dispatcher_;
        psm::memory::vector<std::shared_ptr<psm::resource::worker>> workers_;
        net::io_context ioc_;
        std::shared_ptr<udp::socket> socket_;
        std::unordered_map<std::uint64_t, connection_state> conns_;
        std::unique_ptr<std::thread> thread_;
        bool closed_{false};
    };

} // namespace psm::runtime::front
