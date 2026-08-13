/**
 * @file session.hpp
 * @brief AnyTLS 会话管理
 * @details 管理 AnyTLS 多路复用连接的完整生命周期。
 * recv_loop 协程持续从 TLS 传输层读取帧，根据命令类型分发给各 stream。
 * 每个 stream 通过 concurrent_channel 缓冲接收的数据。
 */
#pragma once

#include <prism/diagnose/context.hpp>
#include <prism/foundation/fault/code.hpp>
#include <prism/foundation/memory/container.hpp>
#include <prism/handshake/anytls/mux/frame.hpp>
#include <prism/handshake/anytls/padding.hpp>
#include <prism/net/transport/transmission.hpp>

#include <boost/asio.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>

#include <array>
#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <system_error>

namespace psm::handshake::anytls
{

    namespace net = boost::asio;

    /**
     * @brief write_frame 参数收敛结构体
     */
    struct frame_input
    {
        command cmd = command::waste;   // 帧命令类型
        std::uint32_t stream_id = 0;    // 目标流 ID
        std::span<const std::byte> data; // 帧载荷数据
        std::error_code &ec;             // 错误码输出
    };

    /**
     * @class anytls_session
     * @brief AnyTLS 多路复用会话
     * @details 管理 recv_loop、帧收发、stream 生命周期。
     * recv_loop 在独立协程中运行，通过 concurrent_channel
     * 将数据传递到各 stream 的异步读取端。
     */
    class anytls_session final : public std::enable_shared_from_this<anytls_session>
    {
    public:
        using channel_type = net::experimental::concurrent_channel<void(boost::system::error_code,
                                                                        memory::vector<std::uint8_t>)>;

        /**
         * @brief 设置日志前缀上下文
         * @param p 日志上下文
         */
        auto set_prefix(std::shared_ptr<diagnose::context> p) noexcept -> void
        {
            prefix_ = std::move(p);
        }

        /**
         * @brief 新 stream 回调
         * @param stream_id 流 ID
         * @param stream_transport 传输层（可用于 tunnel 转发）
         * @param preread_data 第一个 PSH 帧的数据（SOCKS 地址）
         */
        using stream_callback = std::function<void(std::uint32_t stream_id,
                                                   std::shared_ptr<transport::transmission> stream_transport,
                                                   memory::vector<std::uint8_t> preread_data)>;

        /**
         * @brief 构造 anytls_session
         * @param tls_transport TLS 传输层
         * @param padding padding 方案（可选）
         * @param on_new_stream 新 stream 回调
         */
        explicit anytls_session(transport::shared_transmission tls_transport,
                                std::shared_ptr<padding_factory> padding, stream_callback on_new_stream);

        /**
         * @brief 启动 recv_loop（在独立协程中运行）
         */
        void start();

        /**
         * @brief 等待第一个 Stream 的 cmdSettings + cmdSYN + 第一个 PSH
         * @return (error_code, (stream_id, preread_data))
         */
        [[nodiscard]] auto wait_first_stream() -> net::awaitable<
            std::pair<fault::code, std::tuple<std::uint32_t, memory::vector<std::uint8_t>>>>;

        /**
         * @brief 写 PSH 帧到指定 stream
         */
        [[nodiscard]] auto write_psh(std::uint32_t stream_id, std::span<const std::byte> data,
                                     std::error_code &ec) -> net::awaitable<std::size_t>;

        /**
         * @brief 写 FIN 帧关闭指定 stream
         */
        auto write_fin(std::uint32_t stream_id, std::error_code &ec) -> net::awaitable<void>;

        /**
         * @brief 写 SYNACK 帧（v2+）
         */
        auto write_synack(std::uint32_t stream_id, std::error_code &ec) -> net::awaitable<void>;

        /**
         * @brief 获取指定 stream 的读 channel
         */
        [[nodiscard]] auto get_stream_channel(std::uint32_t stream_id) const -> std::shared_ptr<channel_type>;

        /**
         * @brief 关闭 session
         */
        void close();

        /**
         * @brief 获取底层传输层的 executor
         */
        [[nodiscard]] auto get_transport_executor() const -> net::any_io_executor
        {
            return transport_->executor();
        }

    private:
        /**
         * @brief 接收循环协程（常驻）
         * @details 持续从 TLS 传输层读取帧，按命令类型分发处理。
         */
        auto recv_loop() -> net::awaitable<void>;
        /**
         * @brief 分发一帧到对应处理函数
         * @param hdr 帧头
         * @param payload 帧载荷
         */
        auto dispatch_frame(const frame_header &hdr, memory::vector<std::uint8_t> payload)
            -> net::awaitable<void>;
        /**
         * @brief 处理 cmdSettings 帧
         * @param payload 帧载荷
         */
        auto on_settings(memory::vector<std::uint8_t> payload) -> net::awaitable<void>;
        /**
         * @brief 处理 cmdSYN 帧（创建新流）
         * @param stream_id 流 ID
         */
        auto on_syn(std::uint32_t stream_id) -> net::awaitable<void>;
        /**
         * @brief 处理 cmdPSH 帧（数据推送）
         * @param stream_id 流 ID
         * @param payload 帧载荷
         */
        auto on_psh(std::uint32_t stream_id, memory::vector<std::uint8_t> payload) -> net::awaitable<void>;
        /**
         * @brief 处理 cmdFIN 帧（关闭流）
         * @param stream_id 流 ID
         */
        auto on_fin(std::uint32_t stream_id) -> net::awaitable<void>;
        /**
         * @brief 序列化并写入一帧（经 write_strand_ 串行化）
         * @param input 帧参数
         */
        auto write_frame(struct frame_input input) -> net::awaitable<void>;
        /**
         * @brief 发送 waste 帧（padding 填充）
         * @param pkt_num 帧序号
         * @param ec 错误码输出
         */
        auto send_waste_frame(std::uint32_t pkt_num, std::error_code &ec) -> net::awaitable<void>;
        /**
         * @brief 从传输层精确读取指定字节数
         * @param buf 接收缓冲区
         * @return 是否读取成功（EOF 或错误返回 false）
         */
        [[nodiscard]] auto read_exact(std::span<std::byte> buf) -> net::awaitable<bool>;

        transport::shared_transmission transport_;  // 底层 TLS 传输层
        stream_callback on_new_stream_;              // 新 stream 回调

        // 每个 stream 的数据 channel
        memory::unordered_map<std::uint32_t, std::shared_ptr<channel_type>> streams_;

        // 后续 stream 等待第一个 PSH（携带 SOCKS 地址）
        memory::unordered_set<std::uint32_t> pending_syns_;

        // 写入串行化（避免多个协程同时写帧）
        net::strand<net::any_io_executor> write_strand_;

        std::shared_ptr<padding_factory> padding_; // padding 填充方案
        std::uint32_t pkt_counter_{0};             // waste 帧序号计数器
        bool received_settings_{false};            // 是否已收到客户端 cmdSettings
        std::uint32_t peer_version_{1};            // 对端协议版本
        bool closed_{false};                       // 会话是否已关闭

        // 等待第一个 stream 的 promise
        bool init_resolved_{false};                         // 首流等待是否已解决
        fault::code init_error_{fault::code::success};      // 首流等待的错误码
        std::uint32_t init_id_{0};                          // 首个匹配的 stream ID
        memory::vector<std::uint8_t> init_preread_;         // 首个 stream 的预读数据（SOCKS 地址）
        net::steady_timer init_waiter_;                     // 首流等待定时器
        std::shared_ptr<diagnose::context> prefix_;         // 日志前缀上下文
    };
} // namespace psm::handshake::anytls
