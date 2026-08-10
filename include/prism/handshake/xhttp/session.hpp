/**
 * @file session.hpp
 * @brief XHTTP HTTP/2 会话（stream-one 模式）
 * @details 基于 nghttp2 的轻量 HTTP/2 服务端会话：
 *          1. 帧循环读取 TLS 流 → mem_recv
 *          2. 匹配 POST {path} 请求
 *          3. 提取该 stream 的双向裸流（请求体/响应体）
 *          4. 响应 200 + SSE 伪装头
 */

#pragma once

#include <prism/foundation/memory/container.hpp>
#include <prism/handshake/xhttp/config.hpp>
#include <prism/net/transport/transmission.hpp>
#include <prism/diagnose/context.hpp>

#include <nghttp2/nghttp2.h>

#include <boost/asio.hpp>

#include <memory>

namespace psm::handshake::xhttp
{

    namespace net = boost::asio;

    /**
     * @class session
     * @brief XHTTP HTTP/2 会话
     */
    class session : public std::enable_shared_from_this<session>
    {
    public:
        session(psm::transport::shared_transmission transport, const config &cfg,
                memory::resource_pointer mr, std::shared_ptr<diagnose::context> prefix);

        ~session() noexcept;

        session(const session &) = delete;
        session &operator=(const session &) = delete;

        void start();
        void close();

        [[nodiscard]] auto is_active() const noexcept -> bool
        {
            return active_.load(std::memory_order_acquire);
        }

        /**
         * @brief 等待并获取匹配流的双向传输
         * @return 匹配流的裸流传输（200 已响应），连接关闭返回 nullptr
         */
        [[nodiscard]] auto wait_transport()
            -> net::awaitable<psm::transport::shared_transmission>;

    private:
        [[nodiscard]] auto init_nghttp2() -> std::int32_t;
        auto frame_loop() -> net::awaitable<void>;
        auto send_pending() -> net::awaitable<void>;
        auto accept_stream(std::int32_t stream_id) -> std::int32_t;

        static auto on_begin_headers(nghttp2_session *, const nghttp2_frame *, void *) -> int;
        static auto on_header(nghttp2_session *, const nghttp2_frame *,
                              const uint8_t *, size_t, const uint8_t *, size_t,
                              uint8_t, void *) -> int;
        static auto on_frame_recv(nghttp2_session *, const nghttp2_frame *, void *) -> int;
        static auto on_data(nghttp2_session *, uint8_t, int32_t,
                            const uint8_t *, size_t, void *) -> int;
        static auto on_stream_close(nghttp2_session *, int32_t, uint32_t, void *) -> int;

        /// 匹配流的数据缓冲投递
        void push_data(std::span<const std::byte> data);

        /// nghttp2 DATA 数据源（生命周期绑定会话映射，防延迟读取悬垂）
        struct data_source
        {
            std::shared_ptr<memory::vector<std::byte>> buf;
            std::size_t offset{0};
        };

        /// 提交 DATA 帧（数据源存入 pending_data_ 随流存活）
        auto submit_data_frame(std::int32_t stream_id, memory::vector<std::byte> frame)
            -> net::awaitable<void>;

        /// nghttp2 DATA read_callback（读取 pending_data_ 中对应流的数据源）
        static auto read_data_source(nghttp2_session *, int32_t, uint8_t *, size_t,
                                     uint32_t *, nghttp2_data_source *, void *) -> ssize_t;

        psm::transport::shared_transmission transport_;
        config config_;
        memory::resource_pointer mr_;
        std::shared_ptr<diagnose::context> prefix_;
        std::atomic<bool> active_{false};

        nghttp2_session *session_{nullptr};

        // 流匹配状态
        std::int32_t matched_stream_{-1};
        psm::transport::shared_transmission matched_transport_;
        memory::vector<std::byte> request_path_;
        bool request_is_post_{false};
        bool stream_accepted_{false};
        memory::vector<std::byte> read_buffer_;
        std::pmr::unordered_map<std::int32_t, std::unique_ptr<data_source>> pending_data_;

        net::steady_timer wait_timer_;
        bool transport_ready_{false};
    };

    using shared_session = std::shared_ptr<session>;

    /**
     * @brief 创建 XHTTP 会话
     */
    [[nodiscard]] inline auto make_session(psm::transport::shared_transmission transport,
                                           const config &cfg,
                                           memory::resource_pointer mr,
                                           std::shared_ptr<diagnose::context> prefix)
        -> shared_session
    {
        return std::make_shared<session>(std::move(transport), cfg, mr, std::move(prefix));
    }

} // namespace psm::handshake::xhttp
