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

#include <prism/diagnose/context.hpp>
#include <prism/foundation/memory/container.hpp>
#include <prism/handshake/xhttp/config.hpp>
#include <prism/net/transport/transmission.hpp>

#include <boost/asio.hpp>

#include <memory>

#include <nghttp2/nghttp2.h>

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
        /**
         * @brief 构造 XHTTP 会话
         * @param transport TLS 传输层（已握手）
         * @param cfg xhttp 配置
         * @param mr 内存资源
         * @param prefix 日志前缀
         */
        session(psm::transport::shared_transmission transport, const config &cfg, memory::resource_pointer mr,
                std::shared_ptr<diagnose::context> prefix);

        /**
         * @brief 析构会话
         * @details 销毁 nghttp2 会话，释放内部资源。
         */
        ~session() noexcept;

        session(const session &) = delete;
        session &operator=(const session &) = delete;

        /**
         * @brief 启动会话（spawn 帧循环）
         */
        void start();
        /**
         * @brief 关闭会话
         */
        void close();

        /**
         * @brief 是否活跃
         * @return 会话是否处于活跃状态
         */
        [[nodiscard]] auto is_active() const noexcept -> bool
        {
            return active_.load(std::memory_order_acquire);
        }

        /**
         * @brief 等待并获取匹配流的双向传输
         * @return 匹配流的裸流传输（200 已响应），连接关闭返回 nullptr
         */
        [[nodiscard]] auto wait_transport() -> net::awaitable<psm::transport::shared_transmission>;

    private:
        /**
         * @brief 初始化 nghttp2 会话
         * @return 0 成功，非 0 为 nghttp2 错误码
         */
        [[nodiscard]] auto init_nghttp2() -> std::int32_t;
        /**
         * @brief 帧循环协程（常驻）
         * @details 从 TLS 传输层读取数据 → mem_recv → 处理 nghttp2 事件。
         */
        auto frame_loop() -> net::awaitable<void>;
        /**
         * @brief 发送累积的 nghttp2 输出数据
         */
        auto send_pending() -> net::awaitable<void>;
        /**
         * @brief 响应 200 并标记流建立
         * @param stream_id 匹配的流 ID
         * @return 0 成功，非 0 为 nghttp2 错误码
         */
        auto accept_stream(std::int32_t stream_id) -> std::int32_t;

        // nghttp2 回调
        /**
         * @brief nghttp2 头块开始回调
         * @return 0 继续处理
         */
        static auto on_begin_headers(nghttp2_session *, const nghttp2_frame *, void *) -> int;
        /**
         * @brief nghttp2 头部字段回调
         * @return 0 继续处理
         */
        static auto on_header(nghttp2_session *, const nghttp2_frame *, const uint8_t *, size_t,
                              const uint8_t *, size_t, uint8_t, void *) -> int;
        /**
         * @brief nghttp2 帧接收完成回调
         * @return 0 继续处理
         */
        static auto on_frame_recv(nghttp2_session *, const nghttp2_frame *, void *) -> int;
        /**
         * @brief nghttp2 DATA 数据回调
         * @return 0 继续处理
         */
        static auto on_data(nghttp2_session *, uint8_t, int32_t, const uint8_t *, size_t, void *) -> int;
        /**
         * @brief nghttp2 流关闭回调
         * @return 0 继续处理
         */
        static auto on_stream_close(nghttp2_session *, int32_t, uint32_t, void *) -> int;

        /**
         * @brief 匹配流的数据缓冲投递
         * @param data 待投递的数据
         */
        void push_data(std::span<const std::byte> data);

        /// nghttp2 DATA 数据源（生命周期绑定会话映射，防延迟读取悬垂）
        struct data_source
        {
            std::shared_ptr<memory::vector<std::byte>> buf;
            std::size_t offset{0};
        };

        /**
         * @brief 提交 DATA 帧（数据源存入 pending_data_ 随流存活）
         * @param stream_id 目标流 ID
         * @param frame DATA 帧数据
         */
        auto submit_data_frame(std::int32_t stream_id, memory::vector<std::byte> frame)
            -> net::awaitable<void>;

        /**
         * @brief nghttp2 DATA read_callback（读取 pending_data_ 中对应流的数据源）
         * @return 读取字节数，0 表示数据源结束
         */
        static auto read_data_source(nghttp2_session *, int32_t, uint8_t *, size_t, uint32_t *,
                                     nghttp2_data_source *, void *) -> ssize_t;

        psm::transport::shared_transmission transport_; // 底层 TLS 传输层（已握手）
        config config_;                                 // xhttp 配置
        memory::resource_pointer mr_;                   // 内存资源
        std::shared_ptr<diagnose::context> prefix_;     // 日志前缀上下文
        net::strand<net::any_io_executor> strand_;      // 串行化 nghttp2 状态与输出
        std::atomic<bool> active_{false};               // 会话是否活跃

        nghttp2_session *session_{nullptr};             // nghttp2 会话指针

        // 流匹配状态
        std::int32_t matched_stream_{-1};                          // 匹配成功的流 ID（-1 表示未匹配）
        psm::transport::shared_transmission matched_transport_;    // 匹配流的裸流传输
        memory::vector<std::byte> request_path_;                   // 当前请求路径
        bool request_is_post_{false};                              // 当前请求是否为 POST
        bool stream_accepted_{false};                              // 流是否已接受（200 已响应）
        memory::vector<std::byte> read_buffer_;                    // 读取缓冲
        std::pmr::unordered_map<std::int32_t, std::unique_ptr<data_source>> pending_data_; // DATA 数据源

        net::steady_timer wait_timer_;              // 等待定时器（通知 wait_transport）
        bool transport_ready_{false};               // 匹配流传输是否已就绪
    };

    using shared_session = std::shared_ptr<session>;

    /**
     * @brief 创建 XHTTP 会话
     */
    [[nodiscard]] inline auto make_session(psm::transport::shared_transmission transport, const config &cfg,
                                           memory::resource_pointer mr,
                                           std::shared_ptr<diagnose::context> prefix) -> shared_session
    {
        return std::make_shared<session>(std::move(transport), cfg, mr, std::move(prefix));
    }

} // namespace psm::handshake::xhttp
