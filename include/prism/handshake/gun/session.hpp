/**
 * @file session.hpp
 * @brief gRPC (gun) HTTP/2 会话
 * @details 基于 nghttp2 的轻量 HTTP/2 服务端会话：
 *          1. 帧循环读取 TLS 流 → mem_recv
 *          2. 匹配 POST {path} + application/grpc 请求
 *          3. 首个匹配流建立 gun 传输（解帧/封帧）
 *          4. 响应 200 + grpc 头
 */

#pragma once

#include <prism/diagnose/context.hpp>
#include <prism/foundation/memory/container.hpp>
#include <prism/handshake/gun/config.hpp>
#include <prism/handshake/gun/transport.hpp>
#include <prism/net/transport/transmission.hpp>

#include <boost/asio.hpp>

#include <memory>
#include <memory_resource>
#include <unordered_map>

#include <nghttp2/nghttp2.h>

namespace psm::handshake::gun
{

    namespace net = boost::asio;

    /**
     * @class session
     * @brief gun HTTP/2 会话
     * @details 生命周期由 scheme 持有；流匹配成功后回调通知。
     */
    class session : public std::enable_shared_from_this<session>
    {
    public:
        /**
         * @brief 构造 gun 会话
         * @param transport TLS 传输层（已握手）
         * @param cfg gun 配置
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
         */
        [[nodiscard]] auto is_active() const noexcept -> bool
        {
            return active_.load(std::memory_order_acquire);
        }

        /**
         * @brief 等待并获取匹配的 gun 传输
         * @return 匹配流的 gun 传输（含 200 已响应），连接关闭返回 nullptr
         * @details scheme 调用此协程等待流建立。
         */
        [[nodiscard]] auto wait_transport() -> net::awaitable<shared_transport>;

    private:
        /// nghttp2 DATA 帧数据源（生命周期随流存活，防悬垂）
        struct data_source
        {
            std::shared_ptr<memory::vector<std::byte>> buf;
            std::size_t offset{0};
        };

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
         * @brief 提交 DATA 帧（数据源存入 pending_data_ 随流存活）
         * @param stream_id 目标流 ID
         * @param frame DATA 帧数据
         */
        auto submit_data_frame(std::int32_t stream_id, memory::vector<std::byte> frame)
            -> net::awaitable<void>;

        /**
         * @brief 响应 grpc 头并标记流建立
         * @param stream_id 待接受的流 ID
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
         * @brief nghttp2 DATA read_callback（读取 pending_data_ 中对应流的数据源）
         * @return 读取字节数，0 表示数据源结束
         */
        static auto read_data_source(nghttp2_session *, int32_t, uint8_t *, size_t, uint32_t *,
                                     nghttp2_data_source *, void *) -> ssize_t;

        /**
         * @brief 解帧并投递明文
         * @param payload 待处理的明文数据
         * @return false 表示非法帧/拥塞，应终止会话
         */
        auto process_data(std::span<const std::byte> payload) -> bool;

        psm::transport::shared_transmission transport_; // 底层 TLS 传输层（已握手）
        config config_;                                 // gun 配置
        memory::resource_pointer mr_;                   // 内存资源
        std::shared_ptr<diagnose::context> prefix_;     // 日志前缀上下文
        std::atomic<bool> active_{false};               // 会话是否活跃

        nghttp2_session *session_{nullptr};             // nghttp2 会话指针

        // 流匹配状态
        std::int32_t matched_stream_{-1};                   // 匹配成功的流 ID（-1 表示未匹配）
        shared_transport gun_transport_;                    // 匹配流的 gun 传输
        memory::vector<std::byte> request_path_; ///< 当前请求路径
        bool request_is_post_{false};                       // 当前请求是否为 POST
        bool request_is_grpc_{false};                       // 当前请求是否为 application/grpc
        bool stream_accepted_{false};                       // 流是否已接受（200 已响应）
        memory::vector<std::byte> frame_buf_;                                              ///< gun 帧累积缓冲
        std::pmr::unordered_map<std::int32_t, std::unique_ptr<data_source>> pending_data_; ///< DATA 数据源

        // 等待者
        net::steady_timer wait_timer_;              // 等待定时器（通知 wait_transport）
        bool transport_ready_{false};               // 匹配流传输是否已就绪
    };

    using shared_session = std::shared_ptr<session>;

    /**
     * @brief 创建 gun 会话
     */
    [[nodiscard]] inline auto make_session(psm::transport::shared_transmission transport, const config &cfg,
                                           memory::resource_pointer mr,
                                           std::shared_ptr<diagnose::context> prefix) -> shared_session
    {
        return std::make_shared<session>(std::move(transport), cfg, mr, std::move(prefix));
    }

} // namespace psm::handshake::gun
