/**
 * @file craft.hpp
 * @brief smux 多路复用会话服务端（兼容 Mihomo/xtaci/smux v1 + sing-mux 协商）
 * @details smux::craft 是 multiplex::core 的 smux 协议实现，
 * 负责协议协商、帧循环、地址解析。帧格式为 8 字节定长帧头
 * [Version 1B][Cmd 1B][Length 2B LE][StreamID 4B LE]。
 * 数据流：协议协商 → SYN 帧 → pending_entry → PSH 帧累积数据 →
 * 数据足够时解析地址并发起连接 → 连接成功创建 duct/parcel →
 * 后续 PSH 帧由帧循环直接 co_await 写入 target，天然反压。
 */
#pragma once

#include <cstdint>
#include <span>

#include <prism/multiplex/core.hpp>
#include <prism/multiplex/config.hpp>
#include <prism/multiplex/smux/frame.hpp>
#include <prism/memory/container.hpp>

namespace psm::multiplex::smux
{
    namespace net = boost::asio;

    /**
     * @class craft
     * @brief smux 多路复用会话服务端
     * @details 继承 core，实现 smux v1 帧协议 + sing-mux 协议协商。
     */
    class craft final : public core
    {
    public:
        /**
         * @brief 构造 smux 会话
         * @param transport 已建立的传输层连接（通常是 Trojan 隧道）
         * @param router 路由器引用，用于解析地址并连接目标
         * @param cfg smux 配置参数
         * @param mr 内存资源，为空时使用默认资源
         */
        craft(channel::transport::shared_transmission transport, resolve::router &router,
              const config &cfg, memory::resource_pointer mr = {});

        ~craft() override;

        /// 发送 PSH 帧
        auto send_data(std::uint32_t stream_id, std::span<const std::byte> payload) const
            -> net::awaitable<void> override;

        /// 发送 FIN 帧（异步，不阻塞调用者）
        void send_fin(std::uint32_t stream_id) override;

        /// 获取 transport executor
        [[nodiscard]] net::any_io_executor executor() const override;

    private:
        auto run() -> net::awaitable<void> override;

        /**
         * @brief sing-mux 协议协商
         * @details 读取 sing-mux 协议头：[Version 1B][Protocol 1B]，
         * Version > 0 时额外读取 [PaddingLen 2B BE][Padding N bytes]。
         */
        auto negotiate_protocol() const -> net::awaitable<std::error_code>;

        /**
         * @brief 帧循环主协程
         * @details 循环读取帧头 + 负载，按命令类型分发到对应 handler。
         */
        auto frame_loop() -> net::awaitable<void>;

        /// 处理 SYN 帧，创建 pending_entry
        auto handle_syn(std::uint32_t stream_id) -> net::awaitable<void>;

        /// 处理 PSH 帧，三路分发
        auto handle_data(std::uint32_t stream_id, std::span<const std::byte> payload)
            -> net::awaitable<void>;

        /// 处理 FIN 帧
        void handle_fin(std::uint32_t stream_id);

        /// 从 pending 解析地址、连接目标、创建 duct/parcel
        auto activate_stream(std::uint32_t stream_id) -> net::awaitable<void>;

        /// 发送帧到客户端（通过 strand 串行化）
        auto send_frame(const frame_header &hdr, std::span<const std::byte> payload) const
            -> net::awaitable<void>;

        memory::vector<std::byte> recv_buffer_; // 帧头读取缓冲
    }; // class craft

} // namespace psm::multiplex::smux