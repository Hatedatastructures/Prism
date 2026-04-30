/**
 * @file craft.hpp
 * @brief smux 多路复用会话服务端（兼容 Mihomo/xtaci/smux v1 + sing-mux 协商）
 * @details smux::craft 继承 multiplex::core，实现 smux v1 帧协议和 sing-mux 协议协商。
 * 帧格式为 8 字节定长帧头 [Version 1B][Cmd 1B][Length 2B LE][StreamID 4B LE]，
 * 最大帧载荷 65535 字节。协议会话生命周期：negotiate() 读取 sing-mux 协议头
 * 完成握手，frame_loop() 循环读取帧按命令分发，SYN 创建 pending_entry
 * 累积首个 PSH 的地址数据，地址完整后 activate_stream() 连接目标创建
 * duct（TCP）或 parcel（UDP），后续 PSH 帧通过 dispatch_push() 非阻塞
 * 分发到 duct/parcel。发送路径（客户端下载方向）：
 * duct::target_read_loop() 到 send_data() 到 push_frame() 到 channel_ 到
 * send_loop() 到 transport，header 与 payload 分离传递消除 serialize 的
 * payload memcpy。
 * @note 通过 core 的虚函数接口发送帧，不依赖具体协议
 */
#pragma once

#include <array>
#include <cstdint>

#include <boost/asio/experimental/concurrent_channel.hpp>

#include <prism/multiplex/core.hpp>
#include <prism/multiplex/config.hpp>
#include <prism/multiplex/smux/frame.hpp>
#include <prism/memory/container.hpp>

namespace psm::multiplex::smux
{
    namespace net = boost::asio;

    /**
     * @brief 构建 DATA (PSH) 帧字节序列
     * @param stream_id 流标识符
     * @param payload 数据负载
     * @return 完整的帧字节序列（8 字节帧头 + payload）
     * @details 帧格式：[Version 1B][Cmd=PSH 1B][Length 2B LE][StreamID 4B LE][Payload]
     */
    [[nodiscard]] auto make_data_frame(std::uint32_t stream_id,
                                       std::span<const std::byte> payload)
        -> memory::vector<std::byte>;

    /**
     * @brief 构建 SYN 帧字节序列
     * @param stream_id 流标识符
     * @return 8 字节 SYN 帧头（无 payload）
     * @details 帧格式：[Version 1B][Cmd=SYN 1B][Length=0 2B LE][StreamID 4B LE]
     */
    [[nodiscard]] auto make_syn_frame(std::uint32_t stream_id)
        -> std::array<std::byte, frame_header_size>;

    /**
     * @brief 构建 FIN 帧字节序列
     * @param stream_id 流标识符
     * @return 8 字节 FIN 帧头（无 payload）
     * @details 帧格式：[Version 1B][Cmd=FIN 1B][Length=0 2B LE][StreamID 4B LE]
     */
    [[nodiscard]] auto make_fin_frame(std::uint32_t stream_id)
        -> std::array<std::byte, frame_header_size>;

    /**
     * @struct outbound_frame
     * @brief 出站帧结构，header 与 payload 分离传递
     * @details header 为 8 字节编码后的帧头，payload 持有实际数据。
     * 两者分离传递至 send_loop，由 send_loop 分别写入 transport，
     * 消除 serialize 中将 header+payload 拼接到单一 buffer 的 memcpy 开销。
     */
    struct outbound_frame
    {
        std::array<std::byte, frame_header_size> header{}; // 编码后的帧头（8 字节）
        memory::vector<std::byte> payload;                 // 帧载荷数据（所有权转移）

        outbound_frame() = default;
        explicit outbound_frame(memory::resource_pointer mr) : payload(mr) {}
    };

    /**
     * @class craft
     * @brief smux 多路复用会话服务端
     * @details 继承 core，实现 smux v1 帧协议和 sing-mux 协议协商。
     * 是 smux 多路复用的协议层实现，负责帧的读写、解析和分发。
     * 生命周期由 core::start() 启动，通过 co_spawn 运行 run() 协程。
     */
    class craft final : public core
    {
    public:
        /**
         * @brief 构造 smux 会话
         * @details 初始化传输层、配置和发送通道，会话处于未启动状态，
         * 调用 start() 后才会进入协议主循环
         * @param transport 已建立的传输层连接（通常是 Trojan 隧道）
         * @param router 路由器引用，用于解析地址并连接目标
         * @param cfg smux 配置参数
         * @param mr PMR 内存资源，为空时使用默认资源
         */
        craft(channel::transport::shared_transmission transport, resolve::router &router,
              const multiplex::config &cfg, memory::resource_pointer mr = {});

        ~craft() override;

        /**
         * @brief 发送 PSH 帧到客户端
         * @param stream_id 目标流标识符
         * @param payload 要发送的数据（所有权转移，零拷贝传递至发送通道）
         * @details 将 payload 编码为 outbound_frame（header 与 payload 分离），
         * 推入 channel_ 发送通道。不执行 memcpy，payload 直接 move。
         * @note 方法定义在 craft.cpp 中
         */
        auto send_data(std::uint32_t stream_id, memory::vector<std::byte> payload) const
            -> net::awaitable<void> override;

        /**
         * @brief 发送 FIN 匇到客户端
         * @param stream_id 目标流标识符
         * @details 通过 co_spawn 异步发送，不阻塞调用者（通常是 duct 的 target_read_loop）。
         * @note 方法定义在 craft.cpp 中
         */
        void send_fin(std::uint32_t stream_id) override;

        /**
         * @brief 获取 transport executor
         * @details 返回传输层连接的执行器，用于 duct/parcel 协程调度
         * @return net::any_io_executor transport 的执行器
         * @note 用于 duct/parcel 协程调度
         */
        [[nodiscard]] net::any_io_executor executor() const override;

    private:
        /**
         * @brief 协议主循环（纯虚，由 core::start() 通过 co_spawn 启动）
         * @details 依次执行协议协商和帧循环。
         */
        auto run() -> net::awaitable<void> override;

        /**
         * @brief 帧循环主协程
         * @details 循环读取帧头（8 字节）+ 载荷，按命令类型分发：
         * SYN 创建 pending_entry，PSH 由 dispatch_push 非阻塞三路分发，
         * FIN 关闭对应流，NOP 忽略。读取失败或无效帧时退出循环。
         */
        auto frame_loop() -> net::awaitable<void>;

        /**
         * @brief 处理 SYN 帧，创建 pending_entry
         * @param stream_id 新建的流标识符
         * @details 检查 max_streams 限制，未超出则在 pending_ 中创建条目，
         * 等待后续 PSH 帧累积地址数据。
         */
        auto handle_syn(std::uint32_t stream_id) -> net::awaitable<void>;

        /**
         * @brief 处理 PSH 帧，非阻塞三路分发
         * @param stream_id 流标识符
         * @param payload 帧载荷数据（所有权转移）
         * @details 三路分发逻辑：
         * 1. pending 流：累积数据到 entry.buffer，数据足够时 spawn activate_stream
         * 2. 已连接 duct：co_spawn(detached) 调用 on_mux_data，不阻塞帧循环
         * 3. 活跃 parcel：co_spawn(detached) 调用 on_mux_data，不阻塞帧循环
         * duct/parcel 使用 detached 协程避免慢速 target 阻塞帧循环。
         */
        void dispatch_push(std::uint32_t stream_id, memory::vector<std::byte> payload);

        /**
         * @brief 处理 FIN 帧
         * @param stream_id 要关闭的流标识符
         * @details 按顺序检查：pending → duct（on_mux_fin 半关闭） → parcel（close 完全关闭）。
         */
        void handle_fin(std::uint32_t stream_id);

        /**
         * @brief 从 pending 解析地址、连接目标、创建 duct/parcel
         * @param stream_id 流标识符
         * @details 解析 SOCKS5 格式目标地址，区分 TCP/UDP：
         * UDP 发送成功状态后创建 parcel 并转发剩余数据，
         * TCP 通过 router 连接目标后发送状态并创建 duct 转发剩余数据。
         * 地址解析失败时发送错误状态并 FIN。
         */
        auto activate_stream(std::uint32_t stream_id) -> net::awaitable<void>;

        /**
         * @brief 将帧推送到发送通道
         * @param cmd 帧命令类型
         * @param stream_id 流标识符
         * @param payload 帧载荷（所有权转移）
         * @details 编码帧头为 8 字节数组，与 payload 组装为 outbound_frame，
         * 通过 channel_ 发送通道传递给 send_loop。header 与 payload 分离，
         * 不执行 serialize 的 payload memcpy。
         */
        auto push_frame(command cmd, std::uint32_t stream_id, memory::vector<std::byte> payload) const
            -> net::awaitable<void>;

        // 发送通道类型，容量与 config::max_streams 对齐
        using channel_type = net::experimental::concurrent_channel<void(boost::system::error_code, outbound_frame)>;
        mutable channel_type channel_; // 有界发送通道，串行化多流写入

        /**
         * @brief 发送循环协程
         * @details 从 channel_ 取出 outbound_frame，scatter-gather 写入 transport：
         * 先写 8 字节帧头，再写 payload。零拷贝。
         * 写入失败时调用 close() 关闭整个会话。
         */
        auto send_loop() -> net::awaitable<void>;

        /**
         * @brief NOP 心跳循环
         * @details 当 keepalive_interval_ms > 0 时运行，按配置间隔发送 NOP 帧，
         * 保持连接活性。定时器等待期间会话关闭则退出。
         */
        auto keepalive_loop() -> net::awaitable<void>;
    }; // class craft

} // namespace psm::multiplex::smux
