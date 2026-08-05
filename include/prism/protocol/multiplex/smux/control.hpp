/**
 * @file control.hpp
 * @brief smux 多路复用协议会话控制（中心调度控制）
 * @details 定义 multiplex::smux::control，smux v1 协议的会话实现。
 *          继承 multiplex::multiplexer，负责 smux 协议的帧循环、
 *          帧分发与流激活，是这条 mux 连接上的"中心调度控制"：
 *          frame_loop 读取 8 字节帧头 → codec 解析语义 → 按命令分发
 *          （SYN 建 pending / PSH 推流 / FIN 半关闭 / NOP 心跳）。
 *          流激活时创建 stream（TCP 转发管道）或 datagram（UDP
 *          中继管道），UDP 数据报的跨帧重组在此层完成（协议语义），
 *          datagram 只收完整数据报。
 *          帧编码通过 smux_codec 策略完成，发送串行化由基类
 *          multiplexer 的发送通道承载。
 *          相当于 smux 协议在服务端的"翻译官 + 调度器"。
 * @note 线程安全：单个实例非线程安全，应在 transport executor 上串行使用
 * @note 生命周期：由 multiplexer::start() 启动，经 shared_from_this 保活
 */
#pragma once

#include <prism/foundation/memory/container.hpp>
#include <prism/protocol/multiplex/codec.hpp>
#include <prism/protocol/multiplex/datagram.hpp>
#include <prism/protocol/multiplex/multiplexer.hpp>
#include <prism/protocol/multiplex/smux/codec.hpp>
#include <prism/protocol/multiplex/smux/frame.hpp>

#include <cstdint>
#include <memory>


namespace psm::multiplex::smux
{

    /**
     * @class control
     * @brief smux 多路复用协议会话控制
     * @details 实现 smux v1 帧协议与 sing-mux 流语义：
     *          - run() 启动 keepalive 心跳与 frame_loop 帧循环
     *          - write_frame() 经 smux_codec 编码逻辑帧并写入传输层
     *          - dispatch_push() 三路分发：pending 累积地址、stream 投递数据、
     *            datagram 重组 UDP 数据报
     *          - activate_stream() 解析地址后创建 stream/datagram
     * @note 协议差异（帧头/命令/心跳）全部隔离在本类与 smux_codec，
     *       基类与 stream/datagram 不感知 smux 细节
     */
    class control final : public multiplexer
    {
    public:
        /**
         * @brief 构造 smux 会话
         * @param opts 基类构造参数（传输层、出站代理、配置、内存资源）
         */
        explicit control(multiplexer_options opts);

        ~control() noexcept override;

    protected:
        /**
         * @brief 协议主循环
         * @details 启动 keepalive 心跳（配置开启时），然后执行 frame_loop。
         *          退出时由基类 close() 清理。
         */
        auto run()
            -> net::awaitable<void> override;

        /**
         * @brief 编码并写入一个逻辑帧
         * @details data/fin 经 smux_codec 编码为 PSH/FIN 帧字节写入传输层；
         *          control 帧（NOP 心跳）编码为 8 字节 NOP 帧。
         *          写失败时关闭整个会话。
         */
        auto write_frame(outbound_frame frame)
            -> net::awaitable<void> override;

    private:
        /**
         * @struct udp_entry
         * @brief UDP 流重组缓冲
         * @details sing-mux 客户端可能将一个 UDP 数据报拆成多个 PSH 帧
         *          发送，需累积后按协议格式（packet_addr 或 length_prefixed）
         *          解析出完整数据报。processing 防并发处理。
         */
        struct udp_entry
        {
            memory::vector<std::byte> buffer; ///< 累积的未解析数据
            bool processing = false;          ///< 处理循环运行标志
            memory::string dest_host;         ///< length_prefixed 模式固定目标主机
            std::uint16_t dest_port = 0;      ///< length_prefixed 模式固定目标端口
            addr_mode mode{addr_mode::length_prefixed}; ///< 地址编码模式

            explicit udp_entry(memory::resource_pointer mr) : buffer(mr), dest_host(mr) {}
        };

        /**
         * @brief 帧循环主协程
         * @details 读取 8 字节帧头 + 载荷，经 smux_codec 解析后分发：
         *          syn → handle_syn，data → dispatch_push，
         *          fin → handle_fin，control（NOP）忽略。
         */
        auto frame_loop()
            -> net::awaitable<void>;

        /**
         * @brief 处理 SYN 帧，创建 pending_entry
         * @param stream_id 新建的流标识符
         */
        auto handle_syn(std::uint32_t stream_id)
            -> net::awaitable<void>;

        /**
         * @brief 处理 PSH 帧，非阻塞三路分发
         * @param stream_id 流标识符
         * @param payload 帧载荷数据（所有权转移）
         * @details pending 流累积地址数据触发激活；已连接 stream
         *          投递数据（co_spawn 防慢 target 阻塞帧循环）；
         *          datagram 流进入重组缓冲。
         */
        void dispatch_push(std::uint32_t stream_id, memory::vector<std::byte> payload);

        /**
         * @brief 处理 FIN 帧
         * @param stream_id 要关闭的流标识符
         * @details pending → 移除；stream → 半关闭；datagram → 完全关闭。
         */
        void handle_fin(std::uint32_t stream_id);

        /**
         * @brief 从 pending 解析地址、连接目标、创建 stream/datagram
         * @param stream_id 流标识符
         */
        auto activate_stream(std::uint32_t stream_id)
            -> net::awaitable<void>;

        /**
         * @brief 发送地址解析错误状态并关闭流
         * @param stream_id 流标识符
         */
        auto send_addr_err(std::uint32_t stream_id)
            -> net::awaitable<void>;

        /**
         * @brief 激活 UDP 流，创建 datagram
         * @param opts 激活参数
         */
        auto activate_udp(activate_opts opts)
            -> net::awaitable<void>;

        /**
         * @brief 激活 TCP 流，连接目标并创建 stream
         * @param opts 激活参数
         */
        auto activate_tcp(activate_opts opts)
            -> net::awaitable<void>;

        /**
         * @brief 处理单个 datagram 流的重组与发送
         * @param stream_id 流标识符
         * @param payload 新增的帧载荷
         * @details 累积到 udp_entry.buffer，按模式解析出完整数据报
         *          逐个调用 datagram.send_to。
         */
        auto process_udp(std::uint32_t stream_id, memory::vector<std::byte> payload)
            -> net::awaitable<void>;

        /**
         * @brief NOP 心跳循环
         * @details 按配置间隔发送 NOP 帧保持连接活性。
         */
        auto keepalive_loop()
            -> net::awaitable<void>;

        /**
         * @brief 构造 datagram 端点解析回调
         * @return 解析回调（host/port → endpoint），替代直接持有 outbound
         */
        [[nodiscard]] auto make_resolve() const
            -> resolve_fn;

        /**
         * @brief 构造 datagram 响应回传回调
         * @param stream_id 流标识符
         * @param mode 地址编码模式
         * @return 回传回调（编码数据报并经 egress.send 发出）
         */
        [[nodiscard]] auto make_emit(std::uint32_t stream_id, addr_mode mode)
            -> emit_fn;

        smux_codec codec_;                                ///< smux 帧编解码策略
        std::function<net::awaitable<std::pair<fault::code,
                                               net::ip::udp::endpoint>>(std::string_view, std::string_view)> router_fn_; ///< UDP 路由回调（构造时从 outbound 获取）
        memory::unordered_map<std::uint32_t, udp_entry> udp_bufs_; ///< UDP 重组缓冲表
    };

    /**
     * @brief 创建 smux 会话共享指针
     * @param opts 基类构造参数
     * @return control 的共享指针
     */
    [[nodiscard]] inline auto make_control(multiplexer_options opts)
        -> std::shared_ptr<control>
    {
        return std::make_shared<control>(std::move(opts));
    }

} // namespace psm::multiplex::smux
