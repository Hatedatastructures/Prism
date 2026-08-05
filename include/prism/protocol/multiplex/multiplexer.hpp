/**
 * @file multiplexer.hpp
 * @brief 多路复用会话基类（通用会话层）
 * @details 定义 multiplex::multiplexer，所有多路复用协议（smux/yamux/h2mux）
 *          共享的会话骨架。负责四类公共职责：
 *          1. 发送串行化：有界并发通道 + send_loop 单消费者，多流写入
 *             不交错，通道满时提供背压
 *          2. 流注册表：pending（等待地址解析）、streams（TCP 流管道）、
 *             datagrams（UDP 数据报管道）三张映射 + 流数量上限
 *          3. 生命周期：start() 启动帧循环，close() 幂等关闭并清理全部流
 *          4. 流量统计与日志前缀：set_traffic/set_prefix/accumulate_traffic
 *          同时实现 egress 接口，作为 stream/datagram 的数据出口。
 *          协议差异（帧布局、窗口、心跳、CONNECT 协商）由子类
 *          *_control 与 codec 策略承载。
 *          相当于一个"交换机"：帧循环调度、流管理、发送仲裁都在这里，
 *          具体协议只决定帧长什么样、流怎么建立。
 * @note 线程安全：单个实例非线程安全，应在 transport executor 上串行使用
 * @note 生命周期：子类经 shared_from_this 保活，start() 用 co_spawn 运行
 */
#pragma once

#include <prism/foundation/memory/container.hpp>
#include <prism/protocol/multiplex/codec.hpp>
#include <prism/protocol/multiplex/config.hpp>
#include <prism/protocol/multiplex/egress.hpp>
#include <prism/net/connect/types.hpp>
#include <prism/trace/context.hpp>
#include <prism/net/transport/transmission.hpp>

#include <boost/asio.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>

#include <atomic>
#include <cstdint>
#include <memory>


// 前向声明
namespace psm::outbound
{

    class proxy;

}

namespace psm::runtime::stats
{


}

namespace psm::multiplex
{

    namespace net = boost::asio;

    class stream;
    class datagram;

    /**
     * @struct activate_opts
     * @brief 流激活参数（协议无关）
     * @details smux/yamux 共用：pending 地址解析结果传递到激活方法。
     *          host/port 为目标地址，addr_offset 为地址在 pending 缓冲
     *          中的结束位置（重取激活期间累积数据用），remaining 为
     *          地址之后的上行数据，addr 为 UDP 数据报地址编码模式。
     */
    struct activate_opts
    {
        std::uint32_t stream_id{0};                    ///< 流标识符
        memory::string host;                           ///< 目标主机
        std::uint16_t port{0};                         ///< 目标端口
        std::size_t addr_offset{0};                    ///< 地址在 pending 缓冲中的结束位置
        addr_mode addr{addr_mode::length_prefixed};    ///< 地址编码模式（UDP 专用）
        memory::vector<std::byte> remaining;           ///< 地址之后的剩余数据
    };

    /**
     * @struct multiplexer_options
     * @brief multiplexer 构造参数聚合
     * @details 将传输层连接、出站代理、配置和内存资源聚合为单一结构体。
     */
    struct multiplexer_options
    {
        transport::shared_transmission transport; ///< 已建立的传输层连接（通常是 TLS 隧道）
        outbound::proxy *outbound{nullptr};       ///< 出站代理接口（非拥有，worker 生命周期）
        const config &cfg;                        ///< 多路复用配置参数
        memory::resource_pointer mr = {};         ///< PMR 内存资源，为空时使用默认资源
        std::size_t channel_capacity{512};        ///< 发送通道容量（由子类按协议 max_streams 传入）
    };

    /**
     * @class multiplexer
     * @brief 多路复用会话基类
     * @details 管理流生命周期、发送串行化和流量统计。SYN 帧创建
     *          pending_entry 累积地址数据，地址完整后子类激活流，
     *          创建 stream（TCP）或 datagram（UDP）进行数据转发。
     *          send()/fin() 把逻辑帧投入发送通道，send_loop 单消费者
     *          调用 write_frame() 由子类编码成线上字节写入传输层。
     * @note 子类必须实现 run()（帧循环）和 write_frame()（帧编码写）
     */
    class multiplexer : public std::enable_shared_from_this<multiplexer>, public egress
    {
        friend class stream;
        friend class datagram;

    public:
        /**
         * @brief 构造 multiplexer
         * @param opts 构造参数（传输层、出站代理、配置、内存资源）
         */
        explicit multiplexer(multiplexer_options opts);

        ~multiplexer() noexcept override;

        /**
         * @brief 启动会话
         * @details 通过 co_spawn 在 transport executor 上启动 run() 协程，
         *          异常或正常退出时自动调用 close()。
         */
        void start();

        /**
         * @brief 关闭会话（幂等）
         * @details 原子地标记非活跃，取消并关闭 transport，
         *          清空 pending_，取出 streams_/datagrams_ 后逐一关闭。
         */
        virtual void close();

        /**
         * @brief 设置会话日志前缀
         * @param p 调用方的 trace_context shared_ptr
         */
        void set_prefix(std::shared_ptr<trace::trace_context> p) noexcept
        {
            prefix_ = std::move(p);
        }

        /**
         * @brief 检查会话是否活跃
         * @return true 表示会话正在运行
         */
        [[nodiscard]] auto is_active() const noexcept -> bool
        {
            return active_.load(std::memory_order_acquire);
        }

        /**
         * @brief 获取 transport executor
         * @return 底层传输层的执行器，用于协程调度与 co_spawn
         */
        [[nodiscard]] auto executor() const noexcept
            -> net::any_io_executor
        {
            return transport_->executor();
        }

        // ─── egress 实现 ───────────────────────────────────

        /**
         * @brief 回传流数据（egress）
         * @details 把数据载荷作为逻辑帧投入发送通道，由 send_loop
         *          经 write_frame() 编码后写入传输层。
         */
        auto send(std::uint32_t stream_id, memory::vector<std::byte> payload)
            -> net::awaitable<void> override;

        /**
         * @brief 通知会话层流结束（egress）
         * @details 投递 fin 逻辑帧，由子类编码为协议结束帧。
         */
        void fin(std::uint32_t stream_id) override;

        /**
         * @brief 会话活跃查询（egress）
         */
        [[nodiscard]] auto active() const noexcept -> bool override
        {
            return is_active();
        }

        /**
         * @brief 上报流累计流量（egress）
         */

        /**
         * @brief 从注册表移除流（egress）
         * @details 流自行关闭时清理对应映射条目，子类可 override
         *          补充协议特定清理（如 yamux 窗口）。
         */
        virtual void drop(std::uint32_t stream_id) override;

    protected:
        /**
         * @enum outbound_kind
         * @brief 逻辑帧类型
         * @details data 为流数据帧，fin 为结束帧，control 为协议
         *          控制帧（心跳/窗口等，编码语义由子类决定）。
         */
        enum class outbound_kind : std::uint8_t
        {
            data,   ///< 流数据帧
            fin,    ///< 流结束帧
            control ///< 协议控制帧
        };

        /**
         * @struct outbound_frame
         * @brief 发送通道中的逻辑帧
         * @details 与协议无关：send_loop 取出后由 write_frame 编码。
         *          payload 所有权转移，零拷贝传递。
         */
        struct outbound_frame
        {
            std::uint32_t stream_id{0};          ///< 目标流标识符
            memory::vector<std::byte> payload;   ///< 数据载荷（fin/control 帧可为空）
            outbound_kind kind{outbound_kind::data}; ///< 帧类型
        };

        /**
         * @brief 帧循环（纯虚，子类实现）
         * @details 读取传输层字节流，经 codec 解析帧头后按语义分发：
         *          syn 建立 pending、data 投递流管道、fin 半关闭、
         *          rst 强制关闭、control 协议特定处理。
         */
        virtual auto run()
            -> net::awaitable<void> = 0;

        /**
         * @brief 编码并写入一个逻辑帧（纯虚，子类实现）
         * @param frame 逻辑帧（流标识符 + 载荷 + 结束标志，所有权转移）
         * @details smux/yamux：codec.encode_data/fin → async_write；
         *          h2mux：nghttp2_submit_data + send_pending。
         *          由 send_loop 单消费者调用，保证写不交错。
         */
        virtual auto write_frame(outbound_frame frame)
            -> net::awaitable<void> = 0;

        /**
         * @brief 投递逻辑帧到发送通道（带背压）
         * @param frame 待发送的逻辑帧（所有权转移）
         * @return 异步操作，通道满时挂起等待
         * @details 子类控制帧（SYN/窗口/心跳）也通过此通道投递，
         *          与数据帧共用同一发送串行化。
         */
        auto push_frame(outbound_frame frame)
            -> net::awaitable<void>;

        /**
         * @brief 发送循环协程
         * @details 从发送通道取出逻辑帧，调用 write_frame() 编码写入。
         *          通道被取消（close 触发）时退出。
         */
        auto send_loop()
            -> net::awaitable<void>;

        /**
         * @brief run 协程完成回调
         */
        void on_exception(const std::exception_ptr &ep);

        /**
         * @struct pending_entry
         * @brief 等待地址解析的流条目
         * @details SYN 帧创建后累积后续数据帧，地址数据足够时
         *          子类解析目标并发起连接。connecting 防重复激活。
         */
        struct pending_entry
        {
            memory::vector<std::byte> buffer; ///< 累积的地址+数据
            bool connecting = false;          ///< 是否已发起连接

            explicit pending_entry(memory::resource_pointer mr) : buffer(mr) {}
        };

        // 资源
        transport::shared_transmission transport_; ///< 底层传输连接
        outbound::proxy *outbound_{nullptr};       ///< 出站代理接口（非拥有）
        const config &config_;                     ///< 多路复用配置
        memory::resource_pointer mr_;              ///< PMR 内存资源

        // 生命周期
        std::atomic<bool> active_{false}; ///< 会话活跃标志

        // 日志
        std::shared_ptr<trace::trace_context> prefix_; ///< 会话日志前缀

        // 流注册表
        memory::unordered_map<std::uint32_t, pending_entry> pending_;       ///< 待连接流
        memory::unordered_map<std::uint32_t, std::shared_ptr<stream>> streams_;    ///< 活跃 TCP 流
        memory::unordered_map<std::uint32_t, std::shared_ptr<datagram>> datagrams_; ///< 活跃 UDP 流

    private:
        using channel_type = net::experimental::concurrent_channel<
            void(boost::system::error_code, outbound_frame)>;

        channel_type channel_; ///< 有界发送通道，容量与 max_streams 对齐
    };

} // namespace psm::multiplex
