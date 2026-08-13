/**
 * @file stream.hpp
 * @brief 多路复用 TCP 流管道
 * @details 定义 multiplex::stream，一条 mux 流对应的 TCP 双向转发管道。
 *          相当于一条"逻辑 TCP 连接"：一端是已连接的 target 传输层，
 *          另一端通过 egress 接口与会话层交互。stream 不感知任何
 *          协议帧格式，只做三件事：读 target 数据回调 egress.send、
 *          把 egress 入向数据写入 target、管理半关闭状态机。
 *          设计上替代旧 duct：删除 owner_ 弱引用（改为 egress 接口）、
 *          删除协程包装方法（trace 前缀构造注入）、保留有界写通道
 *          背压（防止慢 target 阻塞帧循环）。
 * @note 线程安全：单个实例非线程安全，应在同一 executor 上串行使用
 * @note 生命周期：由 multiplexer 的 streams_ 持有 shared_ptr，
 *       协程经 shared_from_this 保活；egress_ 弱引用防循环
 */
#pragma once

#include <prism/diagnose/context.hpp>
#include <prism/foundation/memory/container.hpp>
#include <prism/net/transport/transmission.hpp>
#include <prism/protocol/multiplex/egress.hpp>

#include <boost/asio.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>

#include <atomic>
#include <cstdint>
#include <memory>

namespace psm::multiplex
{

    namespace net = boost::asio;

    /**
     * @struct stream_options
     * @brief stream 构造参数聚合
     * @details 将流标识符、目标传输层、出口接口、缓冲区大小、
     *          内存资源和日志前缀聚合为单一结构体。
     */
    struct stream_options
    {
        std::uint32_t stream_id{0};                ///< 流标识符，由 mux 协议分配
        transport::shared_transmission target;     ///< 已连接的目标传输层
        std::shared_ptr<egress> egress;            ///< 会话层出口（数据回传通道）
        std::uint32_t buffer_size{4096};           ///< 单次读取缓冲区大小
        memory::resource_pointer mr = {};          ///< PMR 内存资源
        std::shared_ptr<diagnose::context> prefix; ///< 日志前缀
    };

    /**
     * @class stream
     * @brief 多路复用 TCP 流管道
     * @details 双向数据转发：target_readloop 独立协程读 target 数据
     *          （客户端下载方向），经 egress->send 回传会话层编码成帧；
     *          on_data 接收会话层解码后的数据（客户端上传方向），
     *          推入有界写通道，由 target_writeloop 写入 target。
     *          半关闭语义：mux 端 FIN → on_fin 关闭写方向；target EOF
     *          → egress->fin 通知会话层。两端均关闭后管道析构。
     * @note write_channel_ 有界容量提供反压，防止快生产者淹没慢 target
     */
    class stream : public std::enable_shared_from_this<stream>
    {
        using channel_type =
            net::experimental::concurrent_channel<void(boost::system::error_code, memory::vector<std::byte>)>;

    public:
        /**
         * @brief 构造 stream
         * @param opts 构造参数（流标识符、目标传输层、出口、缓冲、内存、日志前缀）
         * @details 构造后处于就绪状态，需调用 start() 启动双向转发协程。
         *          read_size_ 取 buffer_size 与帧载荷上限的较小值。
         */
        explicit stream(stream_options opts);

        ~stream() noexcept;

        /**
         * @brief 启动 target 读循环和写循环
         * @details 在 target executor 上 co_spawn 两个独立协程：
         *          target_readloop（target → mux，下载方向）和
         *          target_writeloop（mux → target，上传方向）。
         */
        void start();

        /**
         * @brief 接收会话层解码后的数据并写入 target
         * @param data 来自 mux 数据帧的数据（所有权转移）
         * @return 异步操作，通道满时挂起（背压）
         */
        auto on_data(memory::vector<std::byte> data) -> net::awaitable<void>;

        /**
         * @brief 处理 mux 端 FIN，触发半关闭
         * @details 标记 mux 端关闭，shutdown target 写方向；
         *          target 端若已关闭则完全关闭管道。
         */
        void on_fin();

        /**
         * @brief 关闭管道（幂等）
         * @details 关闭写通道与 target，累计流量上报出口。
         */
        void close();

        /**
         * @brief 获取流标识符
         * @return mux 协议分配的流标识符
         */
        [[nodiscard]] auto stream_id() const noexcept -> std::uint32_t
        {
            return id_;
        }

    private:
        /**
         * @brief target 读循环：target → 会话层（客户端下载方向）
         * @details 循环读取 target 数据，每次不超过 read_size_，
         *          读后经 egress->send 回传。target EOF 时通知
         *          会话层半关闭并退出。
         */
        auto target_readloop() -> net::awaitable<void>;

        /**
         * @brief target 写循环：会话层 → target（客户端上传方向）
         * @details 从 write_channel_ 取数据写入 target，通道关闭时退出，
         *          写失败时关闭整个管道。
         */
        auto target_writeloop() -> net::awaitable<void>;

        std::uint32_t id_{0};                       ///< 流标识符
        std::weak_ptr<egress> egress_;              ///< 会话层出口弱引用（防循环）
        memory::resource_pointer mr_{};             ///< PMR 内存资源
        transport::shared_transmission target_;     ///< 已连接的目标传输层
        std::shared_ptr<diagnose::context> prefix_; ///< 日志前缀
        bool closed_ = false;                       ///< 关闭标志（close 幂等）
        std::size_t read_size_ = 0;                 ///< 单次读取上限（≤ 帧载荷上限）

        std::atomic<bool> mux_closed_{false};    ///< mux 端已半关闭（on_fin 置位）
        std::atomic<bool> target_closed_{false}; ///< target 端已半关闭（EOF 置位）

        channel_type write_channel_; ///< 上传方向写通道（有界背压）
    };

    /**
     * @brief 创建 stream 共享指针
     * @param opts 构造参数
     * @return stream 的共享指针
     */
    [[nodiscard]] inline auto make_stream(stream_options opts) -> std::shared_ptr<stream>
    {
        return std::make_shared<stream>(std::move(opts));
    }

} // namespace psm::multiplex
