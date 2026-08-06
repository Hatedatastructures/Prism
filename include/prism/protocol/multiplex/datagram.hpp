/**
 * @file datagram.hpp
 * @brief 多路复用 UDP 数据报管道
 * @details 定义 multiplex::datagram，一条 mux 流对应的 UDP 数据报中继管道。
 *          相当于一个"UDP 会话"：入向通过 send_to 接收完整数据报
 *          （含目标地址），解析端点后经 egress_socket_ 发出；出向由
 *          recv_loop 读取响应，经 emit 回调交还会话层编码成帧。
 *          与旧 parcel 相比的职责净化：
 *          - 删除协议地址模式分支（packet_addr/length_prefixed），
 *            数据报重组与地址解析归 *_control 层
 *          - 删除 owner_ 弱引用与 outbound::direct 直接持有，
 *            只依赖两个注入回调（resolve 解析端点、emit 回传响应）
 *          - 保留 UDP socket 管理、空闲超时、首包启动接收循环
 * @note 线程安全：单个实例非线程安全，应在同一 executor 上串行使用
 * @note 生命周期：由 multiplexer 的 datagrams_ 持有 shared_ptr，
 *       协程经 shared_from_this 保活；egress_ 弱引用防循环
 */
#pragma once

#include <prism/foundation/fault/code.hpp>
#include <prism/protocol/multiplex/codec.hpp>
#include <prism/foundation/memory/container.hpp>
#include <prism/protocol/multiplex/egress.hpp>
#include <prism/diagnose/context.hpp>

#include <boost/asio.hpp>

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string_view>
#include <utility>


namespace psm::multiplex
{

    namespace net = boost::asio;

    /// UDP 端点解析回调（由 *_control 注入，替代直接持有 outbound::direct）
    using resolve_fn = std::function<net::awaitable<std::pair<fault::code,
                                                              net::ip::udp::endpoint>>(std::string_view, std::string_view)>;

    /// 响应回传回调（由 *_control 注入：编码数据报帧并经 egress.send 发出）
    using emit_fn = std::function<net::awaitable<void>(std::string_view host,
                                                       std::uint16_t port,
                                                       std::span<const std::byte> payload)>;

    /**
     * @struct datagram_options
     * @brief datagram 构造参数聚合
     * @details 将流标识符、UDP 参数、出口接口、解析/回传回调、
     *          内存资源和日志前缀聚合为单一结构体。
     */
    struct datagram_options
    {
        std::uint32_t stream_id = 0;               ///< 流标识符，由 mux 协议分配
        std::uint32_t idle_timeout = 30000;        ///< 空闲超时（毫秒），超时自动关闭
        std::uint32_t max_dgram = 4096;            ///< 数据报最大长度（字节）
        net::any_io_executor executor;             ///< 执行器（通常为 transport executor）
        std::shared_ptr<egress> egress;            ///< 会话层出口（数据回传通道）
        resolve_fn resolve;                        ///< 目标端点解析回调
        emit_fn emit;                              ///< 响应回传回调
        memory::resource_pointer mr = {};          ///< PMR 内存资源
        std::shared_ptr<diagnose::context> prefix; ///< 日志前缀
    };

    /**
     * @class datagram
     * @brief 多路复用 UDP 数据报管道
     * @details 管理单条 UDP 流的生命周期：send_to 逐个处理入向完整
     *          数据报（由 control 重组并解析地址后调用），解析端点、
     *          发送到目标；recv_loop 独立协程读取目标响应，经 emit
     *          回调回传。空闲超时通过 idle_timer_ 管理，每次活动
     *          重置计时器，超时后自动关闭。UDP socket 延迟创建，
     *          按目标协议族（IPv4/IPv6）初始化，协议切换时重建。
     * @note 入向串行处理保证同一时刻只有一个数据报在发送，
     *       避免并发写同一 egress_socket_
     */
    class datagram : public std::enable_shared_from_this<datagram>
    {
    public:
        /**
         * @brief 构造 datagram
         * @param opts 构造参数（流标识符、UDP 参数、出口、回调、内存、日志前缀）
         * @details 构造后处于就绪状态，需调用 start() 启动空闲超时监控。
         */
        explicit datagram(datagram_options opts);

        ~datagram() noexcept;

        /**
         * @brief 启动空闲超时监控
         * @details 启动 idle 协程等待 idle_timer_ 到期，超时后自动 close()。
         */
        void start();

        /**
         * @brief 发送一个完整数据报到目标
         * @param host 目标主机
         * @param port 目标端口
         * @param payload 数据报负载
         * @return 异步操作，完成表示已投递（不等待响应）
         * @details 解析目标端点、确保 socket 可用、首次发送时启动
         *          recv_loop，然后 async_send_to。
         */
        auto send_to(std::string_view host, std::uint16_t port,
                     std::span<const std::byte> payload)
            -> net::awaitable<void>;

        /**
         * @brief 关闭管道（幂等）
         * @details 标记关闭，累计流量上报出口，关闭 socket 与定时器，
         *          通知会话层从注册表移除。
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
         * @brief 空闲超时等待协程
         * @details 等待 idle_timer_ 到期（每次活动 touch_timer 重置），
         *          到期后 close() 关闭管道。
         */
        auto idle_loop()
            -> net::awaitable<void>;

        /**
         * @brief 响应接收循环
         * @details 独立协程，持续从 egress_socket_ 读取 UDP 响应，
         *          经 emit 回调回传会话层。socket 关闭时退出。
         */
        auto recv_loop()
            -> net::awaitable<void>;

        /**
         * @brief 重置空闲计时器
         * @details 将 idle_timer_ 重新设置为 idle_timeout，延迟关闭。
         */
        void touch_timer();

        /**
         * @brief 确保 UDP socket 可用
         * @param protocol 目标协议类型（IPv4/IPv6）
         * @return true 表示 socket 可用，false 表示创建失败
         * @details socket 已存在且协议匹配则直接返回；否则重建。
         */
        [[nodiscard]] auto ensure_socket(net::ip::udp::endpoint::protocol_type protocol)
            -> net::awaitable<bool>;

        std::uint32_t id_{0};                          ///< 流标识符
        std::weak_ptr<egress> egress_;                 ///< 会话层出口弱引用（防循环）
        resolve_fn resolve_;                           ///< 目标端点解析回调
        emit_fn emit_;                                 ///< 响应回传回调
        net::any_io_executor executor_;                ///< 缓存的 executor
        std::uint32_t idle_timeout_{30000};            ///< 空闲超时（毫秒）
        std::uint32_t max_dgram_{4096};                ///< 数据报最大长度（字节）
        memory::resource_pointer mr_{};                ///< PMR 内存资源
        std::shared_ptr<diagnose::context> prefix_; ///< 日志前缀
        bool closed_ = false;                          ///< 关闭标志（close 幂等）

        net::steady_timer idle_timer_;                                      ///< 空闲超时计时器
        std::optional<net::ip::udp::socket> egress_socket_;                 ///< 出站 UDP socket（延迟创建）
        net::ip::udp::endpoint::protocol_type socket_protocol_{net::ip::udp::v4()}; ///< 当前 socket 协议族
        memory::vector<std::byte> recv_buffer_;                             ///< 响应接收缓冲区

        std::atomic<bool> recv_running_{false}; ///< 接收循环运行标志（防并发启动）
    };

    /**
     * @brief 创建 datagram 共享指针
     * @param opts 构造参数
     * @return datagram 的共享指针
     */
    [[nodiscard]] inline auto make_datagram(datagram_options opts)
        -> std::shared_ptr<datagram>
    {
        return std::make_shared<datagram>(std::move(opts));
    }

} // namespace psm::multiplex
