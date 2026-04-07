/**
 * @file parcel.hpp
 * @brief 多路复用 UDP 数据报管道声明
 * @details 声明 multiplex::parcel，协议无关的 UDP 数据报中继管道。
 * 每个 mux 流中的 UDP 流对应一个 parcel 实例。与 duct 的面向连接
 * 模型不同，parcel 是无连接的数据报中继：每个 PSH 帧承载一个完整
 * SOCKS5 UDP relay 格式数据报（包含目标地址和负载数据），可发往
 * 不同目标地址和端口。parcel 通过 egress_socket_ 发送 UDP 数据报，
 * 同一 socket 复用接收所有目标的响应。空闲超时自动关闭，避免资源泄露。
 * 方法实现位于 parcel.cpp 中。
 *
 * @note 设计原则：parcel 是协议无关的，通过 core 虚函数接口发送帧，不依赖具体协议
 * @note 线程安全：单个实例非线程安全，应在 transport executor 上串行使用
 * @note 生命周期：通过 shared_from_this 保活，协程持有 self 防止提前析构
 * @warning owner_ 持有 core 的 shared_ptr，core 的 parcels_ 持有 parcel 的 shared_ptr，
 *          构成循环引用，依赖 core::close() 中 std::move(parcels_) 打破
 */
#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>

#include <boost/asio.hpp>

#include <prism/memory/container.hpp>

// 前向声明
namespace psm::resolve
{
    class router;
}

namespace psm::multiplex
{
    class core;

    namespace net = boost::asio;

    /**
     * @class parcel
     * @brief 多路复用 UDP 数据报管道，属于 core 管理的活跃 UDP 流，在 core 的下层
     * @details parcel 管理单条 UDP 流的完整生命周期，从 activate_stream 解析出
     * UDP 目标地址后创建，到空闲超时或 mux 会话结束时关闭。每个 PSH 帧的载荷
     * 为 SOCKS5 UDP relay 格式数据报：[ATYP 1B][Addr(var)][Port 2B][Data]，
     * parcel 解析后通过 egress_socket_ 发送到目标，响应数据编码为相同格式
     * 通过 owner_->send_data 发回 mux 客户端。
     *
     * 与 duct 的双向流模型不同，parcel 是请求-响应模型：
     * on_mux_data 逐个处理入站数据报（由 craft::dispatch_push co_spawn 非阻塞调用），
     * relay_datagram 完成单次 DNS 解析 → UDP 发送 → 等待响应 → 编码回传的完整流程。
     * 空闲超时通过 idle_timer_ 管理，每次数据活动重置计时器，
     * 超时后自动调用 close() 关闭管道。继承 std::enable_shared_from_this，
     * 各协程通过 self 保活。
     *
     * @note 线程安全：单个实例非线程安全，应在同一 executor 上串行使用
     * @note 生命周期：core::close() 通过 std::move(parcels_) 取出所有 parcel 后逐一 close
     * @warning on_mux_data 中的串行处理保证同一时刻只有一个数据报在处理中，
     *          避免多个 relay_datagram 并发写入同一 egress_socket_
     * @warning owner_ (shared_ptr<core>) 与 core 的 parcels_ (shared_ptr<parcel>) 构成循环引用
     */
    class parcel : public std::enable_shared_from_this<parcel>
    {
    public:
        /**
         * @brief 构造 parcel
         * @param stream_id 流标识符，由 mux 协议在 SYN 帧中分配
         * @param owner 所属 core 的共享指针，用于调用 send_data 发送 mux 帧
         * @param router 路由器引用，用于 DNS 解析目标主机名
         * @param udp_idle_timeout UDP 管道空闲超时（毫秒），超时自动关闭
         * @param udp_max_dg UDP 数据报最大长度（字节）
         * @param mr PMR 内存资源，用于分配缓冲区和编码数据
         * @param packet_addr 是否为 PacketAddr 模式（每帧携带目标地址）
         * @details 构造后 parcel 处于就绪状态，需调用 start() 启动空闲超时监控。
         * egress_socket_ 延迟创建，首次发送数据报时按目标协议族（IPv4/IPv6）初始化。
         * packet_addr=true 时每帧使用 SOCKS5 地址格式，packet_addr=false 时使用
         * length-prefixed 格式（目标地址使用 SYN 时解析的地址）。
         * @note 方法定义在 parcel.cpp 中
         */
        parcel(std::uint32_t stream_id, std::shared_ptr<core> owner,
               resolve::router &router,
               std::uint32_t udp_idle_timeout, std::uint32_t udp_max_dg,
               memory::resource_pointer mr, bool packet_addr = false);

        ~parcel();

        /**
         * @brief 启动空闲超时监控
         * @details 通过 co_spawn 启动 uplink_loop 协程，监控 parcel 数据活动。
         * 空闲超时由 config::udp_idle_timeout_ms 控制，超时后自动 close()。
         * uplink_loop 通过 shared_from_this 持有 self 保活。
         * @note 方法定义在 parcel.cpp 中
         */
        void start();

        /**
         * @brief 接收 mux 数据报并转发到目标
         * @param data SOCKS5 UDP relay 格式数据（[ATYP][Addr][Port][Data]）
         * @details 解析 SOCKS5 UDP relay 格式数据报，提取目标地址和负载数据，
         * 调用 relay_datagram 完成单次 UDP 请求-响应中继。
         * 由 craft::dispatch_push 通过 co_spawn 非阻塞调用，不阻塞帧循环。
         * 每次调用重置空闲计时器。数据格式错误时静默丢弃。
         * @note 方法定义在 parcel.cpp 中
         */
        auto on_mux_data(std::span<const std::byte> data) -> net::awaitable<void>;

        /**
         * @brief 关闭管道（幂等）
         * @details 首次调用时：标记 closed_ 为 true，关闭 egress_socket_ 和
         * idle_timer_，调用 owner_->remove_parcel 从 core 的 parcels_ 映射中
         * 移除自身。多次调用无副作用。由空闲超时、core::close() 或
         * craft::handle_fin 触发。
         * @note 方法定义在 parcel.cpp 中
         */
        void close();

        /**
         * @brief 获取流标识符
         * @return std::uint32_t mux 协议分配的流标识符
         */
        [[nodiscard]] std::uint32_t stream_id() const noexcept
        {
            return id_;
        }

        /**
         * @brief 设置无 PacketAddr 模式的固定目标地址
         * @param host 目标主机名
         * @param port 目标端口
         * @details 仅在 packet_addr=false 模式下有效。目标地址在 SYN 阶段解析，
         * 后续所有数据报发送到同一目标。
         */
        void set_destination(std::string_view host, std::uint16_t port)
        {
            destination_host_.assign(host.data(), host.size());
            destination_port_ = port;
        }

    private:
        /**
         * @brief 空闲超时监控循环
         * @details 启动 idle_timer_ 定时器，每次 touch_idle_timer 重置超时。
         * 超时后调用 close() 关闭管道。通过 shared_from_this 持有 self 保活，
         * 防止 parcel 在等待期间被析构。
         * @note 方法定义在 parcel.cpp 中
         */
        auto uplink_loop() -> net::awaitable<void>;

        /**
         * @brief 缓冲区处理循环
         * @details 从 mux_buffer_ 中流式解析完整 UDP 数据报并逐个中继。
         * sing-mux 客户端可能将一个 UDP 数据报拆成多个 PSH 帧发送
         * （SOCKS5 地址、Length、Payload 各一帧），因此需要缓冲累积后
         * 再解析完整数据报。processing_ 标志保证同一时刻只有一个处理循环运行。
         * @note 方法定义在 parcel.cpp 中
         */
        auto process_buffer() -> net::awaitable<void>;

        /**
         * @brief 发送单个已解析的 UDP 数据报（不等待响应）
         * @param target_host 目标主机
         * @param target_port 目标端口
         * @param payload UDP 负载数据
         * @details 仅执行 DNS 解析 + async_send_to，不等待响应。
         * 首次发送时启动 downlink_loop 协程异步读取响应并回传。
         * @note 方法定义在 parcel.cpp 中
         */
        auto do_send(const memory::string &target_host, std::uint16_t target_port,
                     std::span<const std::byte> payload) -> net::awaitable<void>;

        /**
         * @brief 下行中继循环
         * @details 独立协程，持续从 egress_socket_ 读取 UDP 响应，
         * 编码为 SOCKS5/length-prefixed 格式后通过 owner_->send_data 回传。
         * 由 do_send 首次发送时启动，socket 重建或关闭时自动退出。
         * @note 方法定义在 parcel.cpp 中
         */
        auto downlink_loop() -> net::awaitable<void>;

        /**
         * @brief 重置空闲计时器
         * @details 将 idle_timer_ 的超时时间重新设置为 config_.udp_idle_timeout_ms，
         * 延迟管道的空闲关闭。每次 on_mux_data 调用时触发。
         * @note 方法定义在 parcel.cpp 中
         */
        void touch_idle_timer();

        /**
         * @brief 确保 UDP socket 可用
         * @param protocol 目标协议类型（IPv4/IPv6）
         * @return bool true 表示 socket 可用，false 表示创建失败
         * @details 如果 egress_socket_ 已存在且协议匹配则直接返回 true；
         * 否则关闭旧 socket 并创建新的 UDP socket，绑定到任意端口。
         * 协议切换时（目标从 IPv4 变为 IPv6 或反之）自动重建 socket。
         * @note 方法定义在 parcel.cpp 中
         */
        auto ensure_socket(net::ip::udp::endpoint::protocol_type protocol) -> net::awaitable<bool>;

        std::uint32_t id_;                   // 流标识符，由 mux SYN 帧分配
        std::shared_ptr<core> owner_;        // 所属 core，用于发送 mux 帧和管理流映射
        resolve::router &router_;            // 路由器引用，用于 DNS 解析目标主机名
        std::uint32_t udp_idle_timeout_ms_;  // UDP 管道空闲超时（毫秒）
        std::uint32_t udp_max_datagram_;     // UDP 数据报最大长度（字节）
        memory::resource_pointer mr_;        // PMR 内存资源，用于缓冲区分配
        bool closed_ = false;                // 关闭标志，close() 幂等性保证
        bool packet_addr_ = false;           // PacketAddr 模式标志，true=每帧带地址，false=仅 length+payload
        memory::string destination_host_;    // 无 PacketAddr 模式时，SYN 阶段解析的目标主机
        std::uint16_t destination_port_ = 0; // 无 PacketAddr 模式时，SYN 阶段解析的目标端口

        net::steady_timer idle_timer_;                                              // 空闲超时计时器，超时触发 close()
        std::optional<net::ip::udp::socket> egress_socket_;                         // 出站 UDP socket，延迟创建，按协议族初始化
        net::ip::udp::endpoint::protocol_type socket_protocol_{net::ip::udp::v4()}; // 当前 socket 协议族
        memory::vector<std::byte> recv_buffer_;                                     // UDP 响应接收缓冲区

        memory::vector<std::byte> mux_buffer_;  // mux 数据累积缓冲区，处理跨 PSH 帧的 UDP 数据报
        std::atomic<bool> processing_{false};   // 缓冲区处理标志，防止并发 process_buffer
        std::atomic<bool> recv_running_{false}; // recv_loop 运行标志，防止并发接收循环
    }; // class parcel

    /**
     * @brief 创建 parcel 共享指针
     * @param stream_id 流标识符
     * @param owner 所属 core 的共享指针
     * @param router 路由器引用
     * @param udp_idle_timeout UDP 管道空闲超时（毫秒）
     * @param udp_max_dg UDP 数据报最大长度（字节）
     * @param mr PMR 内存资源
     * @param packet_addr 是否为 PacketAddr 模式
     * @return parcel 的共享指针
     */
    [[nodiscard]] inline auto make_parcel(std::uint32_t stream_id, std::shared_ptr<core> owner,
                                          resolve::router &router,
                                          std::uint32_t udp_idle_timeout, std::uint32_t udp_max_dg,
                                          memory::resource_pointer mr = {}, bool packet_addr = false)
        -> std::shared_ptr<parcel>
    {
        return std::make_shared<parcel>(stream_id, std::move(owner), router,
                                        udp_idle_timeout, udp_max_dg, mr, packet_addr);
    }

} // namespace psm::multiplex
