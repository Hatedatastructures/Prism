/**
 * @file duct.hpp
 * @brief 多路复用 TCP 流管道声明
 * @details 声明 multiplex::duct，协议无关的双向 TCP 转发管道。
 * 每条 duct 绑定一个已连接的 target 传输层，提供 mux 帧到 target 的
 * 透明双向转发。构造时即持有 target，不存在空管道阶段。
 * target_read_loop（target 读 → mux 发送，客户端下载方向）由独立协程
 * 循环读取 target 数据并通过 core::send_data 发送到 mux 客户端；
 * on_mux_data 将 mux 推来的数据推入有界写通道，由独立的
 * target_write_loop 写入 target（客户端上传方向），解耦帧循环与
 * target 写入速度差异，消除队头阻塞。方法实现位于 duct.cpp 中。
 *
 * @note 设计原则：duct 是协议无关的，通过 core 虚函数接口发送帧，不依赖具体协议
 * @note 线程安全：单个实例非线程安全，应在 transport executor 上串行使用
 * @note 生命周期：通过 shared_from_this 保活，协程持有 self 防止提前析构
 * @warning owner_ 持有 core 的 shared_ptr，core 的 ducts_ 持有 duct 的 shared_ptr，
 *          构成循环引用，依赖 core::close() 中 std::move(ducts_) 打破
 */
#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <span>

#include <boost/asio.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>

#include <prism/channel/transport/transmission.hpp>
#include <prism/memory/container.hpp>

namespace psm::multiplex
{
    class core;

    namespace net = boost::asio;

    /**
     * @class duct
     * @brief 多路复用 TCP 流管道，属于 core 管理的活跃 TCP 流，在 core 的下层
     * @details duct 管理单条 TCP 流的完整生命周期，从 activate_stream 创建 target
     * 连接成功后开始，到任一端关闭或 mux 会话结束时终止。双向数据转发：
     * target_read_loop 独立协程读 target 数据，通过 owner_->send_data 发送到 mux
     * （客户端下载方向）；on_mux_data 接收 mux 帧数据，推入 write_channel_，
     * 由 target_write_loop 独立协程写入 target（客户端上传方向）。
     *
     * 半关闭语义：mux 端收到 FIN 时调用 on_mux_fin，标记 mux_closed_ 并关闭
     * write_channel_ 通知 target_write_loop 退出；target 端读到 EOF 时标记
     * target_closed_ 并调用 owner_->send_fin 通知 mux 端。两端均关闭后 duct
     * 自行析构。write_channel_ 有界容量提供反压，防止快生产者淹没慢 target。
     * 继承 std::enable_shared_from_this，start() 和各协程通过 self 保活。
     *
     * @note 线程安全：单个实例非线程安全，应在同一 executor 上串行使用
     * @note 生命周期：core::close() 通过 std::move(ducts_) 取出所有 duct 后逐一 close
     * @warning owner_ (shared_ptr<core>) 与 core 的 ducts_ (shared_ptr<duct>) 构成循环引用
     */
    class duct : public std::enable_shared_from_this<duct>
    {
        using write_channel_type = net::experimental::concurrent_channel<void(boost::system::error_code, memory::vector<std::byte>)>;

    public:
        /**
         * @brief 构造 duct
         * @param stream_id 流标识符，由 mux 协议在 SYN 帧中分配
         * @param owner 所属 core 的共享指针，用于调用 send_data/send_fin 发送 mux 帧
         * @param target 已连接的目标传输层，生命周期转移给 duct
         * @param buffer_size 每流读取缓冲区大小，与帧最大载荷取较小值
         * @param mr PMR 内存资源，用于分配读缓冲和写通道数据
         * @details 构造后 duct 处于就绪状态，需调用 start() 启动双向转发协程。
         * read_size_ 根据 buffer_size 和 max_frame_payload 取较小值，
         * 确保 target 读取的单次数据量不超过 mux 帧最大载荷。
         * @note 方法定义在 duct.cpp 中
         */
        duct(std::uint32_t stream_id, std::shared_ptr<core> owner,
             channel::transport::shared_transmission target,
             std::uint32_t buffer_size, memory::resource_pointer mr);

        ~duct();

        /**
         * @brief 启动 target 读循环和写循环
         * @details 通过 co_spawn 在 owner executor 上启动两个独立协程：
         * target_read_loop（target → mux，客户端下载）和
         * target_write_loop（mux → target，客户端上传）。
         * 两个协程通过 shared_from_this 持有 self 保活，
         * 协程退出时回调中调用 close() 清理资源。
         * @note 方法定义在 duct.cpp 中
         */
        void start();

        /**
         * @brief 接收 mux 数据并写入 target
         * @param data 来自 mux 数据帧的数据（所有权转移）
         * @details 将数据推入 write_channel_，由独立的 target_write_loop 写入 target。
         * 有界 write_channel_ 提供反压：当通道满时协程挂起等待，防止帧循环
         * 无限制推送数据导致内存膨胀。由 craft::dispatch_push 通过 co_spawn
         * 非阻塞调用，不阻塞帧循环。
         * @note 方法定义在 duct.cpp 中
         */
        auto on_mux_data(memory::vector<std::byte> data) -> net::awaitable<void>;

        /**
         * @brief 处理 mux 端 FIN，触发半关闭
         * @details 标记 mux_closed_ 为 true，关闭 write_channel_ 通知
         * target_write_loop 退出写入循环。target 端可能仍在发送数据，
         * target_read_loop 继续运行直到 target EOF 后调用 owner_->send_fin
         * 完成全双工关闭。由 craft::handle_fin 调用。
         * @note 方法定义在 duct.cpp 中
         */
        void on_mux_fin();

        /**
         * @brief 关闭管道（幂等）
         * @details 首次调用时：标记 closed_ 为 true，关闭并释放 target 传输层，
         * 调用 owner_->remove_duct 从 core 的 ducts_ 映射中移除自身。
         * 多次调用无副作用。由协程退出回调、core::close() 或 on_mux_fin 触发。
         * @note 方法定义在 duct.cpp 中
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

    private:
        /**
         * @brief target 读循环：从 target 读取数据发送到 mux（客户端下载方向）
         * @details 循环读取 target 数据，每次读取量不超过 read_size_（受 mux 帧
         * 最大载荷限制），读取后通过 owner_->send_data 将数据编码为 mux PSH 帧
         * 发送到客户端。target EOF 时标记 target_closed_，调用 owner_->send_fin
         * 通知 mux 端半关闭，然后退出循环。mux 会话不活跃时也退出。
         * @note 方法定义在 duct.cpp 中
         */
        auto target_read_loop() -> net::awaitable<void>;

        /**
         * @brief target 写循环：从写通道取数据写入 target（客户端上传方向）
         * @details 循环从 write_channel_ 取出数据并写入 target 传输层。
         * write_channel_ 关闭时（on_mux_fin 或 close 触发）退出循环。
         * 写入失败时调用 close() 关闭整个管道。
         * @note 方法定义在 duct.cpp 中
         */
        auto target_write_loop() -> net::awaitable<void>;

        std::uint32_t id_;                               // 流标识符，由 mux SYN 帧分配
        std::shared_ptr<core> owner_;                    // 所属 core，用于发送 mux 帧和管理流映射
        memory::resource_pointer mr_;                    // PMR 内存资源，用于读缓冲分配
        channel::transport::shared_transmission target_; // 已连接的目标传输层
        bool closed_ = false;                            // 关闭标志，close() 幂等性保证
        std::size_t read_size_ = 0;                      // 单次从 target 读取上限，不超过 mux 帧最大载荷
        std::atomic<bool> mux_closed_{false};            // mux 端已半关闭，on_mux_fin 设为 true
        std::atomic<bool> target_closed_{false};         // target 端已半关闭，target EOF 后设为 true

        write_channel_type write_channel_; // 客户端上传方向写通道（mux → target），有界容量提供反压
    }; // class duct

    /**
     * @brief 创建 duct 共享指针
     * @param stream_id 流标识符
     * @param owner 所属 core 的共享指针
     * @param target 已连接的目标传输层
     * @param mr PMR 内存资源
     * @return duct 的共享指针
     */
    [[nodiscard]] inline auto make_duct(std::uint32_t stream_id, std::shared_ptr<core> owner,
                                        channel::transport::shared_transmission target,
                                        std::uint32_t buffer_size, memory::resource_pointer mr = {})
        -> std::shared_ptr<duct>
    {
        return std::make_shared<duct>(stream_id, std::move(owner), std::move(target), buffer_size, mr);
    }

} // namespace psm::multiplex
