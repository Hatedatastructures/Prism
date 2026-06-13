/**
 * @file traffic.hpp
 * @brief per-worker 流量统计 + 全局聚合
 * @details traffic_state 是 per-worker 单写者的流量计数器集合。
 * 所有热路径流量在局部变量累积，会话/子流结束时通过
 * flush_traffic() 批量刷入（4 次 fetch_add/会话）。
 * 全局聚合使用 COW 注册表，按需遍历。
 */
#pragma once

#include <prism/proto/protocol/types.hpp>
#include <prism/account/stats/snapshot.hpp>

#include <atomic>
#include <cstdint>
#include <memory>
#include <vector>


namespace psm::stats::traffic
{

    /**
     * @struct alignas(64) protocol_slot
     * @brief 单个协议维度的原子计数器组
     * @details 32 字节，2 个 slot 占一条缓存行。
     * 单写者场景下无需逐字段 alignas(64)。
     * connections 为历史累计值（仅增不减），active 反映当前在线。
     */
    struct alignas(64) protocol_slot
    {
        std::atomic<std::uint64_t> connections{0};      ///< 历史总连接数（仅增不减）
        std::atomic<std::uint64_t> active{0};           ///< 当前活跃连接数
        std::atomic<std::uint64_t> uplink_bytes{0};     ///< 上行总字节数
        std::atomic<std::uint64_t> downlink_bytes{0};   ///< 下行总字节数
    };

    /**
     * @class alignas(64) traffic_state
     * @brief per-worker 流量计数器
     * @details 整个类 alignas(64) 确保不与 worker 其他成员共享缓存行。
     * 内部紧凑排列，因为只有一个写者（本 worker 线程）。
     * 所有热路径流量在局部变量累积，会话/子流结束时通过
     * flush_traffic() 批量刷入，每次会话仅 4 次 fetch_add。
     * 全局聚合使用 COW 注册表（register_instance/unregister_instance），
     * aggregate() 按需遍历所有已注册实例。
     * @note 线程安全：所有方法均为原子操作，但设计上仅由单写者调用
     * @note 生命周期：由 worker 持有，随 worker 析构自动析构
     */
    class alignas(64) traffic_state final
    {
    public:
        explicit traffic_state() = default;

        /**
         * @brief 新连接建立时调用
         * @details 在 launch::start() 中调用，递增 total_connections 和 total_active
         */
        void on_connect() noexcept;

        /**
         * @brief 协议识别完成后调用
         * @param type 识别到的协议类型
         * @details 在 session::diversion() 识别完成后调用，
         * 递增对应协议槽位的 connections 和 active 计数器
         */
        void on_protocol_detected(protocol::protocol_type type) noexcept;

        /**
         * @brief 连接断开时调用
         * @param type 断开连接的协议类型
         * @details 在 session::release_resources() 中调用，
         * 递减 total_active 和对应协议槽位的 active 计数器
         */
        void on_disconnect(protocol::protocol_type type) noexcept;

        /**
         * @brief 批量刷入会话累积的流量数据
         * @param proto 协议类型，用于定位协议维度槽位
         * @param up 上行字节数（含协议开销）
         * @param down 下行字节数（含协议开销）
         * @details 在 tunnel/udp_relay/mux core 结束时调用，
         * 每次调用产生 4 次 fetch_add（total_uplink, total_downlink,
         * protocols_[i].uplink_bytes, protocols_[i].downlink_bytes）
         */
        void flush_traffic(protocol::protocol_type proto, std::uint64_t up, std::uint64_t down) noexcept;

        /**
         * @brief 认证成功计数 +1
         * @details 在 launch::start() 的 credential_function 中调用
         */
        void on_auth_success() noexcept;

        /**
         * @brief 认证失败计数 +1
         * @details 在 launch::start() 的 credential_function 中调用
         */
        void on_auth_failure() noexcept;

        /**
         * @brief 获取当前计数器快照
         * @return 包含所有字段松散一致值的快照
         */
        [[nodiscard]] auto snapshot() const noexcept
            -> traffic_snapshot;

        /**
         * @brief 归零所有计数器
         * @details 用于测试或管理端重置，所有字段 store(0)
         */
        void reset() noexcept;

        /**
         * @brief 将实例注册到全局 COW 注册表
         * @param s 要注册的 traffic_state 指针
         * @details 在 worker 构造时调用。注册后可被 aggregate() 遍历。
         * 采用 Copy-on-Write 模式：创建新的 vector 替换旧的，
         * 旧的 vector 不释放（可能有并发的 aggregate() 在读）。
         * @note worker 数量有限（通常 < 64），内存泄漏可忽略
         */
        static void register_instance(traffic_state *s) noexcept;

        /**
         * @brief 从全局 COW 注册表移除实例
         * @param s 要移除的 traffic_state 指针
         * @note 当前未被调用（worker 生命周期等于进程生命周期）
         */
        static void unregister_instance(traffic_state *s) noexcept;

        /**
         * @brief 聚合所有已注册实例的快照
         * @return 所有 worker 流量计数器之和
         * @details 遍历 COW 注册表中的每个实例，读取其 snapshot()
         * 并逐字段累加。返回的快照为所有 worker 的聚合值。
         */
        [[nodiscard]] static auto aggregate() noexcept
            -> traffic_snapshot;

    private:
        std::atomic<std::uint64_t> total_connections_{0};              ///< 全局总连接数
        std::atomic<std::uint64_t> total_active_{0};                   ///< 全局活跃连接数
        std::atomic<std::uint64_t> total_uplink_{0};                   ///< 全局上行字节
        std::atomic<std::uint64_t> total_downlink_{0};                 ///< 全局下行字节

        protocol_slot protocols_[slot_count];                 ///< 按 protocol_type 索引的协议槽位数组

        std::atomic<std::uint64_t> auth_success_{0};                   ///< 认证成功次数
        std::atomic<std::uint64_t> auth_failure_{0};                   ///< 认证失败次数
    };
} // namespace psm::stats::traffic
