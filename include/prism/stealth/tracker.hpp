/**
 * @file tracker.hpp
 * @brief 探测行为追踪器(RFC-065 Phase 2)
 * @details per-worker 的主动探测行为追踪。记录每个来源 IP 的
 *          连续握手失败次数,达到阈值后触发挑战-响应防御。
 *          所有操作在同一线程(worker io_context)上执行,无需 mutex。
 */

#pragma once

#include <prism/core/memory/container.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <span>
#include <unordered_map>


namespace psm::stealth
{

    /**
     * @brief 地址哈希键(IPv4 直接存储,IPv6 用 BLAKE3 哈希 /64 前缀)
     */
    struct address_hash
    {
        std::array<std::byte, 16> bytes{};

        [[nodiscard]] auto operator==(const address_hash &) const noexcept -> bool = default;

        /// 从 IPv4 地址构造(写入前 4 字节,其余置零)
        [[nodiscard]] static auto from_v4(std::uint32_t ip) noexcept -> address_hash;

        /// 从 IPv6 地址构造(取前 16 字节作为 key)
        [[nodiscard]] static auto from_v6(std::span<const std::byte, 16> addr) noexcept -> address_hash;

        /// 从 boost::asio endpoint 构造(IPv4/IPv6 自动判断)
        [[nodiscard]] static auto from_endpoint(
            bool is_v6, const std::uint8_t *addr_bytes, std::size_t addr_len) noexcept -> address_hash;
    };

    /**
     * @brief address_hash 的 hash 函数
     */
    struct address_hasher
    {
        [[nodiscard]] auto operator()(const address_hash &key) const noexcept -> std::size_t;
    };

    /**
     * @brief 单次探测记录
     */
    struct probe_record
    {
        std::chrono::steady_clock::time_point timestamp;
        std::uint16_t fail_count{0};
        std::uint16_t tier{0};
    };

    /**
     * @brief 探测防御配置
     */
    struct probe_defense_config
    {
        std::uint32_t challenge_timeout_ms{3000};
        std::uint32_t track_window_sec{300};
        std::uint32_t fail_threshold{2};
        std::uint32_t max_records{100000};
    };

    /**
     * @class probe_tracker
     * @brief 探测行为追踪器(per-worker 实例,单线程访问)
     * @details 所有方法在 worker io_context 单线程上调用,无需 mutex。
     *          records_ 使用全局 PMR 池(per-worker 生命周期,非热路径)。
     */
    class probe_tracker
    {
    public:
        explicit probe_tracker(
            std::uint32_t window_sec = 300,
            std::uint32_t threshold = 2,
            std::uint32_t max_records = 100000) noexcept
            : window_sec_(window_sec)
            , threshold_(threshold)
            , max_records_(max_records)
        {
        }

        /// @brief 记录一次探测失败
        auto record(const address_hash &src, std::uint16_t tier) -> void;

        /// @brief 查询指定地址的连续失败次数
        [[nodiscard]] auto fail_count(const address_hash &src) const noexcept -> std::uint16_t;

        /// @brief 检查是否应触发挑战(threshold=0 永远返回 false)
        [[nodiscard]] auto should_challenge(const address_hash &src) const noexcept -> bool;

        /// @brief 认证成功后重置计数
        auto reset(const address_hash &src) -> void;

        /// @brief 清除过期记录,超出 max_records 时淘汰最旧记录
        auto expire() -> void;

    private:
        std::uint32_t window_sec_;
        std::uint32_t threshold_;
        std::uint32_t max_records_;
        std::unordered_map<address_hash, probe_record, address_hasher> records_;
    };

} // namespace psm::stealth
