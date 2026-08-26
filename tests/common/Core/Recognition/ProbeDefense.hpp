/**
 * @file ProbeDefense.hpp
 * @brief 探测行为追踪器(RFC-065 Phase 2)
 * @details per-worker 的主动探测行为追踪。记录每个来源 IP 的
 *          连续握手失败次数,达到阈值后触发挑战-响应防御。
 *          所有操作在同一线程(worker io_context)上执行,无需 mutex。
 */

#pragma once

#include <common/Core/Memory/Container.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <span>
#include <unordered_map>

namespace Preview::Recognition
{

    /**
     * @brief 地址哈希键(IPv4 直接存储,IPv6 用 BLAKE3 哈希 /64 前缀)
     */
    struct AddressHash
    {
        std::array<std::byte, 16> Bytes{};

        [[nodiscard]] auto operator==(const AddressHash &) const noexcept -> bool = default;

        /**
         * 从 IPv4 地址构造(写入前 4 字节,其余置零)
         */
        [[nodiscard]] static auto FromV4(std::uint32_t Ip) noexcept 
            -> AddressHash;

        /**
         * 从 IPv6 地址构造(取前 16 字节作为 key)
         */
        [[nodiscard]] static auto FromV6(std::span<const std::byte, 16> addr) noexcept 
            -> AddressHash;

        /**
         * 从 boost::asio Endpoint 构造(IPv4/IPv6 自动判断)
         */
        [[nodiscard]] static auto FromEndpoint(bool is_v6, std::uint8_t *AddrBytes, std::size_t addr_len) noexcept 
            -> AddressHash;
    };

    /**
     * @brief AddressHash 的 Hash 函数
     */
    struct AddressHasher
    {
        [[nodiscard]] auto operator()(const AddressHash &key) const noexcept -> std::size_t;
    };

    /**
     * @brief 单次探测记录
     */
    struct ProbeRecord
    {
        std::chrono::steady_clock::time_point timestamp;
        std::uint16_t FailCount{0};
        std::uint16_t tier{0};
    };

    /**
     * @brief 探测防御配置
     */
    struct ProbeDefenseConfig
    {
        std::uint32_t ChallengeTimeoutMs{3000};
        std::uint32_t TrackWindowSec{300};
        std::uint32_t FailThreshold{2};
        std::uint32_t MaxRecords{100000};
    };

    /**
     * @class ProbeDefenseTracker
     * @brief 探测行为追踪器(per-worker 实例,单线程访问)
     * @details 所有方法在 worker io_context 单线程上调用,无需 mutex。
     *          Records_ 使用全局 PMR 池(per-worker 生命周期,非热路径)。
     */
    class ProbeDefenseTracker
    {
    public:
        explicit ProbeDefenseTracker(std::uint32_t WindowSec = 300, std::uint32_t Threshold = 2,
                         std::uint32_t MaxRecords = 100000) noexcept
            : WindowSec_(WindowSec), Threshold_(Threshold), MaxRecords_(MaxRecords)
        {
        }

        /**
         * @brief 记录一次探测失败
         * @param src 来源地址哈希
         * @param tier 探测层级
         */
        auto Record(const AddressHash &src, std::uint16_t tier) 
            -> void;

        /**
         * @brief 查询指定地址的连续失败次数
         * @param src 来源地址哈希
         * @return 连续失败次数
         */
        [[nodiscard]] auto FailCount(const AddressHash &src) const noexcept 
            -> std::uint16_t;

        /**
         * @brief 检查是否应触发挑战(threshold=0 永远返回 false)
         * @param src 来源地址哈希
         * @return 是否应触发挑战
         */
        [[nodiscard]] auto ShouldChallenge(const AddressHash &src) const noexcept 
            -> bool;

        /**
         * @brief 认证成功后重置计数
         * @param src 来源地址哈希
         */
        auto Reset(const AddressHash &src) -> void;

        /**
         * @brief 清除过期记录,超出 MaxRecords 时淘汰最旧记录
         */
        auto Expire() -> void;

    private:
        std::uint32_t WindowSec_;
        std::uint32_t Threshold_;
        std::uint32_t MaxRecords_;
        std::unordered_map<AddressHash, ProbeRecord, AddressHasher> Records_;
    };



    inline auto AddressHash::FromV4(std::uint32_t Ip) noexcept 
        -> AddressHash
    {
        AddressHash H{};
        // IPv4 地址写入前 4 字节(大端序)
        H.Bytes[0] = static_cast<std::byte>((Ip >> 24) & 0xFF);
        H.Bytes[1] = static_cast<std::byte>((Ip >> 16) & 0xFF);
        H.Bytes[2] = static_cast<std::byte>((Ip >> 8) & 0xFF);
        H.Bytes[3] = static_cast<std::byte>(Ip & 0xFF);
        return H;
    }

    inline auto AddressHash::FromV6(std::span<const std::byte, 16> addr) noexcept 
        -> AddressHash
    {
        AddressHash H{};
        std::memcpy(H.Bytes.data(), addr.data(), 16);
        return H;
    }

    inline auto AddressHash::FromEndpoint(bool is_v6, std::uint8_t *AddrBytes, std::size_t addr_len) noexcept 
        -> AddressHash
    {
        if (is_v6 && addr_len >= 16)
        {
            AddressHash H{};
            std::memcpy(H.Bytes.data(), AddrBytes, 16);
            return H;
        }
        if (!is_v6 && addr_len >= 4)
        {
            std::uint32_t Ip = (static_cast<std::uint32_t>(AddrBytes[0]) << 24) |
                               (static_cast<std::uint32_t>(AddrBytes[1]) << 16) |
                               (static_cast<std::uint32_t>(AddrBytes[2]) << 8) |
                               static_cast<std::uint32_t>(AddrBytes[3]);
            return FromV4(Ip);
        }
        return {};
    }

    inline auto AddressHasher::operator()(const AddressHash &key) const noexcept
        -> std::size_t
    {
        // FNV-1a Hash,简单高效
        std::size_t H = 14695981039346656037ULL;
        for (auto b : key.Bytes)
        {
            H ^= static_cast<std::size_t>(b);
            H *= 1099511628211ULL;
        }
        return H;
    }

    inline auto ProbeDefenseTracker::Record(const AddressHash &src, std::uint16_t tier) -> void
    {
        auto Now = std::chrono::steady_clock::now();
        auto It = Records_.find(src);
        if (It == Records_.end())
        {
            if (Records_.size() >= MaxRecords_)
            {
                Expire();
            }
            Records_.emplace(src, ProbeRecord{Now, 1, tier});
        }
        else
        {
            It->second.timestamp = Now;
            It->second.FailCount++;
            It->second.tier = tier;
        }
    }

    inline auto ProbeDefenseTracker::FailCount(const AddressHash &src) const noexcept 
        -> std::uint16_t
    {
        auto It = Records_.find(src);
        if (It == Records_.end())
        {
            return 0;
        }
        return It->second.FailCount;
    }

    inline auto ProbeDefenseTracker::ShouldChallenge(const AddressHash &src) const noexcept -> bool
    {
        if (Threshold_ == 0)
        {
            return false;
        }
        return FailCount(src) >= Threshold_;
    }

    inline auto ProbeDefenseTracker::Reset(const AddressHash &src)
        -> void
    {
        Records_.erase(src);
    }

    inline auto ProbeDefenseTracker::Expire() -> void
    {
        const auto Now = std::chrono::steady_clock::now();
        const auto Window = std::chrono::seconds(WindowSec_);

        // 清除过期记录
        for (auto It = Records_.begin(); It != Records_.end();)
        {
            if (Now - It->second.timestamp > Window)
            {
                It = Records_.erase(It);
            }
            else
            {
                ++It;
            }
        }

        // 如果仍超限,淘汰最旧记录
        while (Records_.size() > MaxRecords_)
        {
            auto Oldest = Records_.begin();
            for (auto It = Records_.begin(); It != Records_.end(); ++It)
            {
                if (It->second.timestamp < Oldest->second.timestamp)
                {
                    Oldest = It;
                }
            }
            Records_.erase(Oldest);
        }
    }


} // namespace Preview::Recognition
