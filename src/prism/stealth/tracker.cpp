/**
 * @file probe_tracker.cpp
 * @brief 探测行为追踪器实现
 */

#include <prism/stealth/tracker.hpp>

#include <algorithm>
#include <cstring>

namespace psm::stealth
{

    auto address_hash::from_v4(std::uint32_t ip) noexcept -> address_hash
    {
        address_hash h{};
        // IPv4 地址写入前 4 字节(大端序)
        h.bytes[0] = static_cast<std::byte>((ip >> 24) & 0xFF);
        h.bytes[1] = static_cast<std::byte>((ip >> 16) & 0xFF);
        h.bytes[2] = static_cast<std::byte>((ip >> 8) & 0xFF);
        h.bytes[3] = static_cast<std::byte>(ip & 0xFF);
        return h;
    }


    auto address_hash::from_v6(std::span<const std::byte, 16> addr) noexcept -> address_hash
    {
        address_hash h{};
        std::memcpy(h.bytes.data(), addr.data(), 16);
        return h;
    }


    auto address_hash::from_endpoint(
        bool is_v6, const std::uint8_t *addr_bytes, std::size_t addr_len) noexcept -> address_hash
    {
        if (is_v6 && addr_len >= 16)
        {
            address_hash h{};
            std::memcpy(h.bytes.data(), addr_bytes, 16);
            return h;
        }
        if (!is_v6 && addr_len >= 4)
        {
            std::uint32_t ip = (static_cast<std::uint32_t>(addr_bytes[0]) << 24) |
                               (static_cast<std::uint32_t>(addr_bytes[1]) << 16) |
                               (static_cast<std::uint32_t>(addr_bytes[2]) << 8) |
                               static_cast<std::uint32_t>(addr_bytes[3]);
            return from_v4(ip);
        }
        return {};
    }


    auto address_hasher::operator()(const address_hash &key) const noexcept -> std::size_t
    {
        // FNV-1a hash,简单高效
        std::size_t h = 14695981039346656037ULL;
        for (auto b : key.bytes)
        {
            h ^= static_cast<std::size_t>(b);
            h *= 1099511628211ULL;
        }
        return h;
    }


    auto probe_tracker::record(const address_hash &src, std::uint16_t tier) -> void
    {
        auto now = std::chrono::steady_clock::now();
        auto it = records_.find(src);
        if (it == records_.end())
        {
            if (records_.size() >= max_records_)
                expire();
            records_.emplace(src, probe_record{now, 1, tier});
        }
        else
        {
            it->second.timestamp = now;
            it->second.fail_count++;
            it->second.tier = tier;
        }
    }


    auto probe_tracker::fail_count(const address_hash &src) const noexcept -> std::uint16_t
    {
        auto it = records_.find(src);
        if (it == records_.end())
            return 0;
        return it->second.fail_count;
    }


    auto probe_tracker::should_challenge(const address_hash &src) const noexcept -> bool
    {
        if (threshold_ == 0)
            return false;
        return fail_count(src) >= threshold_;
    }


    auto probe_tracker::reset(const address_hash &src) -> void
    {
        records_.erase(src);
    }


    auto probe_tracker::expire() -> void
    {
        const auto now = std::chrono::steady_clock::now();
        const auto window = std::chrono::seconds(window_sec_);

        // 清除过期记录
        for (auto it = records_.begin(); it != records_.end();)
        {
            if (now - it->second.timestamp > window)
                it = records_.erase(it);
            else
                ++it;
        }

        // 如果仍超限,淘汰最旧记录
        while (records_.size() > max_records_)
        {
            auto oldest = records_.begin();
            for (auto it = records_.begin(); it != records_.end(); ++it)
            {
                if (it->second.timestamp < oldest->second.timestamp)
                    oldest = it;
            }
            records_.erase(oldest);
        }
    }

} // namespace psm::stealth
