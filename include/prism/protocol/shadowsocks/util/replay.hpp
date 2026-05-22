/**
 * @file replay.hpp
 * @brief WireGuard 风格 PacketID 滑动窗口重放检测
 * @details SS2022 (SIP022) UDP 使用 PacketID 进行重放保护。
 * 采用 WireGuard 式滑动窗口：维护最近 N 个 PacketID 的位图，
 * 拒绝窗口外的旧包和重复包
 */

#pragma once

#include <bitset>
#include <cstdint>

namespace psm::protocol::shadowsocks
{
    /**
     * @class replay_window
     * @brief PacketID 滑动窗口重放过滤器
     * @details 窗口大小 64，支持 64 位 PacketID 空间。
     * 线程不安全，每个 UDP 会话独立持有
     * @note 每个 UDP 会话独立持有，无需线程同步
     */
    class replay_window
    {
    public:
        static constexpr std::size_t window_size = 64;

        /**
         * @brief 检查并更新 PacketID
         * @param packet_id 收到的 PacketID（大端序转本地后的值）
         * @return true 表示首次出现（可接受），false 表示重放或太旧
         */
        auto check_and_update(std::uint64_t packet_id) -> bool
        {
            // 首次使用：任何值都接受
            if (!initialized_)
            {
                base_ = packet_id;
                bitmap_.reset();
                bitmap_.set(0);
                initialized_ = true;
                return true;
            }

            // 在窗口右侧：移动窗口
            if (packet_id >= base_ + window_size)
            {
                const auto shift = packet_id - base_ - (window_size - 1);
                if (shift >= window_size)
                {
                    // 完全跳过窗口，重置
                    bitmap_.reset();
                }
                else
                {
                    // 部分移动：利用 std::bitset 移位操作符一次性完成
                    bitmap_ >>= shift;
                }
                base_ = packet_id - (window_size - 1);
                bitmap_.set(window_size - 1);
                return true;
            }

            // 在窗口内部
            if (packet_id >= base_)
            {
                const auto idx = packet_id - base_;
                if (bitmap_.test(idx))
                {
                    return false; // 重复
                }
                bitmap_.set(idx);
                return true;
            }

            // 在窗口左侧（太旧）
            return false;
        }

    private:
        std::uint64_t base_{0};
        std::bitset<window_size> bitmap_;
        bool initialized_{false};
    };
} // namespace psm::protocol::shadowsocks
