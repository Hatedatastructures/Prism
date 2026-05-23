/**
 * @file account.hpp
 * @brief 账户统计观察者
 * @details 从 account::directory 读取快照，不修改 entry。
 * stats 模块只做观察者，不依赖 stats 的其他头文件。
 */
#pragma once

#include <cstdint>

#include <prism/account/entry.hpp>
#include <prism/account/directory.hpp>
#include <prism/memory/container.hpp>

namespace psm::stats::account
{
    /**
     * @struct account_snapshot
     * @brief 单个账户的统计快照
     * @details 从 account::entry 的原子计数器读取，零写入纯观察者
     */
    struct account_snapshot
    {
        memory::string credential;             ///< 账户凭证哈希
        std::uint64_t uplink_bytes{0};         ///< 上行总字节数
        std::uint64_t downlink_bytes{0};       ///< 下行总字节数
        std::uint32_t active_connections{0};   ///< 当前活跃连接数
        std::uint32_t max_connections{0};      ///< 最大允许连接数
    };

    /**
     * @brief 从 directory 读取所有账户快照
     * @param dir 账户目录（COW 无锁读取）
     * @param mr PMR 内存资源
     * @return 账户快照列表
     * @note 遍历 dir 内部 map，对每个 entry 读三个原子计数器的
     * relaxed 值，构造快照返回。零写入，纯观察者。
     */
    [[nodiscard]] inline auto collect(const psm::account::directory &dir, memory::resource_pointer mr = memory::current_resource())
        -> memory::vector<account_snapshot>
    {
        memory::vector<account_snapshot> result(mr);
        // TODO: 需要在 account::directory 中添加 for_each 遍历接口
        return result;
    }
} // namespace psm::stats::account
