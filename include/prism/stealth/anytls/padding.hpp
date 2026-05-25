/**
 * @file padding.hpp
 * @brief AnyTLS padding 方案解析器
 * @details 解析 AnyTLS padding 方案字符串，生成每包的 payload 大小列表。
 * CheckMark (-1) 表示该位置应放入实际 payload。
 *
 * 格式示例：
 * stop=8
 * 0=30-30
 * 1=100-400
 * 2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000
 * 3=9-9,500-1000
 * 4=500-1000
 * ...
 */
#pragma once

#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

#include <prism/memory/container.hpp>

namespace psm::stealth::anytls
{
    /**
     * @class padding_factory
     * @brief AnyTLS padding 方案解析与大小生成
     * @details 解析 padding 方案字符串，为每个包序号生成 payload 大小列表。
     * CheckMark (-1) 标记实际 payload 的位置。
     * MD5 用于 Settings 交换阶段的服务端/客户端方案比对。
     */
    class padding_factory
    {
    public:
        /// CheckMark 值：此位置放入实际 payload
        static constexpr std::int32_t checkmark = -1;

        /**
         * @brief 默认构造（使用空方案，不做 padding）
         */
        padding_factory() = default;

        /**
         * @brief 解析 padding 方案字符串
         * @param raw_scheme 原始方案字符串
         */
        explicit padding_factory(std::string_view raw_scheme);

        /**
         * @brief 生成第 pkt 个包的 payload 大小列表
         * @param pkt 包序号（从 0 开始）
         * @return 大小列表，-1 表示 CheckMark（放实际 payload），正数为随机 padding 大小
         */
        [[nodiscard]] auto generate_sizes(std::uint32_t pkt) const
            -> std::vector<std::int32_t>;

        /**
         * @brief 是否启用 padding
         */
        [[nodiscard]] auto enabled() const noexcept
            -> bool
        {
            return stop > 0;
        }

        /// 前 N 个包做 padding，之后停止
        std::uint32_t stop{0};

        /// MD5(raw_scheme)，用于 Settings 交换比对
        memory::string md5;

    private:
        /// 每个包序号对应的 segment 列表
        /// segment 格式: "min-max" 或 "c"
        memory::unordered_map<std::int32_t, memory::string> scheme_;

        friend class anytls_session;
        /// 原始方案字节（用于 MD5 计算和 UpdatePaddingScheme 发送）
        memory::string raw_scheme_;
    };
} // namespace psm::stealth::anytls
