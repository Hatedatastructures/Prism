/**
 * @file script.hpp
 * @brief Restls 流量控制脚本解析器
 * @details 解析 Restls script 字符串，生成按序执行的 script_line 序列。
 * 每条 script_line 描述一个 TLS 记录的填充策略和写阻塞行为。
 *
 * Script 语法：逗号分隔的规则列表，每条格式：
 *   targetLen[~randomRange|?randomRange][<responseCount]
 *
 * 示例："250?100<1,350~100<1,600~100,300~200,300~100"
 * - 250?100<1 : base=250, 一次性随机 +rand(100), 等待 1 个响应
 * - 350~100<1 : base=350, 每次动态 +rand(100), 等待 1 个响应
 * - 600~100   : base=600, 每次动态 +rand(100), 无阻塞
 */
#pragma once

#include <prism/core/memory/container.hpp>

#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <vector>


namespace psm::stealth::restls
{

    /**
     * @enum command_type
     * @brief Script 行命令类型
     */
    enum class command_type : std::uint8_t
    {
        noop = 0x00,     // 无需响应
        response = 0x01  // 请求随机响应
    }; // enum class command_type

    /**
     * @struct script_line
     * @brief 单条 script 规则
     * @details 描述一个 TLS 记录的目标长度和命令行为。
     * ? 语法在解析时一次性 resolve（random_is_fixed=true），
     * ~ 语法每次调用 target_length() 动态计算。
     */
    struct script_line
    {
        std::int16_t target_base{0};       // 基础目标长度
        std::int16_t target_random{0};     // 随机范围
        bool random_is_fixed{false};       // true = ?语法（已 resolve）
        command_type cmd{command_type::noop};
        std::uint8_t response_count{0};

        /**
         * @brief 获取本次目标长度
         * @details random_is_fixed 时直接返回 target_base + target_random；
         * 否则动态计算 target_base + rand(0..target_random)。
         * @return 目标 TLS 记录 payload 长度
         */
        [[nodiscard]] auto target_length() const
            -> std::int16_t;
    }; // struct script_line

    /**
     * @struct allocation
     * @brief 单次写入分配方案
     * @details 由 script_engine 根据 counter 和可用数据量计算，
     * 描述本次 TLS 记录的 payload 布局。
     */
    struct allocation
    {
        std::int16_t payload_len{0};    // 含 auth_header 的完整 payload
        std::int16_t data_len{0};       // 实际用户数据长度
        std::int16_t padding_len{0};    // 填充长度
        command_type cmd{command_type::noop};
        std::uint8_t response_count{0};
        bool write_blocking{false};     // 是否阻塞后续写入
    }; // struct allocation

    /**
     * @class script_engine
     * @brief Script 解析与分配引擎
     * @details 解析 script 字符串为 script_line 序列，
     * 按 counter 递进为每次写入生成分配方案。
     */
    class script_engine
    {
    public:
        /**
         * @brief 默认构造（使用默认脚本）
         * @details 空 script 时使用内置默认脚本。
         */
        script_engine() = default;

        /**
         * @brief 解析 script 字符串
         * @param script Restls script 字符串
         */
        explicit script_engine(std::string_view script);

        /**
         * @brief 根据 counter 和可用数据量计算分配方案
         * @details counter < lines_.size() 时使用对应行的 target_length，
         * 否则无 padding。data_len==0 时填充随机 padding。
         * @param counter 写入计数器
         * @param data_available 待写入的可用用户数据量
         * @return 本次写入的分配方案
         */
        [[nodiscard]] auto allocate(std::uint64_t counter, std::size_t data_available) const
            -> allocation;

        /**
         * @brief 获取解析后的 script 行数
         */
        [[nodiscard]] auto size() const noexcept
            -> std::size_t
        {
            return lines_.size();
        }

    private:
        memory::vector<script_line> lines_;
    }; // class script_engine
} // namespace psm::stealth::restls
