/**
 * @file executor.hpp
 * @brief 伪装方案执行器
 * @details 根据分析结果或配置优先级执行方案管道。
 */

#pragma once

#include <memory>
#include <vector>
#include <boost/asio.hpp>
#include <prism/stealth/scheme.hpp>
#include <prism/recognition/result.hpp>
#include <prism/recognition/handshake/priority.hpp>

namespace psm::recognition::handshake
{
    namespace net = boost::asio;

    /**
     * @class scheme_executor
     * @brief 伪装方案执行器
     * @details 根据分析结果或配置优先级执行方案管道。
     * 支持三种执行模式：
     * 1. analysis_driven: 按 analysis_result.candidates 顺序执行
     * 2. config_driven: 按 execution_priority.order 顺序执行
     * 3. hybrid: 分析优先 + 配置兜底
     *
     * **执行流程**：
     * 1. 获取候选方案列表
     * 2. 对每个候选方案：
     *    - 检查 is_enabled()
     *    - 执行 execute()
     *    - 成功则返回
     *    - 失败(not_me)则继续下一个
     * 3. 所有候选失败则执行 Native 兜底
     *
     * **与现有 stealth 模块关系**：
     * - executor 持有 stealth::shared_scheme 列表
     * - 通过 stealth::scheme::execute() 执行方案
     * - 返回 stealth::scheme_result 封装为 execution_result
     */
    class scheme_executor
    {
    public:
        /**
         * @brief 构造执行器
         * @param schemes 所有注册的方案列表
         */
        explicit scheme_executor(std::vector<stealth::shared_scheme> schemes);

        /**
         * @brief 按分析结果执行方案
         * @param analysis ClientHello 分析结果
         * @param ctx 方案执行上下文
         * @return 执行结果
         * @details 按 analysis.candidates 顺序执行方案。
         */
        [[nodiscard]] auto execute_by_analysis(const analysis_result &analysis, stealth::scheme_context ctx) const
            -> net::awaitable<execution_result>;

        /**
         * @brief 按配置优先级执行方案
         * @param priority 执行优先级配置
         * @param ctx 方案执行上下文
         * @return 执行结果
         * @details 按 priority.order 顺序执行方案。
         */
        [[nodiscard]] auto execute_by_priority(const execution_priority &priority, stealth::scheme_context ctx) const
            -> net::awaitable<execution_result>;

        /**
         * @brief 注册方案
         * @param scheme 方案实例
         */
        auto register_scheme(stealth::shared_scheme scheme) -> void;

        /**
         * @brief 创建默认执行器
         * @return 包含所有默认方案的执行器
         * @details 创建并注册 Reality/ShadowTLS/RestLS/Native 方案。
         */
        static auto create_default() -> std::unique_ptr<scheme_executor>;

    private:
        std::vector<stealth::shared_scheme> schemes_;

        /**
         * @brief 查找方案 by name
         * @param name 方案名称
         * @return 方案实例，如果不存在返回 nullptr
         */
        [[nodiscard]] auto find_scheme(std::string_view name) const -> stealth::shared_scheme;

        /**
         * @brief 执行单个方案
         * @param scheme 方案实例
         * @param ctx 执行上下文
         * @return 执行结果
         */
        static auto execute_single(stealth::shared_scheme scheme, stealth::scheme_context ctx)
            -> net::awaitable<execution_result>;
    };
} // namespace psm::recognition::handshake