/**
 * @file executor.hpp
 * @brief 伪装方案执行器
 * @details 根据分析结果依次尝试伪装方案，直到某个方案成功。
 * 每个方案执行后通过 detected 类型判断是否"是我"：返回 TLS 表示不匹配，
 * 继续下一个；返回具体协议表示匹配，终止执行。全部失败时返回错误。
 * 执行器从 scheme_registry 构建，不硬编码方案列表。
 */

#pragma once

#include <vector>
#include <boost/asio.hpp>
#include <prism/stealth/scheme.hpp>
#include <prism/stealth/registry.hpp>
#include <prism/recognition/result.hpp>

namespace psm::stealth
{
    namespace net = boost::asio;

    /**
     * @class scheme_executor
     * @brief 伪装方案执行器
     * @details 按候选方案列表依次尝试执行，支持分析驱动模式。
     * 从 scheme_registry 构建，不硬编码方案列表。
     */
    class scheme_executor
    {
    public:
        /**
         * @brief 从注册表构建执行器
         * @param registry 方案注册表
         */
        explicit scheme_executor(const scheme_registry &registry);

        /**
         * @brief 按分析结果驱动执行方案管道
         * @param analysis ClientHello 分析结果（含候选方案名称列表）
         * @param ctx 方案执行上下文
         * @return 执行结果
         * @details 候选为空时按注册顺序执行；全部失败则执行 native 兜底。
         * 每个方案返回 TLS 表示 "不是我"，transport 和 preread 数据传递给下一个方案。
         */
        [[nodiscard]] auto execute_by_analysis(const recognition::analysis_result &analysis, scheme_context ctx) const
            -> net::awaitable<scheme_result>;

        /**
         * @brief 按候选列表执行方案管道
         * @param candidates 候选方案名称列表
         * @param ctx 方案执行上下文
         * @return 执行结果
         */
        [[nodiscard]] auto execute(const memory::vector<memory::string> &candidates, scheme_context ctx) const
            -> net::awaitable<scheme_result>;

    private:
        std::vector<shared_scheme> schemes_;

        [[nodiscard]] auto find_scheme(std::string_view name) const -> shared_scheme;

        [[nodiscard]] static auto execute_single(shared_scheme scheme, scheme_context ctx)
            -> net::awaitable<scheme_result>;

        static auto pass_through(scheme_context &ctx, const scheme_result &res) -> void;

        [[nodiscard]] auto execute_pipeline(const memory::vector<memory::string> &order, scheme_context ctx) const
            -> net::awaitable<scheme_result>;
    };

} // namespace psm::stealth
