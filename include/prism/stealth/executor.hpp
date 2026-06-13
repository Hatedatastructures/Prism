/**
 * @file executor.hpp
 * @brief 伪装方案执行器
 * @details 根据分析结果依次尝试伪装方案，直到某个方案成功。
 * 每个方案执行后通过 detected 类型判断是否"是我"：返回 TLS 表示不匹配，
 * 继续下一个；返回具体协议表示匹配，终止执行。全部失败时返回错误。
 * 执行器从 scheme_registry 构建，不硬编码方案列表。
 */

#pragma once

#include <prism/stealth/recognition/result.hpp>
#include <prism/stealth/registry.hpp>
#include <prism/stealth/scheme.hpp>

#include <boost/asio.hpp>

#include <vector>


namespace psm::stealth
{

    namespace net = boost::asio;

    /**
     * @brief 传输层回绕模式
     * @details 控制方案执行失败后是否可以回绕传输层到握手前状态
     */
    enum class rewind_mode : std::uint8_t
    {
        clean,     ///< 传输层未被污染，可以安全回绕
        polluted   ///< 传输层已被写入数据，不可回绕
    };

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
        [[nodiscard]] auto execute_by_analysis(const recognition::analysis_result &analysis, handshake_context ctx) const
            -> net::awaitable<handshake_result>;

        /**
         * @brief 按候选列表执行方案管道
         * @param candidates 候选方案名称列表
         * @param ctx 方案执行上下文
         * @return 执行结果
         */
        [[nodiscard]] auto execute(const memory::vector<memory::string> &candidates, handshake_context ctx) const
            -> net::awaitable<handshake_result>;

    private:
        std::vector<shared_scheme> schemes_;

        [[nodiscard]] auto find_scheme(std::string_view name) const
            -> shared_scheme;

        [[nodiscard]] static auto execute_single(shared_scheme scheme, handshake_context ctx)
            -> net::awaitable<handshake_result>;

        static void pass_through(handshake_context &ctx, const handshake_result &res);

        static void ensure_snapshot(handshake_context &ctx);

        [[nodiscard]] static auto try_rewind(handshake_context &ctx, rewind_mode mode = rewind_mode::clean)
            -> bool;

        [[nodiscard]] auto execute_pipeline(const memory::vector<memory::string> &order, handshake_context ctx) const
            -> net::awaitable<handshake_result>;
    };

} // namespace psm::stealth