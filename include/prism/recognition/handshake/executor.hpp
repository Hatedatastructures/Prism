/**
 * @file executor.hpp
 * @brief 伪装方案执行器
 * @details 根据分析结果或配置优先级依次尝试伪装方案，直到某个方案成功。
 * 每个方案执行后通过 detected 类型判断是否"是我"：返回 TLS 表示不匹配，
 * 继续下一个；返回具体协议表示匹配，终止执行。全部失败时返回错误。
 * 调用方应通过 create_default() 或手动注册方案后使用。
 * @note 执行器持有 scheme 列表，方案由调用方注册或 create_default() 初始化。
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
     * @details 按给定名称列表依次尝试执行伪装方案，支持分析驱动和配置驱动两种模式。
     * 核心逻辑：对每个候选方案调用 find_scheme → is_enabled → execute，
     * 返回 TLS 则继续下一个，返回具体协议则终止，返回错误则终止。
     * 方案列表在构造时确定，可通过 register_scheme() 追加。
     * @note 默认方案顺序：reality → shadowtls → restls → native
     */
    class scheme_executor
    {
    public:
        /**
         * @brief 构造函数
         * @param schemes 已注册的方案列表
         * @details 方案列表确定后可用方案的完整集合，后续可通过 register_scheme 追加。
         */
        explicit scheme_executor(std::vector<stealth::shared_scheme> schemes);

        /**
         * @brief 按分析结果驱动执行方案管道
         * @param analysis ClientHello 分析结果（含候选方案列表）
         * @param ctx 方案执行上下文（含传输层、配置、router、session）
         * @return 执行结果，成功时含识别出的协议类型和传输层
         * @details 候选为空时回退到默认顺序 reality → shadowtls → restls → native；
         * 全部失败则执行 native 兜底。每个方案返回 TLS 表示 "不是我"，
         * transport 和 preread 数据会传递给下一个方案，避免数据丢失。
         */
        [[nodiscard]] auto execute_by_analysis(const analysis_result &analysis, stealth::scheme_context ctx) const
            -> net::awaitable<stealth::scheme_result>;

        /**
         * @brief 按配置优先级执行方案管道
         * @param priority 执行优先级配置（含用户定义顺序）
         * @param ctx 方案执行上下文
         * @return 执行结果
         * @details 完全按 priority.order 定义的顺序执行，不参考分析结果。
         * 预留供配置驱动场景使用。
         */
        [[nodiscard]] auto execute_by_priority(const execution_priority &priority, stealth::scheme_context ctx) const
            -> net::awaitable<stealth::scheme_result>;

        /**
         * @brief 注册方案
         * @param scheme 方案实例
         * @details 追加方案到已注册列表，后续 execute 时可被 find_scheme 找到。
         */
        auto register_scheme(stealth::shared_scheme scheme) -> void;

        /**
         * @brief 创建默认执行器
         * @return 已注册所有默认方案的执行器
         * @details 注册顺序即为默认优先级：reality → shadowtls → restls → native。
         */
        static auto create_default() -> std::unique_ptr<scheme_executor>;

    private:
        std::vector<stealth::shared_scheme> schemes_;

        /**
         * @brief 按名称查找方案
         * @param name 方案名称
         * @return 找到的方案，未找到返回 nullptr
         */
        [[nodiscard]] auto find_scheme(std::string_view name) const -> stealth::shared_scheme;

        /**
         * @brief 执行单个方案
         * @param scheme 方案实例
         * @param ctx 执行上下文
         * @return 方案原始执行结果
         * @details 调用 scheme->execute() 完成实际握手，写入 executed_scheme 字段。
         */
        [[nodiscard]] static auto execute_single(stealth::shared_scheme scheme, stealth::scheme_context ctx)
            -> net::awaitable<stealth::scheme_result>;

        /**
         * @brief 将 transport 和 preread 传递给下一个方案
         * @param ctx 上下文（inbound 会被更新）
         * @param res 上一个方案的执行结果
         * @details 使用 preview 原语包装传输层，确保下一个方案能读到已消耗的数据。
         */
        static auto pass_through(stealth::scheme_context &ctx, const stealth::scheme_result &res) -> void;

        /**
         * @brief 核心管道：按名称列表逐个执行方案
         * @param order 方案名称列表
         * @param ctx 执行上下文
         * @return 执行结果
         * @details 遍历 order 中的每个名称，执行 find_scheme → is_enabled → execute，
         * 返回 TLS 时调用 pass_through 更新上下文继续下一个。
         */
        [[nodiscard]] auto execute_pipeline(const memory::vector<memory::string> &order, stealth::scheme_context ctx) const
            -> net::awaitable<stealth::scheme_result>;
    };
} // namespace psm::recognition::handshake
