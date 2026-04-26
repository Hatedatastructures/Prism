/**
 * @file registry.hpp
 * @brief ClientHello 特征分析器注册表
 * @details 单例模式，管理所有 feature_analyzer 的注册和执行。
 * 线程安全设计，支持静态注册和动态查询。
 */

#pragma once

#include <vector>
#include <mutex>
#include <prism/recognition/clienthello/analyzer.hpp>
#include <prism/recognition/result.hpp>

// 前置声明
namespace psm
{
    struct config;
} // namespace psm

namespace psm::recognition::clienthello
{
    /**
     * @class analyzer_registry
     * @brief 特征分析器注册表（单例，线程安全）
     * @details 管理所有 ClientHello 特征分析器的注册和执行。
     * 启动时各方案通过 REGISTER_CLIENTHELLO_ANALYZER 宏注册分析器，
     * session 调用 analyze() 执行所有启用的分析器并合并结果。
     *
     * **使用流程**：
     * 1. 各方案实现 feature_analyzer 子类
     * 2. 在实现文件末尾使用 REGISTER_CLIENTHELLO_ANALYZER 宏注册
     * 3. session 调用 analyzer_registry::instance().analyze(features, cfg)
     * 4. 根据返回的 analysis_result 执行方案
     *
     * **线程安全**：
     * - 注册操作使用 mutex 保护（启动阶段）
     * - 分析操作只读，无锁
     */
    class analyzer_registry
    {
    public:
        /**
         * @brief 获取单例实例
         * @return 注册表单例引用
         */
        static auto instance() -> analyzer_registry &;

        /**
         * @brief 注册分析器
         * @param analyzer 分析器实例
         * @details 启动阶段调用，添加分析器到注册表。
         * 使用 REGISTER_CLIENTHELLO_ANALYZER 宏自动注册。
         */
        auto register_analyzer(shared_analyzer analyzer) -> void;

        /**
         * @brief 执行所有启用的分析器
         * @param features 已提取的 ClientHello 特征
         * @param cfg 全局配置
         * @return 合并的分析结果
         * @details 按置信度排序候选方案，高置信度在前。
         */
        [[nodiscard]] auto analyze(
            const clienthello_features &features,
            const psm::config &cfg) const -> analysis_result;

        /**
         * @brief 获取所有启用的分析器
         * @param cfg 全局配置
         * @return 启用的分析器列表
         */
        [[nodiscard]] auto get_enabled_analyzers(const psm::config &cfg) const
            -> std::vector<shared_analyzer>;

        /**
         * @brief 获取所有注册的分析器
         * @return 所有分析器列表
         */
        [[nodiscard]] auto get_all_analyzers() const -> const std::vector<shared_analyzer> &;

    private:
        analyzer_registry() = default;
        std::vector<shared_analyzer> analyzers_;
        std::mutex mutex_; // 保护注册操作
    };

    /**
     * @def REGISTER_CLIENTHELLO_ANALYZER
     * @brief 注册分析器的便捷宏
     * @details 新方案只需在实现文件末尾添加一行注册。
     * 使用静态初始化在程序启动时自动注册。
     *
     * **使用示例**：
     * ```cpp
     * // reality.cpp 末尾
     * REGISTER_CLIENTHELLO_ANALYZER(psm::recognition::clienthello::reality_analyzer)
     * ```
     */
    #define REGISTER_CLIENTHELLO_ANALYZER(AnalyzerClass)                           \
        namespace                                                                   \
        {                                                                           \
            inline const bool &_analyzer_registered_ = [] {                         \
                psm::recognition::clienthello::analyzer_registry::instance()        \
                    .register_analyzer(std::make_shared<AnalyzerClass>());          \
                return true;                                                         \
            }();                                                                     \
        }
} // namespace psm::recognition::clienthello