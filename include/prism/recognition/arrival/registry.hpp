/**
 * @file registry.hpp
 * @brief ClientHello 特征分析器注册表
 * @details 单例模式，管理所有 feature 的注册和执行。
 * 注册仅在启动阶段（静态初始化），运行时只读，无需同步。
 */

#pragma once

#include <vector>
#include <prism/recognition/arrival/feature.hpp>
#include <prism/recognition/result.hpp>

// 前置声明
namespace psm
{
    struct config;
} // namespace psm

namespace psm::recognition::arrival
{
    /**
     * @class registry
     * @brief 特征注册表（单例）
     * @details 管理所有 feature 的注册和执行。
     * 启动时各方案通过 REGISTER_ARRIVAL 宏注册，
     * session 调用 analyze() 执行所有启用的 feature 并合并结果。
     *
     * **使用流程**：
     * 1. 各方案实现 feature 子类
     * 2. 在实现文件末尾使用 REGISTER_ARRIVAL 宏注册
     * 3. session 调用 registry::instance().analyze(features, cfg)
     * 4. 根据返回的 analysis_result 执行方案
     */
    class registry
    {
    public:
        static auto instance() -> registry &;

        /**
         * @brief 注册 feature
         * @param f feature 实例
         * @details 启动阶段调用，使用 REGISTER_ARRIVAL 宏自动注册。
         */
        auto add(shared_feature f) -> void;

        /**
         * @brief 执行所有启用的 feature
         * @param features 已提取的 ClientHello 特征
         * @param cfg 全局配置
         * @return 合并的分析结果，按置信度排序
         */
        [[nodiscard]] auto analyze(const arrival_features &features,const config &cfg) const
            -> analysis_result;

        /**
         * @brief 获取所有注册的 feature
         * @return feature 列表的 const 引用
         */
        [[nodiscard]] auto features() const -> const std::vector<shared_feature> &;

    public:
        /**
         * @brief 默认构造函数（供测试使用本地实例）
         */
        registry() = default;

    private:
        std::vector<shared_feature> features_;
    };

    /**
     * @def REGISTER_ARRIVAL
     * @brief 注册 feature 的便捷宏
     * @details 新方案只需在实现文件末尾添加一行。
     *
     * **使用示例**：
     * ```cpp
     * // reality.cpp 末尾
     * REGISTER_ARRIVAL(psm::recognition::arrival::reality)
     * ```
     */
    #define REGISTER_ARRIVAL(FeatureClass)                           \
        namespace                                                          \
        {                                                                  \
            inline const bool &_feature_registered_ = [] {                \
                psm::recognition::arrival::registry::instance()       \
                    .add(std::make_shared<FeatureClass>());               \
                return true;                                                \
            }();                                                            \
        }
} // namespace psm::recognition::arrival